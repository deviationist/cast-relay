# cast-relay — spec

Status: **draft, 2026-11-08**. Nothing built yet. Open questions are marked
**[verify]** (a fact to check on the hardware) or **[decide]** (a choice for
the operator).

## 1. Goal

Make two IoT devices discoverable from the main and guest networks, and make
**nothing else** discoverable across networks:

| Device | IoT address | MAC | Used for |
|---|---|---|---|
| Samsung The Frame (2019, Tizen) | `10.0.30.11` | `aa:bb:cc:00:00:11` | AirPlay, YouTube/Netflix casting (DIAL) |
| Sonos Move (S2) | `10.0.30.192` | `aa:bb:cc:00:00:12` | Sonos app, Spotify Connect, AirPlay |

Both addresses are static leases on the MikroTik (`iot` DHCP server).

Plex is **out of scope** unless the Plex cast test fails (roadmap TODO,
2026-11-08): the TV's Plex app is found through the plex.tv account, not local
discovery.

### Policy

| Flow | Allowed |
|---|---|
| Main/guest client asks "who offers X?" (X on the allowlist) | reaches IoT |
| TV/Sonos answer or announce an allowlisted service | reaches main and guest |
| Any other IoT device's announcements or answers | dropped |
| Any announcement from main or guest | never leaves its own network |
| main ↔ guest | nothing |
| Anything not on the allowlist (service type, SSDP target, record type) | dropped |

The relay **never forwards IP traffic**. It only relays discovery. The actual
connections (AirPlay streams, DIAL HTTP, Sonos control) go through the router
and its firewall (§7).

### Non-goals

- Waking the TV from deep standby (it's off the network then).
- IPv6 (disabled on the router and on every host).
- Casting from the router VPN or Tailscale (discovery doesn't cross tunnels;
  use the main network).
- Discovery *into* IoT for anything except the allowlisted devices.

## 2. Why a relay, not the router

Checked on RouterOS 7.25.1 (2026-11-08):

- **mDNS:** the only control is `/ip dns mdns-repeat-ifaces`, which repeats
  everything between the listed interfaces. Input firewall rules can limit
  *which IoT devices* the repeater hears (UDP 5353 only from the TV and
  Sonos), but not the direction: main and guest must be heard so their
  queries reach IoT, and then their own announcements (Macs, a server's shares,
  guests' phones) are repeated too. The firewall can't tell a query from an
  answer (no payload-offset matching) and the repeater sends everything from
  the router's own address. No service-type filter.
- **SSDP:** RouterOS has nothing. Multicast routing (IGMP proxy, PIM) goes
  the wrong way and wouldn't filter.

## 3. Placement: a RouterOS container

Runs as a container on the RB5009 (arm64, 1 GB RAM, ~975 MB free flash).
The `container` package is installed; `device-mode` has `container: no`, so
enabling it needs the reset-button press (operator, on site).

Not on the servers: that would mean tagging VLANs 52/53 onto a server's
port, making a general-purpose host a bridge into the isolated networks.

### Network attachment

The relay needs a layer-2 presence in all three networks (multicast doesn't
route). One address per network, outside the DHCP pools (all three pools
start at `.20` or higher on IoT/guest and `.10` on the LAN; `.2` is unused on
all three, checked 2026-11-08):

| Network | Interface in container | Address |
|---|---|---|
| main LAN | `lan` | `192.168.1.2/24` |
| guest (VLAN 52) | `guest` | `10.0.20.2/24` |
| IoT (VLAN 53) | `iot` | `10.0.30.2/24` |

**No default route, no gateway.** The relay only talks on-link. It has no
internet and no route between its legs.

Two ways to wire it **[verify]** which RouterOS 7.25 supports:

- **A (preferred): three veths**, one per network, if `/container` accepts
  more than one interface. Each veth is a bridge port with its own PVID
  (1, 52, 53), untagged. The container needs no extra capabilities.
- **B: one veth as a trunk.** Bridge port with PVID 1 plus 52/53 tagged; the
  binary creates `lan`/`guest`/`iot` as VLAN sub-interfaces at start-up.
  Needs `CAP_NET_ADMIN`, which also lets it change its own routing, so prefer
  A.

### Not a router (hard requirement)

At start-up the binary reads `/proc/sys/net/ipv4/ip_forward` and **exits if
it is `1`**. A relay with three legs that forwarded packets would bypass the
isolation entirely. (A new network namespace defaults to `0`; this is a guard
against a misconfiguration, not the primary control.)

## 4. mDNS relay

Listens on `224.0.0.251:5353` on all three interfaces (one socket per
interface, `IP_ADD_MEMBERSHIP` on that interface, `IP_PKTINFO` to know where a
packet came in). Every packet is **parsed, filtered and re-encoded**, never
forwarded byte-for-byte, so nothing the filter didn't understand gets through.

### 4.1 Queries: main/guest → IoT

1. Drop if the source isn't in the receiving interface's subnet, or is the
   relay's own address (loop guard).
2. Drop responses (`QR=1`) arriving on main/guest. Those are announcements of
   client devices and never leave their network.
3. Keep only questions whose name is:
   - an allowlisted service type (`_airplay._tcp.local`, …),
   - `_services._dns-sd._udp.local` (service enumeration), or
   - a **learned name** (§4.3): an instance name or host name an allowlisted
     device has announced. Clients ask for these after browsing (SRV/TXT for
     the instance, A for the host).
4. Strip the answer section (known-answer suppression), the authority section
   (probing) and the additional section. Clear the `QU` (unicast-response)
   bit so answers come back by multicast to the relay.
5. If any questions remain, send the new query from `10.0.30.2:5353` to
   `224.0.0.251` on IoT.
6. Rate limit (§6).

### 4.2 Answers and announcements: IoT → main/guest

1. Drop unless the source IP is an allowlisted device. Optional MAC check
   (§6.2).
2. Drop queries (`QR=0`) from IoT. IoT devices never get to search the client
   networks.
3. Keep only records that belong to that device's allowed services:
   - `PTR` *service type* → *instance* (allowed types only)
   - `PTR` `_services._dns-sd._udp.local` → *allowed type*
   - `SRV` and `TXT` for those instances
   - `A` for the host names those `SRV` records target, **only if the address
     is the device's own IP**
   - `NSEC` for the above (negative answers)
   - Everything else (`AAAA`, other services, `_device-info`, reverse
     `PTR`s, …) is dropped.
4. Re-encode with only the kept records, as an unsolicited response
   (`QR=1, AA=1`, ID 0). Send from the relay's own address on each client
   network allowed for that device (§5) to `224.0.0.251:5353`. Keep TTLs as
   given, so goodbye packets (TTL 0) pass through and devices disappear when
   they go to sleep.

### 4.3 Learned names

From every accepted response, the relay records the instance names (from
`PTR`/`SRV`) and host names (from `SRV` targets) of each allowlisted device,
with the record's TTL. These are the only extra names client queries may ask
for (§4.1 step 3). A learned name expires with its TTL, or immediately on a
goodbye packet.

### 4.4 Cache: none (v1)

The relay doesn't answer from a cache; it always asks the real device. That
keeps it simple and correct (a sleeping TV disappears). **[verify]** that
discovery is quick enough; a cache can come later if it isn't.

## 5. SSDP relay

SSDP is HTTP-over-UDP on `239.255.255.250:1900`. Searches (`M-SEARCH`) are
multicast; answers come back by **unicast, from a random source port** (seen
on this TV), to whoever searched.

### 5.1 Searches: main/guest → IoT

1. Listen on `239.255.255.250:1900` on `lan` and `guest` only. The relay never
   listens for searches on IoT.
2. Parse `M-SEARCH * HTTP/1.1`. Drop if malformed, the source isn't in the
   interface's subnet, or `MAN` isn't `"ssdp:discover"`.
3. Drop unless `ST` is on the allowlist or is `ssdp:all`.
4. Open a fresh UDP socket on `10.0.30.2` (ephemeral port) and send a
   **new** `M-SEARCH` with the same `ST`, `MX` capped at 2, a fixed
   `USER-AGENT`, and none of the client's other headers.
5. For `MX` + 1 s, accept unicast replies on that socket **from any source
   port**. Drop replies whose source IP isn't an allowlisted device.
6. For each accepted reply:
   - It must be `HTTP/1.1 200 OK` with `ST` and `USN`, and an `ST` that is
     allowlisted for that device (for `ssdp:all`, each reply is checked
     separately).
   - `LOCATION` must point at the device's own IP. The port must be in the
     device's `location_ports`.
   - Re-emit it with the headers `CACHE-CONTROL`, `EXT`, `LOCATION`, `SERVER`,
     `ST`, `USN` and (if present) `BOOTID.UPNP.ORG`, `CONFIGID.UPNP.ORG`, and
     nothing else.
   - Send it by unicast from the relay's address on the client's network
     (port 1900) to the client's address and port.
7. Rate limit (§6).

### 5.2 Announcements: IoT → main/guest

`NOTIFY` packets (`ssdp:alive` / `ssdp:byebye`) from allowlisted devices with
an allowlisted `NT` are re-emitted, filtered the same way, as multicast on the
client networks. **[decide]** On by default? It helps apps that only listen
passively. The risk is low because the same allowlist applies.

### 5.3 DIAL quirk (TV)

The TV's DIAL endpoints (`7678/nservice/`, `8080/ws/app/…`) answer **401 to
any source outside its own subnet**. After discovery, the phone fetches
`LOCATION` directly, so something has to make those requests look local.
**[decide]**:

- **(a) Router masquerade (recommended for v1):** srcnat LAN/guest → TV TCP
  7678,8080 to `10.0.30.1`. Two ports, two rules, no relay code. Side effect:
  on those ports the TV can't tell guests from the main network.
- **(b) DIAL proxy in the relay:** rewrite `LOCATION` to the relay's address
  on the client's network and proxy only DIAL paths to the TV from
  `10.0.30.2`. No router NAT, and every TV control request goes through one
  place we control. It costs an HTTP proxy in the relay, and
  `Application-URL` headers and XML bodies need rewriting. Worth it only if
  (a) causes problems.

## 6. Abuse limits

### 6.1 Rate limits

- Per client IP: mDNS 20 queries/s, burst 40. SSDP 2 searches/s, burst 5.
  Excess is dropped silently.
- Global: at most 8 SSDP searches in flight. Reply collection is bounded by
  the `MX` timer, so a flood can't hold sockets open.
- Packet size: mDNS ≤ 9000 bytes (the spec maximum); SSDP ≤ 2048 bytes.
  Larger packets are dropped.

### 6.2 Spoofing

An IoT device that spoofs the TV's IP can only announce services that are
allowlisted for the TV, pointing at the TV's IP. That's annoying, not a
breach. Two optional hardenings:

- **Router (recommended):** bridge filter rules on the IoT VLAN that drop
  frames claiming `10.0.30.11` / `10.0.30.192` from any other MAC. Cheap, and
  it protects more than the relay.
- **Relay:** check the source MAC with an `AF_PACKET` socket. Needs
  `CAP_NET_RAW`, so leave it out of v1.

## 7. Router-side changes (operator applies)

The relay does discovery only. These rules make the connections that follow
it work. The names are only suggestions.

| # | Chain | Rule | Why |
|---|---|---|---|
| F1 | forward | guest → TV `10.0.30.11`, all TCP/UDP | AirPlay picks its ports per session (control and stream), so they can't be listed |
| F2 | forward | guest → Sonos `10.0.30.192` TCP 1400, 1443 **[verify]** plus the Spotify Connect port from its `SRV` | Sonos control; Spotify Connect's zeroconf endpoint |
| F3 | forward | TV → LAN and guest, UDP 49152–65535 | AirPlay timing: the TV opens this connection back to the sender |
| N1 | srcnat | LAN/guest → TV TCP 7678, 8080, masquerade | DIAL quirk (§5.3 a) |
| — | — | main → IoT | already allowed (connections opened from the trusted side) |

All of these sit above the `isolated: internet only` drop. Nothing changes on
the WAN side.

Container setup (sketch, **[verify]** syntax on 7.25):

```
/system/device-mode/update container=yes      # then press the reset button
/interface/veth add name=veth-cast-lan   address=192.168.1.2/24
/interface/veth add name=veth-cast-guest address=10.0.20.2/24
/interface/veth add name=veth-cast-iot   address=10.0.30.2/24
/interface/bridge/port add bridge=bridge interface=veth-cast-lan   pvid=1
/interface/bridge/port add bridge=bridge interface=veth-cast-guest pvid=52
/interface/bridge/port add bridge=bridge interface=veth-cast-iot   pvid=53
# + untagged membership for 52/53 in /interface/bridge/vlan
/container/config set registry-url=https://registry.example.com username=… password=…
/container add remote-image=registry.example.com/cast-relay:<ver> \
    interface=veth-cast-lan,veth-cast-guest,veth-cast-iot \
    start-on-boot=yes logging=yes memory-high=32M root-dir=…
```

**Restart if it crashes:** RouterOS containers have no restart policy, and
device-mode has `scheduler: no`. Instead, a **netwatch** on `10.0.30.2` (the
same mechanism as `fibre-guard`) runs `/container start` when the address
stops answering pings. The binary also recovers from per-packet panics
itself.

## 8. Configuration

One JSON file baked into the image (no volume; flash wear and simplicity).
Changing it means building a new image tag.

```json
{
  "interfaces": {
    "lan":   { "name": "lan",   "addr": "192.168.1.2/24", "role": "client" },
    "guest": { "name": "guest", "addr": "10.0.20.2/24",   "role": "client" },
    "iot":   { "name": "iot",   "addr": "10.0.30.2/24",   "role": "devices" }
  },
  "devices": [
    {
      "name": "frame-tv",
      "ip": "10.0.30.11",
      "clients": ["lan", "guest"],
      "mdns": ["_airplay._tcp", "_raop._tcp"],
      "ssdp": ["urn:dial-multiscreen-org:service:dial:1",
               "urn:dial-multiscreen-org:device:dialreceiver:1"],
      "location_ports": [7678, 8080]
    },
    {
      "name": "sonos-move",
      "ip": "10.0.30.192",
      "clients": ["lan", "guest"],
      "mdns": ["_sonos._tcp", "_spotify-connect._tcp", "_airplay._tcp", "_raop._tcp"],
      "ssdp": [],
      "location_ports": [1400]
    }
  ]
}
```

**[verify]** the service types by observation (`--observe`, §10) before
fixing the lists. For example, whether the Sonos S2 app also needs SSDP
(`urn:schemas-upnp-org:device:ZonePlayer:1`), and whether the TV announces
anything AirPlay needs beyond `_airplay`/`_raop`.

## 9. Build and run

- **Go**, standard library plus `golang.org/x/net/dns/dnsmessage` (the
  standard DNS message parser/builder) and `golang.org/x/net/ipv4` (per-
  interface multicast and `PKTINFO`). No other dependencies.
- `CGO_ENABLED=0 GOARCH=arm64`, `FROM scratch`. Target ≤ 5 MB image, ≤ 16 MB
  RSS.
- Runs as a non-root uid. Ports 1900 and 5353 are above 1024, and joining
  multicast needs no capabilities, so it runs with **no capabilities** in
  layout A.
- Image in `registry.example.com/cast-relay`, pulled by the router with a
  read-only registry account.
- `make test`, `make image`, `make push`; deploying = router-side
  `/container` update (operator).

## 10. Logging and observability

- Logs to stdout as `key=value` lines, picked up by the router (`logging=yes`)
  and forwarded to a server's syslog with the rest of the router log.
- At `info`: start-up (interfaces, allowlist), errors, and a **summary every
  5 min** with counters (queries relayed and dropped, answers passed and
  dropped, by reason). A quiet but healthy relay still says so.
- At `debug`: one line per decision (`mdns drop reason=not-allowlisted
  src=10.0.30.250 name=_roborock._tcp`).
- **`--observe` mode:** relay nothing; log every mDNS/SSDP packet seen on all
  three interfaces (source, type, names, ST/NT). Used once at the start to
  confirm the real service types and the TV's SSDP behaviour, since the
  router's packet sniffer is disabled by device-mode.

## 11. Testing

**Unit:** golden packets (captured in `--observe` mode from the real TV and
Sonos, plus hand-made hostile ones) through the mDNS and SSDP filters: wrong
source, disallowed type, smuggled records in the additional section, `A`
pointing elsewhere, `LOCATION` pointing elsewhere, oversized packets, a
malformed name compression loop.

**Integration (on a Linux host, no router needed):** a test harness creates
three network namespaces joined by veth pairs (client-lan, client-guest, iot)
around a relay namespace, with fake devices (an allowlisted "TV", a
non-allowlisted "robot") and `avahi-browse`/`gssdp-discover` as clients.

**Acceptance (on the real network), from an iPhone and the Mac on `MainWiFi`
and on `GuestWiFi`:**

| Test | Expect |
|---|---|
| AirPlay picker | TV and Sonos listed; mirroring to the TV and audio to the Sonos work |
| Sonos app | Move found and controllable |
| Spotify → devices | Move listed and plays |
| YouTube → cast | TV listed as a local device; launches the app on the TV |
| Netflix → cast | TV listed |
| `dns-sd -B _services._dns-sd._udp` on guest | only the allowlisted types |
| `dns-sd -B _airplay._tcp` on guest | no Macs listed |
| Roborock/Mill | not visible from main or guest |
| From an IoT device | no main/guest services visible |
| TV goes to sleep | disappears from pickers within about a minute |
| Container killed | netwatch restarts it |

## 12. Open questions

1. **[verify]** Several veths per container on 7.25 (layout A vs B).
2. **[verify]** The real service types and SSDP behaviour (`--observe`).
3. **[verify]** Whether Sonos/Spotify Connect need ports beyond 1400/1443
   from guest.
4. **[decide]** DIAL: router masquerade (a) or relay proxy (b). Recommended:
   (a).
5. **[decide]** SSDP `NOTIFY` relaying on by default.
6. **[decide]** Router bridge anti-spoof rules for the TV/Sonos addresses.
7. **[verify]** Whether discovery is fast enough without a cache.
