# cast-relay — spec

Status: **draft, 2026-11-08**. Nothing built yet. Open questions are marked
**[verify]** (a fact to check against real devices or platforms) or
**[decide]** (a design choice still open).

## 1. What it is

A small container that makes **selected** devices on one network discoverable
from other networks, for **mDNS** (Bonjour/zeroconf) and **SSDP** (UPnP,
DIAL), and makes **nothing else** discoverable.

The typical setup: media receivers (smart TVs, speakers, streaming boxes) live
on an isolated IoT network, and people want to cast to them from the main
network or a guest network: AirPlay, YouTube and Netflix (DIAL), Spotify
Connect, Google Cast, Plex.

Existing tools fall short here:

- **mDNS reflectors** (avahi's reflector, router "mDNS repeaters") copy
  everything both ways. Every laptop, phone and file share on the trusted
  network is announced to the IoT and guest networks, and every IoT gadget is
  announced to the trusted network. Filters, where they exist, are by service
  type only, not by device, and they apply to both directions.
- **SSDP** has no common relay at all. Multicast routing (IGMP proxy, PIM)
  doesn't fit the search/unicast-reply pattern and can't filter.

cast-relay is **directional and allowlist-based**: client networks may ask;
only allowlisted devices on device networks may answer; only allowlisted
services and records are passed; nothing is ever announced from a client
network.

## 2. Model

### Terms

- **Client network**: where people cast *from* (main LAN, guest Wi-Fi).
- **Device network**: where the receivers live (IoT VLAN).
- **Device**: an allowlisted receiver on a device network, identified by IP
  address. Each device has a list of **services** it may announce and a list
  of client networks it is **visible to**.
- **Profile**: a named bundle of mDNS service types and SSDP search targets
  for one casting technology (`airplay`, `dial`, …), so the config says what a
  device *does* instead of listing protocol strings.

There may be several client networks and several device networks.

### Policy

| Flow | Result |
|---|---|
| Client asks "who offers X?", where X is allowed for some device visible to that client network | relayed to that device's network |
| Allowlisted device answers or announces an allowed service | relayed to the client networks it is visible to |
| Any other device's answers or announcements | dropped |
| Any announcement or answer from a client network | dropped (never leaves its network) |
| Device network asks anything | dropped (devices never search client networks) |
| Client network ↔ client network | nothing |
| Anything not on the allowlist (service type, search target, record type) | dropped |

### The relay is not a router

It relays **discovery only** and never forwards IP traffic. The connections
that follow discovery (an AirPlay stream, a DIAL HTTP request, a Spotify
Connect handshake) go through the network's router and firewall, which must
allow them (§8).

**Forwarding must be impossible.** A container with legs on several networks
and `net.ipv4.ip_forward=1` is a router: a host on one network that uses the
relay's address as its gateway gets routed into another network by the
kernel, past the real router's firewall, without the relay program doing
anything. At start-up the binary reads `/proc/sys/net/ipv4/ip_forward`:

- `0`: fine.
- `1` and `IP_FORWARD=off` (the default): **exits**.
- `1` and `IP_FORWARD=filtered`: runs, with a warning at every start. The
  operator asserts that the platform drops traffic routed through the relay.

Some platforms start containers with forwarding on and give the container no
way to change it (RouterOS: the namespace has `ip_forward=1`, `/proc/sys` is
read-only, and the relay runs unprivileged). There, block it at layer 2
around each leg (example in §10):

- **out of the relay:** drop IPv4 whose source isn't the relay's own address
  on that leg (forwarded packets keep the original sender's address);
- **into the relay:** accept multicast (`224.0.0.0/4`) and, if GDM is used,
  UDP broadcasts to ports 32410–32414 (both `255.255.255.255` and the
  subnet's broadcast address); drop IPv4 whose destination isn't the relay's
  own address (stops "use the relay as a gateway").

ARP and the relay's own unicast and multicast traffic are unaffected.

### Non-goals

- IPv6 (v1 is IPv4 only; `AAAA` records are dropped).
- Wake-on-LAN or waking devices from deep standby.
- Discovery across routed tunnels (VPNs).
- Caching or answering on a device's behalf (v1 always asks the real device,
  §4.4).

## 3. Network attachment

The relay needs a **layer-2 presence on every network it serves**, because
mDNS and SSDP multicast don't cross routers. One interface and one static
address per network, outside any DHCP pool. **No default route and no
gateway**: the relay only talks on-link.

Platform examples (§10): a RouterOS container with one veth per network, or a
Docker container with host networking on a Linux box that has a VLAN
interface per network.

Interfaces are referred to by name in the config. The relay doesn't create or
configure interfaces; the platform does that. So it needs **no
capabilities** (ports 1900 and 5353 are above 1024, and joining multicast
groups needs no privilege).

## 4. mDNS relay

One socket per interface on `224.0.0.251:5353` (`IP_ADD_MEMBERSHIP` on that
interface, `IP_PKTINFO` to know the ingress interface). Every packet is
**parsed, filtered and re-encoded**, never forwarded byte-for-byte, so nothing
the filter doesn't understand gets through.

### 4.1 Queries: client network → device networks

1. Drop if the source isn't in the receiving interface's subnet, or is one of
   the relay's own addresses (loop guard).
2. Drop responses (`QR=1`). Client devices' announcements stay on their
   network.
3. Keep only questions whose name is:
   - a service type allowed for at least one device visible to this client
     network,
   - `_services._dns-sd._udp.local` (service enumeration), or
   - a **learned name** (§4.3) of such a device: an instance name or host
     name it has announced (clients ask for these after browsing: `SRV`/`TXT`
     for the instance, `A` for the host).
4. Strip the answer section (known-answer suppression), the authority section
   (probing) and the additional section. Clear the `QU` (unicast-response)
   bit, so answers come back by multicast to the relay.
5. If questions remain, send the new query from the relay's address on each
   device network that has a matching device.
6. Rate limit (§6).

### 4.2 Answers and announcements: device network → client networks

1. Drop unless the source IP is an allowlisted device on this network.
2. Drop queries (`QR=0`).
3. Keep only records that belong to that device's allowed services:
   - `PTR` *service type* → *instance*, for allowed types
   - `PTR` `_services._dns-sd._udp.local` → *allowed type*
   - `SRV` and `TXT` for those instances
   - `A` for the host names those `SRV` records target, **only if the address
     is the device's own IP**
   - `NSEC` for the names above (negative answers)
   - everything else (`AAAA`, other services, `_device-info`, reverse `PTR`s,
     …) is dropped
4. Re-encode with only the kept records as an unsolicited response
   (`QR=1, AA=1`, ID 0). Send it from the relay's address on each client
   network the device is visible to, to `224.0.0.251:5353`. TTLs are kept as
   given, so goodbye packets (TTL 0) pass through and a device that goes to
   sleep disappears from pickers.

### 4.3 Learned names

From every accepted response, the relay records each device's instance names
(from `PTR`/`SRV`) and host names (from `SRV` targets), with the record TTL.
These are the only names beyond service types that client queries may ask for
(§4.1). A learned name expires with its TTL, or at once on a goodbye packet.

### 4.4 No cache (v1)

The relay never answers from memory; it always asks the device. That keeps it
simple and correct (a sleeping device disappears). **[verify]** that
discovery is quick enough; a cache can be added later if it isn't.

## 5. SSDP relay

SSDP is HTTP-over-UDP on `239.255.255.250:1900`. Searches (`M-SEARCH`) are
multicast; answers come back by **unicast, often from a random source port**,
to whoever searched. That's why simple socket forwarders (e.g. `socat`) fail
at it.

### 5.1 Searches: client network → device networks

1. Listen on `239.255.255.250:1900` on client networks only. The relay never
   listens for searches on device networks.
2. Parse `M-SEARCH * HTTP/1.1`. Drop if malformed, if the source isn't in the
   interface's subnet, or if `MAN` isn't `"ssdp:discover"`.
3. Drop unless `ST` is allowed for a device visible to this client network,
   or is `ssdp:all`.
4. Open a fresh UDP socket on the relay's device-network address (ephemeral
   port) and send a **new** `M-SEARCH`: same `ST`, `MX` capped at 2, a fixed
   `USER-AGENT`, none of the client's other headers.
5. For `MX` + 1 s, accept unicast replies on that socket **from any source
   port**. Drop replies whose source isn't an allowlisted device.
6. For each accepted reply:
   - It must be `HTTP/1.1 200 OK` with `ST` and `USN`, and an `ST` allowed for
     that device (for `ssdp:all`, each reply is checked on its own).
   - `LOCATION` must point at the device's own IP, on a port in the device's
     `location_ports` if that list is set.
   - Re-emit it with only `CACHE-CONTROL`, `EXT`, `LOCATION`, `SERVER`, `ST`,
     `USN` and, if present, `BOOTID.UPNP.ORG` and `CONFIGID.UPNP.ORG`.
   - Send it by unicast from the relay's address on the client network (port
     1900) to the client's address and port.
7. Rate limit (§6).

### 5.2 Announcements: device network → client networks

`NOTIFY` packets (`ssdp:alive` / `ssdp:byebye`) from allowlisted devices with
an allowed `NT` are filtered the same way and re-emitted as multicast on the
client networks the device is visible to. Controlled by `SSDP_NOTIFY`
(§7.1). **[decide]** the default; some apps only listen passively.

### 5.3 DIAL and subnet-checking devices

DIAL (YouTube, Netflix) continues over HTTP to the device's `LOCATION`. Some
TVs answer **401 Unauthorized to any client outside their own subnet**. Two
remedies, both outside the discovery relay itself:

- **Router source NAT** (simplest): masquerade client → device traffic on the
  DIAL ports, so the device sees the router's own address in its subnet.
- **DIAL proxy in the relay** (v2, **[decide]**): rewrite `LOCATION` to the
  relay's client-side address and proxy only DIAL paths to the device. No
  router NAT, and DIAL control goes through one auditable place. It costs an
  HTTP proxy, plus rewriting `Application-URL` headers and XML bodies.

## 6. Abuse limits

- **Rate limits** per client IP: mDNS 20 queries/s (burst 40), SSDP 2
  searches/s (burst 5). Global: at most 8 SSDP searches in flight; reply
  collection is bounded by the `MX` timer. Excess is dropped silently and
  counted.
- **Packet size:** mDNS ≤ 9000 bytes, SSDP ≤ 2048 bytes.
- **Parser safety:** name-compression loops, truncated records and oversized
  label counts are rejected. A panic while handling one packet is recovered
  and counted; it never takes the relay down.
- **Spoofing:** devices are identified by IP. A device-network host that
  spoofs an allowlisted IP can only announce that device's allowed services,
  pointing at that device's IP. Platforms that can pin IP-to-MAC on the
  device network should do so (§8). A MAC check in the relay itself needs
  `CAP_NET_RAW`, so it's left for later.

## 7. Configuration

Two layers:

- **Environment variables** for simple, general switches.
- **A JSON config file** (normally on a mounted volume) for anything
  structured: interfaces, devices, profiles.

A change to either takes effect on a container restart. The image holds only
the binary.

### 7.1 Environment variables

| Variable | Values | Default | Meaning |
|---|---|---|---|
| `MODE` | `relay`, `observe` | `relay` | `observe` relays nothing and logs every mDNS/SSDP packet on every interface (§9) |
| `LOG_LEVEL` | `info`, `debug` | `info` | `debug` logs one line per relay/drop decision |
| `CONFIG` | path | `/config/cast-relay.json` | the config file |
| `SUMMARY_INTERVAL` | duration | `5m` | how often the counter summary is logged |
| `SSDP_NOTIFY` | `on`, `off` | **[decide]** | relay `NOTIFY` announcements (§5.2) |
| `IP_FORWARD` | `off`, `filtered` | `off` | what to do if the kernel forwards IPv4 in the relay's namespace (§2): `off` refuses to start; `filtered` runs, trusting that the platform drops routed traffic |
| `INTERFACES` | comma list | all | observe mode only: limit to these interface names (relay mode takes them from the config file) |
| `OBSERVE_PROBE` | `on`, `off` | `on` | observe mode: send an mDNS service enumeration (then browse each type found) and an SSDP `ssdp:all` search on every interface |
| `OBSERVE_PROBE_INTERVAL` | duration | `1m` | how often observe mode probes |

Observe mode needs no config file: it listens on every interface with an
IPv4 address.

The rule: a single value that changes how the relay runs is an environment
variable. Anything that describes networks or devices goes in the file.

### 7.2 Config file

```json
{
  "networks": {
    "lan":   { "interface": "eth0", "role": "client" },
    "guest": { "interface": "eth1", "role": "client" },
    "iot":   { "interface": "eth2", "role": "devices" }
  },
  "devices": [
    {
      "name": "living-room-tv",
      "network": "iot",
      "ip": "10.0.30.11",
      "profiles": ["airplay", "dial"],
      "visible_to": ["lan", "guest"]
    },
    {
      "name": "kitchen-speaker",
      "network": "iot",
      "ip": "10.0.30.12",
      "profiles": ["airplay", "spotify-connect"],
      "mdns": ["_vendor-app._tcp"],
      "visible_to": ["lan"]
    }
  ],
  "profiles": {
    "my-custom": { "mdns": ["_example._tcp"], "ssdp": [] }
  }
}
```

- `networks`: the relay reads each interface's IPv4 address and subnet from
  the system; it doesn't set them.
- `devices[].profiles`: built-in (§7.3) or defined under `profiles`.
- `devices[].mdns` / `devices[].ssdp`: extra service types / search targets
  for this device only.
- `devices[].location_ports` (optional): restricts SSDP `LOCATION` ports.

**Validated strictly at start-up:** unknown keys, a missing interface or one
without an IPv4 address, a device IP outside its network's subnet, a
`visible_to` naming a non-client network, an unknown profile, an empty
allowlist, or a malformed service type (`_name._tcp` / `_name._udp`) → the
relay logs the exact error and **exits without relaying anything**. It never
runs half-configured.

### 7.3 Built-in profiles

| Profile | mDNS service types | SSDP search targets | Used by |
|---|---|---|---|
| `airplay` | `_airplay._tcp`, `_raop._tcp` | — | AirPlay video and audio |
| `dial` | — | `urn:dial-multiscreen-org:service:dial:1`, `urn:dial-multiscreen-org:device:dialreceiver:1` | YouTube, Netflix and other DIAL apps |
| `spotify-connect` | `_spotify-connect._tcp` | — | Spotify Connect |
| `googlecast` | `_googlecast._tcp` | — | Chromecast / Google Cast |
| `plex` | `_plexmediasvr._tcp` | — | Plex server announcement (see below) |
| `upnp-media` | — | `urn:schemas-upnp-org:device:MediaRenderer:1`, `urn:schemas-upnp-org:device:MediaServer:1` | DLNA renderers and servers |

**Verified 2026-11-08** with `MODE=observe` against a smart TV, a speaker
and an iPhone's apps: `airplay`, `dial` and `spotify-connect` match what
receivers announce and what senders ask for. `googlecast`, `plex` and
`upnp-media` are unverified. Observations that shaped the design:

- **Senders ask for more than receivers offer**: an iPhone browsing AirPlay
  also asks for `_airplay-bds._tcp`; YouTube asks for `_googlecast._tcp` and
  a subtype (`_233637DE._sub._googlecast._tcp`) next to its DIAL search.
  Unanswered questions are harmless.
- **Receivers offer more than casting needs**: a TV also announced DLNA
  renderer and vendor screen-sharing targets; a speaker about 20 UPnP
  services. Only the allowlist passes.
- **Vendor apps may need their own entries**: one speaker app searched for a
  vendor mDNS type *and* a vendor SSDP target at once, so per-device `mdns`
  and `ssdp` extras (§7.2) are necessary, not a nicety.
- **Senders announce services of their own.** iOS apps check local-network
  access by briefly publishing an instance of a service type and resolving
  it (seen: `_spotify-ln-check._tcp`, and an allowlisted vendor type). This
  is why announcements from client networks are dropped regardless of type
  (§4.1 step 2).
- **SSDP replies come from random ports**, one TV used a different source
  port for each of its 15 replies. A speaker used one port for all of them.
- **TXT records carry identifiers** (serial number, device ID). They pass
  unchanged, because AirPlay needs them.
- Some senders emit SSDP packets with no complete start line; they are
  dropped as malformed.
- Several apps also find devices **through the cloud** (YouTube, Spotify
  Connect) when signed in to the same account, so "it works" on one phone
  does not prove local discovery works. AirPlay and some vendor apps have no
  such fallback.

**Plex:** Plex players are mostly found through the plex.tv account, and
Plex's local discovery (GDM) uses its own broadcast protocol on UDP
32410–32414, not mDNS or SSDP. The `plex` profile covers only the mDNS
announcement. A GDM relay would be a third protocol module (**[decide]**, v2,
only if account-based discovery isn't enough).

## 8. What the network must allow

The relay finds devices; the router must let the follow-up connections
through. Per technology (**[verify]** against real devices):

| Technology | Client → device | Device → client |
|---|---|---|
| AirPlay | TCP and UDP, ports chosen per session (allow all to the device) | UDP 49152–65535 (timing/NTP back to the sender) |
| DIAL (YouTube, Netflix) | TCP to the `LOCATION` port and the app URL port; see §5.3 for subnet-checking TVs | — |
| Spotify Connect | TCP to the port in the device's `SRV` record | — |
| Google Cast | TCP 8008, 8009, 8443 | — |
| Plex player | TCP 32500 (player control), plus the device → Plex server path | — |

Recommended hardening where the platform supports it: pin each allowlisted
device's IP to its MAC on the device network (bridge filter or static ARP),
so another device can't claim its address.

## 9. Logging

- `key=value` lines on stdout.
- `info`: start-up (interfaces, addresses, resolved allowlist), errors, and a
  summary every `SUMMARY_INTERVAL` with counters (relayed and dropped, by
  protocol and reason). A quiet, healthy relay still reports.
- `debug`: one line per decision, e.g.
  `mdns drop reason=not-allowlisted src=10.0.30.50 name=_vacuum._tcp`.
- `MODE=observe`: relays nothing and logs every mDNS/SSDP packet on every
  interface (source, type, names, `ST`/`NT`). Use it first on a new network to
  see what devices really announce before writing the allowlist.

## 10. Platforms

Built as a static binary in a `FROM scratch` image for `linux/arm64` and
`linux/amd64`. Target ≤ 5 MB image, ≤ 16 MB RSS. Runs as a non-root uid with
no capabilities.

**RouterOS 7 container** (e.g. MikroTik RB5009):

- `device-mode` must allow `container` (needs a physical button press).
- One veth per network, each a bridge port with that network's PVID,
  untagged. **[verify]** that one container can take several veths; the
  fallback is a single trunk veth with VLAN sub-interfaces created inside,
  which needs `CAP_NET_ADMIN`.
- Env vars via `/container/envs` (a named list, attached with `envlists=`),
  the config file via `/container/mounts` with `mode=ro,noexec` (attached
  with `mountlists=`).
- `restart-policy=on-failure` restarts it after a crash (checked on 7.25).
- Set `dns=""`. Without a DNS server RouterOS refuses to start the container
  ("no default dns servers"), and the relay needs none.
- **Containers run with `ip_forward=1`** (7.25.1), so set
  `IP_FORWARD=filtered` and add bridge filter rules per leg (§2). Example for
  one leg with the relay at `10.0.30.2`; repeat for each veth:

  ```
  /interface bridge filter
  add chain=forward in-interface=veth-iot mac-protocol=ip src-address=!10.0.30.2/32 action=drop comment="relay: nothing routed out"
  add chain=forward out-interface=veth-iot mac-protocol=ip dst-address=224.0.0.0/4 action=accept comment="relay: multicast in"
  add chain=forward out-interface=veth-iot mac-protocol=ip dst-address=!10.0.30.2/32 action=drop comment="relay: only its own address in"
  ```

  Test it: from a host on one network, add a route to another network via
  the relay's address and ping something there. It must time out.
- The image can be imported from a tar file on the router
  (`/container add file=…`), so the router needs no registry credentials.
  Prefer this when the registry has no read-only accounts. **The tar must be
  in the classic `docker save` layout** (`<id>/layer.tar`, `manifest.json`,
  `repositories`, uncompressed). The OCI layout that buildx and Docker 25+
  write fails with `could not load next layer`, compressed or not (RouterOS
  7.25.1, 2026-11-08). `make image-arm64` converts it with
  `tools/legacy-tar.py`.

**Docker on Linux:** `network_mode: host` on a machine that already has an
interface on each network (VLAN sub-interfaces), with `/proc/sys/net/ipv4/ip_forward`
checked as above. Note that a host with legs on isolated networks becomes a
bridge point by its nature. Prefer running on the router.

## 11. Build and test

- **Go**, standard library plus `golang.org/x/net/dns/dnsmessage` (DNS
  message parsing and building) and `golang.org/x/net/ipv4` (per-interface
  multicast and `PKTINFO`). No other dependencies.
- `make test`, `make image` (multi-arch), `make push REGISTRY=…`.
- **Unit tests:** golden packets (recorded with `MODE=observe`, plus
  hand-made hostile ones) through the mDNS and SSDP filters: wrong source,
  disallowed type, records smuggled in the additional section, `A` pointing
  elsewhere, `LOCATION` pointing elsewhere, oversized packets, compression
  loops.
- **Integration tests** on any Linux host: network namespaces joined by veth
  pairs (two client networks, one device network, the relay in the middle),
  fake devices (one allowlisted, one not) and `avahi-browse` /
  `gssdp-discover` as clients. Assert both what passes and what doesn't.

## 12. Open questions

1. **[verify]** Several veths per RouterOS container (§10).
2. ~~**[verify]** The built-in profiles against real devices (§7.3).~~
   Done for `airplay`, `dial`, `spotify-connect` (2026-11-08).
3. **[verify]** Follow-up ports per technology (§8).
4. **[decide]** `SSDP_NOTIFY` default (§5.2).
5. **[decide]** DIAL proxy in the relay (§5.3), v2.
6. **[decide]** GDM module for Plex (§7.3), v2.
7. **[verify]** Discovery speed without a cache (§4.4).
