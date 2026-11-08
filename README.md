# cast-relay

Cast across VLANs without opening them up. A small container that makes
**selected** devices on an isolated network discoverable from your other
networks over **mDNS** (Bonjour) and **SSDP** (UPnP, DIAL), and makes
**nothing else** discoverable.

Typical use: the TV and speakers live on an IoT VLAN; you want AirPlay,
YouTube/Netflix casting (DIAL), Spotify Connect and vendor apps to work from
the main network and the guest Wi-Fi.

## Why not an mDNS reflector?

Reflectors (avahi's, or a router's built-in mDNS repeater) copy everything in
both directions. Your laptops, phones and file shares get announced to the IoT
and guest networks, and every IoT gadget to your main network. Filters, where
they exist, work by service type only. And nothing common relays SSDP, which
DIAL (YouTube, Netflix) needs.

cast-relay is directional and allowlist-based:

- client networks may **ask**; only allowlisted devices may **answer**;
- only allowlisted service types and SSDP targets pass;
- every packet is parsed, filtered **record by record** and rebuilt, never
  copied byte for byte;
- nothing from a client network is ever announced anywhere, and client
  networks never see each other;
- SSDP is relayed properly: a fresh search from the relay, replies accepted
  from any source port (many TVs reply from random ports), `LOCATION` pinned
  to the device's own address, then unicast back to whoever asked.

It relays discovery only and never forwards traffic. The connections that
follow (an AirPlay stream, a DIAL request) go through your router and its
firewall.

## Quick start

1. Give the relay one interface and a static address on each network
   (client and device networks), with no default route.
2. Write a config file (see [`config.example.json`](config.example.json)):

   ```json
   {
     "networks": {
       "lan":   { "interface": "eth0", "role": "client" },
       "guest": { "interface": "eth1", "role": "client" },
       "iot":   { "interface": "eth2", "role": "devices" }
     },
     "devices": [
       { "name": "living-room-tv", "network": "iot", "ip": "10.0.30.11",
         "profiles": ["airplay", "dial"], "visible_to": ["lan", "guest"] }
     ]
   }
   ```

3. Run it with the file mounted at `/config/cast-relay.json`.
4. Allow the follow-up connections on your router (client → device), see
   [SPEC.md §8](SPEC.md).

Not sure what your devices announce? Start with `MODE=observe`: it relays
nothing and logs every mDNS, SSDP and GDM (Plex) packet on every interface,
with periodic probes so quiet devices show up too.

## Built-in profiles

| Profile | Covers |
|---|---|
| `airplay` | AirPlay video and audio |
| `dial` | YouTube, Netflix and other DIAL apps |
| `spotify-connect` | Spotify Connect |
| `googlecast` | Chromecast / Google Cast |
| `plex` | Plex server announcement |
| `upnp-media` | DLNA renderers and servers |

Devices can add their own mDNS types and SSDP targets, e.g. a speaker
vendor's app.

## Settings

| Variable | Default | |
|---|---|---|
| `MODE` | `relay` | `relay` or `observe` |
| `CONFIG` | `/config/cast-relay.json` | config file path |
| `LOG_LEVEL` | `info` | `debug` logs every decision |
| `SSDP_NOTIFY` | `on` | relay devices' SSDP announcements |
| `SUMMARY_INTERVAL` | `5m` | counter summary in the log |
| `IP_FORWARD` | `off` | refuse to run if the kernel would route between the relay's networks; `filtered` if your platform blocks it (see below) |

The config is validated strictly at start-up. On any error the relay logs it
and exits without relaying anything.

## Safety: the relay must not route

A container with a leg on several networks and IP forwarding on is a router:
a host could use the relay's address as a gateway into another network,
bypassing your firewall. cast-relay refuses to start if forwarding is on.
Some platforms (RouterOS containers) start with forwarding on and give the
container no way to turn it off. There, block routed traffic at layer 2 on
each leg and set `IP_FORWARD=filtered`; [SPEC.md §2 and §10](SPEC.md) have
the rules and a test.

## Platforms

- **RouterOS 7 containers** (tested on 7.25 / arm64): one veth per network,
  env vars and a read-only mount for the config. RouterOS imports only the
  classic `docker save` tar layout; `make image-arm64` produces it.
- **Docker on Linux** with host networking on a machine that has an interface
  on each network.

## Build

```sh
make test          # go vet + unit tests
make image-arm64   # dist/cast-relay-<version>-arm64.tar (also image-amd64)
```

A static Go binary in a `FROM scratch` image, about 4 MB, running as a
non-root user with no capabilities.

## Design

[SPEC.md](SPEC.md) has the full design: policy, packet handling, abuse
limits, and what was learned observing real TVs, speakers and phones.
