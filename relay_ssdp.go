package main

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// ssdpSearch is a client's validated M-SEARCH.
type ssdpSearch struct {
	ST    string // lower-case, for comparisons
	RawST string // as the client wrote it; sent on, since devices match exactly
	MX    int    // capped at 2
}

// checkSSDPSearch validates an M-SEARCH from client network n (SPEC.md
// §5.1 steps 2-3) and returns the devices networks to search, or a drop reason.
func checkSSDPSearch(cfg *config, n *network, info ssdpInfo) (ssdpSearch, []*network, string) {
	if info.Kind != "M-SEARCH" {
		return ssdpSearch{}, nil, "not-a-search"
	}
	if strings.Trim(info.Headers["MAN"], `"`) != "ssdp:discover" {
		return ssdpSearch{}, nil, "bad-man"
	}
	raw := strings.TrimSpace(info.Headers["ST"])
	st := strings.ToLower(raw)
	if st == "" || strings.ContainsAny(raw, "\r\n") {
		return ssdpSearch{}, nil, "no-st"
	}
	mx, err := strconv.Atoi(strings.TrimSpace(info.Headers["MX"]))
	if err != nil || mx < 1 {
		mx = 1
	}
	mx = min(mx, 2)
	var nets []*network
	for _, d := range cfg.Devices {
		if !d.visibleTo(n) || len(d.SSDP) == 0 {
			continue
		}
		if (st == "ssdp:all" || d.SSDP[st]) && !slices.Contains(nets, d.Net) {
			nets = append(nets, d.Net)
		}
	}
	if len(nets) == 0 {
		return ssdpSearch{}, nil, "no-allowed-target"
	}
	return ssdpSearch{ST: st, RawST: raw, MX: mx}, nets, ""
}

func buildRelaySearch(s ssdpSearch) []byte {
	return []byte(fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: %d\r\nST: %s\r\nUSER-AGENT: cast-relay/%s\r\n\r\n", s.MX, s.RawST, version))
}

// relaySSDPReply checks a reply from device d to a search for st (§5.1 step
// 6) and returns the rebuilt reply for the client, or a drop reason.
func relaySSDPReply(d *device, st string, info ssdpInfo) ([]byte, string) {
	if info.Kind != "RESPONSE" {
		return nil, "not-a-response"
	}
	got := strings.ToLower(strings.TrimSpace(info.Headers["ST"]))
	if !d.SSDP[got] {
		return nil, "target-not-allowed"
	}
	if st != "ssdp:all" && got != st {
		return nil, "target-mismatch"
	}
	if info.Headers["USN"] == "" {
		return nil, "no-usn"
	}
	if reason := checkLocation(d, info.Headers["LOCATION"]); reason != "" {
		return nil, reason
	}
	return buildSSDP("HTTP/1.1 200 OK", info, []string{"CACHE-CONTROL", "EXT", "LOCATION", "SERVER", "ST", "USN", "BOOTID.UPNP.ORG", "CONFIGID.UPNP.ORG"}), ""
}

// relaySSDPNotify checks a NOTIFY from device d (§5.2) and returns the
// rebuilt announcement, or a drop reason.
func relaySSDPNotify(d *device, info ssdpInfo) ([]byte, string) {
	if info.Kind != "NOTIFY" {
		return nil, "not-a-notify"
	}
	if !d.SSDP[strings.ToLower(strings.TrimSpace(info.Headers["NT"]))] {
		return nil, "target-not-allowed"
	}
	switch strings.ToLower(info.Headers["NTS"]) {
	case "ssdp:alive":
		if reason := checkLocation(d, info.Headers["LOCATION"]); reason != "" {
			return nil, reason
		}
	case "ssdp:byebye":
	default:
		return nil, "bad-nts"
	}
	if info.Headers["USN"] == "" {
		return nil, "no-usn"
	}
	info.Headers["HOST"] = "239.255.255.250:1900"
	return buildSSDP("NOTIFY * HTTP/1.1", info, []string{"HOST", "CACHE-CONTROL", "LOCATION", "NT", "NTS", "SERVER", "USN", "BOOTID.UPNP.ORG", "CONFIGID.UPNP.ORG"}), ""
}

// checkLocation: an http URL on the device's own address, on an allowed port.
func checkLocation(d *device, loc string) string {
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil || u.Scheme != "http" || u.User != nil {
		return "bad-location"
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || ip != d.IP {
		return "location-elsewhere"
	}
	port := 80
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return "bad-location"
		}
	}
	if len(d.LocationPorts) > 0 && !slices.Contains(d.LocationPorts, port) {
		return "location-port"
	}
	return ""
}

// buildSSDP writes a start line and only the listed headers, with values
// stripped of anything that could start a new header.
func buildSSDP(start string, info ssdpInfo, keep []string) []byte {
	var b strings.Builder
	b.WriteString(start + "\r\n")
	for _, k := range keep {
		v, ok := info.Headers[k]
		if !ok {
			continue
		}
		v = strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, v)
		b.WriteString(k + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}
