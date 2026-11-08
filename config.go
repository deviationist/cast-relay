package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
)

// fileConfig is the JSON config file (SPEC.md §7.2).
type fileConfig struct {
	Networks map[string]fileNetwork `json:"networks"`
	Devices  []fileDevice           `json:"devices"`
	Profiles map[string]profile     `json:"profiles"`
}

type fileNetwork struct {
	Interface string `json:"interface"`
	Role      string `json:"role"` // "client" or "devices"
}

type fileDevice struct {
	Name          string   `json:"name"`
	Network       string   `json:"network"`
	IP            string   `json:"ip"`
	Profiles      []string `json:"profiles"`
	MDNS          []string `json:"mdns"`
	SSDP          []string `json:"ssdp"`
	VisibleTo     []string `json:"visible_to"`
	LocationPorts []int    `json:"location_ports"`
}

type profile struct {
	MDNS []string `json:"mdns"`
	SSDP []string `json:"ssdp"`
}

// builtinProfiles (SPEC.md §7.3).
var builtinProfiles = map[string]profile{
	"airplay":         {MDNS: []string{"_airplay._tcp", "_raop._tcp"}},
	"dial":            {SSDP: []string{"urn:dial-multiscreen-org:service:dial:1", "urn:dial-multiscreen-org:device:dialreceiver:1"}},
	"spotify-connect": {MDNS: []string{"_spotify-connect._tcp"}},
	"googlecast":      {MDNS: []string{"_googlecast._tcp"}},
	"plex":            {MDNS: []string{"_plexmediasvr._tcp"}},
	"upnp-media":      {SSDP: []string{"urn:schemas-upnp-org:device:MediaRenderer:1", "urn:schemas-upnp-org:device:MediaServer:1"}},
}

// Resolved configuration.

type network struct {
	Name   string
	Client bool // role "client"; otherwise "devices"
	If     netIf
}

type device struct {
	Name          string
	Net           *network
	IP            netip.Addr
	MDNS          map[string]bool // lower-case service types, e.g. "_airplay._tcp"
	SSDP          map[string]bool // lower-case search targets
	VisibleTo     []*network
	LocationPorts []int // empty: any port
}

type config struct {
	Networks []*network
	Devices  []*device
}

var serviceTypeRE = regexp.MustCompile(`^_[a-z0-9][a-z0-9-]*\._(tcp|udp)$`)

// loadConfig reads, validates and resolves the config file against the
// system's interfaces. Every problem is an error: the relay never runs
// half-configured.
func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var fc fileConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: trailing data after the JSON object", path)
	}
	var ifNames []string
	for _, n := range fc.Networks {
		ifNames = append(ifNames, n.Interface)
	}
	ifs, err := discoverInterfaces(ifNames)
	if err != nil {
		return nil, err
	}
	return resolveConfig(fc, ifs)
}

func resolveConfig(fc fileConfig, ifs []netIf) (*config, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	cfg := &config{}
	nets := map[string]*network{}
	names := make([]string, 0, len(fc.Networks))
	for name := range fc.Networks {
		names = append(names, name)
	}
	slices.Sort(names)
	hasClient, hasDevices := false, false
	for _, name := range names {
		fn := fc.Networks[name]
		n := &network{Name: name}
		switch fn.Role {
		case "client":
			n.Client, hasClient = true, true
		case "devices":
			hasDevices = true
		default:
			fail("networks.%s.role = %q: want client or devices", name, fn.Role)
			continue
		}
		i := slices.IndexFunc(ifs, func(x netIf) bool { return x.Name == fn.Interface })
		if i < 0 {
			fail("networks.%s.interface = %q: no such interface with an IPv4 address", name, fn.Interface)
			continue
		}
		n.If = ifs[i]
		for _, other := range cfg.Networks {
			if other.If.Name == n.If.Name {
				fail("networks.%s and networks.%s use the same interface %s", other.Name, name, n.If.Name)
			}
		}
		nets[name] = n
		cfg.Networks = append(cfg.Networks, n)
	}
	if !hasClient || !hasDevices {
		fail("networks: need at least one client and one devices network")
	}

	profiles := map[string]profile{}
	for k, v := range builtinProfiles {
		profiles[k] = v
	}
	for k, v := range fc.Profiles {
		if _, ok := builtinProfiles[k]; ok {
			fail("profiles.%s: shadows a built-in profile; pick another name", k)
		}
		profiles[k] = v
	}

	if len(fc.Devices) == 0 {
		fail("devices: empty allowlist")
	}
	seen := map[netip.Addr]string{}
	for i, fd := range fc.Devices {
		where := fmt.Sprintf("devices[%d] (%s)", i, fd.Name)
		if fd.Name == "" {
			fail("devices[%d]: missing name", i)
		}
		d := &device{Name: fd.Name, MDNS: map[string]bool{}, SSDP: map[string]bool{}, LocationPorts: fd.LocationPorts}
		n, ok := nets[fd.Network]
		switch {
		case !ok:
			fail("%s: network %q is not defined", where, fd.Network)
		case n.Client:
			fail("%s: network %q is a client network; devices live on devices networks", where, fd.Network)
		default:
			d.Net = n
		}
		ip, err := netip.ParseAddr(fd.IP)
		switch {
		case err != nil || !ip.Is4():
			fail("%s: ip %q is not an IPv4 address", where, fd.IP)
		case d.Net != nil && !d.Net.If.Prefix.Contains(ip):
			fail("%s: ip %s is outside network %s (%s)", where, ip, d.Net.Name, d.Net.If.Prefix)
		case d.Net != nil && ip == d.Net.If.Addr:
			fail("%s: ip %s is the relay's own address", where, ip)
		default:
			d.IP = ip
			if other, dup := seen[ip]; dup {
				fail("%s: ip %s is also used by %s", where, ip, other)
			}
			seen[ip] = fd.Name
		}
		add := func(src string, p profile) {
			for _, t := range p.MDNS {
				t = strings.ToLower(t)
				if !serviceTypeRE.MatchString(t) {
					fail("%s: %s: mDNS service type %q: want _name._tcp or _name._udp", where, src, t)
					continue
				}
				d.MDNS[t] = true
			}
			for _, st := range p.SSDP {
				st = strings.ToLower(strings.TrimSpace(st))
				if st == "" || st == "ssdp:all" || strings.ContainsAny(st, " \r\n") {
					fail("%s: %s: SSDP target %q is not allowed", where, src, st)
					continue
				}
				d.SSDP[st] = true
			}
		}
		for _, pn := range fd.Profiles {
			p, ok := profiles[pn]
			if !ok {
				fail("%s: unknown profile %q", where, pn)
				continue
			}
			add("profile "+pn, p)
		}
		add("own entries", profile{MDNS: fd.MDNS, SSDP: fd.SSDP})
		if len(d.MDNS) == 0 && len(d.SSDP) == 0 {
			fail("%s: no services allowed (add profiles, mdns or ssdp)", where)
		}
		if len(fd.VisibleTo) == 0 {
			fail("%s: visible_to is empty", where)
		}
		for _, v := range fd.VisibleTo {
			cn, ok := nets[v]
			switch {
			case !ok:
				fail("%s: visible_to %q is not defined", where, v)
			case !cn.Client:
				fail("%s: visible_to %q is not a client network", where, v)
			default:
				d.VisibleTo = append(d.VisibleTo, cn)
			}
		}
		for _, p := range fd.LocationPorts {
			if p < 1 || p > 65535 {
				fail("%s: location_ports: %d is not a port", where, p)
			}
		}
		cfg.Devices = append(cfg.Devices, d)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

// visibleTo reports whether the device may be seen from client network n.
func (d *device) visibleTo(n *network) bool { return slices.Contains(d.VisibleTo, n) }

func (c *config) networkByIndex(index int) *network {
	for _, n := range c.Networks {
		if n.If.Index == index {
			return n
		}
	}
	return nil
}

func (c *config) deviceAt(n *network, ip netip.Addr) *device {
	for _, d := range c.Devices {
		if d.Net == n && d.IP == ip {
			return d
		}
	}
	return nil
}

func (c *config) ownAddr(ip netip.Addr) bool {
	for _, n := range c.Networks {
		if n.If.Addr == ip {
			return true
		}
	}
	return false
}
