package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

// netIf is one network the relay is attached to.
type netIf struct {
	Name   string
	Index  int
	Addr   netip.Addr   // the relay's own IPv4 address on it
	Prefix netip.Prefix // the subnet
	ifi    *net.Interface
}

func (n netIf) String() string { return fmt.Sprintf("%s(%s)", n.Name, n.Prefix) }

// discoverInterfaces returns every up, multicast-capable, non-loopback
// interface with an IPv4 address, optionally limited to the given names.
func discoverInterfaces(only []string) ([]netIf, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netIf
	for i := range all {
		ifi := &all[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		if len(only) > 0 && !slices.Contains(only, ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ifi.Name, err)
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || !ip.Unmap().Is4() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			ip = ip.Unmap()
			out = append(out, netIf{Name: ifi.Name, Index: ifi.Index, Addr: ip, Prefix: netip.PrefixFrom(ip, ones).Masked(), ifi: ifi})
			break // first IPv4 address per interface
		}
	}
	for _, name := range only {
		if !slices.ContainsFunc(out, func(n netIf) bool { return n.Name == name }) {
			return nil, fmt.Errorf("interface %q from INTERFACES is missing, down, or has no IPv4 address", name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable IPv4 multicast interfaces")
	}
	return out, nil
}

// listenUDP binds with SO_REUSEADDR/SO_REUSEPORT so the relay can share
// 5353/1900 with a local responder on a development machine.
func listenUDP(addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
				return
			}
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return lc.ListenPacket(context.Background(), "udp4", addr)
}

type ifTable struct {
	byIndex map[int]netIf
	own     map[netip.Addr]bool
}

func newIfTable(ifs []netIf) ifTable {
	t := ifTable{byIndex: map[int]netIf{}, own: map[netip.Addr]bool{}}
	for _, n := range ifs {
		t.byIndex[n.Index] = n
		t.own[n.Addr] = true
	}
	return t
}

// ingress names the interface a packet arrived on, falling back to the
// subnet of the source address when the platform gives no interface index.
func (t ifTable) ingress(index int, src netip.Addr) string {
	if n, ok := t.byIndex[index]; ok {
		return n.Name
	}
	for _, n := range t.byIndex {
		if n.Prefix.Contains(src) {
			return n.Name
		}
	}
	return "?"
}
