package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

var (
	mdnsGroup = net.IPv4(224, 0, 0, 251)
	ssdpGroup = net.IPv4(239, 255, 255, 250)
)

const (
	maxPacket   = 9000
	repeatQuiet = time.Minute // identical packets are logged at most this often
)

// observer relays nothing. It logs every mDNS and SSDP packet it sees on each
// interface and keeps a per-source tally for the periodic summary.
type observer struct {
	s     settings
	ifs   []netIf
	table ifTable

	mdns     *ipv4.PacketConn
	mdnsSend sync.Mutex

	mu      sync.Mutex
	sources map[string]*sourceStats // key: iface|ip
	lastLog map[string]time.Time
	repeats int
	errors  int
	types   map[string]bool // service types learned, for follow-up probes
}

type sourceStats struct {
	iface, ip  string
	mdnsPkts   int
	ssdpPkts   int
	mdnsTypes  []string
	hosts      []string
	ssdpTarget []string
	servers    []string
	queriesFor []string // types this source asked about
}

func runObserve(ctx context.Context, s settings) error {
	ifs, err := discoverInterfaces(s.Interfaces)
	if err != nil {
		return err
	}
	o := &observer{s: s, ifs: ifs, table: newIfTable(ifs), sources: map[string]*sourceStats{}, lastLog: map[string]time.Time{}, types: map[string]bool{}}
	for _, n := range ifs {
		slog.Info("interface", "name", n.Name, "index", n.Index, "addr", n.Addr, "subnet", n.Prefix)
	}
	slog.Info("observe mode: relaying nothing, logging mDNS and SSDP", "probe", s.Probe, "probe_interval", s.ProbeInterval, "summary_interval", s.SummaryInterval)

	mdnsConn, err := o.listen("0.0.0.0:5353", mdnsGroup)
	if err != nil {
		return fmt.Errorf("mDNS: %w", err)
	}
	defer mdnsConn.Close()
	_ = mdnsConn.SetMulticastTTL(255)
	o.mdns = mdnsConn

	ssdpConn, err := o.listen("0.0.0.0:1900", ssdpGroup)
	if err != nil {
		return fmt.Errorf("SSDP: %w", err)
	}
	defer ssdpConn.Close()

	go func() { <-ctx.Done(); mdnsConn.Close(); ssdpConn.Close() }()
	go o.readLoop(ctx, mdnsConn, "mdns", "multicast")
	go o.readLoop(ctx, ssdpConn, "ssdp", "multicast")
	if s.Probe {
		go o.probeLoop(ctx)
	}

	t := time.NewTicker(s.SummaryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			o.summary()
			return ctx.Err()
		case <-t.C:
			o.summary()
		}
	}
}

func (o *observer) listen(addr string, group net.IP) (*ipv4.PacketConn, error) {
	c, err := listenUDP(addr)
	if err != nil {
		return nil, err
	}
	p := ipv4.NewPacketConn(c)
	for _, n := range o.ifs {
		if err := p.JoinGroup(n.ifi, &net.UDPAddr{IP: group}); err != nil {
			c.Close()
			return nil, fmt.Errorf("join %s on %s: %w", group, n.Name, err)
		}
	}
	if err := p.SetControlMessage(ipv4.FlagInterface|ipv4.FlagDst, true); err != nil {
		slog.Warn("no per-packet interface info; falling back to source subnet", "err", err)
	}
	_ = p.SetMulticastLoopback(false)
	return p, nil
}

func (o *observer) readLoop(ctx context.Context, p *ipv4.PacketConn, proto, via string) {
	buf := make([]byte, maxPacket+1)
	for {
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			if ctx.Err() == nil {
				slog.Error("read failed", "proto", proto, "err", err)
			}
			return
		}
		ifindex := 0
		if cm != nil {
			ifindex = cm.IfIndex
		}
		o.handle(proto, via, ifindex, src, buf[:n])
	}
}

func (o *observer) handle(proto, via string, ifindex int, src net.Addr, b []byte) {
	defer func() {
		if r := recover(); r != nil {
			o.count(func() { o.errors++ })
			slog.Error("panic while handling packet", "proto", proto, "src", src, "panic", r)
		}
	}()
	ua, ok := src.(*net.UDPAddr)
	if !ok {
		return
	}
	ip, _ := netip.AddrFromSlice(ua.IP)
	ip = ip.Unmap()
	if o.table.own[ip] {
		return // our own probe
	}
	iface := o.table.ingress(ifindex, ip)
	if len(b) > maxPacket {
		slog.Warn("oversized packet", "proto", proto, "iface", iface, "src", ua, "bytes", len(b))
		return
	}

	switch proto {
	case "mdns":
		info, err := parseMDNS(b)
		if err != nil {
			o.count(func() { o.errors++ })
			slog.Warn("unparsable mDNS", "iface", iface, "src", ua, "err", err)
			return
		}
		o.recordMDNS(iface, ip.String(), info)
		kind := "query"
		detail := strings.Join(info.Questions, "; ")
		if info.Response {
			kind = "response"
			detail = strings.Join(info.Records, "; ")
		}
		o.logPacket(fmt.Sprintf("mdns|%s|%s|%s", iface, ua, detail), "mdns",
			"iface", iface, "src", ua.String(), "via", via, "kind", kind, "types", strings.Join(info.Types, ","), "detail", truncate(detail, 1500))
	case "ssdp":
		info, err := parseSSDP(b)
		if err != nil {
			o.count(func() { o.errors++ })
			slog.Warn("unparsable SSDP", "iface", iface, "src", ua, "err", err)
			return
		}
		o.recordSSDP(iface, ip.String(), info)
		sum := info.summary()
		o.logPacket(fmt.Sprintf("ssdp|%s|%s|%s|%s", iface, ua.IP, info.Kind, sum), "ssdp",
			"iface", iface, "src", ua.String(), "via", via, "kind", info.Kind, "detail", sum)
	}
}

// logPacket logs a packet unless an identical one was logged within
// repeatQuiet; repeats are counted and reported in the summary.
func (o *observer) logPacket(key, msg string, args ...any) {
	o.mu.Lock()
	now := time.Now()
	if t, ok := o.lastLog[key]; ok && now.Sub(t) < repeatQuiet {
		o.repeats++
		o.mu.Unlock()
		return
	}
	o.lastLog[key] = now
	if len(o.lastLog) > 5000 { // bound memory
		for k, t := range o.lastLog {
			if now.Sub(t) > repeatQuiet {
				delete(o.lastLog, k)
			}
		}
	}
	o.mu.Unlock()
	slog.Info(msg, args...)
}

func (o *observer) stats(iface, ip string) *sourceStats {
	k := iface + "|" + ip
	st, ok := o.sources[k]
	if !ok {
		st = &sourceStats{iface: iface, ip: ip}
		o.sources[k] = st
	}
	return st
}

func (o *observer) recordMDNS(iface, ip string, info mdnsInfo) {
	o.mu.Lock()
	defer o.mu.Unlock()
	st := o.stats(iface, ip)
	st.mdnsPkts++
	for _, t := range info.Types {
		if info.Response {
			st.mdnsTypes = appendUnique(st.mdnsTypes, t)
			o.types[t] = true
		} else {
			st.queriesFor = appendUnique(st.queriesFor, t)
		}
	}
	if info.Response {
		for _, h := range info.Hosts {
			st.hosts = appendUnique(st.hosts, h)
		}
	}
}

func (o *observer) recordSSDP(iface, ip string, info ssdpInfo) {
	o.mu.Lock()
	defer o.mu.Unlock()
	st := o.stats(iface, ip)
	st.ssdpPkts++
	if t := info.target(); t != "" && info.Kind != "M-SEARCH" {
		st.ssdpTarget = appendUnique(st.ssdpTarget, t)
	}
	if v := info.Headers["SERVER"]; v != "" {
		st.servers = appendUnique(st.servers, truncate(v, 80))
	}
}

func (o *observer) count(f func()) {
	o.mu.Lock()
	f()
	o.mu.Unlock()
}

// probeLoop asks each network what it offers, so a quiet network still shows
// its devices: an mDNS service enumeration (then a browse of every type
// learned) and an SSDP ssdp:all search.
func (o *observer) probeLoop(ctx context.Context) {
	t := time.NewTicker(o.s.ProbeInterval)
	defer t.Stop()
	for {
		for _, n := range o.ifs {
			o.probeMDNS(n)
			go o.probeSSDP(ctx, n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (o *observer) probeMDNS(n netIf) {
	o.mu.Lock()
	names := []string{servicesEnum}
	for t := range o.types {
		names = append(names, t+".local.")
	}
	o.mu.Unlock()
	sort.Strings(names[1:])
	// Keep packets small: at most 20 questions each.
	for chunk := range slices.Chunk(names, 20) {
		q, err := buildMDNSQuery(chunk)
		if err != nil {
			slog.Error("build mDNS probe", "err", err)
			return
		}
		o.mdnsSend.Lock()
		err = o.mdns.SetMulticastInterface(n.ifi)
		if err == nil {
			_, err = o.mdns.WriteTo(q, nil, &net.UDPAddr{IP: mdnsGroup, Port: 5353})
		}
		o.mdnsSend.Unlock()
		if err != nil {
			slog.Warn("mDNS probe failed", "iface", n.Name, "err", err)
			return
		}
	}
	slog.Debug("mDNS probe sent", "iface", n.Name, "questions", len(names))
}

// probeSSDP sends ssdp:all from an ephemeral port on the interface and logs
// the unicast replies, which may come from any source port.
func (o *observer) probeSSDP(ctx context.Context, n netIf) {
	c, err := net.ListenPacket("udp4", net.JoinHostPort(n.Addr.String(), "0"))
	if err != nil {
		slog.Warn("SSDP probe socket", "iface", n.Name, "err", err)
		return
	}
	defer c.Close()
	p := ipv4.NewPacketConn(c)
	if err := p.SetMulticastInterface(n.ifi); err != nil {
		slog.Warn("SSDP probe interface", "iface", n.Name, "err", err)
		return
	}
	_ = p.SetMulticastTTL(2)
	const mx = 2
	if _, err := p.WriteTo(buildMSearch("ssdp:all", mx), nil, &net.UDPAddr{IP: ssdpGroup, Port: 1900}); err != nil {
		slog.Warn("SSDP probe failed", "iface", n.Name, "err", err)
		return
	}
	slog.Debug("SSDP probe sent", "iface", n.Name)
	_ = c.SetReadDeadline(time.Now().Add((mx + 1) * time.Second))
	buf := make([]byte, maxPacket+1)
	for ctx.Err() == nil {
		k, src, err := c.ReadFrom(buf)
		if err != nil {
			return // deadline
		}
		o.handle("ssdp", "probe-reply", n.Index, src, buf[:k])
	}
}

func (o *observer) summary() {
	o.mu.Lock()
	defer o.mu.Unlock()
	keys := make([]string, 0, len(o.sources))
	for k := range o.sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	slog.Info("summary", "sources", len(keys), "suppressed_repeats", o.repeats, "parse_errors", o.errors)
	for _, k := range keys {
		st := o.sources[k]
		slog.Info("summary source", "iface", st.iface, "src", st.ip,
			"mdns_pkts", st.mdnsPkts, "ssdp_pkts", st.ssdpPkts,
			"offers_mdns", strings.Join(st.mdnsTypes, ","),
			"hosts", strings.Join(st.hosts, ","),
			"offers_ssdp", strings.Join(st.ssdpTarget, ","),
			"server", strings.Join(st.servers, " | "),
			"asked_for", truncate(strings.Join(st.queriesFor, ","), 400))
	}
}
