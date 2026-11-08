package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

// Rate limits (SPEC.md §6).
const (
	mdnsRate, mdnsBurst = 20, 40
	ssdpRate, ssdpBurst = 2, 5
	maxSearches         = 8
	maxSSDPPacket       = 2048
)

type relay struct {
	s       settings
	cfg     *config
	learned *learnedNames

	mdns     *ipv4.PacketConn
	mdnsSend sync.Mutex
	ssdp     *ipv4.PacketConn
	ssdpSend sync.Mutex

	mdnsLimit, ssdpLimit *rateLimiter
	searches             chan struct{}

	mu       sync.Mutex
	counters map[string]int
}

func runRelay(ctx context.Context, s settings) error {
	cfg, err := loadConfig(s.ConfigPath)
	if err != nil {
		return fmt.Errorf("config invalid, relaying nothing:\n%w", err)
	}
	r := &relay{
		s: s, cfg: cfg, learned: newLearnedNames(),
		mdnsLimit: newRateLimiter(mdnsRate, mdnsBurst),
		ssdpLimit: newRateLimiter(ssdpRate, ssdpBurst),
		searches:  make(chan struct{}, maxSearches),
		counters:  map[string]int{},
	}
	for _, n := range cfg.Networks {
		role := "devices"
		if n.Client {
			role = "client"
		}
		slog.Info("network", "name", n.Name, "role", role, "interface", n.If.Name, "addr", n.If.Addr, "subnet", n.If.Prefix)
	}
	for _, d := range cfg.Devices {
		var vis []string
		for _, v := range d.VisibleTo {
			vis = append(vis, v.Name)
		}
		slog.Info("device", "name", d.Name, "network", d.Net.Name, "ip", d.IP,
			"mdns", strings.Join(sortedKeys(d.MDNS), ","), "ssdp", strings.Join(sortedKeys(d.SSDP), ","),
			"visible_to", strings.Join(vis, ","))
	}
	slog.Info("relay mode", "ssdp_notify", s.SSDPNotify, "summary_interval", s.SummaryInterval)

	var ifs []netIf
	for _, n := range cfg.Networks {
		ifs = append(ifs, n.If)
	}
	ob := &observer{ifs: ifs} // reuse its socket setup
	if r.mdns, err = ob.listen("0.0.0.0:5353", mdnsGroup); err != nil {
		return fmt.Errorf("mDNS: %w", err)
	}
	defer r.mdns.Close()
	_ = r.mdns.SetMulticastTTL(255)
	if r.ssdp, err = ob.listen("0.0.0.0:1900", ssdpGroup); err != nil {
		return fmt.Errorf("SSDP: %w", err)
	}
	defer r.ssdp.Close()
	_ = r.ssdp.SetMulticastTTL(2)

	go func() { <-ctx.Done(); r.mdns.Close(); r.ssdp.Close() }()
	go r.readLoop(ctx, r.mdns, r.handleMDNS)
	go r.readLoop(ctx, r.ssdp, r.handleSSDP)

	t := time.NewTicker(s.SummaryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.summary()
			return ctx.Err()
		case <-t.C:
			r.summary()
		}
	}
}

func (r *relay) readLoop(ctx context.Context, p *ipv4.PacketConn, handle func(*network, netip.AddrPort, []byte)) {
	buf := make([]byte, maxPacket+1)
	for {
		k, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			if ctx.Err() == nil {
				slog.Error("read failed", "err", err)
			}
			return
		}
		ua, ok := src.(*net.UDPAddr)
		if !ok || cm == nil {
			continue
		}
		ap := ua.AddrPort()
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		n := r.cfg.networkByIndex(cm.IfIndex)
		if n == nil || r.cfg.ownAddr(ap.Addr()) {
			continue // not ours, or our own packet
		}
		if !n.If.Prefix.Contains(ap.Addr()) {
			r.count("drop.off-subnet-source")
			continue
		}
		pkt := append([]byte(nil), buf[:k]...)
		func() {
			defer func() {
				if v := recover(); v != nil {
					r.count("panic")
					slog.Error("panic while handling packet", "src", ap, "panic", v)
				}
			}()
			handle(n, ap, pkt)
		}()
	}
}

func (r *relay) handleMDNS(n *network, src netip.AddrPort, b []byte) {
	if len(b) > maxPacket {
		r.drop("mdns", n, src, "oversized")
		return
	}
	now := time.Now()
	if n.Client {
		if !r.mdnsLimit.allow(src.Addr(), now) {
			r.drop("mdns", n, src, "rate-limited")
			return
		}
		out, reason := relayMDNSQuery(r.cfg, r.learned, n, b, now)
		if reason != "" {
			r.drop("mdns", n, src, reason)
			return
		}
		for _, o := range out {
			r.sendMDNS(o.Net, o.Msg)
			r.count("mdns.query.relayed")
			slog.Debug("mdns query relayed", "from", n.Name, "src", src, "to", o.Net.Name)
		}
		return
	}
	d := r.cfg.deviceAt(n, src.Addr())
	if d == nil {
		r.drop("mdns", n, src, "not-allowlisted")
		return
	}
	msg, reason := relayMDNSAnswer(d, r.learned, b, now)
	if reason != "" {
		r.drop("mdns", n, src, reason)
		return
	}
	for _, cn := range d.VisibleTo {
		r.sendMDNS(cn, msg)
	}
	r.count("mdns.answer.relayed")
	slog.Debug("mdns answer relayed", "device", d.Name, "bytes", len(msg))
}

func (r *relay) sendMDNS(n *network, msg []byte) {
	r.mdnsSend.Lock()
	defer r.mdnsSend.Unlock()
	err := r.mdns.SetMulticastInterface(n.If.ifi)
	if err == nil {
		_, err = r.mdns.WriteTo(msg, nil, &net.UDPAddr{IP: mdnsGroup, Port: 5353})
	}
	if err != nil {
		r.count("send-error")
		slog.Warn("mDNS send failed", "network", n.Name, "err", err)
	}
}

func (r *relay) handleSSDP(n *network, src netip.AddrPort, b []byte) {
	if len(b) > maxSSDPPacket {
		r.drop("ssdp", n, src, "oversized")
		return
	}
	info, err := parseSSDP(b)
	if err != nil {
		r.drop("ssdp", n, src, "unparsable")
		return
	}
	if n.Client {
		if info.Kind != "M-SEARCH" {
			return // other clients' announcements stay on their network, silently
		}
		if !r.ssdpLimit.allow(src.Addr(), time.Now()) {
			r.drop("ssdp", n, src, "rate-limited")
			return
		}
		search, nets, reason := checkSSDPSearch(r.cfg, n, info)
		if reason != "" {
			r.drop("ssdp", n, src, reason)
			return
		}
		for _, dn := range nets {
			select {
			case r.searches <- struct{}{}:
				go func() {
					defer func() { <-r.searches }()
					r.search(n, src, dn, search)
				}()
			default:
				r.drop("ssdp", n, src, "too-many-searches")
			}
		}
		return
	}
	// Devices network: only NOTIFY from allowlisted devices, if enabled.
	if info.Kind != "NOTIFY" {
		if info.Kind == "M-SEARCH" {
			r.drop("ssdp", n, src, "device-search")
		}
		return
	}
	d := r.cfg.deviceAt(n, src.Addr())
	if d == nil {
		r.drop("ssdp", n, src, "not-allowlisted")
		return
	}
	if !r.s.SSDPNotify {
		r.count("drop.ssdp.notify-off")
		return
	}
	msg, reason := relaySSDPNotify(d, info)
	if reason != "" {
		r.drop("ssdp", n, src, reason)
		return
	}
	for _, cn := range d.VisibleTo {
		r.sendSSDP(cn, msg, &net.UDPAddr{IP: ssdpGroup, Port: 1900})
	}
	r.count("ssdp.notify.relayed")
}

// search sends a fresh M-SEARCH into devices network dn and passes each
// accepted reply to the client by unicast (§5.1 steps 4-6).
func (r *relay) search(cn *network, client netip.AddrPort, dn *network, s ssdpSearch) {
	c, err := net.ListenPacket("udp4", net.JoinHostPort(dn.If.Addr.String(), "0"))
	if err != nil {
		r.count("send-error")
		slog.Warn("SSDP search socket", "network", dn.Name, "err", err)
		return
	}
	defer c.Close()
	p := ipv4.NewPacketConn(c)
	_ = p.SetMulticastInterface(dn.If.ifi)
	_ = p.SetMulticastTTL(2)
	if _, err := p.WriteTo(buildRelaySearch(s), nil, &net.UDPAddr{IP: ssdpGroup, Port: 1900}); err != nil {
		r.count("send-error")
		slog.Warn("SSDP search failed", "network", dn.Name, "err", err)
		return
	}
	r.count("ssdp.search.relayed")
	slog.Debug("ssdp search relayed", "from", cn.Name, "client", client, "st", s.ST, "to", dn.Name)
	_ = c.SetReadDeadline(time.Now().Add(time.Duration(s.MX+1) * time.Second))
	buf := make([]byte, maxSSDPPacket+1)
	to := net.UDPAddrFromAddrPort(client)
	for {
		k, src, err := c.ReadFrom(buf)
		if err != nil {
			return // deadline
		}
		ua, ok := src.(*net.UDPAddr)
		if !ok || k > maxSSDPPacket {
			continue
		}
		ip, _ := netip.AddrFromSlice(ua.IP)
		d := r.cfg.deviceAt(dn, ip.Unmap())
		if d == nil || !d.visibleTo(cn) {
			r.count("drop.ssdp.reply-not-allowlisted")
			continue
		}
		info, err := parseSSDP(buf[:k])
		if err != nil {
			r.count("drop.ssdp.reply-unparsable")
			continue
		}
		msg, reason := relaySSDPReply(d, s.ST, info)
		if reason != "" {
			r.count("drop.ssdp.reply-" + reason)
			continue
		}
		r.sendSSDP(cn, msg, to)
		r.count("ssdp.reply.relayed")
	}
}

// sendSSDP sends from the relay's own address on network n, port 1900.
func (r *relay) sendSSDP(n *network, msg []byte, to *net.UDPAddr) {
	r.ssdpSend.Lock()
	defer r.ssdpSend.Unlock()
	cm := &ipv4.ControlMessage{IfIndex: n.If.Index, Src: n.If.Addr.AsSlice()}
	err := r.ssdp.SetMulticastInterface(n.If.ifi)
	if err == nil {
		_, err = r.ssdp.WriteTo(msg, cm, to)
	}
	if err != nil {
		r.count("send-error")
		slog.Warn("SSDP send failed", "network", n.Name, "to", to, "err", err)
	}
}

func (r *relay) drop(proto string, n *network, src netip.AddrPort, reason string) {
	r.count("drop." + proto + "." + reason)
	slog.Debug(proto+" drop", "network", n.Name, "src", src, "reason", reason)
}

func (r *relay) count(key string) {
	r.mu.Lock()
	r.counters[key]++
	r.mu.Unlock()
}

func (r *relay) summary() {
	r.mu.Lock()
	keys := make([]string, 0, len(r.counters))
	for k := range r.counters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, r.counters[k]))
	}
	r.mu.Unlock()
	if len(parts) == 0 {
		parts = []string{"nothing yet"}
	}
	slog.Info("summary (since start)", "counters", strings.Join(parts, " "))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rateLimiter is a token bucket per source address.
type rateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst int) *rateLimiter {
	return &rateLimiter{rate: float64(rate), burst: float64(burst), buckets: map[netip.Addr]*bucket{}}
}

func (l *rateLimiter) allow(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) > 4096 { // bound memory: forget idle sources
			for k, v := range l.buckets {
				if now.Sub(v.last) > time.Minute {
					delete(l.buckets, k)
				}
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
