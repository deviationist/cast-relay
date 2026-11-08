package main

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// learnedNames tracks the instance and host names each allowlisted device has
// announced, with their TTL (SPEC.md §4.3). Client queries may ask for these.
type learnedNames struct {
	mu    sync.Mutex
	names map[*device]map[string]time.Time // lower-case name -> expiry
}

func newLearnedNames() *learnedNames {
	return &learnedNames{names: map[*device]map[string]time.Time{}}
}

func (l *learnedNames) learn(d *device, name string, ttl uint32, now time.Time) {
	name = strings.ToLower(name)
	l.mu.Lock()
	defer l.mu.Unlock()
	m := l.names[d]
	if m == nil {
		m = map[string]time.Time{}
		l.names[d] = m
	}
	if ttl == 0 {
		delete(m, name) // goodbye
		return
	}
	m[name] = now.Add(time.Duration(ttl) * time.Second)
}

func (l *learnedNames) has(d *device, name string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	exp, ok := l.names[d][strings.ToLower(name)]
	return ok && now.Before(exp)
}

// mdnsQueryOut is a rebuilt query to send into one devices network.
type mdnsQueryOut struct {
	Net *network
	Msg []byte
}

// relayMDNSQuery handles a packet that arrived on client network n. It
// returns the queries to send into devices networks, or a drop reason.
func relayMDNSQuery(cfg *config, learned *learnedNames, n *network, b []byte, now time.Time) ([]mdnsQueryOut, string) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return nil, "unparsable"
	}
	if h.Response {
		return nil, "client-announcement" // §4.1 step 2
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil, "unparsable"
	}
	byNet := map[*network][]dnsmessage.Question{}
	for _, q := range qs {
		name := strings.ToLower(q.Name.String())
		for _, d := range cfg.Devices {
			if !d.visibleTo(n) || !questionAllowed(d, learned, name, now) {
				continue
			}
			q.Class &^= 0x8000 // clear QU: answers come back by multicast
			if !containsQuestion(byNet[d.Net], q) {
				byNet[d.Net] = append(byNet[d.Net], q)
			}
		}
	}
	if len(byNet) == 0 {
		return nil, "no-allowed-question"
	}
	var out []mdnsQueryOut
	for _, dn := range cfg.Networks { // stable order
		qs := byNet[dn]
		if len(qs) == 0 {
			continue
		}
		bld := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{})
		bld.EnableCompression()
		if err := bld.StartQuestions(); err != nil {
			return nil, "build-error"
		}
		for _, q := range qs {
			if err := bld.Question(q); err != nil {
				return nil, "build-error"
			}
		}
		msg, err := bld.Finish()
		if err != nil {
			return nil, "build-error"
		}
		out = append(out, mdnsQueryOut{Net: dn, Msg: msg})
	}
	return out, ""
}

func containsQuestion(qs []dnsmessage.Question, q dnsmessage.Question) bool {
	for _, x := range qs {
		if strings.EqualFold(x.Name.String(), q.Name.String()) && x.Type == q.Type && x.Class == q.Class {
			return true
		}
	}
	return false
}

// questionAllowed: an allowed service type (or a subtype of one), service
// enumeration, or a name the device has announced.
func questionAllowed(d *device, learned *learnedNames, name string, now time.Time) bool {
	if name == servicesEnum {
		return len(d.MDNS) > 0
	}
	if t, ok := serviceType(name); ok && d.MDNS[t] && isTypeOrSubtype(name, t) {
		return true
	}
	return learned.has(d, name, now)
}

// isTypeOrSubtype: "_t._tcp.local." or "_x._sub._t._tcp.local.", not an
// instance name (instances are only asked for once learned).
func isTypeOrSubtype(name, t string) bool {
	full := t + ".local."
	return name == full || (strings.HasSuffix(name, "._sub."+full) && strings.HasPrefix(name, "_"))
}

// relayMDNSAnswer handles a packet from allowlisted device d. It returns the
// rebuilt response with only the allowed records, or a drop reason.
func relayMDNSAnswer(d *device, learned *learnedNames, b []byte, now time.Time) ([]byte, string) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return nil, "unparsable"
	}
	if !h.Response {
		return nil, "device-query" // devices never search client networks
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, "unparsable"
	}
	var all []dnsmessage.Resource
	sections := []struct {
		header func() (dnsmessage.ResourceHeader, error)
		skip   func() error
	}{{p.AnswerHeader, p.SkipAnswer}, {p.AuthorityHeader, p.SkipAuthority}, {p.AdditionalHeader, p.SkipAdditional}}
	for _, sec := range sections {
		for {
			rh, err := sec.header()
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				break // the rest can't be located; keep what we have
			}
			if body, err := readBody(&p, rh.Type); err == nil {
				all = append(all, dnsmessage.Resource{Header: rh, Body: body})
			} else if sec.skip() != nil {
				break
			}
		}
	}

	// Pass 1: the instances and hosts this packet legitimately describes.
	instances := map[string]bool{}
	hosts := map[string]bool{}
	for _, r := range all {
		name := strings.ToLower(r.Header.Name.String())
		switch body := r.Body.(type) {
		case *dnsmessage.PTRResource:
			if t, ok := serviceType(name); ok && d.MDNS[t] && isTypeOrSubtype(name, t) {
				target := strings.ToLower(body.PTR.String())
				if tt, ok := serviceType(target); ok && tt == t && target != t+".local." {
					instances[target] = true
				}
			}
		case *dnsmessage.SRVResource:
			if isAllowedInstance(d, name) {
				instances[name] = true
				hosts[strings.ToLower(body.Target.String())] = true
			}
		}
	}

	// Pass 2: keep only records about those names.
	var keep []dnsmessage.Resource
	for _, r := range all {
		name := strings.ToLower(r.Header.Name.String())
		switch body := r.Body.(type) {
		case *dnsmessage.PTRResource:
			target := strings.ToLower(body.PTR.String())
			if name == servicesEnum {
				if t, ok := serviceType(target); ok && d.MDNS[t] && target == t+".local." {
					keep = append(keep, r)
				}
			} else if instances[target] && !strings.HasSuffix(name, ".arpa.") {
				keep = append(keep, r)
			}
		case *dnsmessage.SRVResource, *dnsmessage.TXTResource:
			if instances[name] || (isAllowedInstance(d, name) && learned.has(d, name, now)) {
				keep = append(keep, r)
			}
		case *dnsmessage.AResource:
			if (hosts[name] || learned.has(d, name, now)) && addrIs(body.A, d) {
				keep = append(keep, r)
			}
		}
	}
	if len(keep) == 0 {
		return nil, "no-allowed-record"
	}

	// Learn names only from records we pass on.
	for _, r := range keep {
		switch body := r.Body.(type) {
		case *dnsmessage.SRVResource:
			learned.learn(d, r.Header.Name.String(), r.Header.TTL, now)
			learned.learn(d, body.Target.String(), r.Header.TTL, now)
		case *dnsmessage.PTRResource:
			if !strings.EqualFold(r.Header.Name.String(), servicesEnum) {
				learned.learn(d, body.PTR.String(), r.Header.TTL, now)
			}
		}
	}

	bld := dnsmessage.NewBuilder(make([]byte, 0, 1024), dnsmessage.Header{Response: true, Authoritative: true})
	bld.EnableCompression()
	if err := bld.StartAnswers(); err != nil {
		return nil, "build-error"
	}
	for _, r := range keep {
		var err error
		switch body := r.Body.(type) {
		case *dnsmessage.PTRResource:
			err = bld.PTRResource(r.Header, *body)
		case *dnsmessage.SRVResource:
			err = bld.SRVResource(r.Header, *body)
		case *dnsmessage.TXTResource:
			err = bld.TXTResource(r.Header, *body)
		case *dnsmessage.AResource:
			err = bld.AResource(r.Header, *body)
		}
		if err != nil {
			return nil, "build-error"
		}
	}
	msg, err := bld.Finish()
	if err != nil {
		return nil, "build-error"
	}
	return msg, ""
}

// isAllowedInstance: "<instance>._t._tcp.local." for an allowed type t.
func isAllowedInstance(d *device, name string) bool {
	t, ok := serviceType(name)
	return ok && d.MDNS[t] && strings.HasSuffix(name, "."+t+".local.") && !strings.Contains(name, "._sub.")
}

func addrIs(a [4]byte, d *device) bool { return d.IP.As4() == a }
