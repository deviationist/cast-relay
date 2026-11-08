package main

import (
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const servicesEnum = "_services._dns-sd._udp.local."

// mdnsInfo is what observe mode extracts from one mDNS packet.
type mdnsInfo struct {
	Response  bool
	Questions []string // "name TYPE" (+ " QU")
	Records   []string // human-readable record summaries
	Types     []string // service types seen (e.g. "_airplay._tcp")
	Hosts     []string // SRV targets and A-record names
}

func parseMDNS(b []byte) (mdnsInfo, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return mdnsInfo{}, err
	}
	info := mdnsInfo{Response: h.Response}
	qs, err := p.AllQuestions()
	if err != nil {
		return info, err
	}
	for _, q := range qs {
		s := q.Name.String() + " " + typeName(q.Type)
		if uint16(q.Class)&0x8000 != 0 {
			s += " QU"
		}
		info.Questions = append(info.Questions, s)
		if t, ok := serviceType(q.Name.String()); ok {
			info.Types = appendUnique(info.Types, t)
		}
	}
	for _, section := range []func() ([]dnsmessage.Resource, error){p.AllAnswers, p.AllAuthorities, p.AllAdditionals} {
		rs, err := section()
		if err != nil {
			return info, err
		}
		for _, r := range rs {
			info.addRecord(r)
		}
	}
	return info, nil
}

func (info *mdnsInfo) addRecord(r dnsmessage.Resource) {
	name := r.Header.Name.String()
	ttl := r.Header.TTL
	var s string
	switch body := r.Body.(type) {
	case *dnsmessage.PTRResource:
		target := body.PTR.String()
		s = fmt.Sprintf("PTR %s -> %s", name, target)
		if name == servicesEnum {
			if t, ok := serviceType(target); ok {
				info.Types = appendUnique(info.Types, t)
			}
		} else if t, ok := serviceType(name); ok {
			info.Types = appendUnique(info.Types, t)
		}
	case *dnsmessage.SRVResource:
		target := body.Target.String()
		s = fmt.Sprintf("SRV %s -> %s:%d", name, target, body.Port)
		info.Hosts = appendUnique(info.Hosts, target)
		if t, ok := serviceType(name); ok {
			info.Types = appendUnique(info.Types, t)
		}
	case *dnsmessage.TXTResource:
		s = fmt.Sprintf("TXT %s [%s]", name, truncate(strings.Join(body.TXT, " "), 160))
	case *dnsmessage.AResource:
		s = fmt.Sprintf("A %s -> %d.%d.%d.%d", name, body.A[0], body.A[1], body.A[2], body.A[3])
		info.Hosts = appendUnique(info.Hosts, name)
	case *dnsmessage.AAAAResource:
		s = fmt.Sprintf("AAAA %s", name)
	default:
		s = fmt.Sprintf("%s %s", typeName(r.Header.Type), name)
	}
	if ttl == 0 {
		s += " (goodbye)"
	}
	info.Records = append(info.Records, s)
}

// serviceType extracts "_svc._tcp" from a name such as
// "_svc._tcp.local.", "Instance._svc._tcp.local." or "_sub._svc._tcp.local.".
// The enumeration name "_services._dns-sd._udp.local." is not a service.
func serviceType(name string) (string, bool) {
	if strings.EqualFold(name, servicesEnum) {
		return "", false
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i+2 < len(labels); i++ {
		proto := labels[i+1]
		if strings.HasPrefix(labels[i], "_") && (proto == "_tcp" || proto == "_udp") && labels[i+2] == "local" {
			return labels[i] + "." + proto, true
		}
	}
	return "", false
}

func typeName(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeALL:
		return "ANY"
	case 47:
		return "NSEC"
	case 13:
		return "HINFO"
	}
	return fmt.Sprintf("TYPE%d", uint16(t))
}

// buildMDNSQuery builds a multicast query for PTR records of the given names.
func buildMDNSQuery(names []string) ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, n := range names {
		name, err := dnsmessage.NewName(n)
		if err != nil {
			return nil, err
		}
		if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
