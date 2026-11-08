package main

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func mustName(t *testing.T, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A typical answer to a browse: PTR + SRV + TXT + A, as a receiver sends it.
func buildAnnouncement(t *testing.T) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.EnableCompression()
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	hdr := func(name string, ttl uint32) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: mustName(t, name), Class: dnsmessage.ClassINET, TTL: ttl}
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.PTRResource(hdr("_airplay._tcp.local.", 4500), dnsmessage.PTRResource{PTR: mustName(t, "Living Room._airplay._tcp.local.")}))
	must(b.PTRResource(hdr(servicesEnum, 4500), dnsmessage.PTRResource{PTR: mustName(t, "_raop._tcp.local.")}))
	must(b.SRVResource(hdr("Living Room._airplay._tcp.local.", 120), dnsmessage.SRVResource{Target: mustName(t, "tv.local."), Port: 7000}))
	must(b.TXTResource(hdr("Living Room._airplay._tcp.local.", 4500), dnsmessage.TXTResource{TXT: []string{"model=TV1", "features=0x1"}}))
	must(b.AResource(hdr("tv.local.", 0), dnsmessage.AResource{A: [4]byte{10, 0, 30, 11}}))
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestParseMDNSResponse(t *testing.T) {
	info, err := parseMDNS(buildAnnouncement(t))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Response {
		t.Error("want a response")
	}
	for _, want := range []string{"_airplay._tcp", "_raop._tcp"} {
		if !slices.Contains(info.Types, want) {
			t.Errorf("types %v: missing %s", info.Types, want)
		}
	}
	if !slices.Contains(info.Hosts, "tv.local.") {
		t.Errorf("hosts %v: missing tv.local.", info.Hosts)
	}
	all := strings.Join(info.Records, "\n")
	for _, want := range []string{"SRV Living Room._airplay._tcp.local. -> tv.local.:7000", "A tv.local. -> 10.0.30.11 (goodbye)", "model=TV1"} {
		if !strings.Contains(all, want) {
			t.Errorf("records missing %q:\n%s", want, all)
		}
	}
}

func TestBuildAndParseQuery(t *testing.T) {
	q, err := buildMDNSQuery([]string{servicesEnum, "_spotify-connect._tcp.local."})
	if err != nil {
		t.Fatal(err)
	}
	info, err := parseMDNS(q)
	if err != nil {
		t.Fatal(err)
	}
	if info.Response || len(info.Questions) != 2 {
		t.Fatalf("got %+v", info)
	}
	if !slices.Equal(info.Types, []string{"_spotify-connect._tcp"}) {
		t.Errorf("types = %v", info.Types)
	}
}

func TestParseMDNSRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0, 1, 2}, []byte(strings.Repeat("\xff", 40))} {
		if _, err := parseMDNS(b); err == nil {
			t.Errorf("parseMDNS(%q) succeeded", b)
		}
	}
	// A name-compression pointer to itself must not hang.
	loop := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 12, 0, 1}
	if _, err := parseMDNS(loop); err == nil {
		t.Error("compression loop parsed")
	}
}

func TestServiceType(t *testing.T) {
	cases := map[string]string{
		"_airplay._tcp.local.":             "_airplay._tcp",
		"Living Room._airplay._tcp.local.": "_airplay._tcp",
		"_sub._googlecast._tcp.local.":     "_googlecast._tcp",
		"Spk@Kitchen._raop._tcp.local.":    "_raop._tcp",
		servicesEnum:                       "",
		"tv.local.":                        "",
		"_airplay._tcp.example.com.":       "",
	}
	for in, want := range cases {
		got, ok := serviceType(in)
		if got != want || ok != (want != "") {
			t.Errorf("serviceType(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestParseSSDP(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://10.0.30.11:7678/nservice/\r\nSERVER: Linux UPnP/1.0\r\nST: urn:dial-multiscreen-org:service:dial:1\r\nUSN: uuid:abc::urn:dial-multiscreen-org:service:dial:1\r\n\r\n"
	info, err := parseSSDP([]byte(resp))
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "RESPONSE" || info.target() != "urn:dial-multiscreen-org:service:dial:1" || info.Headers["LOCATION"] != "http://10.0.30.11:7678/nservice/" {
		t.Errorf("got %+v", info)
	}

	// No trailing blank line, lower-case headers.
	notify := "NOTIFY * HTTP/1.1\r\nhost: 239.255.255.250:1900\r\nnt: upnp:rootdevice\r\nnts: ssdp:alive"
	info, err = parseSSDP([]byte(notify))
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "NOTIFY" || info.target() != "upnp:rootdevice" || info.Headers["NTS"] != "ssdp:alive" {
		t.Errorf("got %+v", info)
	}

	if _, err := parseSSDP([]byte("GET / HTTP/1.1\r\n\r\n")); err == nil {
		t.Error("plain HTTP parsed as SSDP")
	}
	if _, err := parseSSDP(buildMSearch("ssdp:all", 2)); err != nil {
		t.Errorf("own M-SEARCH: %v", err)
	}
}
