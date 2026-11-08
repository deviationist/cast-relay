package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var testIfs = []netIf{
	{Name: "eth0", Index: 2, Addr: netip.MustParseAddr("10.0.10.2"), Prefix: netip.MustParsePrefix("10.0.10.0/24")},
	{Name: "eth1", Index: 3, Addr: netip.MustParseAddr("10.0.20.2"), Prefix: netip.MustParsePrefix("10.0.20.0/24")},
	{Name: "eth2", Index: 4, Addr: netip.MustParseAddr("10.0.30.2"), Prefix: netip.MustParsePrefix("10.0.30.0/24")},
}

const testConfigJSON = `{
  "networks": {
    "lan":   {"interface": "eth0", "role": "client"},
    "guest": {"interface": "eth1", "role": "client"},
    "iot":   {"interface": "eth2", "role": "devices"}
  },
  "devices": [
    {"name": "tv", "network": "iot", "ip": "10.0.30.11",
     "profiles": ["airplay", "dial"], "visible_to": ["lan", "guest"], "location_ports": [7678, 8080]},
    {"name": "speaker", "network": "iot", "ip": "10.0.30.12",
     "profiles": ["airplay", "spotify-connect"], "mdns": ["_vendor._tcp"],
     "ssdp": ["urn:schemas-upnp-org:device:ZonePlayer:1"], "visible_to": ["lan"]}
  ]
}`

func testConfig(t *testing.T) *config {
	t.Helper()
	var fc fileConfig
	if err := json.Unmarshal([]byte(testConfigJSON), &fc); err != nil {
		t.Fatal(err)
	}
	cfg, err := resolveConfig(fc, testIfs)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func netNamed(cfg *config, name string) *network {
	for _, n := range cfg.Networks {
		if n.Name == name {
			return n
		}
	}
	panic(name)
}

func devNamed(cfg *config, name string) *device {
	for _, d := range cfg.Devices {
		if d.Name == name {
			return d
		}
	}
	panic(name)
}

// ---- config ----

func TestConfigResolves(t *testing.T) {
	cfg := testConfig(t)
	tv := devNamed(cfg, "tv")
	if !tv.MDNS["_airplay._tcp"] || !tv.SSDP["urn:dial-multiscreen-org:service:dial:1"] || len(tv.VisibleTo) != 2 {
		t.Errorf("tv resolved wrong: %+v", tv)
	}
	sp := devNamed(cfg, "speaker")
	if !sp.MDNS["_vendor._tcp"] || !sp.SSDP["urn:schemas-upnp-org:device:zoneplayer:1"] {
		t.Errorf("speaker extras missing: %+v", sp)
	}
}

func TestConfigRejects(t *testing.T) {
	cases := map[string]func(*fileConfig){
		"device outside subnet":    func(c *fileConfig) { c.Devices[0].IP = "10.0.10.11" },
		"relay's own address":      func(c *fileConfig) { c.Devices[0].IP = "10.0.30.2" },
		"duplicate ip":             func(c *fileConfig) { c.Devices[1].IP = c.Devices[0].IP },
		"visible to devices net":   func(c *fileConfig) { c.Devices[0].VisibleTo = []string{"iot"} },
		"device on client net":     func(c *fileConfig) { c.Devices[0].Network = "lan"; c.Devices[0].IP = "10.0.10.11" },
		"unknown profile":          func(c *fileConfig) { c.Devices[0].Profiles = []string{"nope"} },
		"bad service type":         func(c *fileConfig) { c.Devices[1].MDNS = []string{"vendor.tcp"} },
		"ssdp:all as a target":     func(c *fileConfig) { c.Devices[1].SSDP = []string{"ssdp:all"} },
		"empty visible_to":         func(c *fileConfig) { c.Devices[0].VisibleTo = nil },
		"no services":              func(c *fileConfig) { c.Devices[0].Profiles = nil },
		"empty allowlist":          func(c *fileConfig) { c.Devices = nil },
		"missing interface":        func(c *fileConfig) { c.Networks["lan"] = fileNetwork{Interface: "eth9", Role: "client"} },
		"bad role":                 func(c *fileConfig) { c.Networks["lan"] = fileNetwork{Interface: "eth0", Role: "both"} },
		"shadowed builtin profile": func(c *fileConfig) { c.Profiles = map[string]profile{"airplay": {MDNS: []string{"_x._tcp"}}} },
		"bad location port":        func(c *fileConfig) { c.Devices[0].LocationPorts = []int{70000} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var fc fileConfig
			if err := json.Unmarshal([]byte(testConfigJSON), &fc); err != nil {
				t.Fatal(err)
			}
			mutate(&fc)
			if _, err := resolveConfig(fc, testIfs); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// ---- mDNS helpers ----

func query(t *testing.T, response bool, names ...string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: response})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := b.Question(dnsmessage.Question{Name: mustName(t, n), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET | 0x8000}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

type rr struct {
	name, kind, target string
	a                  [4]byte
	ttl                uint32
}

func answer(t *testing.T, response bool, rrs ...rr) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: response, Authoritative: true})
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, x := range rrs {
		ttl := x.ttl
		if ttl == 0 {
			ttl = 120
		}
		if x.ttl == 1 {
			ttl = 0 // goodbye
		}
		h := dnsmessage.ResourceHeader{Name: mustName(t, x.name), Class: dnsmessage.ClassINET, TTL: ttl}
		var err error
		switch x.kind {
		case "PTR":
			err = b.PTRResource(h, dnsmessage.PTRResource{PTR: mustName(t, x.target)})
		case "SRV":
			err = b.SRVResource(h, dnsmessage.SRVResource{Target: mustName(t, x.target), Port: 7000})
		case "TXT":
			err = b.TXTResource(h, dnsmessage.TXTResource{TXT: []string{"model=X"}})
		case "A":
			err = b.AResource(h, dnsmessage.AResource{A: x.a})
		case "AAAA":
			err = b.AAAAResource(h, dnsmessage.AAAAResource{})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func questions(t *testing.T, msg []byte) []string {
	t.Helper()
	info, err := parseMDNS(msg)
	if err != nil {
		t.Fatal(err)
	}
	return info.Questions
}

func records(t *testing.T, msg []byte) string {
	t.Helper()
	info, err := parseMDNS(msg)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(info.Records, "\n")
}

var tvAnnouncement = []rr{
	{name: "_airplay._tcp.local.", kind: "PTR", target: "Living TV._airplay._tcp.local."},
	{name: servicesEnum, kind: "PTR", target: "_airplay._tcp.local."},
	{name: "Living TV._airplay._tcp.local.", kind: "SRV", target: "tv.local."},
	{name: "Living TV._airplay._tcp.local.", kind: "TXT"},
	{name: "tv.local.", kind: "A", a: [4]byte{10, 0, 30, 11}},
	// Must not pass:
	{name: "11.30.0.10.in-addr.arpa.", kind: "PTR", target: "tv.local."},
	{name: "tv.local.", kind: "AAAA"},
	{name: "Living TV._device-info._tcp.local.", kind: "TXT"},
	{name: "_ssh._tcp.local.", kind: "PTR", target: "tv._ssh._tcp.local."},
	{name: "evil.local.", kind: "A", a: [4]byte{10, 0, 10, 99}},
}

// ---- mDNS queries ----

func TestMDNSQueryRelayed(t *testing.T) {
	cfg := testConfig(t)
	out, reason := relayMDNSQuery(cfg, newLearnedNames(), netNamed(cfg, "lan"), query(t, false, "_airplay._tcp.local.", "_spotify-connect._tcp.local.", "_ssh._tcp.local."), time.Now())
	if reason != "" || len(out) != 1 || out[0].Net.Name != "iot" {
		t.Fatalf("out=%v reason=%q", out, reason)
	}
	qs := questions(t, out[0].Msg)
	if len(qs) != 2 || qs[0] != "_airplay._tcp.local. PTR" || qs[1] != "_spotify-connect._tcp.local. PTR" {
		t.Errorf("questions = %q (want the two allowed ones, QU cleared)", qs)
	}
}

func TestMDNSQueryVisibility(t *testing.T) {
	cfg := testConfig(t)
	// The speaker is visible to lan only, so guest may not ask for its types.
	if _, reason := relayMDNSQuery(cfg, newLearnedNames(), netNamed(cfg, "guest"), query(t, false, "_spotify-connect._tcp.local."), time.Now()); reason != "no-allowed-question" {
		t.Errorf("guest asking for a lan-only type: reason %q", reason)
	}
	if _, reason := relayMDNSQuery(cfg, newLearnedNames(), netNamed(cfg, "guest"), query(t, false, "_airplay._tcp.local."), time.Now()); reason != "" {
		t.Errorf("guest asking for the tv's type: reason %q", reason)
	}
}

func TestMDNSQueryEnumerationAndSubtype(t *testing.T) {
	cfg := testConfig(t)
	out, reason := relayMDNSQuery(cfg, newLearnedNames(), netNamed(cfg, "lan"), query(t, false, servicesEnum, "_x1._sub._airplay._tcp.local."), time.Now())
	if reason != "" || len(questions(t, out[0].Msg)) != 2 {
		t.Errorf("reason %q", reason)
	}
}

// A phone briefly announces an instance of an allowlisted type (the iOS
// local-network check). It must never leave its network.
func TestMDNSClientAnnouncementDropped(t *testing.T) {
	cfg := testConfig(t)
	msg := answer(t, true, rr{name: "_vendor._tcp.local.", kind: "PTR", target: "05987952._vendor._tcp.local."})
	if _, reason := relayMDNSQuery(cfg, newLearnedNames(), netNamed(cfg, "lan"), msg, time.Now()); reason != "client-announcement" {
		t.Errorf("reason %q", reason)
	}
}

func TestMDNSInstanceQueryNeedsLearning(t *testing.T) {
	cfg := testConfig(t)
	learned := newLearnedNames()
	lan := netNamed(cfg, "lan")
	q := query(t, false, "Living TV._airplay._tcp.local.")
	if _, reason := relayMDNSQuery(cfg, learned, lan, q, time.Now()); reason == "" {
		t.Fatal("instance query passed before the device announced it")
	}
	if _, reason := relayMDNSAnswer(devNamed(cfg, "tv"), learned, answer(t, true, tvAnnouncement...), time.Now()); reason != "" {
		t.Fatal(reason)
	}
	if _, reason := relayMDNSQuery(cfg, learned, lan, q, time.Now()); reason != "" {
		t.Errorf("instance query after learning: %q", reason)
	}
	if _, reason := relayMDNSQuery(cfg, learned, lan, query(t, false, "tv.local."), time.Now()); reason != "" {
		t.Errorf("host query after learning: %q", reason)
	}
}

// ---- mDNS answers ----

func TestMDNSAnswerFiltered(t *testing.T) {
	cfg := testConfig(t)
	msg, reason := relayMDNSAnswer(devNamed(cfg, "tv"), newLearnedNames(), answer(t, true, tvAnnouncement...), time.Now())
	if reason != "" {
		t.Fatal(reason)
	}
	got := records(t, msg)
	for _, want := range []string{
		"PTR _airplay._tcp.local. -> Living TV._airplay._tcp.local.",
		"PTR _services._dns-sd._udp.local. -> _airplay._tcp.local.",
		"SRV Living TV._airplay._tcp.local. -> tv.local.:7000",
		"TXT Living TV._airplay._tcp.local.",
		"A tv.local. -> 10.0.30.11",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, bad := range []string{"in-addr.arpa", "AAAA", "_device-info", "_ssh", "evil.local", "10.0.10.99"} {
		if strings.Contains(got, bad) {
			t.Errorf("leaked %q in\n%s", bad, got)
		}
	}
}

func TestMDNSAnswerOtherDevicesTypeDropped(t *testing.T) {
	cfg := testConfig(t)
	// The tv may not announce the speaker's types.
	msg := answer(t, true,
		rr{name: "_spotify-connect._tcp.local.", kind: "PTR", target: "x._spotify-connect._tcp.local."},
		rr{name: "x._spotify-connect._tcp.local.", kind: "SRV", target: "tv.local."})
	if _, reason := relayMDNSAnswer(devNamed(cfg, "tv"), newLearnedNames(), msg, time.Now()); reason != "no-allowed-record" {
		t.Errorf("reason %q", reason)
	}
}

func TestMDNSDeviceQueryDropped(t *testing.T) {
	cfg := testConfig(t)
	if _, reason := relayMDNSAnswer(devNamed(cfg, "speaker"), newLearnedNames(), query(t, false, "_vendor._tcp.local."), time.Now()); reason != "device-query" {
		t.Errorf("reason %q", reason)
	}
}

func TestMDNSGoodbyeForgets(t *testing.T) {
	cfg := testConfig(t)
	tv := devNamed(cfg, "tv")
	learned := newLearnedNames()
	now := time.Now()
	if _, reason := relayMDNSAnswer(tv, learned, answer(t, true, tvAnnouncement...), now); reason != "" {
		t.Fatal(reason)
	}
	bye := answer(t, true, rr{name: "Living TV._airplay._tcp.local.", kind: "SRV", target: "tv.local.", ttl: 1})
	msg, reason := relayMDNSAnswer(tv, learned, bye, now)
	if reason != "" || !strings.Contains(records(t, msg), "(goodbye)") {
		t.Fatalf("goodbye not passed: %q", reason)
	}
	if learned.has(tv, "Living TV._airplay._tcp.local.", now) {
		t.Error("instance still learned after goodbye")
	}
	if learned.has(tv, "tv.local.", now.Add(200*time.Second)) {
		t.Error("learned name outlived its TTL")
	}
}

// ---- SSDP ----

func ssdpMsg(t *testing.T, s string) ssdpInfo {
	t.Helper()
	info, err := parseSSDP([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestSSDPSearch(t *testing.T) {
	cfg := testConfig(t)
	lan, guest := netNamed(cfg, "lan"), netNamed(cfg, "guest")
	search := func(st, man, mx string) string {
		return "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: " + man + "\r\nMX: " + mx + "\r\nST: " + st + "\r\n\r\n"
	}
	s, nets, reason := checkSSDPSearch(cfg, lan, ssdpMsg(t, search("urn:dial-multiscreen-org:service:dial:1", `"ssdp:discover"`, "5")))
	if reason != "" || len(nets) != 1 || s.MX != 2 {
		t.Errorf("dial search: %+v %v %q", s, nets, reason)
	}
	if _, _, reason := checkSSDPSearch(cfg, lan, ssdpMsg(t, search("ssdp:all", `"ssdp:discover"`, "1"))); reason != "" {
		t.Errorf("ssdp:all: %q", reason)
	}
	if _, _, reason := checkSSDPSearch(cfg, lan, ssdpMsg(t, search("roku:ecp", `"ssdp:discover"`, "1"))); reason != "no-allowed-target" {
		t.Errorf("roku: %q", reason)
	}
	if _, _, reason := checkSSDPSearch(cfg, guest, ssdpMsg(t, search("urn:schemas-upnp-org:device:ZonePlayer:1", `"ssdp:discover"`, "1"))); reason != "no-allowed-target" {
		t.Errorf("guest asking for a lan-only target: %q", reason)
	}
	if _, _, reason := checkSSDPSearch(cfg, lan, ssdpMsg(t, search("ssdp:all", `"ssdp:notify"`, "1"))); reason != "bad-man" {
		t.Errorf("bad MAN: %q", reason)
	}
}

const dialReply = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://10.0.30.11:7678/nservice/\r\nSERVER: TV\r\nST: urn:dial-multiscreen-org:service:dial:1\r\nUSN: uuid:abc::urn:dial-multiscreen-org:service:dial:1\r\nX-SECRET: leak\r\n\r\n"

func TestSSDPReply(t *testing.T) {
	cfg := testConfig(t)
	tv := devNamed(cfg, "tv")
	msg, reason := relaySSDPReply(tv, "urn:dial-multiscreen-org:service:dial:1", ssdpMsg(t, dialReply))
	if reason != "" {
		t.Fatal(reason)
	}
	got := string(msg)
	if !strings.Contains(got, "LOCATION: http://10.0.30.11:7678/nservice/") || strings.Contains(got, "X-SECRET") {
		t.Errorf("reply rebuilt wrong:\n%s", got)
	}
	cases := map[string]struct{ st, reply, want string }{
		"location elsewhere": {"ssdp:all", strings.Replace(dialReply, "10.0.30.11:7678", "10.0.10.9:7678", 1), "location-elsewhere"},
		"location port":      {"ssdp:all", strings.Replace(dialReply, ":7678/", ":9197/", 1), "location-port"},
		"https location":     {"ssdp:all", strings.Replace(dialReply, "http://", "https://", 1), "bad-location"},
		"target not allowed": {"ssdp:all", strings.Replace(dialReply, "ST: urn:dial-multiscreen-org:service:dial:1", "ST: urn:samsung.com:device:ScreenSharing:1", 1), "target-not-allowed"},
		"answer to other st": {"urn:dial-multiscreen-org:device:dialreceiver:1", dialReply, "target-mismatch"},
		"missing usn":        {"ssdp:all", strings.Replace(dialReply, "USN: uuid:abc::urn:dial-multiscreen-org:service:dial:1\r\n", "", 1), "no-usn"},
	}
	for name, c := range cases {
		if _, reason := relaySSDPReply(tv, c.st, ssdpMsg(t, c.reply)); reason != c.want {
			t.Errorf("%s: reason %q, want %q", name, reason, c.want)
		}
	}
}

func TestSSDPNotify(t *testing.T) {
	cfg := testConfig(t)
	tv := devNamed(cfg, "tv")
	alive := "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://10.0.30.11:7678/nservice/\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\nNTS: ssdp:alive\r\nUSN: uuid:abc\r\n\r\n"
	if _, reason := relaySSDPNotify(tv, ssdpMsg(t, alive)); reason != "" {
		t.Errorf("alive: %q", reason)
	}
	bye := "NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\nNTS: ssdp:byebye\r\nUSN: uuid:abc\r\n\r\n"
	if _, reason := relaySSDPNotify(tv, ssdpMsg(t, bye)); reason != "" {
		t.Errorf("byebye: %q", reason)
	}
	other := strings.Replace(alive, "NT: urn:dial-multiscreen-org:service:dial:1", "NT: urn:samsung.com:device:ScreenSharing:1", 1)
	if _, reason := relaySSDPNotify(tv, ssdpMsg(t, other)); reason != "target-not-allowed" {
		t.Errorf("other target: %q", reason)
	}
}

func TestBuildSSDPStripsLineBreaks(t *testing.T) {
	info := ssdpInfo{Headers: map[string]string{"SERVER": "x\r\nLOCATION: http://evil/"}}
	got := string(buildSSDP("HTTP/1.1 200 OK", info, []string{"SERVER"}))
	if strings.Count(got, "\r\n") != 3 { // start line, one header, blank line
		t.Errorf("header injection survived:\n%q", got)
	}
}

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(2, 3)
	ip := netip.MustParseAddr("10.0.10.50")
	now := time.Now()
	allowed := 0
	for range 10 {
		if l.allow(ip, now) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("burst: %d allowed, want 3", allowed)
	}
	if !l.allow(ip, now.Add(600*time.Millisecond)) {
		t.Error("no refill after 600 ms at 2/s")
	}
}

// Devices match search targets exactly, so the relay must send the client's
// spelling, not the lower-cased form it compares with.
func TestSSDPSearchKeepsCase(t *testing.T) {
	cfg := testConfig(t)
	msg := "M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n"
	s, _, reason := checkSSDPSearch(cfg, netNamed(cfg, "lan"), ssdpMsg(t, msg))
	if reason != "" {
		t.Fatal(reason)
	}
	if got := string(buildRelaySearch(s)); !strings.Contains(got, "ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n") {
		t.Errorf("relayed search lost the case:\n%s", got)
	}
}
