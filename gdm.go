package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/textproto"
	"strings"
)

// GDM ("G'Day Mate") is Plex's own discovery protocol: HTTP-like datagrams,
// mostly sent as broadcasts. Servers answer searches on 32414, players on
// 32412; 32410 and 32413 are used for announcements by some versions. Older
// clients use multicast 239.0.0.250.
var gdmPorts = []int{32410, 32412, 32413, 32414}

// gdmInfo is what observe mode extracts from one GDM packet.
type gdmInfo struct {
	Kind    string // M-SEARCH, HELLO, BYE or RESPONSE
	Headers map[string]string
}

var gdmLogHeaders = []string{"NAME", "PRODUCT", "VERSION", "CONTENT-TYPE", "RESOURCE-IDENTIFIER", "PORT", "PROTOCOL", "PROTOCOL-CAPABILITIES", "DEVICE-CLASS"}

func parseGDM(b []byte) (gdmInfo, error) {
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
	line, err := r.ReadLine()
	if err != nil {
		return gdmInfo{}, err
	}
	var info gdmInfo
	switch {
	case strings.HasPrefix(line, "M-SEARCH "):
		info.Kind = "M-SEARCH"
	case strings.HasPrefix(line, "HELLO "):
		info.Kind = "HELLO"
	case strings.HasPrefix(line, "BYE "):
		info.Kind = "BYE"
	case strings.HasPrefix(line, "HTTP/1.0 200"), strings.HasPrefix(line, "HTTP/1.1 200"):
		info.Kind = "RESPONSE"
	default:
		return info, fmt.Errorf("unrecognised start line %q", truncate(line, 60))
	}
	mh, err := r.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return info, err
	}
	info.Headers = map[string]string{}
	for k, v := range mh {
		if len(v) > 0 {
			info.Headers[strings.ToUpper(k)] = v[0]
		}
	}
	return info, nil
}

func (info gdmInfo) summary() string {
	var parts []string
	for _, k := range gdmLogHeaders {
		if v, ok := info.Headers[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%q", strings.ToLower(k), truncate(v, 120)))
		}
	}
	return strings.Join(parts, " ")
}

// label names what answered, e.g. `plex/player "Living Room" (Plex for Samsung)`.
func (info gdmInfo) label() string {
	if info.Kind != "RESPONSE" && info.Kind != "HELLO" {
		return ""
	}
	l := fmt.Sprintf("%s %q", info.Headers["CONTENT-TYPE"], info.Headers["NAME"])
	if p := info.Headers["PRODUCT"]; p != "" {
		l += " (" + p + ")"
	}
	return l
}

var gdmSearch = []byte("M-SEARCH * HTTP/1.1\r\n\r\n")

// broadcastAddr returns the directed broadcast address of an IPv4 prefix.
func broadcastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	for i := 3; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		a[i] |= byte(1<<n - 1)
		host -= n
	}
	return netip.AddrFrom4(a)
}

// rawPrefix shows the start of a packet that couldn't be parsed.
func rawPrefix(b []byte) string {
	return fmt.Sprintf("%q", truncate(string(b[:min(len(b), 64)]), 64))
}
