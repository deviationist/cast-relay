package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strings"
)

// ssdpInfo is what observe mode extracts from one SSDP packet.
type ssdpInfo struct {
	Kind    string // M-SEARCH, NOTIFY or RESPONSE
	Headers map[string]string
}

// headers worth logging, in this order.
var ssdpLogHeaders = []string{"ST", "NT", "NTS", "MAN", "MX", "USN", "LOCATION", "SERVER", "USER-AGENT", "CACHE-CONTROL"}

func parseSSDP(b []byte) (ssdpInfo, error) {
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
	line, err := r.ReadLine()
	if err != nil {
		return ssdpInfo{}, err
	}
	var info ssdpInfo
	switch {
	case strings.HasPrefix(line, "M-SEARCH "):
		info.Kind = "M-SEARCH"
	case strings.HasPrefix(line, "NOTIFY "):
		info.Kind = "NOTIFY"
	case strings.HasPrefix(line, "HTTP/1.1 200"), strings.HasPrefix(line, "HTTP/1.0 200"):
		info.Kind = "RESPONSE"
	default:
		return info, fmt.Errorf("unrecognised start line %q", truncate(line, 60))
	}
	mh, err := r.ReadMIMEHeader()
	// A packet without the final blank line still parses.
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

func (info ssdpInfo) summary() string {
	var parts []string
	for _, k := range ssdpLogHeaders {
		if v, ok := info.Headers[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%q", strings.ToLower(k), truncate(v, 160)))
		}
	}
	return strings.Join(parts, " ")
}

// target is the ST of a search or response, or the NT of a notify.
func (info ssdpInfo) target() string {
	if info.Kind == "NOTIFY" {
		return info.Headers["NT"]
	}
	return info.Headers["ST"]
}

func buildMSearch(st string, mx int) []byte {
	return []byte(fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: %d\r\nST: %s\r\nUSER-AGENT: cast-relay/%s observe\r\n\r\n", mx, st, version))
}
