//go:build darwin

package vpnc

import (
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestRouteMessageLayoutMatchesDarwinSDK(t *testing.T) {
	if got, want := unsafe.Sizeof(rtMetrics{}), uintptr(unix.SizeofRtMetrics); got != want {
		t.Fatalf("rtMetrics size = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(rtMsghdr{}), uintptr(unix.SizeofRtMsghdr); got != want {
		t.Fatalf("rtMsghdr size = %d, want %d", got, want)
	}
	if rtmVersion != unix.RTM_VERSION {
		t.Fatalf("RTM version = %d, want %d", rtmVersion, unix.RTM_VERSION)
	}
	if routeSocketAlignment != 4 {
		t.Fatalf("route socket alignment = %d, want 4", routeSocketAlignment)
	}
}

func TestParseRoute(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantIP     string
		wantPrefix int
		wantBits   int
	}{
		{
			name:       "IPv4 netmask",
			value:      "10.231.7.123/255.255.0.0",
			wantIP:     "10.231.0.0",
			wantPrefix: 16,
			wantBits:   32,
		},
		{
			name:       "IPv4 CIDR",
			value:      "10.231.7.123/24",
			wantIP:     "10.231.7.0",
			wantPrefix: 24,
			wantBits:   32,
		},
		{
			name:       "IPv6 CIDR",
			value:      "2001:db8:1::123/64",
			wantIP:     "2001:db8:1::",
			wantPrefix: 64,
			wantBits:   128,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip, mask, err := parseRoute(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if got := ip.String(); got != test.wantIP {
				t.Fatalf("network address = %s, want %s", got, test.wantIP)
			}
			prefix, bits := mask.Size()
			if prefix != test.wantPrefix || bits != test.wantBits {
				t.Fatalf("mask = %d/%d, want %d/%d", prefix, bits, test.wantPrefix, test.wantBits)
			}
		})
	}
}

func TestParseRouteRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{
		"10.0.0.1",
		"10.0.0.1/not-a-prefix",
		"10.0.0.1/255.0.255.0",
		"2001:db8::1/255.255.255.0",
		"10.0.0.1/33",
		"2001:db8::1/129",
	} {
		t.Run(value, func(t *testing.T) {
			if _, _, err := parseRoute(value); err == nil {
				t.Fatalf("parseRoute(%q) unexpectedly succeeded", value)
			}
		})
	}
}

func TestBuildIPv4HostRouteMessage(t *testing.T) {
	message, err := buildRtMsg(
		unix.RTM_ADD,
		42,
		7,
		net.ParseIP("198.51.100.42"),
		nil,
		net.ParseIP("192.0.2.1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(message), routeHeaderSize()+16+16; got != want {
		t.Fatalf("message length = %d, want %d", got, want)
	}
	hdr, ok := decodeRtMsg(message)
	if !ok {
		t.Fatal("failed to decode route header")
	}
	if hdr.Msglen != uint16(len(message)) || hdr.Version != rtmVersion || hdr.Type != unix.RTM_ADD || hdr.Index != 7 || hdr.Seq != 42 {
		t.Fatalf("unexpected route header: %+v", hdr)
	}
	if hdr.Addrs != unix.RTA_DST|unix.RTA_GATEWAY {
		t.Fatalf("address bitmap = %#x, want %#x", hdr.Addrs, unix.RTA_DST|unix.RTA_GATEWAY)
	}
	if hdr.Flags&unix.RTF_HOST == 0 {
		t.Fatalf("host route flag is not set: %#x", hdr.Flags)
	}

	dst := message[routeHeaderSize():]
	if got := net.IP(dst[4:8]).String(); got != "198.51.100.42" {
		t.Fatalf("destination = %s", got)
	}
	gateway := dst[16:]
	if got := net.IP(gateway[4:8]).String(); got != "192.0.2.1" {
		t.Fatalf("gateway = %s", got)
	}
}

func TestBuildIPv4NetworkRouteMessage(t *testing.T) {
	_, mask, err := parseRoute("10.231.7.123/255.255.0.0")
	if err != nil {
		t.Fatal(err)
	}

	message, err := buildRtMsg(
		unix.RTM_ADD,
		43,
		8,
		net.ParseIP("10.231.0.0"),
		mask,
		net.ParseIP("10.231.0.1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(message), routeHeaderSize()+16+16+16; got != want {
		t.Fatalf("message length = %d, want %d", got, want)
	}
	hdr, ok := decodeRtMsg(message)
	if !ok {
		t.Fatal("failed to decode route header")
	}
	if hdr.Flags&unix.RTF_HOST != 0 {
		t.Fatalf("network route incorrectly has host flag: %#x", hdr.Flags)
	}
	if hdr.Addrs != unix.RTA_DST|unix.RTA_GATEWAY|unix.RTA_NETMASK {
		t.Fatalf("address bitmap = %#x, want %#x", hdr.Addrs, unix.RTA_DST|unix.RTA_GATEWAY|unix.RTA_NETMASK)
	}

	maskAddress := message[routeHeaderSize()+32:]
	if got := net.IP(maskAddress[4:8]).String(); got != "255.255.0.0" {
		t.Fatalf("netmask = %s", got)
	}
}

func TestBuildIPv6NetworkRouteMessage(t *testing.T) {
	mask := net.CIDRMask(64, 128)
	message, err := buildRtMsg(
		unix.RTM_ADD,
		44,
		9,
		net.ParseIP("2001:db8:1::"),
		mask,
		net.ParseIP("2001:db8:1::1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(message), routeHeaderSize()+28+28+28; got != want {
		t.Fatalf("message length = %d, want %d", got, want)
	}
	hdr, ok := decodeRtMsg(message)
	if !ok {
		t.Fatal("failed to decode route header")
	}
	if hdr.Addrs != unix.RTA_DST|unix.RTA_GATEWAY|unix.RTA_NETMASK {
		t.Fatalf("address bitmap = %#x, want %#x", hdr.Addrs, unix.RTA_DST|unix.RTA_GATEWAY|unix.RTA_NETMASK)
	}

	dst := message[routeHeaderSize():]
	if got := net.IP(dst[8:24]).String(); got != "2001:db8:1::" {
		t.Fatalf("destination = %s", got)
	}
	maskAddress := message[routeHeaderSize()+56:]
	if got := net.IP(maskAddress[8:24]).String(); got != "ffff:ffff:ffff:ffff::" {
		t.Fatalf("netmask = %s", got)
	}
}

func TestDecodeRtMsgRejectsShortMessage(t *testing.T) {
	if _, ok := decodeRtMsg(make([]byte, routeHeaderSize()-1)); ok {
		t.Fatal("short route message unexpectedly decoded")
	}
}

func TestRouteAddressRejectsInvalidAddress(t *testing.T) {
	if _, err := parseRouteAddress("not-an-ip"); err == nil {
		t.Fatal("invalid address unexpectedly accepted")
	}
	if _, err := parseRouteAddress(""); err == nil {
		t.Fatal("empty address unexpectedly accepted")
	}
	if _, err := parseRouteAddress("192.0.2.1:443"); err == nil {
		t.Fatal("host:port unexpectedly accepted")
	}
}
