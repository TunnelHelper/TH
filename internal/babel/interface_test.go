package babel

import (
	"net"
	"net/netip"
	"testing"
)

func TestBabelUsesRegisteredPort(t *testing.T) {
	if Port != 6696 {
		t.Fatalf("Babel port = %d, want registered UDP port 6696", Port)
	}
}

func TestBabelPayloadSizeAccountsForTransportHeaders(t *testing.T) {
	for _, test := range []struct {
		name string
		mtu  int
		ipv6 bool
		want int
	}{
		{name: "IPv4 Ethernet", mtu: 1500, want: 1472},
		{name: "IPv6 Ethernet", mtu: 1500, ipv6: true, want: 1452},
		{name: "minimum", mtu: 400, ipv6: true, want: 512},
		{name: "IPv6 jumbo", mtu: 9000, ipv6: true, want: 8952},
		{name: "IPv4 UDP maximum", mtu: 100000, want: maxBabelIPv4Size},
		{name: "IPv6 UDP maximum", mtu: 100000, ipv6: true, want: maxBabelIPv6Size},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := babelPayloadSize(test.mtu, test.ipv6); got != test.want {
				t.Fatalf("payload size = %d, want %d", got, test.want)
			}
		})
	}
}

func TestIPv4SourceMustBelongToLocalNetwork(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.1/24")
	local := &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), 32)}
	if !ipv4SourceOnLocalNetwork([]net.Addr{local}, netip.MustParseAddr("192.0.2.99")) {
		t.Fatal("same-subnet IPv4 source must be accepted")
	}
	if ipv4SourceOnLocalNetwork([]net.Addr{local}, netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("off-link IPv4 source must be rejected")
	}
	if ipv4SourceOnLocalNetwork([]net.Addr{local}, netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("IPv6 source must not pass IPv4 validation")
	}
}

func TestMulticastGroupsForAddresses(t *testing.T) {
	ipnet := func(value string) *net.IPNet {
		prefix := netip.MustParsePrefix(value)
		addr := prefix.Addr().AsSlice()
		return &net.IPNet{IP: addr, Mask: net.CIDRMask(prefix.Bits(), len(addr)*8)}
	}

	cases := []struct {
		name   string
		addrs  []net.Addr
		wantV6 bool
		wantV4 bool
	}{
		{name: "dual stack", addrs: []net.Addr{ipnet("2001:db8::1/64"), ipnet("192.0.2.1/24")}, wantV6: true, wantV4: true},
		{name: "ipv6 only", addrs: []net.Addr{ipnet("fe80::1/64"), ipnet("2001:db8::2/64")}, wantV6: true, wantV4: false},
		{name: "ipv4 only", addrs: []net.Addr{ipnet("198.51.100.7/24")}, wantV6: false, wantV4: true},
		{name: "unaddressed", addrs: nil, wantV6: false, wantV4: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v6, v4 := multicastGroupsForAddresses(tc.addrs)
			if got := v6 != nil; got != tc.wantV6 {
				t.Fatalf("IPv6 group = %v, want %v", got, tc.wantV6)
			}
			if got := v4 != nil; got != tc.wantV4 {
				t.Fatalf("IPv4 group = %v, want %v", got, tc.wantV4)
			}
			if v6 != nil && v6.IP.String() != MulticastGroupIPv6.String() {
				t.Fatalf("IPv6 group address = %s, want %s", v6.IP, MulticastGroupIPv6)
			}
			if v4 != nil && v4.IP.String() != MulticastGroupIPv4.String() {
				t.Fatalf("IPv4 group address = %s, want %s", v4.IP, MulticastGroupIPv4)
			}
		})
	}
}
