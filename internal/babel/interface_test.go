package babel

import (
	"net"
	"net/netip"
	"testing"
)

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
