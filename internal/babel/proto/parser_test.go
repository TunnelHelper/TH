// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestParserUintRoundTrips(t *testing.T) {
	uint8s := []uint8{0xaa, 0xbb, 0xcc}
	uint16s := []uint16{0xaaaa, 0xbbbb, 0xcccc}
	uint64s := []uint64{0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc}

	p := NewParser()
	var b []byte
	for _, v := range uint8s {
		b = p.appendUint8(b, v)
	}
	for i := 0; len(b) > 0; i++ {
		var n uint8
		var err error
		b, n, err = p.uint8(b)
		if err != nil {
			t.Fatal(err)
		}
		if n != uint8s[i] {
			t.Errorf("uint8[%d] = %#x, want %#x", i, n, uint8s[i])
		}
	}
	if len(b) != 0 {
		t.Fatal("uint8 buffer must be fully consumed")
	}

	b = nil
	for _, v := range uint16s {
		b = p.appendUint16(b, v)
	}
	for i := 0; len(b) > 0; i++ {
		var n uint16
		var err error
		b, n, err = p.uint16(b)
		if err != nil {
			t.Fatal(err)
		}
		if n != uint16s[i] {
			t.Errorf("uint16[%d] = %#x, want %#x", i, n, uint16s[i])
		}
	}

	b = nil
	for _, v := range uint64s {
		b = p.appendUint64(b, v)
	}
	for i := 0; len(b) > 0; i++ {
		var n uint64
		var err error
		b, n, err = p.uint64(b)
		if err != nil {
			t.Fatal(err)
		}
		if n != uint64s[i] {
			t.Errorf("uint64[%d] = %#x, want %#x", i, n, uint64s[i])
		}
	}
}

func TestParserIntervalRoundTrip(t *testing.T) {
	p := NewParser()
	original := 12 * time.Second
	b := p.appendInterval(nil, original)
	if len(b) != 2 {
		t.Fatalf("interval must encode to 2 bytes, got %d", len(b))
	}
	b, decoded, err := p.interval(b)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != original {
		t.Errorf("interval = %v, want %v", decoded, original)
	}
	if len(b) != 0 {
		t.Fatal("interval buffer must be fully consumed")
	}
}

func TestParserRouterIDRoundTrip(t *testing.T) {
	p := NewParser()
	original := RouterID{0x01, 0x23, 0x34, 0x45, 0x67, 0x89, 0x0a, 0xbc}
	b := p.appendRouterID(nil, original)
	if len(b) != 8 {
		t.Fatalf("router id must encode to 8 bytes, got %d", len(b))
	}
	b, decoded, err := p.routerID(b)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != original {
		t.Errorf("router id = %x, want %x", decoded, original)
	}
	if len(b) != 0 {
		t.Fatal("router id buffer must be fully consumed")
	}
}

func TestParserRouterIDInvalid(t *testing.T) {
	p := NewParser()
	for _, rid := range []RouterID{RouterIDAllOnes, RouterIDAllZeros} {
		if _, _, err := p.routerID(rid[:]); err != ErrInvalidRouterID {
			t.Errorf("router id %x must be rejected, got %v", rid, err)
		}
	}
}

func TestRouterIDFromAddr(t *testing.T) {
	cases := []struct {
		addr string
		rid  RouterID
	}{
		{"10.168.44.55", RouterID{0, 0, 0, 0, 10, 168, 44, 55}},
		{"2a09:bac0:35::826:93f9", RouterID{0, 0, 0, 0, 0x08, 0x26, 0x93, 0xf9}},
		{"fe80::210:5aff:feaa:20a2", RouterID{0x02, 0x10, 0x5a, 0xff, 0xfe, 0xaa, 0x20, 0xa2}},
		{"::ffff:1.2.3.4", RouterID{0, 0, 0, 0, 1, 2, 3, 4}},
	}
	for _, tc := range cases {
		if got := RouterIDFromAddr(netip.MustParseAddr(tc.addr)); got != tc.rid {
			t.Errorf("RouterIDFromAddr(%s) = %x, want %x", tc.addr, got, tc.rid)
		}
	}
}

func TestParserAddressRoundTrip(t *testing.T) {
	cases := []struct {
		addr  string
		len   int
		expAE uint8
	}{
		{"1.1.1.1", 4, AddressEncodingIPv4},
		{"fd3d:bd4f:9738::1036:d55b:fb01:b6d1", 16, AddressEncodingIPv6},
		{"::", 0, AddressEncodingWildcard},
		{"fe80::1234:5678:90AB:CDEF", 8, AddressEncodingIPv6LinkLocal},
		{"::ffff:1.2.3.4", 4, AddressEncodingIPv4inIPv6},
	}
	for _, tc := range cases {
		p := NewParser()
		original := netip.MustParseAddr(tc.addr)
		b, ae := p.appendAddress(nil, original, -1)
		if len(b) != tc.len {
			t.Errorf("%s: encoded length = %d, want %d", tc.addr, len(b), tc.len)
		}
		if ae != AddressEncoding(tc.expAE) {
			t.Errorf("%s: AE = %d, want %d", tc.addr, ae, tc.expAE)
		}
		b, decoded, err := p.address(b, ae, 0, -1)
		if err != nil {
			t.Fatal(err)
		}
		if decoded != original {
			t.Errorf("%s: decoded %s != %s", tc.addr, decoded, original)
		}
		if len(b) != 0 {
			t.Errorf("%s: buffer must be fully consumed", tc.addr)
		}
		if ae == AddressEncodingIPv4inIPv6 && (!decoded.Is4In6() || !decoded.Is6()) {
			t.Errorf("%s: decoded address must be 4-in-6", tc.addr)
		}
	}
}

func TestParserPrefixRoundTrip(t *testing.T) {
	cases := []struct {
		addr    string
		len     int
		expAE   uint8
		expPlen uint8
	}{
		{"1.1.0.0/16", 2, AddressEncodingIPv4, 16},
		{"fd3d:bd4f:9738::/48", 6, AddressEncodingIPv6, 48},
		{"::/0", 0, AddressEncodingWildcard, 0},
		{"fe80::1234:5678:90AB:CDEF/128", 8, AddressEncodingIPv6LinkLocal, 128},
		{"::ffff:10.0.0.0/16", 2, AddressEncodingIPv4inIPv6, 16},
	}
	for _, tc := range cases {
		p := NewParser()
		original := netip.MustParsePrefix(tc.addr)
		b, ae, plen, _ := p.appendPrefix(nil, original, false)
		if len(b) != tc.len {
			t.Errorf("%s: encoded length = %d, want %d", tc.addr, len(b), tc.len)
		}
		if ae != AddressEncoding(tc.expAE) || plen != tc.expPlen {
			t.Errorf("%s: (ae, plen) = (%d, %d), want (%d, %d)", tc.addr, ae, plen, tc.expAE, tc.expPlen)
		}
		b, decoded, err := p.prefix(b, ae, plen, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded != original {
			t.Errorf("%s: decoded %s != %s", tc.addr, decoded, original)
		}
		if len(b) != 0 {
			t.Errorf("%s: buffer must be fully consumed", tc.addr)
		}
		if ae == AddressEncodingIPv4inIPv6 {
			if !decoded.Addr().Is4In6() || !decoded.Addr().Is6() {
				t.Errorf("%s: decoded prefix must be 4-in-6", tc.addr)
			}
		}
	}
}

func TestParserFlagUpdateRouterID(t *testing.T) {
	cases := []string{
		"10.168.0.0/16",
		"2a09:bac0:35::826:93f9/128",
		"fe80::210:5aff:feaa:20a2/64",
		"::ffff:1.2.3.4/128",
	}
	for _, prefix := range cases {
		p := NewParser()
		pfx := netip.MustParsePrefix(prefix)
		rid := RouterIDFromAddr(pfx.Addr())

		b := p.AppendValue(nil, &Update{Flags: FlagUpdateRouterID, Prefix: pfx})
		b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("10.169.0.0/16")})
		b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("2a10:bac0:35::826:93f9/128")})
		b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("fe80::310:5aff:feaa:20a2/64")})
		b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("::ffff:1.2.3.5/128")})

		if p.CurrentRouterID != rid {
			t.Errorf("%s: current router id = %x, want %x", prefix, p.CurrentRouterID, rid)
		}

		p.Reset()
		if _, _, err := p.Values(b, false); err != nil {
			t.Fatal(err)
		}
		if p.CurrentRouterID != rid {
			t.Errorf("%s: decoded router id = %x, want %x", prefix, p.CurrentRouterID, rid)
		}
	}
}

func TestParserFlagUpdatePrefix(t *testing.T) {
	pfx4 := netip.MustParsePrefix("10.168.0.0/16")
	pfx6 := netip.MustParsePrefix("fd5e:181e:5bbd::/48")
	pfx6LL := netip.MustParsePrefix("fe80::1234:5678:90ab:cdef/128")
	pfx4in6 := netip.MustParsePrefix("::ffff:1.2.3.4/128")
	expected := map[AddressEncoding]Address{
		AddressEncodingIPv4:          pfx4.Addr(),
		AddressEncodingIPv6:          pfx6.Addr(),
		AddressEncodingIPv6LinkLocal: pfx6LL.Addr(),
		AddressEncodingIPv4inIPv6:    pfx4in6.Addr(),
	}

	p := NewParser()
	b := p.AppendValue(nil, &Update{Flags: FlagUpdatePrefix, Prefix: pfx4})
	b = p.AppendValue(b, &Update{Flags: FlagUpdatePrefix, Prefix: pfx6})
	b = p.AppendValue(b, &Update{Flags: FlagUpdatePrefix, Prefix: pfx6LL})
	b = p.AppendValue(b, &Update{Flags: FlagUpdatePrefix, Prefix: pfx4in6})
	b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("10.169.0.0/16")})
	b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("fe80::1337/128")})

	for encoding, want := range expected {
		if got, ok := p.CurrentDefaultPrefix[encoding]; !ok || got != want {
			t.Errorf("default prefix for AE %d = %s (present %v), want %s", encoding, got, ok, want)
		}
	}

	p.Reset()
	if _, _, err := p.Values(b, false); err != nil {
		t.Fatal(err)
	}
	for encoding, want := range expected {
		if got, ok := p.CurrentDefaultPrefix[encoding]; !ok || got != want {
			t.Errorf("decoded default prefix for AE %d = %s (present %v), want %s", encoding, got, ok, want)
		}
	}
}

func TestParserValuesRoundTrip(t *testing.T) {
	sourcePrefix := netip.MustParsePrefix("10.0.0.0/24")
	cases := []struct {
		name string
		typ  ValueType
		val  Value
	}{
		{"Pad1", TypePad1, &Pad1{}},
		{"PadN", TypePadN, &PadN{N: 111}},
		{"AcknowledgmentRequest", TypeAcknowledgmentRequest, &AcknowledgmentRequest{Opaque: 0x1234, Interval: 4 * time.Second}},
		{"Acknowledgment", TypeAcknowledgment, &Acknowledgment{Opaque: 0x1234}},
		{"Hello", TypeHello, &Hello{Flags: FlagHelloUnicast, Seqno: 1233, Interval: 33 * time.Second}},
		{"Hello with Timestamp", TypeHello, &Hello{Flags: FlagHelloUnicast, Seqno: 1233, Interval: 33 * time.Second, Timestamp: &TimestampHello{Transmit: 532235}}},
		{"IHU", TypeIHU, &IHU{RxCost: 0xABCD, Interval: 2 * time.Second, Address: netip.MustParseAddr("1.2.3.4")}},
		{"IHU with Timestamp", TypeIHU, &IHU{RxCost: 0xABCD, Interval: 2 * time.Second, Address: netip.MustParseAddr("1.2.3.4"), Timestamp: &TimestampIHU{Origin: 42394723, Receive: 23283423}}},
		{"RouterID", TypeRouterID, &RouterIDValue{RouterID: RouterID{0x01, 0x23, 0x34, 0x45, 0x67, 0x89, 0x0a, 0xbc}}},
		{"NextHop", TypeNextHop, &NextHop{NextHop: netip.MustParseAddr("1.2.3.4")}},
		{"Update", TypeUpdate, &Update{Flags: FlagUpdatePrefix, Interval: 2 * time.Second, Seqno: 1233, Metric: 100, Prefix: netip.MustParsePrefix("192.168.0.0/16")}},
		{"Update with SourcePrefix", TypeUpdate, &Update{Flags: FlagUpdatePrefix, Interval: 2 * time.Second, Seqno: 1233, Metric: 100, Prefix: netip.MustParsePrefix("192.168.0.0/16"), SourcePrefix: &sourcePrefix}},
		{"RouteRequest", TypeRouteRequest, &RouteRequest{Prefix: netip.MustParsePrefix("192.168.0.0/16")}},
		{"RouteRequest with SourcePrefix", TypeRouteRequest, &RouteRequest{Prefix: netip.MustParsePrefix("192.168.0.0/16"), SourcePrefix: &sourcePrefix}},
		{"SeqnoRequest", TypeSeqnoRequest, &SeqnoRequest{Seqno: 1233, HopCount: 99, RouterID: RouterID{0x01, 0x23, 0x34, 0x45, 0x67, 0x89, 0x0a, 0xbc}, Prefix: netip.MustParsePrefix("192.168.0.0/16")}},
		{"SeqnoRequest with SourcePrefix", TypeSeqnoRequest, &SeqnoRequest{Seqno: 1233, HopCount: 99, RouterID: RouterID{0x01, 0x23, 0x34, 0x45, 0x67, 0x89, 0x0a, 0xbc}, Prefix: netip.MustParsePrefix("192.168.0.0/16"), SourcePrefix: &sourcePrefix}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser()
			b := p.AppendValue(nil, tc.val)
			if len(b) != p.ValueLength(tc.val) {
				t.Errorf("encoded length = %d, want %d", len(b), p.ValueLength(tc.val))
			}
			p.Reset()
			_, decoded, typ, err := p.value(b)
			if err != nil {
				t.Fatal(err)
			}
			if typ != tc.typ {
				t.Errorf("type = %d, want %d", typ, tc.typ)
			}
			if !reflect.DeepEqual(decoded, tc.val) {
				t.Errorf("decoded %#v != %#v", decoded, tc.val)
			}
		})
	}
}

func TestParserRouterIDStatePropagatesToUpdate(t *testing.T) {
	p := NewParser()
	rid := RouterID{0x01, 0x23, 0x34, 0x45, 0x67, 0x89, 0x0a, 0xbc}
	prefix := netip.MustParsePrefix("fd00:7::/64")
	nextHop := netip.MustParseAddr("fe80::1")

	b := p.AppendValue(nil, &RouterIDValue{RouterID: rid})
	b = p.AppendValue(b, &NextHop{NextHop: nextHop})
	b = p.AppendValue(b, &Update{Prefix: prefix, Seqno: 9, Metric: 100, Interval: 4 * time.Second})

	p.Reset()
	_, values, err := p.Values(b, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 3 {
		t.Fatalf("expected 3 values, got %d", len(values))
	}
	update, ok := values[2].(*Update)
	if !ok {
		t.Fatalf("third value is %T, want *Update", values[2])
	}
	if update.RouterID != rid {
		t.Errorf("update router id = %x, want %x", update.RouterID, rid)
	}
	if update.NextHop != nextHop {
		t.Errorf("update next hop = %s, want %s", update.NextHop, nextHop)
	}
}

func TestParserWildcardRouteRequest(t *testing.T) {
	p := NewParser()
	// A wildcard route request is a RouteRequest TLV (type 8) with the
	// AE=0 wildcard address encoding and plen 0.
	raw := []byte{byte(TypeRouteRequest), 2, byte(AddressEncodingWildcard), 0}
	_, value, _, err := p.value(raw)
	if err != nil {
		t.Fatal(err)
	}
	request, ok := value.(*RouteRequest)
	if !ok {
		t.Fatalf("decoded %T, want *RouteRequest", value)
	}
	if !request.Wildcard {
		t.Fatal("AE=0 request must be marked as wildcard")
	}

	// A default-route request (AE=2, plen=0) must NOT be wildcard.
	raw = []byte{byte(TypeRouteRequest), 2, byte(AddressEncodingIPv6), 0}
	_, value, _, err = p.value(raw)
	if err != nil {
		t.Fatal(err)
	}
	request = value.(*RouteRequest)
	if request.Wildcard {
		t.Fatal("AE=2 /0 request must not be marked as wildcard")
	}
}
