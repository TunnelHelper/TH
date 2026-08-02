// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestParserPacketHonorsBodyLength(t *testing.T) {
	p := NewParser()
	packet := &Packet{
		Body:    []Value{&Hello{Seqno: 7, Interval: time.Second}},
		Trailer: []Value{&Pad1{}},
	}
	encoded := p.AppendPacket(nil, packet)
	wantBodyLength := p.ValuesLength(packet.Body)
	if got := binary.BigEndian.Uint16(encoded[2:4]); got != wantBodyLength {
		t.Fatalf("body length = %d, want %d", got, wantBodyLength)
	}

	remaining, decoded, err := NewParser().Packet(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 || len(decoded.Body) != 1 || len(decoded.Trailer) != 1 {
		t.Fatalf("decoded packet = body %d trailer %d remaining %d", len(decoded.Body), len(decoded.Trailer), len(remaining))
	}
	if _, ok := decoded.Trailer[0].(*Pad1); !ok {
		t.Fatalf("trailer value = %T, want *Pad1", decoded.Trailer[0])
	}
}

func TestParserDoesNotTreatTrailerAsBody(t *testing.T) {
	p := NewParser()
	encoded := []byte{PacketHeaderMagic, PacketHeaderVersion, 0, 0}
	encoded = p.AppendValue(encoded, &Hello{Seqno: 7, Interval: time.Second})
	if _, _, err := NewParser().Packet(encoded); !errors.Is(err, ErrInvalidValueForTrailer) {
		t.Fatalf("body TLV beyond declared body length must be rejected as trailer, got %v", err)
	}
}

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
	}
}

func TestParserV4ViaV6Update(t *testing.T) {
	p := NewParser()
	rid := RouterID{0x01, 0x23, 0x34, 0x45, 0x67, 0x89, 0x0a, 0xbc}
	prefix := netip.MustParsePrefix("10.0.0.0/16")
	nextHop := netip.MustParseAddr("fe80::1")

	b := p.AppendValue(nil, &RouterIDValue{RouterID: rid})
	b = p.AppendValue(b, &NextHop{NextHop: nextHop})
	b = p.AppendValue(b, &Update{Prefix: prefix, Seqno: 1, Metric: 100, Interval: time.Second, V4ViaV6: true})

	p.Reset()
	_, values, err := p.Values(b, false)
	if err != nil {
		t.Fatal(err)
	}
	update, ok := values[2].(*Update)
	if !ok {
		t.Fatalf("third value is %T, want *Update", values[2])
	}
	if !update.V4ViaV6 {
		t.Fatal("AE=4 update must be marked v4-via-v6")
	}
	if update.Prefix != prefix {
		t.Errorf("v4-via-v6 prefix = %s, want %s", update.Prefix, prefix)
	}
	if update.NextHop != nextHop {
		t.Errorf("v4-via-v6 next hop = %s, want IPv6 next hop %s", update.NextHop, nextHop)
	}
}

func TestParserAddressRejectsOutOfRangePlenOmitted(t *testing.T) {
	p := NewParser()

	// Plen larger than the 32-bit IPv4 address length must be rejected
	// instead of indexing past the address buffer.
	if _, _, err := p.prefix(make([]byte, 16), AddressEncodingIPv4, 33, 0); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("IPv4 plen=33: err = %v, want ErrInvalidAddress", err)
	}

	// Omitted larger than the 16-octet IPv6 address length must be rejected.
	p.CurrentDefaultPrefix[AddressEncodingIPv6] = netip.MustParseAddr("fe80::1")
	if _, _, err := p.prefix(make([]byte, 16), AddressEncodingIPv6, 128, 17); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("IPv6 omitted=17: err = %v, want ErrInvalidAddress", err)
	}

	// Omitted larger than the prefix itself (ceil(plen/8) octets) must be
	// rejected; it would otherwise yield a negative Prefix field length.
	if _, _, err := p.prefix(make([]byte, 16), AddressEncodingIPv6, 8, 3); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("IPv6 plen=8 omitted=3: err = %v, want ErrInvalidAddress", err)
	}

	// AE 3 (link-local IPv6) does not allow compression: Omitted MUST be 0.
	if _, _, err := p.prefix(make([]byte, 8), AddressEncodingIPv6LinkLocal, 64, 1); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("AE 3 omitted=1: err = %v, want ErrInvalidAddress", err)
	}

	// Valid compressed prefixes still decode: omitted octets are taken from
	// the previously established default prefix.
	p.CurrentDefaultPrefix[AddressEncodingIPv6] = netip.MustParseAddr("2001:db8::1")
	got, pfx, err := p.prefix([]byte{0, 0, 0, 0, 0, 0}, AddressEncodingIPv6, 80, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("valid compressed prefix must consume the buffer, got %d bytes left", len(got))
	}
	want := netip.MustParsePrefix("2001:db8::/80")
	if pfx != want {
		t.Errorf("compressed prefix = %s, want %s", pfx, want)
	}
}

func TestParserPacketRejectsMalformedUpdatePlen(t *testing.T) {
	// A crafted Update TLV with AE=1 (IPv4) and plen=33 used to panic with
	// "index out of range" while masking bits beyond the prefix length.
	// It must now be rejected as an invalid address.
	pkt := []byte{
		0x2a, 0x02, 0x00, 0x11, // magic, version, body length (17)
		0x08, 0x0f, // Update TLV, body length 15
		0x01, 0x00, 0x21, 0x00, // AE=1, flags=0, plen=33, omitted=0
		0x00, 0x01, 0x00, 0x01, 0x00, 0x64, // interval, seqno, metric
		0x00, 0x00, 0x00, 0x00, 0x00, // 5 prefix octets
	}

	p := NewParser()
	if _, _, err := p.Packet(pkt); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Packet: err = %v, want ErrInvalidAddress", err)
	}
}

func TestParserPathMetricsRoundTrip(t *testing.T) {
	p := NewParser()
	rid := RouterID{0x01, 0x23, 0x34, 0x45, 0x67, 0x89, 0x0a, 0xbc}
	prefix := netip.MustParsePrefix("10.0.0.0/16")

	b := p.AppendValue(nil, &RouterIDValue{RouterID: rid})
	b = p.AppendValue(b, &Update{
		Prefix: prefix, Seqno: 1, Metric: 100, Interval: time.Second,
		PathBottleneckMbps: 10,
		PathRTTMicros:      5000,
	})

	p.Reset()
	_, values, err := p.Values(b, false)
	if err != nil {
		t.Fatal(err)
	}
	update, ok := values[1].(*Update)
	if !ok {
		t.Fatalf("second value is %T, want *Update", values[1])
	}
	if update.PathBottleneckMbps != 10 || update.PathRTTMicros != 5000 {
		t.Fatalf("path metrics = (%d, %d), want (10, 5000)", update.PathBottleneckMbps, update.PathRTTMicros)
	}
}

func TestParserPathQualityRoundTrip(t *testing.T) {
	p := NewParser()
	prefix := netip.MustParsePrefix("10.0.0.0/16")
	b := p.AppendValue(nil, &Update{
		Prefix: prefix, Seqno: 1, Metric: 100, Interval: time.Second,
		PathRTTMicros:        5000,
		PathJitterMicros:     700,
		PathMetricAgeMillis:  1200,
		PathMetricConfidence: 49151,
	})
	p.Reset()
	_, values, err := p.Values(b, false)
	if err != nil {
		t.Fatal(err)
	}
	update := values[0].(*Update)
	if update.PathJitterMicros != 700 || update.PathMetricAgeMillis != 1200 || update.PathMetricConfidence != 49151 {
		t.Fatalf("path quality = (%d, %d, %d)", update.PathJitterMicros, update.PathMetricAgeMillis, update.PathMetricConfidence)
	}
}

func TestParserPathQualityPreservesUnknownAndSaturates(t *testing.T) {
	p := NewParser()
	prefix := netip.MustParsePrefix("10.0.0.0/16")
	b := p.AppendValue(nil, &Update{
		Prefix: prefix, Seqno: 1, Metric: 100, Interval: time.Second,
		PathJitterMicros:     -1,
		PathMetricAgeMillis:  int64(math.MaxUint32) + 100,
		PathMetricConfidence: 1,
	})
	p.Reset()
	_, values, err := p.Values(b, false)
	if err != nil {
		t.Fatal(err)
	}
	update := values[0].(*Update)
	if update.PathJitterMicros != -1 || update.PathMetricAgeMillis != int64(math.MaxUint32-1) {
		t.Fatalf("path quality unknown/saturation = (%d, %d)", update.PathJitterMicros, update.PathMetricAgeMillis)
	}
}

func TestParserPathMetricsUnsetBottleneck(t *testing.T) {
	p := NewParser()
	prefix := netip.MustParsePrefix("10.0.0.0/16")
	b := p.AppendValue(nil, &Update{
		Prefix: prefix, Seqno: 1, Metric: 100, Interval: time.Second,
		PathBottleneckMbps: 0,
		PathRTTMicros:      1000,
	})
	p.Reset()
	_, values, err := p.Values(b, false)
	if err != nil {
		t.Fatal(err)
	}
	update := values[0].(*Update)
	if update.PathBottleneckMbps != 0 || update.PathRTTMicros != 1000 {
		t.Fatalf("unset bottleneck must decode as 0, got (%d, %d)", update.PathBottleneckMbps, update.PathRTTMicros)
	}
	if got := decodeBottleneck(math.MaxUint32 - 1); got <= 0 {
		t.Fatalf("large remote bottleneck overflowed int: %d", got)
	}
}

func TestParserPathMetricsUnsetRTT(t *testing.T) {
	p := NewParser()
	prefix := netip.MustParsePrefix("10.0.0.0/16")
	b := p.AppendValue(nil, &Update{
		Prefix: prefix, Seqno: 1, Metric: 100, Interval: time.Second,
		PathBottleneckMbps: 10,
		PathRTTMicros:      -1,
	})
	p.Reset()
	_, values, err := p.Values(b, false)
	if err != nil {
		t.Fatal(err)
	}
	update := values[0].(*Update)
	if update.PathBottleneckMbps != 10 || update.PathRTTMicros != -1 {
		t.Fatalf("unset RTT must remain unknown, got (%d, %d)", update.PathBottleneckMbps, update.PathRTTMicros)
	}
}

func TestParserIgnoresUnknownSubTLV(t *testing.T) {
	p := NewParser()
	buildUpdate := func(subType uint8) []byte {
		return p.appendValueHeader(nil, TypeUpdate, func(b []byte) []byte {
			b = p.appendUint8(b, AddressEncodingIPv4)
			b = p.appendUint8(b, 0)
			b = p.appendUint8(b, 24)
			b = p.appendUint8(b, 0)
			b = p.appendInterval(b, time.Second)
			b = p.appendUint16(b, 1)
			b = p.appendUint16(b, 100)
			b = append(b, 10, 0, 0) // 10.0.0.0/24 prefix
			return append(b, subType, 1, 0xab)
		})
	}

	// An unknown non-mandatory sub-TLV is silently ignored.
	b := buildUpdate(6)
	p.Reset()
	if _, _, err := p.Values(b, false); err != nil {
		t.Fatalf("unknown non-mandatory sub-TLV must be ignored: %v", err)
	}

	// A mandatory unknown sub-TLV (high bit set) must fail parsing.
	b2 := buildUpdate(0x85)
	p.Reset()
	if _, _, err := p.Values(b2, false); !errors.Is(err, ErrUnsupportedButMandatoryValue) {
		t.Fatalf("mandatory unknown sub-TLV must fail, got %v", err)
	}
}

func TestParserFlagUpdateRouterID(t *testing.T) {
	cases := []string{
		"10.168.0.0/16",
		"2a09:bac0:35::826:93f9/128",
		"fe80::210:5aff:feaa:20a2/64",
		"1.2.3.4/32",
	}
	for _, prefix := range cases {
		p := NewParser()
		pfx := netip.MustParsePrefix(prefix)
		rid := RouterIDFromAddr(pfx.Addr())

		b := p.AppendValue(nil, &Update{Flags: FlagUpdateRouterID, Prefix: pfx})
		b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("10.169.0.0/16")})
		b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("2a10:bac0:35::826:93f9/128")})
		b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("fe80::310:5aff:feaa:20a2/64")})
		b = p.AppendValue(b, &Update{Prefix: netip.MustParsePrefix("1.2.3.5/32")})

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
	expected := map[AddressEncoding]Address{
		AddressEncodingIPv4:          pfx4.Addr(),
		AddressEncodingIPv6:          pfx6.Addr(),
		AddressEncodingIPv6LinkLocal: pfx6LL.Addr(),
	}

	p := NewParser()
	b := p.AppendValue(nil, &Update{Flags: FlagUpdatePrefix, Prefix: pfx4})
	b = p.AppendValue(b, &Update{Flags: FlagUpdatePrefix, Prefix: pfx6})
	b = p.AppendValue(b, &Update{Flags: FlagUpdatePrefix, Prefix: pfx6LL})
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
			// An absent PathMetrics sub-TLV decodes as unknown (-1); the
			// zero value used by the test inputs represents the same state.
			if update, ok := decoded.(*Update); ok && update.PathRTTMicros == -1 {
				update.PathRTTMicros = 0
				update.PathJitterMicros = 0
				update.PathMetricAgeMillis = 0
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
