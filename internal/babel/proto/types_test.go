// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package proto_test

import (
	"testing"

	"github.com/TunnelHelper/TH/internal/babel/proto"
)

func TestSeqnoDistance(t *testing.T) {
	cases := []struct {
		a, b uint16
		d    int16
	}{
		{0x0001, 0x0001, 0},
		{0x0001, 0x0002, 1},
		{0xffff, 0x0000, 1},
		{0x0000, 0x8000, -32768},
		{0x8000, 0x0000, -32768},
		{0x8000, 0x8001, 1},
		{0x0000, 0x7fff, 32767},
		{0x0000, 0x0001, 1},
		{0xfffe, 0x0000, 2},
	}
	for _, tc := range cases {
		if got := proto.SeqnoDistance(tc.a, tc.b); got != tc.d {
			t.Errorf("SeqnoDistance(%#x, %#x) = %d, want %d", tc.a, tc.b, got, tc.d)
		}
		if got := proto.SeqnoDistance(tc.b, tc.a); got != -tc.d {
			t.Errorf("SeqnoDistance(%#x, %#x) = %d, want %d", tc.b, tc.a, got, -tc.d)
		}
	}
}

func TestSeqnoLess(t *testing.T) {
	cases := []struct {
		a, b uint16
		less bool
	}{
		{0x0001, 0x0001, false},
		{0x0001, 0x0002, true},
		{0x0002, 0x0001, false},
		{0xffff, 0x0000, true},
		{0x0000, 0xffff, false},
		{0x0000, 0x8000, false},
		{0x0000, 0x7fff, true},
		{0x0000, 0x8001, false},
	}
	for _, tc := range cases {
		if got := proto.SeqnoLess(tc.a, tc.b); got != tc.less {
			t.Errorf("SeqnoLess(%#x, %#x) = %v, want %v", tc.a, tc.b, got, tc.less)
		}
	}
}

func TestSeqnoEqualityAtHalfRange(t *testing.T) {
	cases := [][2]uint16{
		{0x0000, 0x8000},
		{0x0100, 0x8100},
		{0x0000, 0x0000},
		{0x0100, 0x0100},
	}
	for _, pair := range cases {
		if proto.SeqnoLess(pair[0], pair[1]) || proto.SeqnoLess(pair[1], pair[0]) {
			t.Errorf("seqnos %#x and %#x must be incomparable", pair[0], pair[1])
		}
	}
}

func TestSeqnoAbsDistance(t *testing.T) {
	if got := proto.SeqnoAbsDistance(0x0001, 0x0002); got != 1 {
		t.Errorf("SeqnoAbsDistance(1, 2) = %d, want 1", got)
	}
	if got := proto.SeqnoAbsDistance(0x0002, 0x0001); got != 1 {
		t.Errorf("SeqnoAbsDistance(2, 1) = %d, want 1", got)
	}
}
