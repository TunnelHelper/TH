// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"net/netip"
	"testing"
)

func mustParsePrefixPointer(s string) *netip.Prefix {
	p := netip.MustParsePrefix(s)
	return &p
}

func TestUpdateNotLessThanItself(t *testing.T) {
	u := &Update{}
	if u.Less(u) {
		t.Fatal("an update must not be less than itself")
	}
}

func TestUpdateOrdering(t *testing.T) {
	rid := RouterID{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
	cases := []struct {
		name string
		a, b *Update
	}{
		{"router ID",
			&Update{RouterID: RouterIDUnspecified},
			&Update{RouterID: RouterIDAllOnes},
		},
		{"v4 mapped less",
			&Update{Prefix: netip.MustParsePrefix("::ffff:1.0.0.1/128")},
			&Update{Prefix: netip.MustParsePrefix("::ffff:1.0.0.2/128")},
		},
		{"has router ID",
			&Update{RouterID: rid, Prefix: netip.MustParsePrefix("fe80::1234:5678:90ab:cdef/128")},
			&Update{RouterID: rid, Prefix: netip.MustParsePrefix("fe80::1/128")},
		},
		{"has router ID but wrong prefix",
			&Update{RouterID: rid, Prefix: netip.MustParsePrefix("fe80::1/128")},
			&Update{RouterID: rid, Prefix: netip.MustParsePrefix("fe80::1234:5678:90ab:cdef/127")},
		},
		{"prefix len",
			&Update{Prefix: netip.MustParsePrefix("fe80::1/128")},
			&Update{Prefix: netip.MustParsePrefix("fe80::1/127")},
		},
		{"prefix",
			&Update{Prefix: netip.MustParsePrefix("fe80::1/128")},
			&Update{Prefix: netip.MustParsePrefix("fe80::2/128")},
		},
		{"source prefix len",
			&Update{SourcePrefix: mustParsePrefixPointer("fe80::1/128")},
			&Update{SourcePrefix: mustParsePrefixPointer("fe80::1/127")},
		},
		{"source prefix",
			&Update{SourcePrefix: mustParsePrefixPointer("fe80::1/128")},
			&Update{SourcePrefix: mustParsePrefixPointer("fe80::2/128")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.a.Less(tc.b) {
				t.Error("a must be less than b")
			}
			if tc.b.Less(tc.a) {
				t.Error("b must not be less than a")
			}
		})
	}
}
