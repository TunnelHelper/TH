// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package history_test

import (
	"testing"

	"github.com/TunnelHelper/TH/internal/babel/internal/history"
)

const missed = 0xffff

func TestHelloHistoryOutOf(t *testing.T) {
	cases := []struct {
		name   string
		k, j   int
		seqnos []int
		want   bool
	}{
		{"empty history and 0-out-of-3 is okay", 0, 3, nil, true},
		{"empty history and 1-out-of-3 must fail", 1, 3, nil, false},
		{"1-out-of-3 with 1 entry", 1, 3, []int{1}, true},
		{"2-out-of-3 but only 1 entry", 2, 3, []int{1}, false},
		{"1-out-of-3 with reset is okay", 1, 3, []int{100}, true},
		{"1-out-of-3 with missed in between is okay", 1, 3, []int{1, missed, 2}, true},
		{"2-out-of-3 with missed in between is okay", 2, 3, []int{1, missed, 2}, true},
		{"3-out-of-3 with missed in between must fail", 3, 3, []int{1, missed, 2}, false},
		{"2-out-of-3 with repetition", 2, 3, []int{1, 2, 2}, true},
		{"2-out-of-3 with too many repetitions", 2, 3, []int{1, 1, 1}, false},
		{"2-out-of-3 with single repeated seqno must fail", 2, 2, []int{1, 1, 1}, false},
		{"2-out-of-3 with reset", 2, 3, []int{1, 2, 3, 4, 100, 101}, true},
		{"2-out-of-3 with reset but only 1 valid", 2, 3, []int{1, 2, 3, 4, 100}, false},
		{"2-out-of-3 with skip", 2, 3, []int{1, 2, 3, 6}, false},
		{"2-out-of-3 with less skip", 2, 3, []int{1, 2, 3, 5}, true},
		{"2-out-of-3 with undo", 2, 3, []int{1, 2, 3, 4, 5, 6, 3}, true},
		{"2-out-of-3 with more undo", 2, 3, []int{1, 2, 3, 1}, false},
		{"2-out-of-3: missed and recovered", 2, 3, []int{100, 101, 102, missed, missed, missed, 106, 107}, true},
		{"case 15: missed with rewind", 2, 3, []int{100, 101, 102, missed, missed, missed, 102, 103}, true},
		{"case 16: missed and dead", 2, 3, []int{1, 2, 3, 4, 5, missed, missed}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v history.HelloHistory
			v.Reset()
			for _, seqno := range tc.seqnos {
				if seqno == missed {
					v.Missed()
				} else {
					v.Update(uint16(seqno))
				}
			}
			if got := v.OutOf(tc.k, tc.j); got != tc.want {
				t.Errorf("OutOf(%d, %d) = %v, want %v", tc.k, tc.j, got, tc.want)
			}
		})
	}
}

func TestHelloHistoryEmpty(t *testing.T) {
	var v history.HelloHistory
	v.Reset()
	if !v.Empty() {
		t.Fatal("fresh history must be empty")
	}
	v.Update(1)
	if v.Empty() {
		t.Fatal("history with an entry must not be empty")
	}
}

func TestHelloHistoryDetectsReset(t *testing.T) {
	var v history.HelloHistory
	v.Reset()
	if !v.Update(100) {
		t.Error("first update must reset")
	}
	if !v.Update(200) {
		t.Error("jump of 100 seqnos must reset")
	}
	if v.Update(201) {
		t.Error("consecutive update must not reset")
	}
}
