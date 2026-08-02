// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package table_test

import (
	"errors"
	"testing"

	"github.com/TunnelHelper/TH/internal/babel/internal/table"
)

func TestTableInsertLookupRemove(t *testing.T) {
	tbl := table.New[int, int]()
	tbl.Insert(4, 5)
	if tbl.Len() != 1 {
		t.Fatalf("len = %d, want 1", tbl.Len())
	}
	value, ok := tbl.Lookup(4)
	if !ok || value != 5 {
		t.Fatalf("lookup = (%d, %v), want (5, true)", value, ok)
	}
	tbl.Remove(4)
	if _, ok := tbl.Lookup(4); ok {
		t.Fatal("entry must be gone after removal")
	}
	if _, ok := tbl.Lookup(100); ok {
		t.Fatal("missing key must not be found")
	}
}

func TestTableClearAndEmpty(t *testing.T) {
	tbl := table.New[int, int]()
	if !tbl.Empty() {
		t.Fatal("fresh table must be empty")
	}
	tbl.Insert(6, 7)
	if tbl.Empty() {
		t.Fatal("table with entries must not be empty")
	}
	tbl.Clear()
	if !tbl.Empty() {
		t.Fatal("cleared table must be empty")
	}
}

func TestTableLenWithDuplicates(t *testing.T) {
	tbl := table.New[int, int]()
	if tbl.Len() != 0 {
		t.Fatal("fresh table must have len 0")
	}
	tbl.Insert(1, 1)
	tbl.Insert(1, 1)
	if tbl.Len() != 1 {
		t.Fatalf("duplicate insert must keep len 1, got %d", tbl.Len())
	}
	tbl.Insert(2, 1)
	if tbl.Len() != 2 {
		t.Fatalf("len = %d, want 2", tbl.Len())
	}
}

func TestTableUpdate(t *testing.T) {
	tbl := table.New[int, int]()
	tbl.Insert(1, 1)
	tbl.Update(map[int]int{1: 100})
	if tbl.Len() != 1 {
		t.Fatalf("update must not add entries, len = %d", tbl.Len())
	}
	value, ok := tbl.Lookup(1)
	if !ok || value != 100 {
		t.Fatalf("lookup = (%d, %v), want (100, true)", value, ok)
	}
}

func TestTableForEach(t *testing.T) {
	tbl := table.New[int, int]()
	expected := map[int]int{1: 100, 2: 200, 3: 300}
	tbl.Update(expected)

	got := make(map[int]int)
	if err := tbl.ForEach(func(k, v int) error {
		got[k] = v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(expected) {
		t.Fatalf("iterated %d entries, want %d", len(got), len(expected))
	}
	for k, v := range expected {
		if got[k] != v {
			t.Errorf("entry %d = %d, want %d", k, got[k], v)
		}
	}
}

func TestTableForEachAbortsOnError(t *testing.T) {
	tbl := table.New[int, int]()
	tbl.Update(map[int]int{1: 100, 2: 200, 3: 300})

	abortErr := errors.New("abort here")
	err := tbl.ForEach(func(k int, _ int) error {
		if k == 3 {
			return abortErr
		}
		return nil
	})
	if !errors.Is(err, abortErr) {
		t.Fatalf("ForEach must propagate the abort error, got %v", err)
	}
}
