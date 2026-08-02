// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0
package babel

import (
	"net/netip"

	"github.com/TunnelHelper/TH/internal/babel/internal/table"
	"github.com/TunnelHelper/TH/internal/babel/proto"
)

type sourceKey struct {
	Prefix   netip.Prefix
	RouterID proto.RouterID
}

type SourceTable table.Table[sourceKey, *Source]

func NewSourceTable() SourceTable {
	return SourceTable(table.New[sourceKey, *Source]())
}

func (t *SourceTable) Lookup(pfx netip.Prefix, rid proto.RouterID) (*Source, bool) {
	return (*table.Table[sourceKey, *Source])(t).Lookup(sourceKey{
		Prefix:   pfx,
		RouterID: rid,
	})
}

func (t *SourceTable) Insert(s *Source) {
	(*table.Table[sourceKey, *Source])(t).Insert(sourceKey{
		s.Prefix,
		s.RouterID,
	}, s)
}

func (t *SourceTable) Remove(pfx netip.Prefix, rid proto.RouterID) {
	(*table.Table[sourceKey, *Source])(t).Remove(sourceKey{
		Prefix:   pfx,
		RouterID: rid,
	})
}

// All returns a snapshot of all source entries.
func (t *SourceTable) All() []*Source {
	sources := make([]*Source, 0)
	_ = (*table.Table[sourceKey, *Source])(t).ForEach(func(_ sourceKey, s *Source) error {
		sources = append(sources, s)
		return nil
	})
	return sources
}
