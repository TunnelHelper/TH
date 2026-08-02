// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"github.com/TunnelHelper/TH/internal/babel/internal/table"
	"github.com/TunnelHelper/TH/internal/babel/proto"
)

type pendingSeqNoRequestKey struct {
	Prefix   proto.Prefix
	RouterID proto.RouterID
}

type PendingSeqNoRequestTable table.Table[pendingSeqNoRequestKey, *PendingSeqNoRequest]

func (t *PendingSeqNoRequestTable) Lookup(pfx proto.Prefix, rid proto.RouterID) (*PendingSeqNoRequest, bool) {
	return (*table.Table[pendingSeqNoRequestKey, *PendingSeqNoRequest])(t).Lookup(pendingSeqNoRequestKey{
		Prefix:   pfx,
		RouterID: rid,
	})
}

func (t *PendingSeqNoRequestTable) Insert(req *PendingSeqNoRequest) {
	(*table.Table[pendingSeqNoRequestKey, *PendingSeqNoRequest])(t).Insert(pendingSeqNoRequestKey{
		Prefix:   req.Prefix,
		RouterID: req.RouterID,
	}, req)
}
