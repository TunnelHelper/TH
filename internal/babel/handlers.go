// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

type NeighbourHandler interface {
	NeighbourAdded(*Neighbour)
	NeighbourRemoved(*Neighbour)
}

type InterfaceHandler interface {
	InterfaceAdded(*Interface)
	InterfaceRemoved(*Interface)
}

// RouteHandler is notified whenever the set of selected routes changes.
// The callback is invoked asynchronously and must not call back into the
// Speaker synchronously; use Advertise/Withdraw from another goroutine if
// the handler needs to react by injecting routes.
type RouteHandler interface {
	RoutesChanged()
}
