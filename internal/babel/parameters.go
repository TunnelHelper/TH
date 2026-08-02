// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package babel

import (
	"net/netip"
	"time"
)

// Appendix B. Protocol Parameters
// https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b

type Parameters struct {
	IHUHoldTimeFactor      float32
	IHUInterval            time.Duration
	InitialRequestTimeout  time.Duration
	MulticastHelloInterval time.Duration
	RouteExpiryTime        time.Duration
	SourceGCTime           time.Duration
	UnicastHelloInterval   time.Duration
	UpdateInterval         time.Duration
	UrgentTimeout          time.Duration
	NominalLinkCost        uint16

	// SmoothingAlpha is the exponential-smoothing factor used by the
	// route-selection hysteresis (RFC 8966 Appendix A.3). It must be in
	// (0, 1]; the default 0.25 matches babeld's behaviour of keeping
	// three quarters of the previous smoothed value.
	SmoothingAlpha float64

	// MaxPaths is the maximum number of next hops exported for a single
	// destination prefix. 1 disables multipath. The primary route is
	// always the one with the best metric; additional candidates are
	// feasible routes within MultipathSlack of the best metric.
	MaxPaths int

	// MultipathSlack is the maximum extra metric (relative to the best
	// route) for which an additional feasible route is still exported as
	// a multipath candidate. 0 exports only equal-cost routes.
	MultipathSlack uint16

	// SplitHorizon enables the RFC 8966 Section 3.7.4 optimisation for
	// symmetric, transitive interfaces. It SHOULD be enabled for tunnels.
	SplitHorizon bool
}

const (
	DefaultIHUInterval            = 12 * time.Second // 3 * DefaultMulticastHelloInterval
	DefaultInitialRequestTimeout  = 2 * time.Second
	DefaultMulticastHelloInterval = 4 * time.Second
	DefaultRouteExpiryTime        = 56 * time.Second // 3.5 * DefaultUpdateInterval
	DefaultSourceGCTime           = 3 * time.Minute
	DefaultUnicastHelloInterval   = 0                // infinite, no Hellos are sent
	DefaultUpdateInterval         = 16 * time.Second // 4 * DefaultMulticastHelloInterval
	DefaultUrgentTimeout          = 200 * time.Millisecond

	DefaultIHUHoldTimeFactor = 3.5 // times the advertised IHU interval
	DefaultWiredLinkCost     = 96
	DefaultSmoothingAlpha    = 0.25
	DefaultMaxPaths          = 4
)

var DefaultParameters = Parameters{
	MulticastHelloInterval: DefaultMulticastHelloInterval,
	UnicastHelloInterval:   DefaultUnicastHelloInterval,
	UpdateInterval:         DefaultUpdateInterval,
	IHUInterval:            DefaultIHUInterval,
	IHUHoldTimeFactor:      DefaultIHUHoldTimeFactor,
	RouteExpiryTime:        DefaultRouteExpiryTime,
	InitialRequestTimeout:  DefaultInitialRequestTimeout,
	UrgentTimeout:          DefaultUrgentTimeout,
	SourceGCTime:           DefaultSourceGCTime,
	NominalLinkCost:        DefaultWiredLinkCost,
	SmoothingAlpha:         DefaultSmoothingAlpha,
	MaxPaths:               DefaultMaxPaths,
	SplitHorizon:           true,
}

// LocalRouteMetric is the metric advertised for directly attached or
// redistributed routes injected by the local node (RFC 8966 Section 3.7).
const LocalRouteMetric uint16 = 0

// 5. IANA Considerations
// https://datatracker.ietf.org/doc/html/rfc8966#name-iana-considerations
var (
	Port               = 6697
	MulticastGroupIPv6 = netip.MustParseAddr("ff02::1:6")
	MulticastGroupIPv4 = netip.MustParseAddr("224.0.0.111")
)
