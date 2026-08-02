package model

import (
	"net/netip"
	"time"
)

const (
	SchemaVersion = 4
	BundleVersion = 1

	MaxTunnelRecords       = 1024
	MaxInterfaceAddresses  = 256
	MaxWireGuardPeers      = 1024
	MaxAllowedIPsPerPeer   = 4096
	MaxAllowedIPsPerTunnel = 16384
	MaxManagedRouteClaims  = 262144
	MaxSRv6Sources         = 64
)

type Bundle struct {
	BundleVersion int      `json:"bundle_version"`
	Tunnels       []Tunnel `json:"tunnels"`
}

type Kind string

const (
	KindGRE        Kind = "gre"
	KindVXLAN      Kind = "vxlan"
	KindWireGuard  Kind = "wireguard"
	KindAmneziaWG  Kind = "amneziawg"
	KindXFRMStatic Kind = "xfrm-static"
	KindXFRMIKEv2  Kind = "xfrm-ikev2"
	KindSRv6       Kind = "srv6"
)

var Kinds = []Kind{
	KindGRE,
	KindVXLAN,
	KindWireGuard,
	KindAmneziaWG,
	KindXFRMStatic,
	KindXFRMIKEv2,
	KindSRv6,
}

type Tunnel struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	Generation    uint64    `json:"generation"`
	Name          string    `json:"name"`
	Kind          Kind      `json:"kind"`
	Interface     string    `json:"interface,omitempty"`
	Enabled       bool      `json:"enabled"`
	Spec          Spec      `json:"spec"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Spec struct {
	GRE        *GRESpec        `json:"gre,omitempty"`
	VXLAN      *VXLANSpec      `json:"vxlan,omitempty"`
	WireGuard  *WireGuardSpec  `json:"wireguard,omitempty"`
	AmneziaWG  *AmneziaWGSpec  `json:"amneziawg,omitempty"`
	XFRMStatic *XFRMStaticSpec `json:"xfrm_static,omitempty"`
	XFRMIKEv2  *XFRMIKEv2Spec  `json:"xfrm_ikev2,omitempty"`
	SRv6       *SRv6Spec       `json:"srv6,omitempty"`

	// Babel optionally enables the in-process Babel routing protocol on
	// this tunnel. Tunnels without this section (or with enabled=false)
	// never participate in Babel.
	Babel *BabelTunnelConfig `json:"babel,omitempty"`

	// Mptcp optionally overrides the daemon-wide MPTCP endpoint
	// registration for this tunnel. Tunnels without this section follow
	// the global mptcp.enabled switch; an explicit section can opt the
	// tunnel out (endpoint=false) or force registration on (endpoint=true).
	Mptcp *MptcpTunnelConfig `json:"mptcp,omitempty"`
}

type GRESpec struct {
	Local     netip.Addr     `json:"local"`
	Remote    netip.Addr     `json:"remote"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
	MTU       int            `json:"mtu"`
	TTL       uint8          `json:"ttl"`
}

type VXLANSpec struct {
	VNI               int            `json:"vni"`
	UnderlayInterface string         `json:"underlay_interface"`
	Local             netip.Addr     `json:"local"`
	Remote            netip.Addr     `json:"remote"`
	DestinationPort   int            `json:"destination_port"`
	Learning          bool           `json:"learning"`
	Addresses         []netip.Prefix `json:"addresses,omitempty"`
	MTU               int            `json:"mtu"`
}

type WireGuardSpec struct {
	PrivateKey      string          `json:"private_key,omitempty"`
	PublicKey       string          `json:"public_key"`
	ListenPort      int             `json:"listen_port,omitempty"`
	FirewallMark    int             `json:"firewall_mark,omitempty"`
	Addresses       []netip.Prefix  `json:"addresses,omitempty"`
	MTU             int             `json:"mtu"`
	RouteAllowedIPs bool            `json:"route_allowed_ips"`
	RouteTable      int             `json:"route_table,omitempty"`
	Peers           []WireGuardPeer `json:"peers,omitempty"`
}

type WireGuardPeer struct {
	PublicKey    string         `json:"public_key"`
	PresharedKey string         `json:"preshared_key,omitempty"`
	Endpoint     string         `json:"endpoint,omitempty"`
	Keepalive    int            `json:"keepalive,omitempty"`
	AllowedIPs   []netip.Prefix `json:"allowed_ips,omitempty"`
}

type AmneziaWGSpec struct {
	WireGuardSpec
	JunkPacketCount        int    `json:"jc"`
	JunkPacketMinSize      int    `json:"jmin"`
	JunkPacketMaxSize      int    `json:"jmax"`
	InitPacketJunkSize     int    `json:"s1"`
	ResponsePacketJunkSize int    `json:"s2"`
	InitMagicHeader        string `json:"h1"`
	ResponseMagicHeader    string `json:"h2"`
	UnderloadMagicHeader   string `json:"h3"`
	TransportMagicHeader   string `json:"h4"`
}

type XFRMAlgorithm string

const (
	XFRMAESGCM       XFRMAlgorithm = "aes-gcm-128"
	XFRMAESCBCSHA256 XFRMAlgorithm = "aes-cbc-256-hmac-sha256"
)

type XFRMStaticSpec struct {
	UnderlayInterface    string         `json:"underlay_interface"`
	Local                netip.Addr     `json:"local"`
	Remote               netip.Addr     `json:"remote"`
	Addresses            []netip.Prefix `json:"addresses,omitempty"`
	MTU                  int            `json:"mtu"`
	IfID                 uint32         `json:"if_id"`
	ReqID                uint32         `json:"req_id"`
	SPIInbound           uint32         `json:"spi_inbound"`
	SPIOutbound          uint32         `json:"spi_outbound"`
	Algorithm            XFRMAlgorithm  `json:"algorithm"`
	EncryptionKeyIn      string         `json:"encryption_key_in,omitempty"`
	EncryptionKeyOut     string         `json:"encryption_key_out,omitempty"`
	AuthenticationKeyIn  string         `json:"authentication_key_in,omitempty"`
	AuthenticationKeyOut string         `json:"authentication_key_out,omitempty"`
}

type IKEAuthMethod string

const (
	IKEAuthPSK IKEAuthMethod = "psk"
	IKEAuthRPK IKEAuthMethod = "rpk"
)

type XFRMIKEv2Spec struct {
	UnderlayInterface string         `json:"underlay_interface"`
	LocalAddress      string         `json:"local_address"`
	RemoteAddress     string         `json:"remote_address"`
	LocalID           string         `json:"local_id"`
	RemoteID          string         `json:"remote_id"`
	Addresses         []netip.Prefix `json:"addresses,omitempty"`
	MTU               int            `json:"mtu"`
	IfID              uint32         `json:"if_id"`
	ReqID             uint32         `json:"req_id"`
	AuthMethod        IKEAuthMethod  `json:"auth_method"`
	PSK               string         `json:"psk,omitempty"`
	RPKAlgorithm      string         `json:"rpk_algorithm,omitempty"`
	LocalPrivateKey   string         `json:"local_private_key,omitempty"`
	LocalPublicKey    string         `json:"local_public_key,omitempty"`
	RemotePublicKey   string         `json:"remote_public_key,omitempty"`
	IKEProposal       string         `json:"ike_proposal"`
	ESPProposal       string         `json:"esp_proposal"`
	Encapsulation     bool           `json:"encapsulation"`
	StartAction       string         `json:"start_action"`
}

type SRv6Spec struct {
	UnderlayInterface      string       `json:"underlay_interface"`
	Table                  int          `json:"table"`
	RulePriority           int          `json:"rule_priority"`
	RefreshIntervalSeconds int          `json:"refresh_interval_seconds"`
	Sources                []SRv6Source `json:"sources"`
}

type SRv6AddressFamily string

const (
	SRv6FamilyIPv4 SRv6AddressFamily = "ipv4"
	SRv6FamilyIPv6 SRv6AddressFamily = "ipv6"
)

type SRv6Source struct {
	Name      string            `json:"name"`
	Family    SRv6AddressFamily `json:"family"`
	PrefixURL string            `json:"prefix_url"`
	SID       netip.Addr        `json:"sid"`
	Priority  int               `json:"priority"`
	MTU       int               `json:"mtu"`
}

// BabelTunnelConfig is the per-tunnel Babel participation switch. The
// protocol itself runs in a single daemon-wide engine that aggregates every
// tunnel with Enabled set.
type BabelTunnelConfig struct {
	// Enabled controls whether this tunnel participates in Babel.
	Enabled bool `json:"enabled"`

	// Balance is the per-tunnel ECMP bandwidth/latency bias in [-2, 2],
	// mapped to weight exponents alpha = 1 + balance and beta = 1 - balance
	// (both clamped to [0, 4]). Positive favours bandwidth, negative
	// favours low latency. nil uses the daemon-global exponent defaults.
	Balance *float64 `json:"balance,omitempty"`

	// BandwidthMbps is the operator-declared usable bandwidth of this
	// tunnel. It drives the ECMP next-hop weights (256 * bw_i / bw_best).
	// Zero means the tunnel has no bandwidth claim and gets a default
	// weight.
	BandwidthMbps int `json:"bandwidth_mbps,omitempty"`

	// Neighbours optionally overrides or extends the automatically derived
	// Babel neighbours of this tunnel. Auto-derived neighbours are the
	// tunnel peers (WireGuard public keys) and explicit entries here.
	Neighbours []netip.Addr `json:"neighbours,omitempty"`

	// Multicast overrides the auto-selected Babel link mode: single-peer
	// WireGuard and point-to-point tunnels use multicast auto-discovery,
	// multi-peer WireGuard meshes use unicast + static neighbours. nil
	// selects automatically.
	Multicast *bool `json:"multicast,omitempty"`
}

// MptcpTunnelConfig is the per-tunnel MPTCP endpoint switch. It only
// decides whether TH registers this tunnel's addresses as MPTCP endpoints;
// it does not make any application use MPTCP.
type MptcpTunnelConfig struct {
	// Endpoint is the tri-state per-tunnel switch: nil follows the global
	// mptcp.enabled setting, false never registers an endpoint for this
	// tunnel, true always does. The default (nil) is the recommended value.
	Endpoint *bool `json:"endpoint,omitempty"`
}

type Phase string

const (
	PhasePending  Phase = "pending"
	PhaseReady    Phase = "ready"
	PhaseDisabled Phase = "disabled"
	PhaseError    Phase = "error"
)

type Condition struct {
	Type               string    `json:"type"`
	Status             bool      `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
	LastTransitionTime time.Time `json:"last_transition_time"`
}

type Status struct {
	TunnelID            string            `json:"tunnel_id"`
	DesiredGeneration   uint64            `json:"desired_generation"`
	ObservedGeneration  uint64            `json:"observed_generation"`
	Phase               Phase             `json:"phase"`
	InterfaceExists     bool              `json:"interface_exists"`
	InterfaceUp         bool              `json:"interface_up"`
	LastReconcileTime   time.Time         `json:"last_reconcile_time,omitempty"`
	LastObservationTime time.Time         `json:"last_observation_time,omitempty"`
	LastSuccessfulTime  time.Time         `json:"last_successful_time,omitempty"`
	Conditions          []Condition       `json:"conditions,omitempty"`
	Details             map[string]string `json:"details,omitempty"`
	Peers               []PeerStatus      `json:"peers,omitempty"`
}

type PeerStatus struct {
	Protocol          string     `json:"protocol,omitempty"`
	PublicKey         string     `json:"public_key"`
	Endpoint          string     `json:"endpoint,omitempty"`
	AllowedIPs        []string   `json:"allowed_ips,omitempty"`
	KeepaliveSeconds  int        `json:"keepalive_seconds,omitempty"`
	LastHandshakeTime *time.Time `json:"last_handshake_time,omitempty"`
	ReceiveBytes      int64      `json:"receive_bytes"`
	TransmitBytes     int64      `json:"transmit_bytes"`
	RTTMicros         *int64     `json:"rtt_micros,omitempty"`
	JitterMicros      *int64     `json:"jitter_micros,omitempty"`
	MetricAgeMillis   *int64     `json:"metric_age_millis,omitempty"`
	MetricConfidence  *float64   `json:"metric_confidence,omitempty"`
	MetricFresh       *bool      `json:"metric_fresh,omitempty"`
}

type TunnelView struct {
	Tunnel       Tunnel   `json:"tunnel"`
	SecretFields []string `json:"secret_fields,omitempty"`
	Status       Status   `json:"status"`
}
