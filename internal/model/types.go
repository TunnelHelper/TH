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
	KindBabel      Kind = "babel"
)

var Kinds = []Kind{
	KindGRE,
	KindVXLAN,
	KindWireGuard,
	KindAmneziaWG,
	KindXFRMStatic,
	KindXFRMIKEv2,
	KindSRv6,
	KindBabel,
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
	Babel      *BabelSpec      `json:"babel,omitempty"`
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

// BabelSpec configures the in-process Babel routing protocol (RFC 8966).
// The daemon runs the protocol itself and installs the selected routes into
// TH-owned route tables; no external routing daemon is involved.
type BabelSpec struct {
	// Interfaces lists the tunnel interfaces the protocol runs on. They
	// must be links managed by TH.
	Interfaces []string `json:"interfaces"`

	// StaticNeighbours maps an interface name to the unicast addresses of
	// its Babel peers. Required for bootstrap on non-multicast links
	// (WireGuard, unicast VXLAN); optional elsewhere.
	StaticNeighbours map[string][]netip.Addr `json:"static_neighbours,omitempty"`

	// StrictNeighbours restricts non-multicast interfaces to packets from
	// configured static neighbours.
	StrictNeighbours bool `json:"strict_neighbours,omitempty"`

	// UnicastHelloSeconds enables periodic unicast Hellos used to form and
	// keep adjacencies on links without multicast. Zero means disabled.
	UnicastHelloSeconds int `json:"unicast_hello_seconds,omitempty"`

	// Multicast enables multicast Hellos and updates. Disable on links
	// that cannot carry multicast.
	Multicast bool `json:"multicast,omitempty"`

	// RouteTable is the kernel table Babel routes are installed into. Zero
	// means the main table.
	RouteTable int `json:"route_table,omitempty"`

	// AdvertisedPrefixes are prefixes originated by this node (for example
	// tunnel subnets) and announced into the Babel domain.
	AdvertisedPrefixes []netip.Prefix `json:"advertised_prefixes,omitempty"`

	// MaxPaths limits the number of next hops installed for one prefix.
	// Zero means the default (4).
	MaxPaths int `json:"max_paths,omitempty"`

	// MultipathSlack is the maximum extra metric for which an additional
	// feasible route is still used as a multipath candidate. Zero means
	// equal-cost multipath only.
	MultipathSlack int `json:"multipath_slack,omitempty"`

	// SplitHorizon controls the RFC 8966 Section 3.7.4 optimisation.
	SplitHorizon *bool `json:"split_horizon,omitempty"`

	// RouterID is the stable 8-octet router identifier as 16 lowercase hex
	// characters. When empty, a random one is generated at record creation.
	RouterID string `json:"router_id,omitempty"`
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
	PublicKey         string     `json:"public_key"`
	Endpoint          string     `json:"endpoint,omitempty"`
	AllowedIPs        []string   `json:"allowed_ips,omitempty"`
	KeepaliveSeconds  int        `json:"keepalive_seconds,omitempty"`
	LastHandshakeTime *time.Time `json:"last_handshake_time,omitempty"`
	ReceiveBytes      int64      `json:"receive_bytes"`
	TransmitBytes     int64      `json:"transmit_bytes"`
}

type TunnelView struct {
	Tunnel       Tunnel   `json:"tunnel"`
	SecretFields []string `json:"secret_fields,omitempty"`
	Status       Status   `json:"status"`
}
