package model

import (
	"encoding/json"
	"time"

	"github.com/OboardProject/oboard-agent/internal/authorization"
)

type AuthorizationLease = authorization.Lease

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

type Protocol string

const (
	ProtocolVLESS  Protocol = "vless"
	ProtocolHY2    Protocol = "hy2"
	ProtocolAnyTLS Protocol = "anytls"
	ProtocolSS     Protocol = "shadowsocks"
	ProtocolMieru  Protocol = "mieru"
	ProtocolSocks  Protocol = "socks"
	ProtocolSSH    Protocol = "ssh"
)

type ServerStatus string

const (
	ServerUnknown  ServerStatus = "unknown"
	ServerOnline   ServerStatus = "online"
	ServerOffline  ServerStatus = "offline"
	ServerDegraded ServerStatus = "degraded"
)

type EntryIPMode string

const (
	EntryIPModeAuto   EntryIPMode = "auto"
	EntryIPModeIPv4   EntryIPMode = "ipv4"
	EntryIPModeIPv6   EntryIPMode = "ipv6"
	EntryIPModeCustom EntryIPMode = "custom"
)

type IPStack string

const (
	IPStackAuto       IPStack = "auto"
	IPStackIPv4Only   IPStack = "ipv4_only"
	IPStackIPv6Only   IPStack = "ipv6_only"
	IPStackDualStack  IPStack = "dual_stack"
	IPStackPreferIPv4 IPStack = "prefer_ipv4"
	IPStackPreferIPv6 IPStack = "prefer_ipv6"
)

type UDPInboundMode string

const (
	UDPInboundAllow UDPInboundMode = "allow"
	UDPInboundBlock UDPInboundMode = "block"
	UDPInboundUoT   UDPInboundMode = "uot"
)

type DNSTransport string

const (
	DNSTransportUDP DNSTransport = "udp"
	DNSTransportTCP DNSTransport = "tcp"
	DNSTransportDoT DNSTransport = "dot"
	DNSTransportDoH DNSTransport = "doh"
	DNSTransportDoQ DNSTransport = "doq"
)

type DNSAutoTestMode string

const (
	DNSAutoTestNever      DNSAutoTestMode = "never"
	DNSAutoTestFirstApply DNSAutoTestMode = "first_apply"
	DNSAutoTestPeriodic   DNSAutoTestMode = "periodic"
	DNSAutoTestAlways     DNSAutoTestMode = "always"
)

type MTUMode string

const (
	MTUModeDisabled MTUMode = "disabled"
	MTUModeDetect   MTUMode = "detect"
	MTUModeApply    MTUMode = "apply"
)

type TimeCorrectionMode string

const (
	TimeCorrectionOff  TimeCorrectionMode = "off"
	TimeCorrectionAuto TimeCorrectionMode = "auto"
	TimeCorrectionNTP  TimeCorrectionMode = "ntp"
)

type RouteAction string

const (
	RouteActionDirect   RouteAction = "direct"
	RouteActionBlock    RouteAction = "block"
	RouteActionOutbound RouteAction = "outbound"
	RouteActionExternal RouteAction = "external"
)

type ExternalOutboundScope string

const (
	ExternalOutboundScopeGlobal ExternalOutboundScope = "global"
	ExternalOutboundScopeServer ExternalOutboundScope = "server"
)

type WARPStatus string

const (
	WARPStatusNeeded    WARPStatus = "needed"
	WARPStatusRequested WARPStatus = "requested"
	WARPStatusReady     WARPStatus = "ready"
	WARPStatusFailed    WARPStatus = "failed"
)

type User struct {
	ID                int64     `json:"id"`
	Username          string    `json:"username"`
	PasswordHash      string    `json:"-"`
	Role              Role      `json:"role"`
	Status            string    `json:"status"`
	ProxyUUID         string    `json:"proxy_uuid"`
	ProxyPassword     string    `json:"proxy_password"`
	SpeedLimitMbps    int       `json:"speed_limit_mbps"`
	TrafficLimitBytes int64     `json:"traffic_limit_bytes"`
	TrafficUsedBytes  int64     `json:"traffic_used_bytes"`
	TrafficResetMode  string    `json:"traffic_reset_mode"`
	TrafficResetDay   int       `json:"traffic_reset_day"`
	TrafficPeriodKey  string    `json:"traffic_period_key,omitempty"`
	TrafficPeriodEnd  string    `json:"traffic_period_end,omitempty"`
	TrafficQuotaState string    `json:"traffic_quota_state,omitempty"`
	SubscriptionToken string    `json:"subscription_token,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type SubscriptionFormat string

const (
	SubscriptionFormatStash        SubscriptionFormat = "stash"
	SubscriptionFormatClashMeta    SubscriptionFormat = "clash-meta"
	SubscriptionFormatMihomo       SubscriptionFormat = "mihomo"
	SubscriptionFormatSurfboard    SubscriptionFormat = "surfboard"
	SubscriptionFormatSurge        SubscriptionFormat = "surge"
	SubscriptionFormatSurgeMac     SubscriptionFormat = "surge-mac"
	SubscriptionFormatLoon         SubscriptionFormat = "loon"
	SubscriptionFormatEgern        SubscriptionFormat = "egern"
	SubscriptionFormatShadowrocket SubscriptionFormat = "shadowrocket"
	SubscriptionFormatQX           SubscriptionFormat = "qx"
	SubscriptionFormatSingBox      SubscriptionFormat = "sing-box"
	SubscriptionFormatV2Ray        SubscriptionFormat = "v2ray"
	SubscriptionFormatV2RayURI     SubscriptionFormat = "v2ray-uri"
	SubscriptionFormatClash        SubscriptionFormat = "clash"
)

type SubscriptionProfile struct {
	ID          int64              `json:"id"`
	Name        string             `json:"name"`
	Format      SubscriptionFormat `json:"format"`
	GroupName   string             `json:"group_name"`
	Description string             `json:"description"`
	ConfigJSON  string             `json:"config_json"`
	Enabled     bool               `json:"enabled"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

type SubscriptionAssignment struct {
	ID        int64     `json:"id"`
	ProfileID int64     `json:"profile_id"`
	UserID    int64     `json:"user_id"`
	ServerID  *int64    `json:"server_id,omitempty"`
	InboundID *int64    `json:"inbound_id,omitempty"`
	GroupName string    `json:"group_name"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Server struct {
	ID                 int64          `json:"id"`
	Name               string         `json:"name"`
	AgentID            string         `json:"agent_id"`
	AgentTokenHash     string         `json:"-"`
	EnrollmentHash     string         `json:"-"`
	PublicIPv4         string         `json:"public_ipv4"`
	PublicIPv6         string         `json:"public_ipv6"`
	EntryIPMode        EntryIPMode    `json:"entry_ip_mode"`
	ListenIP           string         `json:"listen_ip"`
	IPStack            IPStack        `json:"ip_stack"`
	UDPInboundMode     UDPInboundMode `json:"udp_inbound_mode"`
	MTUMode            MTUMode        `json:"mtu_mode"`
	MTUValue           int            `json:"mtu_value"`
	MTUProbeHost       string         `json:"mtu_probe_host"`
	MTUProbePort       int            `json:"mtu_probe_port"`
	MTUOverheadBytes   int            `json:"mtu_overhead_bytes"`
	PortRangeStart     int            `json:"port_range_start"`
	PortRangeEnd       int            `json:"port_range_end"`
	Status             ServerStatus   `json:"status"`
	OS                 string         `json:"os"`
	DistroID           string         `json:"distro_id"`
	DistroVersion      string         `json:"distro_version"`
	DistroName         string         `json:"distro_name"`
	Libc               string         `json:"libc"`
	ServiceManager     string         `json:"service_manager"`
	PackageManager     string         `json:"package_manager"`
	Arch               string         `json:"arch"`
	Kernel             string         `json:"kernel"`
	CPU                string         `json:"cpu"`
	MemoryBytes        uint64         `json:"memory_bytes"`
	CPUUsagePercent    float64        `json:"cpu_usage_percent"`
	MemoryUsedBytes    uint64         `json:"memory_used_bytes"`
	MemoryTotalBytes   uint64         `json:"memory_total_bytes"`
	AgentMemoryBytes   uint64         `json:"agent_memory_bytes"`
	DiskBytes          uint64         `json:"disk_bytes"`
	DiskTotalBytes     uint64         `json:"disk_total_bytes"`
	TCPConnectionCount uint64         `json:"tcp_connection_count"`
	UDPConnectionCount uint64         `json:"udp_connection_count"`
	ProcessCount       uint64         `json:"process_count"`
	AgentVersion       string         `json:"agent_version"`
	AgentBuild         string         `json:"agent_build"`
	SingBoxVersion     string         `json:"sing_box_version"`
	LastSeenAt         *time.Time     `json:"last_seen_at,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type Inbound struct {
	ID              int64       `json:"id"`
	ServerID        int64       `json:"server_id"`
	Name            string      `json:"name"`
	Protocol        Protocol    `json:"protocol"`
	ListenIP        string      `json:"listen_ip"`
	Port            int         `json:"port"`
	EntryIPMode     EntryIPMode `json:"entry_ip_mode"`
	ExternalIP      string      `json:"external_ip"`
	DNSSyncEnabled  bool        `json:"dns_sync_enabled"`
	DNSCredentialID *int64      `json:"dns_credential_id,omitempty"`
	DNSDomain       string      `json:"dns_domain"`
	DNSProxyEnabled bool        `json:"dns_proxy_enabled"`
	DNSRecordTypes  string      `json:"dns_record_types"`
	TLS             bool        `json:"tls"`
	ConfigJSON      string      `json:"config_json"`
	Enabled         bool        `json:"enabled"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

const (
	CertificateModeExternal = "external"
	CertificateModeAuto     = "auto"
	CertificateModeExact    = "exact"
	CertificateModeWildcard = "wildcard"
	CertificateModeExplicit = "explicit"
)

const (
	CertificateChallengeHTTP      = "http01"
	CertificateChallengeDNS       = "dns01"
	CertificateChallengeDNSManual = "dns01_manual"
)

const (
	CertificateStatusPending     = "pending"
	CertificateStatusIssuing     = "issuing"
	CertificateStatusAwaitingDNS = "awaiting_dns"
	CertificateStatusReady       = "ready"
	CertificateStatusFailed      = "failed"
)

type InboundUser struct {
	ID        int64     `json:"id"`
	InboundID int64     `json:"inbound_id"`
	UserID    int64     `json:"user_id"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AccessSubjectType string

const (
	AccessSubjectUser  AccessSubjectType = "user"
	AccessSubjectGroup AccessSubjectType = "group"
)

type AccessScopeType string

const (
	AccessScopeGlobal  AccessScopeType = "global"
	AccessScopeServer  AccessScopeType = "server"
	AccessScopeInbound AccessScopeType = "inbound"
)

type UserGroup struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type UserGroupMember struct {
	ID        int64     `json:"id"`
	GroupID   int64     `json:"group_id"`
	UserID    int64     `json:"user_id"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type InboundAccessGrant struct {
	ID          int64             `json:"id"`
	SubjectType AccessSubjectType `json:"subject_type"`
	SubjectID   int64             `json:"subject_id"`
	ScopeType   AccessScopeType   `json:"scope_type"`
	ServerID    *int64            `json:"server_id,omitempty"`
	InboundID   *int64            `json:"inbound_id,omitempty"`
	Enabled     bool              `json:"enabled"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type Outbound struct {
	ID            int64     `json:"id"`
	ServerID      int64     `json:"server_id"`
	NextServerID  *int64    `json:"next_server_id,omitempty"`
	Name          string    `json:"name"`
	Protocol      Protocol  `json:"protocol"`
	TargetAddress string    `json:"target_address"`
	TargetPort    int       `json:"target_port"`
	ConfigJSON    string    `json:"config_json"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type RoutingRule struct {
	ID                 int64       `json:"id"`
	ServerID           int64       `json:"server_id"`
	Name               string      `json:"name"`
	Priority           int         `json:"priority"`
	MatchJSON          string      `json:"match_json"`
	Action             RouteAction `json:"action"`
	OutboundID         *int64      `json:"outbound_id,omitempty"`
	ExternalOutboundID *int64      `json:"external_outbound_id,omitempty"`
	TargetServerID     *int64      `json:"target_server_id,omitempty"`
	OutboundTag        string      `json:"outbound_tag"`
	Enabled            bool        `json:"enabled"`
	CreatedAt          time.Time   `json:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at"`
}

type ExternalOutbound struct {
	ID            int64                 `json:"id"`
	ServerID      *int64                `json:"server_id,omitempty"`
	Name          string                `json:"name"`
	Protocol      Protocol              `json:"protocol"`
	Scope         ExternalOutboundScope `json:"scope"`
	TargetAddress string                `json:"target_address"`
	TargetPort    int                   `json:"target_port"`
	ConfigJSON    string                `json:"config_json"`
	ExposeToUsers bool                  `json:"expose_to_users"`
	Enabled       bool                  `json:"enabled"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

type ExternalOutboundAccessGrant struct {
	ID                 int64             `json:"id"`
	ExternalOutboundID int64             `json:"external_outbound_id"`
	SubjectType        AccessSubjectType `json:"subject_type"`
	SubjectID          int64             `json:"subject_id"`
	Enabled            bool              `json:"enabled"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

type ProxyPath struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	InboundID int64     `json:"inbound_id"`
	Secret    string    `json:"-"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ProxyPathStepNodeType string

const (
	ProxyPathStepServerInbound ProxyPathStepNodeType = "server_inbound"
	ProxyPathStepImported      ProxyPathStepNodeType = "imported"
	ProxyPathStepWARP          ProxyPathStepNodeType = "warp"
)

type ProxyPathStepTransportMode string

const (
	ProxyPathTransportSingBox     ProxyPathStepTransportMode = "singbox"
	ProxyPathTransportPortForward ProxyPathStepTransportMode = "port_forward"
	ProxyPathTransportTunnel      ProxyPathStepTransportMode = "tunnel"
)

type ProxyPathPlanStep struct {
	ID                 int64                      `json:"id"`
	Position           int                        `json:"position"`
	NodeType           ProxyPathStepNodeType      `json:"node_type"`
	TransportMode      ProxyPathStepTransportMode `json:"transport_mode"`
	ProcessingRole     bool                       `json:"processing_role"`
	ServerID           *int64                     `json:"server_id,omitempty"`
	InboundID          *int64                     `json:"inbound_id,omitempty"`
	ExternalOutboundID *int64                     `json:"external_outbound_id,omitempty"`
	TunnelID           int64                      `json:"tunnel_id,omitempty"`
}

type ProxyPathPlan struct {
	PathID       int64               `json:"path_id"`
	Name         string              `json:"name"`
	InboundID    int64               `json:"inbound_id"`
	Enabled      bool                `json:"enabled"`
	Steps        []ProxyPathPlanStep `json:"steps"`
	Warnings     []string            `json:"warnings,omitempty"`
	PortForwards []PortForward       `json:"port_forwards,omitempty"`
	Tunnels      []Tunnel            `json:"tunnels,omitempty"`
}

type ProxyPathStep struct {
	ID                 int64                      `json:"id"`
	PathID             int64                      `json:"path_id"`
	Position           int                        `json:"position"`
	NodeType           ProxyPathStepNodeType      `json:"node_type"`
	TransportMode      ProxyPathStepTransportMode `json:"transport_mode"`
	ProcessingRole     bool                       `json:"processing_role"`
	ServerID           *int64                     `json:"server_id,omitempty"`
	InboundID          *int64                     `json:"inbound_id,omitempty"`
	ExternalOutboundID *int64                     `json:"external_outbound_id,omitempty"`
	ConfigJSON         string                     `json:"config_json"`
	CreatedAt          time.Time                  `json:"created_at"`
	UpdatedAt          time.Time                  `json:"updated_at"`
}

type WARPProfile struct {
	ID              int64      `json:"id"`
	ServerID        int64      `json:"server_id"`
	Name            string     `json:"name"`
	Status          WARPStatus `json:"status"`
	ConfigJSON      string     `json:"config_json"`
	MTU             int        `json:"mtu"`
	DNSStrategy     string     `json:"dns_strategy"`
	LastRequestedAt *time.Time `json:"last_requested_at,omitempty"`
	Error           string     `json:"error"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type DNSCandidate struct {
	Tag       string       `json:"tag"`
	Transport DNSTransport `json:"transport"`
	Server    string       `json:"server"`
	Port      int          `json:"port"`
	Path      string       `json:"path,omitempty"`
	TLSName   string       `json:"tls_name,omitempty"`
}

type DNSBenchmarkPlan struct {
	Version               int64           `json:"version"`
	ServerID              int64           `json:"server_id"`
	PolicyRevision        int64           `json:"policy_revision"`
	EncryptedListID       int64           `json:"encrypted_list_id"`
	EncryptedListRevision int64           `json:"encrypted_list_revision"`
	BootstrapListID       int64           `json:"bootstrap_list_id"`
	BootstrapListRevision int64           `json:"bootstrap_list_revision"`
	Mode                  DNSAutoTestMode `json:"mode"`
	IntervalSeconds       int             `json:"interval_seconds"`
	RequestID             string          `json:"request_id,omitempty"`
	EncryptedCandidates   []DNSCandidate  `json:"encrypted_candidates"`
	BootstrapCandidates   []DNSCandidate  `json:"bootstrap_candidates"`
}

type DialConstraint struct {
	Mode          string `json:"mode"`
	InterfaceName string `json:"interface_name,omitempty"`
	SourceAddress string `json:"source_address,omitempty"`
	Family        string `json:"family,omitempty"`
}

type WARPRequestPlan struct {
	Version     int64           `json:"version"`
	ServerID    int64           `json:"server_id"`
	ProfileID   int64           `json:"profile_id"`
	OutboundTag string          `json:"outbound_tag"`
	IPStack     IPStack         `json:"ip_stack"`
	MTU         int             `json:"mtu"`
	DNSStrategy string          `json:"dns_strategy"`
	Underlay    *DialConstraint `json:"underlay,omitempty"`
}

type WARPConfigReport struct {
	ServerID   int64      `json:"server_id"`
	ProfileID  int64      `json:"profile_id"`
	Status     WARPStatus `json:"status"`
	ConfigJSON string     `json:"config_json"`
	MTU        int        `json:"mtu"`
	Error      string     `json:"error"`
	ResultJSON string     `json:"result_json"`
}

type DNSBenchmarkResult struct {
	ID                    int64             `json:"id"`
	ReportID              string            `json:"report_id"`
	RequestID             string            `json:"request_id,omitempty"`
	ServerID              int64             `json:"server_id"`
	PolicyRevision        int64             `json:"policy_revision"`
	EncryptedListID       int64             `json:"encrypted_list_id"`
	EncryptedListRevision int64             `json:"encrypted_list_revision"`
	BootstrapListID       int64             `json:"bootstrap_list_id"`
	BootstrapListRevision int64             `json:"bootstrap_list_revision"`
	Encrypted             DNSBenchmarkGroup `json:"encrypted"`
	Bootstrap             DNSBenchmarkGroup `json:"bootstrap"`
	Status                string            `json:"status"`
	Error                 string            `json:"error"`
	CreatedAt             time.Time         `json:"created_at"`
}

type DNSBenchmarkItem struct {
	Tag       string `json:"tag"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

type DNSBenchmarkGroup struct {
	Items    []DNSBenchmarkItem `json:"items"`
	BestTags []string           `json:"best_tags"`
}

// DNSBenchmarkNoUsableCandidatesError is the shared marker for a benchmark that
// produced no usable resolver in a bound group. Controller matches this exact
// string to fall the server back to local DNS, so it is a wire sentinel rather
// than a message: it must stay byte-identical to the Controller constant and
// must never be reworded for display. The panel localizes it per policy.
const DNSBenchmarkNoUsableCandidatesError = "both encrypted and bootstrap dns groups require at least one usable candidate"

type MTUDetectionMethod struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	MTU       int    `json:"mtu"`
	LatencyMS int64  `json:"latency_ms"`
	Detail    string `json:"detail,omitempty"`
	Error     string `json:"error,omitempty"`
}

type MTUDetectionPlan struct {
	Version       int64   `json:"version"`
	ServerID      int64   `json:"server_id"`
	Mode          MTUMode `json:"mode"`
	TargetHost    string  `json:"target_host"`
	TargetPort    int     `json:"target_port"`
	InterfaceName string  `json:"interface_name,omitempty"`
	OverheadBytes int     `json:"overhead_bytes"`
	DesiredMTU    int     `json:"desired_mtu"`
	SampleCount   int     `json:"sample_count"`
	TimeoutMS     int     `json:"timeout_ms"`
	MinMTU        int     `json:"min_mtu"`
	MaxMTU        int     `json:"max_mtu"`
}

type MTUDetectionResult struct {
	ID             int64                `json:"id"`
	ServerID       int64                `json:"server_id"`
	Mode           MTUMode              `json:"mode"`
	TargetHost     string               `json:"target_host"`
	TargetPort     int                  `json:"target_port"`
	InterfaceName  string               `json:"interface_name"`
	CurrentMTU     int                  `json:"current_mtu"`
	PathMTU        int                  `json:"path_mtu"`
	RecommendedMTU int                  `json:"recommended_mtu"`
	AppliedMTU     int                  `json:"applied_mtu"`
	Confidence     string               `json:"confidence"`
	Methods        []MTUDetectionMethod `json:"methods,omitempty"`
	Error          string               `json:"error"`
	ResultJSON     string               `json:"result_json"`
	CreatedAt      time.Time            `json:"created_at"`
}

type ForwardBackend string

const (
	ForwardBackendRealm ForwardBackend = "realm"
)

type ForwardProtocol string

const (
	ForwardProtocolTCP    ForwardProtocol = "tcp"
	ForwardProtocolUDP    ForwardProtocol = "udp"
	ForwardProtocolTCPUDP ForwardProtocol = "tcp_udp"
)

type PortForward struct {
	ID                   int64           `json:"id"`
	Name                 string          `json:"name"`
	SourceServerID       int64           `json:"source_server_id"`
	TargetServerID       int64           `json:"target_server_id,omitempty"`
	ListenIP             string          `json:"listen_ip"`
	ListenPort           int             `json:"listen_port"`
	TargetAddress        string          `json:"target_address"`
	TargetPort           int             `json:"target_port"`
	Protocol             ForwardProtocol `json:"protocol"`
	Backend              ForwardBackend  `json:"backend"`
	ProbeMode            string          `json:"probe_mode"`
	ProbeIntervalSeconds int             `json:"probe_interval_seconds"`
	Priority             int             `json:"priority"`
	ConfigJSON           string          `json:"config_json"`
	Enabled              bool            `json:"enabled"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

type TunnelType string

const (
	TunnelTypeWireGuard TunnelType = "wireguard"
	TunnelTypeSSH       TunnelType = "ssh"
)

type Tunnel struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	SourceServerID int64      `json:"source_server_id"`
	TargetServerID int64      `json:"target_server_id"`
	Type           TunnelType `json:"type"`
	LocalAddress   string     `json:"local_address"`
	PeerAddress    string     `json:"peer_address"`
	ListenPort     int        `json:"listen_port"`
	TargetEndpoint string     `json:"target_endpoint"`
	TargetPort     int        `json:"target_port"`
	Priority       int        `json:"priority"`
	ConfigJSON     string     `json:"config_json"`
	Enabled        bool       `json:"enabled"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type TunnelPlan struct {
	Version int64    `json:"version"`
	Tunnels []Tunnel `json:"tunnels"`
}

type PortForwardProbeResult struct {
	ID            int64     `json:"id"`
	PortForwardID int64     `json:"port_forward_id"`
	ServerID      int64     `json:"server_id"`
	Mode          string    `json:"mode"`
	Available     bool      `json:"available"`
	LatencyMS     int64     `json:"latency_ms"`
	SampleCount   int       `json:"sample_count"`
	Error         string    `json:"error"`
	ResultJSON    string    `json:"result_json"`
	CreatedAt     time.Time `json:"created_at"`
}

type PortForwardPlan struct {
	Version int64         `json:"version"`
	Rules   []PortForward `json:"rules"`
}

// SSHInboundPlan configures OBoard's deliberately restricted SSH proxy
// listeners.  It is separate from the core configuration because it is
// implemented by the Agent, not sing-box.
type SSHAuthenticationVerification struct {
	AuthenticationPlanDigest string `json:"authentication_plan_digest"`
	Version                  int64  `json:"version"`
	AuthenticationVerified   bool   `json:"authentication_verified"`
	AuthenticatedUsers       int    `json:"authenticated_users"`
	RejectedUsers            int    `json:"rejected_users"`
}

type SSHInboundPlan struct {
	Version  int64        `json:"version"`
	Inbounds []SSHInbound `json:"inbounds"`
}

// SSHInbound accepts password-only SSH client authentication and permits
// direct-tcpip channels, including the fixed in-process BadVPN UDP gateway.
// Address is the panel-visible endpoint; the Agent listens on ListenIP:Port.
type SSHInbound struct {
	InboundID int64                           `json:"inbound_id"`
	ServerID  int64                           `json:"server_id"`
	Name      string                          `json:"name"`
	ListenIP  string                          `json:"listen_ip"`
	Address   string                          `json:"address"`
	Port      int                             `json:"port"`
	Enabled   bool                            `json:"enabled"`
	Users     []SSHInboundUser                `json:"users"`
	Policies  map[string]TrafficRuntimePolicy `json:"policies"`
}

// SSHInboundUser maps one panel user to an isolated SSH login. Shell access
// and agent forwarding are intentionally unsupported.
type SSHInboundUser struct {
	AuthorizationKey string `json:"authorization_key,omitempty"`
	UserID           int64  `json:"user_id"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	DeviceIDHash     string `json:"device_id_hash,omitempty"`
	CredentialEpoch  int64  `json:"credential_epoch,omitempty"`
	CredentialStatus string `json:"credential_status,omitempty"`
	PathID           int64  `json:"path_id"`
	RouteKind        string `json:"route_kind"`
	OutboundTag      string `json:"outbound_tag,omitempty"`
	RouteInboundTag  string `json:"route_inbound_tag,omitempty"`
	RouteAuthUser    string `json:"route_auth_user,omitempty"`
	Enabled          bool   `json:"enabled"`
}

type AgentTask struct {
	ID            int64      `json:"id"`
	ServerID      int64      `json:"server_id"`
	Type          string     `json:"type"`
	PayloadJSON   string     `json:"payload_json"`
	Status        string     `json:"status"`
	ResultJSON    string     `json:"result_json"`
	ConfigVersion int64      `json:"config_version"`
	Nonce         string     `json:"nonce"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

const (
	AgentTaskTypeApplyDeployment       = "apply_deployment"
	AgentTaskTypeApplyCoreConfig       = "apply_core_config"
	AgentTaskTypeApplyTrafficPolicy    = "apply_traffic_policy"
	AgentTaskTypeUpdateAgent           = "update_agent"
	AgentTaskTypeUninstallAgent        = "uninstall_agent"
	AgentTaskTypeUpdateAgentConfig     = "update_agent_config"
	AgentTaskTypeDiagnoseNetwork       = "diagnose_network"
	AgentTaskTypeListNetworkInterfaces = "list_network_interfaces"
	AgentTaskTypeProbeInbounds         = "probe_inbounds"
	AgentTaskTypeProbePortForwards     = "probe_port_forwards"
	AgentTaskTypeProbeExternalEgress   = "probe_external_egress"
	AgentTaskTypeProbeLatencyTargets   = "probe_latency_targets"
	AgentTaskTypeDetectMTU             = "detect_mtu"
	AgentTaskTypeBenchmarkDNS          = "benchmark_dns"
	AgentTaskTypeCollectLogs           = "collect_logs"
	AgentTaskTypeManageLogs            = "manage_logs"
	AgentTaskTypeCheckTime             = "check_time"
	AgentTaskTypeIssueCertificateHTTP  = "issue_certificate_http01"
	AgentTaskTypeRemoteExec            = "remote_exec"
	AgentTaskTypeRemoteOperation       = "remote_operation"
	AgentTaskTypeApplyStealth          = "apply_stealth"
	AgentTaskTypeApplyVPNGatePool      = "apply_vpngate_pool"
	AgentTaskTypeProbeVPNGate          = "probe_vpngate_candidates"
)

// AgentCapabilityStealth is advertised by Agents that can switch the local
// installation into (and out of) the security-process layout via the
// apply_stealth task.
const AgentCapabilityStealth = "stealth_v1"

// AgentCapabilityStealthActive is reported while the Agent actually runs in
// the security-process layout, so the panel can show desired versus actual
// state for the per-server switch.
const AgentCapabilityStealthActive = "stealth_active_v1"

const AgentCapabilityTrafficPolicy = "traffic_policy_v1"

// AgentCapabilityAuthorizationControl is advertised by Agents that verify and
// apply signed authorization envelopes outside the task slot and confirm them
// with authorization_ack / applied_authorization health fields.
const AgentCapabilityAuthorizationControl = "authorization_control_v1"

// AgentCapabilityRuntimeUsers is advertised by Agents that verify and apply
// signed users_update envelopes outside the task slot.
const AgentCapabilityRuntimeUsers = "runtime_users_control_v1"

const (
	AgentControlAuthorizationUpdate = "authorization_update"
	AgentControlAuthorizationAck    = "authorization_ack"
	AgentControlUsersUpdate         = "users_update"
	AgentControlUsersAck            = "users_ack"
)

// AuthorizationEnvelope carries one signed AuthorizationLease. LeaseJSON is the
// exact encoding the signature covers; the Agent verifies before decoding.
type AuthorizationEnvelope struct {
	Type      string `json:"type,omitempty"`
	MessageID string `json:"message_id"`
	ServerID  int64  `json:"server_id"`
	LeaseJSON string `json:"lease_json"`
	Signature string `json:"signature"`
}

// AuthorizationAppliedSnapshot is the opaque identity of the authorization the
// data plane enforces. It never carries grants, credentials, or payloads.
type AuthorizationAppliedSnapshot struct {
	Revision int64  `json:"revision"`
	Sequence int64  `json:"sequence,omitempty"`
	Digest   string `json:"digest,omitempty"`
	BootID   string `json:"boot_id,omitempty"`
}

// AuthorizationAck confirms one applied envelope on the control channel.
type AuthorizationAck struct {
	Type      string                        `json:"type,omitempty"`
	MessageID string                        `json:"message_id"`
	Revision  int64                         `json:"revision"`
	Sequence  int64                         `json:"sequence"`
	Digest    string                        `json:"digest,omitempty"`
	Confirmed bool                          `json:"confirmed"`
	BootID    string                        `json:"boot_id,omitempty"`
	Runtimes  map[string]string             `json:"runtimes,omitempty"`
	Error     string                        `json:"error,omitempty"`
	Applied   *AuthorizationAppliedSnapshot `json:"applied,omitempty"`
}

// UsersEnvelope carries one signed runtime-user install request.
type UsersEnvelope struct {
	Type      string `json:"type,omitempty"`
	MessageID string `json:"message_id"`
	ServerID  int64  `json:"server_id"`
	UsersJSON string `json:"users_json"`
	Signature string `json:"signature"`
}

type UsersInstallChunk struct {
	Index  int    `json:"index"`
	Total  int    `json:"total"`
	SHA256 string `json:"sha256"`
}

type UsersInstallRequest struct {
	Scope         []string            `json:"scope"`
	UsersRevision int64               `json:"users_revision"`
	UsersDigest   string              `json:"users_digest"`
	Mode          string              `json:"mode"`
	BaseRevision  int64               `json:"base_revision,omitempty"`
	Chunk         *UsersInstallChunk  `json:"chunk,omitempty"`
	Entries       []UsersInstallEntry `json:"entries"`

	// ContentDigest is the identity the revision is allocated against: the
	// snapshot without the lease-accounting counters the traffic lane owns.
	//
	// UsersDigest covers those counters, because the kernel recomputes it over
	// the bytes it is handed. They move on every accepted traffic report, so one
	// revision legitimately describes several delivered payloads, and a gate
	// built on UsersDigest alone reads that refresh as a conflict and stops the
	// lane for good. This field is what makes the revision gate decidable: equal
	// revision plus equal content is the same desired state, whatever the
	// counters say.
	ContentDigest string `json:"content_digest,omitempty"`
}

type UsersInstallEntry struct {
	InboundTag       string             `json:"inbound_tag"`
	AuthUser         string             `json:"auth_user"`
	Credential       UsersCredential    `json:"credential"`
	AuthorizationKey string             `json:"authorization_key"`
	Identity         UsersIdentity      `json:"identity"`
	RouteOutbound    string             `json:"route_outbound"`
	Policy           UsersRuntimePolicy `json:"policy"`
}

type UsersCredential struct {
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	UserKey  string `json:"userkey,omitempty"`
	PSK      string `json:"psk,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

type UsersIdentity struct {
	UserID           int64  `json:"user_id,omitempty"`
	InboundID        int64  `json:"inbound_id,omitempty"`
	PathID           int64  `json:"path_id,omitempty"`
	DeviceIDHash     string `json:"device_id_hash,omitempty"`
	CredentialEpoch  int64  `json:"credential_epoch,omitempty"`
	CredentialStatus string `json:"credential_status,omitempty"`
}

type UsersRuntimePolicy struct {
	AuthorizationKey  string `json:"authorization_key,omitempty"`
	UserID            int64  `json:"user_id,omitempty"`
	InboundID         int64  `json:"inbound_id,omitempty"`
	PathID            int64  `json:"path_id,omitempty"`
	DeviceIDHash      string `json:"device_id_hash,omitempty"`
	CredentialEpoch   int64  `json:"credential_epoch,omitempty"`
	CredentialStatus  string `json:"credential_status,omitempty"`
	Billable          bool   `json:"billable"`
	SpeedLimitMbps    int    `json:"speed_limit_mbps,omitempty"`
	TrafficLimitBytes int64  `json:"traffic_limit_bytes,omitempty"`
	UsedBaselineBytes int64  `json:"used_baseline_bytes,omitempty"`
	LeaseBytes        int64  `json:"lease_bytes,omitempty"`
	ResetLeaseBytes   int64  `json:"reset_lease_bytes,omitempty"`
	LeaseEnforced     bool   `json:"lease_enforced,omitempty"`
	PeriodKey         string `json:"period_key,omitempty"`
	PeriodStart       string `json:"period_start,omitempty"`
	PeriodEnd         string `json:"period_end,omitempty"`
	ResetMode         string `json:"reset_mode,omitempty"`
	ResetDay          int    `json:"reset_day,omitempty"`
	Timezone          string `json:"timezone,omitempty"`
	QuotaState        string `json:"quota_state,omitempty"`
}

type UsersAppliedSnapshot struct {
	Revision int64  `json:"revision"`
	Digest   string `json:"digest,omitempty"`
	BootID   string `json:"boot_id,omitempty"`
	// ContentDigest is the content identity of the revision this node holds. The
	// full digest above covers the lease counters too, so it differs between two
	// deliveries of the same desired state; only this field can tell a node that
	// is behind from one that merely received fresher quota numbers.
	ContentDigest string `json:"content_digest,omitempty"`
}

type UsersAck struct {
	Type      string                `json:"type,omitempty"`
	MessageID string                `json:"message_id"`
	Revision  int64                 `json:"revision"`
	Digest    string                `json:"digest,omitempty"`
	Confirmed bool                  `json:"confirmed"`
	BootID    string                `json:"boot_id,omitempty"`
	Runtimes  map[string]string     `json:"runtimes,omitempty"`
	Error     string                `json:"error,omitempty"`
	Applied   *UsersAppliedSnapshot `json:"applied,omitempty"`
}

type NetworkInterfaceInfo struct {
	Name      string   `json:"name"`
	Up        bool     `json:"up"`
	Running   bool     `json:"running"`
	Loopback  bool     `json:"loopback"`
	Addresses []string `json:"addresses"`
}

type NetworkInterfaceInventory struct {
	Interfaces []NetworkInterfaceInfo `json:"interfaces"`
	Hash       string                 `json:"hash,omitempty"`
}

type AgentEnrollRequest struct {
	EnrollmentToken string       `json:"enrollment_token"`
	Health          HealthReport `json:"health"`
}

type AgentEnrollResponse struct {
	ServerID               int64  `json:"server_id"`
	AgentID                string `json:"agent_id"`
	AgentToken             string `json:"agent_token"`
	ConnectionAuditEnabled bool   `json:"connection_audit_enabled"`
}

type AgentSocketMessage struct {
	Type                     string          `json:"type"`
	ServerID                 int64           `json:"server_id,omitempty"`
	Timestamp                time.Time       `json:"ts,omitempty"`
	Task                     *AgentTask      `json:"task,omitempty"`
	Signature                string          `json:"signature,omitempty"`
	HealthReport             *HealthReport   `json:"health_report,omitempty"`
	MetricReport             *MetricReport   `json:"metric_report,omitempty"`
	ReportID                 string          `json:"report_id,omitempty"`
	DesiredConfigRevision    uint64          `json:"desired_config_revision,omitempty"`
	ConfigurationSyncState   string          `json:"configuration_sync_state,omitempty"`
	ConfigurationSyncVersion int64           `json:"configuration_sync_version,omitempty"`
	Raw                      json.RawMessage `json:"-"`
}

type AgentTaskResultReport struct {
	TaskID       int64         `json:"task_id"`
	Status       string        `json:"status"`
	ResultJSON   string        `json:"result_json"`
	HealthReport *HealthReport `json:"health_report,omitempty"`
}

type ApplyCoreConfigTaskPayload struct {
	SSHInbounds  *SSHInboundPlan         `json:"ssh_inbounds,omitempty"`
	Config       string                  `json:"config"`
	Reason       string                  `json:"reason,omitempty"`
	PrunedUserID int64                   `json:"pruned_user_id,omitempty"`
	Assets       []ManagedAssetReference `json:"assets,omitempty"`
}

type ApplyTrafficPolicyTaskPayload struct {
	Authorization  *AuthorizationLease             `json:"authorization,omitempty"`
	PolicyRevision int64                           `json:"policy_revision"`
	Reason         string                          `json:"reason,omitempty"`
	Policies       map[string]TrafficRuntimePolicy `json:"policies"`
}

// DeploymentTaskPayload keeps one user deployment as one Agent task while
// preserving the individual execution plans needed by the Agent.
type DeploymentTaskPayload struct {
	Version              int64                      `json:"version"`
	Config               ApplyCoreConfigTaskPayload `json:"config"`
	ConfigChanged        bool                       `json:"config_changed"`
	ForceRefresh         bool                       `json:"force_refresh,omitempty"`
	TriggerReason        string                     `json:"trigger_reason,omitempty"`
	WARPRequests         []WARPRequestPlan          `json:"warp_requests,omitempty"`
	TimeCheck            *TimeCheckPlan             `json:"time_check,omitempty"`
	PortForwards         PortForwardPlan            `json:"port_forwards"`
	InboundProbe         *InboundProbePlan          `json:"inbound_probe,omitempty"`
	ExternalInboundProbe *InboundProbePlan          `json:"external_inbound_probe,omitempty"`
	PortForwardProbe     *PortForwardPlan           `json:"port_forward_probe,omitempty"`
	ExternalEgressProbe  *ExternalEgressProbePlan   `json:"external_egress_probe,omitempty"`
	Tunnels              TunnelPlan                 `json:"tunnels"`
	SSHInbounds          SSHInboundPlan             `json:"ssh_inbounds"`
	DNSBenchmark         *DNSBenchmarkPlan          `json:"dns_benchmark,omitempty"`
	MTUDetection         *MTUDetectionPlan          `json:"mtu_detection,omitempty"`
}

// OpenVPNSpec is the complete, Controller-sanitized description of one
// OpenVPN server used by a VPNGate exit pool.
type OpenVPNSpec struct {
	Server     string   `json:"server"`
	ServerPort uint16   `json:"server_port"`
	Network    string   `json:"network"`
	Cipher     string   `json:"cipher"`
	Auth       string   `json:"auth"`
	CA         string   `json:"ca"`
	Cert       string   `json:"cert"`
	Key        string   `json:"key"`
	Username   string   `json:"username,omitempty"`
	Password   string   `json:"password,omitempty"`
	MTU        int      `json:"mtu,omitempty"`
	Resolvers  []string `json:"resolvers,omitempty"`
}

type VPNGatePoolMember struct {
	MemberID string `json:"member_id"`
	OpenVPNSpec
}

// VPNGatePoolPlan is the signed membership of one vpngate-<pool_id> outbound.
// Membership is runtime state: applying it never rewrites the kernel
// configuration or restarts the kernel.
type VPNGatePoolPlan struct {
	PoolID        int64               `json:"pool_id"`
	Tag           string              `json:"tag"`
	Revision      int64               `json:"revision"`
	ContentDigest string              `json:"content_digest"`
	HotStandby    int                 `json:"hot_standby"`
	Members       []VPNGatePoolMember `json:"members"`
}

type VPNGateProbeCandidate struct {
	ProbeID string `json:"probe_id"`
	OpenVPNSpec
}

type VPNGateProbePlan struct {
	PoolID     int64                   `json:"pool_id"`
	Tag        string                  `json:"tag"`
	RequestID  string                  `json:"request_id"`
	Candidates []VPNGateProbeCandidate `json:"candidates"`
}

type VPNGateProbeResult struct {
	ProbeID     string  `json:"probe_id"`
	Status      string  `json:"status"`
	Stage       string  `json:"stage,omitempty"`
	Error       string  `json:"error,omitempty"`
	HandshakeMS int64   `json:"handshake_ms,omitempty"`
	RTTMS       []int64 `json:"rtt_ms,omitempty"`
	TTFBMS      int64   `json:"ttfb_ms,omitempty"`
	EgressIP    string  `json:"egress_ip,omitempty"`
}

type VPNGateProbeReport struct {
	PoolID    int64                `json:"pool_id"`
	RequestID string               `json:"request_id"`
	Results   []VPNGateProbeResult `json:"results"`
}

type VPNGateMemberStatus struct {
	MemberID    string `json:"member_id"`
	State       string `json:"state"`
	Active      bool   `json:"active"`
	Failures    int    `json:"failures"`
	LastError   string `json:"last_error,omitempty"`
	HandshakeMS int64  `json:"handshake_ms,omitempty"`
	RTTMS       int64  `json:"rtt_ms,omitempty"`
	LastChange  string `json:"last_change,omitempty"`
}

// VPNGatePoolStatus is the bounded, secret-free pool health an Agent reports.
type VPNGatePoolStatus struct {
	Tag           string                `json:"tag"`
	PoolID        int64                 `json:"pool_id"`
	Revision      int64                 `json:"revision"`
	ContentDigest string                `json:"content_digest"`
	ActiveMember  string                `json:"active_member,omitempty"`
	Healthy       int                   `json:"healthy"`
	Members       []VPNGateMemberStatus `json:"members"`
}

type ExternalOutboundProbe struct {
	ExternalOutboundID int64           `json:"external_outbound_id"`
	Fingerprint        string          `json:"fingerprint"`
	Outbound           json.RawMessage `json:"outbound"`
}

type ExternalEgressProbePlan struct {
	Standalone            *ExternalOutboundProbe      `json:"standalone,omitempty"`
	Version               int64                       `json:"version"`
	ExpectedConfigVersion int64                       `json:"expected_config_version,omitempty"`
	TimeoutMS             int                         `json:"timeout_ms"`
	Targets               []ExternalEgressProbeTarget `json:"targets"`
}

type LatencyProbeTarget struct {
	MeasurementRevision string           `json:"measurement_revision,omitempty"`
	Mode                LatencyProbeMode `json:"mode,omitempty"`
	URL                 string           `json:"url,omitempty"`
	ProbeID             string           `json:"probe_id"`
	Kind                string           `json:"kind"`
	TaskID              int64            `json:"task_id,omitempty"`
	TaskName            string           `json:"task_name,omitempty"`
	Province            string           `json:"province,omitempty"`
	Carrier             string           `json:"carrier,omitempty"`
	Host                string           `json:"host"`
	IP                  string           `json:"ip,omitempty"`
	Port                int              `json:"port"`
	// IntervalSeconds is the autonomous cadence for this single target. Zero means the plan cadence.
	IntervalSeconds int `json:"interval_seconds,omitempty"`
}

type LatencyProbeMode string

const (
	LatencyProbeModeTCP  LatencyProbeMode = "tcp"
	LatencyProbeModeICMP LatencyProbeMode = "icmp"
	LatencyProbeModeHTTP LatencyProbeMode = "http"
)

type LatencyProbeRegion struct {
	Province string `json:"province"`
	Carrier  string `json:"carrier"`
}

type LatencyProbeTargetsPlan struct {
	Version         int64                `json:"version"`
	ResourceVersion string               `json:"resource_version"`
	Mode            LatencyProbeMode     `json:"mode"`
	Enabled         bool                 `json:"enabled"`
	IntervalSeconds int                  `json:"interval_seconds"`
	SampleCount     int                  `json:"sample_count"`
	IntervalMS      int                  `json:"interval_ms"`
	TimeoutMS       int                  `json:"timeout_ms"`
	Targets         []LatencyProbeTarget `json:"targets"`
}

type LatencyProbeResult struct {
	MeasurementRevision string    `json:"measurement_revision,omitempty"`
	ProbeID             string    `json:"probe_id"`
	Kind                string    `json:"kind"`
	TaskID              int64     `json:"task_id,omitempty"`
	TaskName            string    `json:"task_name,omitempty"`
	Mode                string    `json:"mode"`
	Province            string    `json:"province"`
	Carrier             string    `json:"carrier"`
	Host                string    `json:"host"`
	IP                  string    `json:"ip"`
	Port                int       `json:"port"`
	Available           bool      `json:"available"`
	LatencyMS           int64     `json:"latency_ms"`
	MinLatencyMS        int64     `json:"min_latency_ms"`
	P95LatencyMS        int64     `json:"p95_latency_ms"`
	JitterMS            int64     `json:"jitter_ms"`
	SampleCount         int       `json:"sample_count"`
	SuccessCount        int       `json:"success_count"`
	Error               string    `json:"error,omitempty"`
	CheckedAt           time.Time `json:"checked_at"`
}

type LatencyProbeResultReport struct {
	ReportID        string               `json:"report_id"`
	ResourceVersion string               `json:"resource_version"`
	CheckedAt       time.Time            `json:"checked_at"`
	Items           []LatencyProbeResult `json:"items"`
}

type ExternalEgressProbeTarget struct {
	ProbeID             string `json:"probe_id"`
	PathID              int64  `json:"path_id"`
	ExternalOutboundID  int64  `json:"external_outbound_id"`
	OwnerServerID       int64  `json:"owner_server_id"`
	OutboundTag         string `json:"outbound_tag"`
	TopologyFingerprint string `json:"topology_fingerprint"`
}

type ExternalEgressProbeItem struct {
	ProbeID string `json:"probe_id"`
	Status  string `json:"status"`
	ExitIP  string `json:"exit_ip,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ExternalEgressProbeResult struct {
	Items []ExternalEgressProbeItem `json:"items"`
}

type IssueCertificateHTTPTaskPayload struct {
	CertificateID int64    `json:"certificate_id"`
	Domains       []string `json:"domains"`
	AccountEmail  string   `json:"account_email"`
	ACMECA        string   `json:"acme_ca"`
	Renew         bool     `json:"renew"`
}

type ManagedAssetReference struct {
	Kind     string `json:"kind"`
	ID       int64  `json:"id"`
	Revision string `json:"revision"`
}

type ManagedAssetRequest struct {
	Assets []ManagedAssetReference `json:"assets"`
}

type ManagedAssetFile struct {
	Name       string `json:"name"`
	ContentB64 string `json:"content_b64"`
	Mode       uint32 `json:"mode"`
}

type ManagedAsset struct {
	ManagedAssetReference
	Files []ManagedAssetFile `json:"files"`
}

type ManagedAssetResponse struct {
	Assets []ManagedAsset `json:"assets"`
}

type CertificateIssueReport struct {
	TaskID         int64    `json:"task_id"`
	CertificateID  int64    `json:"certificate_id"`
	Domains        []string `json:"domains"`
	CertificatePEM string   `json:"certificate_pem"`
	FullchainPEM   string   `json:"fullchain_pem"`
	PrivateKeyPEM  string   `json:"private_key_pem"`
}

type UpdateAgentTaskPayload struct {
	ControllerURL string `json:"controller_url"`
	ExpectedBuild string `json:"expected_build"`
	Source        string `json:"source"`
	GitHubRepo    string `json:"github_repo"`
	AutoUpdate    bool   `json:"auto_update"`
}

type UninstallAgentTaskPayload struct {
	Purge   bool  `json:"purge"`
	ActorID int64 `json:"actor_id,omitempty"`
}

// ApplyStealthTaskPayload is the apply_stealth task body: enable switches the
// local installation into the security-process layout (random process,
// service, and file names with encrypted state), disable restores the
// standard layout.
type ApplyStealthTaskPayload struct {
	Enable  bool  `json:"enable"`
	ActorID int64 `json:"actor_id,omitempty"`
}

type AgentUpdateRequest struct {
	Source     string `json:"source"`
	GitHubRepo string `json:"github_repo"`
}

type AgentConfigPatch struct {
	ControllerURL         string             `json:"controller_url,omitempty"`
	StateDir              string             `json:"state_dir,omitempty"`
	CoreBinary            string             `json:"core_binary,omitempty"`
	CoreService           string             `json:"core_service,omitempty"`
	CommandTimeoutSeconds int                `json:"command_timeout_seconds,omitempty"`
	ReloadCommand         string             `json:"reload_command,omitempty"`
	RestartCommand        string             `json:"restart_command,omitempty"`
	TimeSyncCommand       string             `json:"time_sync_command,omitempty"`
	TimeCorrectionMode    TimeCorrectionMode `json:"time_correction_mode,omitempty"`
	LogMaxMB              int                `json:"log_max_mb,omitempty"`
	LogBackups            int                `json:"log_backups,omitempty"`
	CoreLogMaxMB          int                `json:"core_log_max_mb,omitempty"`
	CoreLogBackups        int                `json:"core_log_backups,omitempty"`
	UpdateSource          string             `json:"update_source,omitempty"`
	AllowPanelUpdate      bool               `json:"allow_panel_update,omitempty"`
	UpdateRepo            string             `json:"update_repo,omitempty"`
}

type DiagnosticTarget struct {
	Name     string   `json:"name"`
	Protocol Protocol `json:"protocol"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
}

type DiagnoseNetworkTaskPayload struct {
	Version      int64              `json:"version"`
	ServerID     int64              `json:"server_id"`
	EntryTargets []DiagnosticTarget `json:"entry_targets"`
}

type InboundProbeTarget struct {
	InboundID   int64    `json:"inbound_id"`
	Name        string   `json:"name"`
	Protocol    Protocol `json:"protocol"`
	Host        string   `json:"host"`
	ListenIP    string   `json:"listen_ip"`
	Port        int      `json:"port"`
	Transport   string   `json:"transport"`
	SampleCount int      `json:"sample_count,omitempty"`
}

type InboundProbePlan struct {
	Version      int64                `json:"version"`
	ServerID     int64                `json:"server_id"`
	SampleCount  int                  `json:"sample_count"`
	IntervalMS   int                  `json:"interval_ms"`
	TimeoutMS    int                  `json:"timeout_ms"`
	EntryTargets []InboundProbeTarget `json:"entry_targets"`
}

type InboundProbeResult struct {
	ID            int64     `json:"id"`
	InboundID     int64     `json:"inbound_id"`
	ServerID      int64     `json:"server_id"`
	ConfigVersion int64     `json:"config_version"`
	Mode          string    `json:"mode"`
	Transport     string    `json:"transport"`
	Endpoint      string    `json:"endpoint"`
	Available     bool      `json:"available"`
	Confirmed     bool      `json:"confirmed"`
	LatencyMS     int64     `json:"latency_ms"`
	MinLatencyMS  int64     `json:"min_latency_ms"`
	P95LatencyMS  int64     `json:"p95_latency_ms"`
	JitterMS      int64     `json:"jitter_ms"`
	SampleCount   int       `json:"sample_count"`
	SuccessCount  int       `json:"success_count"`
	Error         string    `json:"error"`
	ResultJSON    string    `json:"result_json"`
	CreatedAt     time.Time `json:"created_at"`
}

type CollectLogsTaskPayload struct {
	Lines    int    `json:"lines"`
	Services string `json:"services"`
}

type ManageLogsTaskPayload struct {
	Action   string `json:"action"`
	Services string `json:"services"`
}

type TimeCheckPlan struct {
	Version          int64              `json:"version"`
	CorrectionMode   TimeCorrectionMode `json:"correction_mode"`
	ThresholdSeconds int                `json:"threshold_seconds"`
	NTPServers       []string           `json:"ntp_servers"`
	Force            bool               `json:"force,omitempty"`
}

// TimeCheckStatusConfigError means the requested mode could not be saved;
// no time measurement or correction was attempted.
const TimeCheckStatusConfigError = "config_error"

type TimeCheckResult struct {
	Status               string             `json:"status"`
	CorrectionMode       TimeCorrectionMode `json:"correction_mode"`
	RawOffsetMS          int64              `json:"raw_offset_ms"`
	EffectiveOffsetMS    int64              `json:"effective_offset_ms"`
	Source               string             `json:"source"`
	CheckedAt            time.Time          `json:"checked_at"`
	SystemSyncAttempted  bool               `json:"system_sync_attempted"`
	SystemSyncSucceeded  bool               `json:"system_sync_succeeded"`
	SystemSyncError      string             `json:"system_sync_error,omitempty"`
	LogicalTimeActive    bool               `json:"logical_time_active"`
	UnsupportedTimePaths []string           `json:"unsupported_time_paths,omitempty"`
	Error                string             `json:"error,omitempty"`
}

type NotificationChannel struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Enabled    bool      `json:"enabled"`
	Events     string    `json:"events"`
	ConfigJSON string    `json:"config_json"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type AuditLog struct {
	ID        int64     `json:"id"`
	ActorID   *int64    `json:"actor_id,omitempty"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

type TrafficStat struct {
	ID        int64     `json:"id"`
	ServerID  int64     `json:"server_id"`
	UserID    *int64    `json:"user_id,omitempty"`
	InboundID *int64    `json:"inbound_id,omitempty"`
	Upload    int64     `json:"upload_bytes"`
	Download  int64     `json:"download_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

type TrafficPeriod struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	PeriodKey string    `json:"period_key"`
	StartedAt time.Time `json:"started_at"`
	EndsAt    time.Time `json:"ends_at"`
	Upload    int64     `json:"upload_bytes"`
	Download  int64     `json:"download_bytes"`
	Limit     int64     `json:"traffic_limit_bytes"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

type TrafficReport struct {
	ReportID  string    `json:"report_id"`
	ServerID  int64     `json:"server_id"`
	UserID    int64     `json:"user_id"`
	InboundID *int64    `json:"inbound_id,omitempty"`
	PathID    *int64    `json:"path_id,omitempty"`
	PeriodKey string    `json:"period_key"`
	Upload    int64     `json:"upload_bytes"`
	Download  int64     `json:"download_bytes"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

type TrafficRuntimePolicy struct {
	UserID            int64  `json:"user_id"`
	InboundID         int64  `json:"inbound_id,omitempty"`
	PathID            int64  `json:"path_id,omitempty"`
	DeviceIDHash      string `json:"device_id_hash,omitempty"`
	CredentialEpoch   int64  `json:"credential_epoch,omitempty"`
	CredentialStatus  string `json:"credential_status,omitempty"`
	Billable          bool   `json:"billable"`
	SpeedLimitMbps    int    `json:"speed_limit_mbps,omitempty"`
	TrafficLimitBytes int64  `json:"traffic_limit_bytes,omitempty"`
	UsedBaselineBytes int64  `json:"used_baseline_bytes,omitempty"`
	LeaseBytes        int64  `json:"lease_bytes,omitempty"`
	ResetLeaseBytes   int64  `json:"reset_lease_bytes,omitempty"`
	LeaseEnforced     bool   `json:"lease_enforced,omitempty"`
	PeriodKey         string `json:"period_key,omitempty"`
	PeriodStart       string `json:"period_start,omitempty"`
	PeriodEnd         string `json:"period_end,omitempty"`
	ResetMode         string `json:"reset_mode,omitempty"`
	ResetDay          int    `json:"reset_day,omitempty"`
	ResetAnchor       string `json:"reset_anchor,omitempty"`
	PreviousPeriodKey string `json:"previous_period_key,omitempty"`
	Timezone          string `json:"timezone,omitempty"`
	QuotaState        string `json:"quota_state,omitempty"`
	PolicyRevision    int64  `json:"policy_revision,omitempty"`
}

// Linux exposes TCP Fast Open through the net.ipv4.tcp_fastopen bitmask, where
// the client and server halves are enabled independently. Agent reports the raw
// value plus the derived state so Controller never has to guess whether a
// generated tcp_fast_open listen option can take effect; most hosts ship with
// the client bit only.
const (
	TCPFastOpenClientBit = 0x1
	TCPFastOpenServerBit = 0x2
)

// TCPFastOpen* are the reported host states. An empty state means no report,
// which is different from a host that answered "disabled".
const (
	TCPFastOpenStateUnknown      = ""
	TCPFastOpenStateUnavailable  = "unavailable"
	TCPFastOpenStateDisabled     = "disabled"
	TCPFastOpenStateClient       = "client"
	TCPFastOpenStateServer       = "server"
	TCPFastOpenStateClientServer = "client_server"
)

// TCPFastOpenStateFromMask maps a net.ipv4.tcp_fastopen value to a report state.
func TCPFastOpenStateFromMask(mask int) string {
	client := mask&TCPFastOpenClientBit != 0
	server := mask&TCPFastOpenServerBit != 0
	switch {
	case client && server:
		return TCPFastOpenStateClientServer
	case server:
		return TCPFastOpenStateServer
	case client:
		return TCPFastOpenStateClient
	default:
		return TCPFastOpenStateDisabled
	}
}

type HealthReport struct {
	ProxyDSCP                 *ProxyDSCPReport              `json:"proxy_dscp,omitempty"`
	RuntimeSecurity           *RuntimeSecurityReport        `json:"runtime_security,omitempty"`
	VPNGatePools              []VPNGatePoolStatus           `json:"vpngate_pools,omitempty"`
	AgentID                   string                        `json:"agent_id"`
	Status                    ServerStatus                  `json:"status"`
	PublicIPv4                string                        `json:"public_ipv4"`
	PublicIPv6                string                        `json:"public_ipv6"`
	InterfaceIPv6             string                        `json:"interface_ipv6"`
	RegionCode                string                        `json:"region_code"`
	OS                        string                        `json:"os"`
	DistroID                  string                        `json:"distro_id"`
	DistroVersion             string                        `json:"distro_version"`
	DistroName                string                        `json:"distro_name"`
	Libc                      string                        `json:"libc"`
	ServiceManager            string                        `json:"service_manager"`
	PackageManager            string                        `json:"package_manager"`
	Arch                      string                        `json:"arch"`
	Kernel                    string                        `json:"kernel"`
	CPU                       string                        `json:"cpu"`
	CPUCores                  int                           `json:"cpu_cores,omitempty"`
	HostUptimeSeconds         uint64                        `json:"host_uptime_seconds,omitempty"`
	MemoryBytes               uint64                        `json:"memory_bytes"`
	CPUUsagePercent           float64                       `json:"cpu_usage_percent"`
	MemoryUsedBytes           uint64                        `json:"memory_used_bytes"`
	MemoryTotalBytes          uint64                        `json:"memory_total_bytes"`
	AgentMemoryBytes          uint64                        `json:"agent_memory_bytes"`
	DiskBytes                 uint64                        `json:"disk_bytes"`
	DiskTotalBytes            uint64                        `json:"disk_total_bytes"`
	DiskAvailableBytes        uint64                        `json:"disk_available_bytes,omitempty"`
	DiskPressure              string                        `json:"disk_pressure,omitempty"`
	StorageProfile            string                        `json:"storage_profile,omitempty"`
	TCPConnectionCount        uint64                        `json:"tcp_connection_count"`
	UDPConnectionCount        uint64                        `json:"udp_connection_count"`
	ProcessCount              uint64                        `json:"process_count"`
	AgentVersion              string                        `json:"agent_version"`
	AgentBuild                string                        `json:"agent_build"`
	SingBoxVersion            string                        `json:"sing_box_version"`
	KernelCapabilities        []string                      `json:"kernel_capabilities,omitempty"`
	TCPFastOpenState          string                        `json:"tcp_fastopen_state,omitempty"`
	TCPFastOpenValue          int                           `json:"tcp_fastopen_value,omitempty"`
	NetworkUploadBPS          uint64                        `json:"network_upload_bps"`
	NetworkDownloadBPS        uint64                        `json:"network_download_bps"`
	NetworkTotalUploadBytes   uint64                        `json:"network_total_upload_bytes"`
	NetworkTotalDownloadBytes uint64                        `json:"network_total_download_bytes"`
	ConnectivityProbeEnabled  bool                          `json:"-"`
	ConnectivityProbeTarget   string                        `json:"-"`
	ConnectivityAvailable     bool                          `json:"-"`
	ConnectivityLatencyMS     int64                         `json:"-"`
	ConnectivityCheckedAt     time.Time                     `json:"-"`
	ConnectivityError         string                        `json:"-"`
	Timestamp                 time.Time                     `json:"timestamp"`
	AppliedConfigVersion      int64                         `json:"applied_config_version,omitempty"`
	AppliedConfigDigest       string                        `json:"applied_config_digest,omitempty"`
	RemoteAccess              RemoteAccessReport            `json:"remote_access,omitempty"`
	NetworkInventory          *NetworkInterfaceInventory    `json:"network_inventory,omitempty"`
	Storage                   *StorageDiskInfo              `json:"storage,omitempty"`
	AppliedAuthorization      *AuthorizationAppliedSnapshot `json:"applied_authorization,omitempty"`
	AppliedUsers              *UsersAppliedSnapshot         `json:"applied_users,omitempty"`
	// AppliedLatencyProbe is the probe plan this node currently runs. It is
	// diagnostic only: it never selects a plan, it only lets the Controller see
	// that the node holds a different plan than the one bound to that version.
	AppliedLatencyProbe *LatencyProbeAppliedSnapshot `json:"applied_latency_probe,omitempty"`
}

type StorageDiskInfo struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
	StorageProfile string  `json:"storage_profile"`
	Pressure       string  `json:"pressure"`
}

type MetricReport struct {
	ReportID           string    `json:"report_id"`
	SampledAt          time.Time `json:"sampled_at"`
	CPUUsagePercent    float64   `json:"cpu_usage_percent"`
	MemoryUsedBytes    uint64    `json:"memory_used_bytes"`
	MemoryTotalBytes   uint64    `json:"memory_total_bytes"`
	DiskUsedBytes      uint64    `json:"disk_used_bytes"`
	DiskTotalBytes     uint64    `json:"disk_total_bytes"`
	TCPConnectionCount uint64    `json:"tcp_connection_count"`
	UDPConnectionCount uint64    `json:"udp_connection_count"`
	ProcessCount       uint64    `json:"process_count"`
	NetworkUploadBPS   uint64    `json:"network_upload_bps"`
	NetworkDownloadBPS uint64    `json:"network_download_bps"`
}

type DashboardSummary struct {
	ServersTotal      int64 `json:"servers_total"`
	ServersOnline     int64 `json:"servers_online"`
	ServersOffline    int64 `json:"servers_offline"`
	ServersDegraded   int64 `json:"servers_degraded"`
	UsersTotal        int64 `json:"users_total"`
	UsersActive       int64 `json:"users_active"`
	TrafficUpload     int64 `json:"traffic_upload_bytes"`
	TrafficDownload   int64 `json:"traffic_download_bytes"`
	PendingTasks      int64 `json:"pending_tasks"`
	RunningTasks      int64 `json:"running_tasks"`
	FailedTasks       int64 `json:"failed_tasks"`
	LastConfigVersion int64 `json:"last_config_version"`
}

type VersionInfo struct {
	Name                 string   `json:"name"`
	Version              string   `json:"version"`
	Build                string   `json:"build"`
	Commit               string   `json:"commit"`
	BuiltAt              string   `json:"built_at"`
	Dev                  bool     `json:"dev"`
	AgentExpectedVersion string   `json:"agent_expected_version"`
	AgentExpectedBuild   string   `json:"agent_expected_build"`
	AgentUpdateRepo      string   `json:"agent_update_repo"`
	KernelVersion        string   `json:"kernel_version"`
	KernelBuild          string   `json:"kernel_build"`
	Protocols            []string `json:"protocols"`
	Kernel               string   `json:"kernel"`
	APIPrefix            string   `json:"api_prefix"`
}
