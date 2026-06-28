package config

// Schema definitions for the global and per-proxy YAML configuration files.
//
// Naming, ordering and field shapes mirror the RouteX configuration reference
// spec exactly. Numeric fields that semantically accept "0 = disabled" keep
// their plain int types and are validated by the loaders — see global.go and
// proxy.go for the per-field rules.

// ──────────────────────────────────────────────────────────────────────────
// GLOBAL CONFIG
// ──────────────────────────────────────────────────────────────────────────

// Global is the parsed root of configs/global.yaml. It governs cross-cutting
// settings that apply to every proxy unless overridden per-proxy.
type Global struct {
	API        GlobalAPI      `yaml:"api"`
	Metrics    GlobalMetrics  `yaml:"metrics"`
	ICMP       GlobalICMP     `yaml:"icmp"`
	Network    GlobalNetwork  `yaml:"network"`
	Defaults   GlobalDefaults `yaml:"defaults"`
	Iptables   GlobalIptables `yaml:"iptables"`
ACL        GlobalACL      `yaml:"acl"`
Timezone    string         `yaml:"timezone"`
	Logging    GlobalLogging  `yaml:"logging"`
	ConfigPath string         `yaml:"-"` // path the global config was loaded from
}

// GlobalAPI configures the management REST API surface.
type GlobalAPI struct {
	Enabled bool          `yaml:"enabled"`
	Bind    string        `yaml:"bind"`
	APIKeys []GlobalAPIKey `yaml:"api_keys"`
	TLS     GlobalAPITLS  `yaml:"tls"`
	// allowAll is set to true by the validator when the API is disabled — the
	// server layer treats that as bypassing authentication in process.
	allowAll bool `yaml:"-"`
}

// GlobalAPIKey is a single management API credential with scoped permissions.
type GlobalAPIKey struct {
	Key         string   `yaml:"key"`
	Label       string   `yaml:"label"`
	Permissions []string `yaml:"permissions"`
}

// GlobalAPITLS configures optional TLS termination for the management API.
type GlobalAPITLS struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

// GlobalMetrics configures the universal metrics store and emission formats.
type GlobalMetrics struct {
	Enabled               bool     `yaml:"enabled"`
	RetentionHours        int      `yaml:"retention_hours"`
	FlushIntervalSeconds  int      `yaml:"flush_interval_seconds"`
	SqlitePath            string   `yaml:"sqlite_path"`
	Formats               []string `yaml:"formats"`
}

// GlobalICMP configures global ICMP echo handling behaviour.
type GlobalICMP struct {
	PingEnabled    bool `yaml:"ping_enabled"`
	PingRateLimit  int  `yaml:"ping_rate_limit"`
}

// GlobalNetwork configures socket-level defaults applied to every proxy.
type GlobalNetwork struct {
	SocketBufferSize       int  `yaml:"socket_buffer_size"`
	TCPKeepaliveEnabled    bool `yaml:"tcp_keepalive_enabled"`
	TCPKeepaliveInterval   int  `yaml:"tcp_keepalive_interval"`
	TCPNoDelay             bool `yaml:"tcp_nodelay"`
	UDPReadBuffer          int  `yaml:"udp_read_buffer"`
	UDPWriteBuffer        int  `yaml:"udp_write_buffer"`
}

// GlobalDefaults defines per-proxy defaults overridable in proxy config files.
type GlobalDefaults struct {
	UpstreamConnectTimeout      Duration `yaml:"upstream_connect_timeout"`
	UpstreamReadTimeout         Duration `yaml:"upstream_read_timeout"`
	UpstreamWriteTimeout        Duration `yaml:"upstream_write_timeout"`
	ClientReadTimeout           Duration `yaml:"client_read_timeout"`
	ClientWriteTimeout          Duration `yaml:"client_write_timeout"`
	HealthCheckInterval         Duration `yaml:"health_check_interval"`
	HealthCheckTimeout          Duration `yaml:"health_check_timeout"`
	HealthCheckFailuresBeforeEject int   `yaml:"health_check_failures_before_eject"`
	HealthCheckPassesBeforeReadmit int  `yaml:"health_check_passes_before_readmit"`
	UDPSessionTimeout           Duration `yaml:"udp_session_timeout"`
}

// GlobalIptables configures the RouteX-managed iptables chain lifecycle.
type GlobalIptables struct {
	Enabled          bool   `yaml:"enabled"`
	ChainPrefix      string `yaml:"chain_prefix"`
	CommentPrefix    string `yaml:"comment_prefix"`
	AutoCreateChains bool   `yaml:"auto_create_chains"`
	FlushOnStart     bool   `yaml:"flush_on_start"`
	IPv6Enabled      bool   `yaml:"ipv6_enabled"`
}

// GlobalLogging configures structured logging output.
type GlobalLogging struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	FilePath   string `yaml:"file_path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
}

// ──────────────────────────────────────────────────────────────────────────
// PER-PROXY CONFIG
// ──────────────────────────────────────────────────────────────────────────

// Proxy is the parsed root of a single configs/proxies/<name>.yaml file. Each
// instance is loaded, validated, and run in total isolation from its peers.
type Proxy struct {
	Name             string            `yaml:"name"`
	Enabled          bool              `yaml:"enabled"`
	Description      string            `yaml:"description"`
	OriginIP         string            `yaml:"origin-ip"`
	OriginPort       string            `yaml:"origin-port"`
	DestIP           string            `yaml:"dest-ip"`
	DestPort         string            `yaml:"dest-port"`
	OneToOne         bool              `yaml:"one-to-one"`
	Protocol         string            `yaml:"protocol"`
	LoadBalancing    ProxyLoadBalancing `yaml:"load_balancing"`
	RateLimits       ProxyRateLimits   `yaml:"rate_limits"`
	L7Protection     ProxyL7Protection `yaml:"l7_protection"`
	ACL              ProxyACL          `yaml:"acl"`
	TLS              ProxyTLS          `yaml:"tls"`
Bandwidth          ProxyBandwidth `yaml:"bandwidth"`
	Timeouts         ProxyTimeouts     `yaml:"timeouts"`
	ConnectionDraining ProxyConnectionDraining `yaml:"connection_draining"`
	Logging          ProxyLogging      `yaml:"logging"`
	Metadata         ProxyMetadata    `yaml:"metadata"`
	ConfigPath       string            `yaml:"-"`
}

// ProxyLoadBalancing configures the upstream selection strategy.
type ProxyLoadBalancing struct {
	Algorithm       string                `yaml:"algorithm"`
	StickySessions  bool                  `yaml:"sticky_sessions"`
	StickyTTL       int                   `yaml:"sticky_ttl"`
	UpstreamWeights map[string]int         `yaml:"upstream_weights"`
	HealthCheck     ProxyHealthCheckOverride `yaml:"health_check"`
}

// ProxyHealthCheckOverride allows per-proxy tuning of the global health probe
// settings. Zero values inherit the global default.
type ProxyHealthCheckOverride struct {
	Interval                 Duration `yaml:"interval"`
	Timeout                  Duration `yaml:"timeout"`
	FailuresBeforeEject      int      `yaml:"failures_before_eject"`
	PassesBeforeReadmit      int      `yaml:"passes_before_readmit"`
}

// ProxyRateLimits is the iptables rate-limit specification validated by the
// iptables validator before being applied. Every numeric field accepts 0 to
// mean "disabled".
type ProxyRateLimits struct {
	TCPPSSPerIP              int  `yaml:"tcp_pps_per_ip"`
	UDPPSSPerIP              int  `yaml:"udp_pps_per_ip"`
	NewConnsPerSecPerIP      int  `yaml:"new_conns_per_sec_per_ip"`
	NewConnsPerSecGlobal     int  `yaml:"new_conns_per_sec_global"`
	MaxSimultaneousConnsPerIP int  `yaml:"max_simultaneous_conns_per_ip"`
	MaxTotalConns            int  `yaml:"max_total_conns"`
	DropFragmentedPackets    bool `yaml:"drop_fragmented_packets"`
	MinTTL                   int  `yaml:"min_ttl"`
	MaxTTL                   int  `yaml:"max_ttl"`
	MinPacketSize            int  `yaml:"min_packet_size"`
	MaxPacketSize            int  `yaml:"max_packet_size"`
	TCPSYNRatePerIP          int  `yaml:"tcp_syn_rate_per_ip"`
	TCPInvalidStateDrop      bool `yaml:"tcp_invalid_state_drop"`
	TCPRSTRatePerIP          int  `yaml:"tcp_rst_rate_per_ip"`
	UDPMaxPayload            int  `yaml:"udp_max_payload"`
	UDPMinPayload            int  `yaml:"udp_min_payload"`
}

// ProxyL7Protection enables and configures the Go-native L7 protection engine.
type ProxyL7Protection struct {
	Enabled              bool                       `yaml:"enabled"`
	SlowConnection       ProxyL7SlowConnection      `yaml:"slow_connection"`
	PayloadRateLimit     ProxyL7PayloadRateLimit    `yaml:"payload_rate_limit"`
	ConnectionCycling   ProxyL7ConnectionCycling   `yaml:"connection_cycling"`
	PayloadInspection   ProxyL7PayloadInspection   `yaml:"payload_inspection"`
	Amplification       ProxyL7Amplification       `yaml:"amplification"`
	BehavioralScoring   ProxyL7BehavioralScoring   `yaml:"behavioral_scoring"`
}

// ProxyL7SlowConnection detects and blocks slow-connection / slow-data attacks.
type ProxyL7SlowConnection struct {
	Enabled              bool     `yaml:"enabled"`
	MinBytesInFirst      int      `yaml:"min_bytes_in_first"`
	HandshakeTimeout     Duration `yaml:"handshake_timeout"`
	MinRecvRateBPS       int      `yaml:"min_recv_rate_bps"`
}

// ProxyL7PayloadRateLimit enforces per-connection and per-IP byte rates in Go.
type ProxyL7PayloadRateLimit struct {
	Enabled                 bool    `yaml:"enabled"`
	MaxBytesPerSecPerConn   int64   `yaml:"max_bytes_per_sec_per_conn"`
	MaxBytesPerSecPerIP     int64   `yaml:"max_bytes_per_sec_per_ip"`
	BurstMultiplier         float64 `yaml:"burst_multiplier"`
}

// ProxyL7ConnectionCycling detects rapid open/close cycling of connections.
type ProxyL7ConnectionCycling struct {
	Enabled           bool     `yaml:"enabled"`
	Window            Duration `yaml:"window"`
	MaxConnsInWindow  int      `yaml:"max_conns_in_window"`
	BanDuration        Duration `yaml:"ban_duration"`
}

// ProxyL7PayloadInspection runs protocol-aware validation of the first payload.
type ProxyL7PayloadInspection struct {
	Enabled     bool                  `yaml:"enabled"`
	Mode        string                `yaml:"mode"`
	CustomRules []ProxyL7CustomRule   `yaml:"custom_rules"`
}

// ProxyL7CustomRule defines a custom first-bytes match for inspection.
type ProxyL7CustomRule struct {
	Name        string `yaml:"name"`
	MatchOffset int    `yaml:"match_offset"`
	MatchBytes  string `yaml:"match_bytes"`
	Action      string `yaml:"action"`
}

// ProxyL7Amplification flags upstream responses greatly exceeding the request.
type ProxyL7Amplification struct {
	Enabled                       bool    `yaml:"enabled"`
	MaxResponseToRequestRatio     float64 `yaml:"max_response_to_request_ratio"`
	Window                        Duration `yaml:"window"`
}

// ProxyL7BehavioralScoring assigns per-IP threat scores based on event signals.
type ProxyL7BehavioralScoring struct {
	Enabled       bool                       `yaml:"enabled"`
	ScoreWindow   Duration                   `yaml:"score_window"`
	BanThreshold  int                        `yaml:"ban_threshold"`
	BanDuration   Duration                   `yaml:"ban_duration"`
	ScoreRules    []ProxyL7BehavioralScoreRule `yaml:"score_rules"`
}

// ProxyL7BehavioralScoreRule binds a named event to a threat-score increment.
type ProxyL7BehavioralScoreRule struct {
	Event string `yaml:"event"`
	Score int    `yaml:"score"`
}

// ProxyACL is the ordered access-control list applied to inbound connections.
type ProxyACL struct {
	DefaultAction string         `yaml:"default_action"`
	Rules         []ProxyACLRule `yaml:"rules"`
}

// ProxyACLRule is a single CIDR-scoped allow/deny decision.
type ProxyACLRule struct {
	Action  string `yaml:"action"`
	CIDR    string `yaml:"cidr"`
	Comment string `yaml:"comment"`
}

// GlobalACL is the global access-control list applied before per-proxy ACLs.
type GlobalACL struct {
	Enabled       bool           `yaml:"enabled"`
	DefaultAction string         `yaml:"default_action"`
	Rules         []ProxyACLRule `yaml:"rules"`
}

// ProxyTLS configures TLS passthrough behaviour.
type ProxyTLS struct {
	Passthrough bool `yaml:"passthrough"`
	SNIRouting  bool `yaml:"sni_routing"`
}

// ProxyTimeouts overrides per-connection timeouts. Zero values inherit the
// global defaults resolved by the proxy manager at runtime.
type ProxyTimeouts struct {
	UpstreamConnect Duration `yaml:"upstream_connect"`
	UpstreamRead    Duration `yaml:"upstream_read"`
	UpstreamWrite   Duration `yaml:"upstream_write"`
	ClientRead      Duration `yaml:"client_read"`
	ClientWrite     Duration `yaml:"client_write"`
	UDPSessionTimeout Duration `yaml:"udp_session_timeout"`
}

// ProxyConnectionDraining configures the drain window used during reload/stop.
type ProxyConnectionDraining struct {
	Enabled bool     `yaml:"enabled"`
	Timeout Duration `yaml:"timeout"`
}

// ProxyLogging allows per-proxy overrides of the global log configuration.
type ProxyLogging struct {
	Level           string `yaml:"level"`
	LogConnections  bool   `yaml:"log_connections"`
	LogBytes        bool   `yaml:"log_bytes"`
}

// ProxyBandwidth configures per-proxy bandwidth quotas and auto-suspension.
type ProxyBandwidth struct {
	Enabled         bool  `yaml:"enabled"`
	HourlyLimit     int64 `yaml:"hourly_limit"`
	DailyLimit      int64 `yaml:"daily_limit"`
	WeeklyLimit     int64 `yaml:"weekly_limit"`
	MonthlyLimit    int64 `yaml:"monthly_limit"`
	SuspendOnLimit  bool  `yaml:"suspend_on_limit"`
}

func (p ProxyBandwidth) IsZero() bool { return p.HourlyLimit == 0 && p.DailyLimit == 0 && p.WeeklyLimit == 0 && p.MonthlyLimit == 0 }

// ProxyMetadata is an opaque tag set used for grouping and dashboard routing.
type ProxyMetadata struct {
	Tags  []string `yaml:"tags"`
	Owner string   `yaml:"owner"`
}