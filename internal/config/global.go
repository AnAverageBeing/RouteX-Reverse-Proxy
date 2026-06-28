package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// allowedMetricsFormats is the closed set of metrics output formats accepted by
// the metrics endpoint. The order mirrors the spec ordering for stable output.
var allowedMetricsFormats = []string{"json", "prometheus", "influx", "csv"}

// allowedLogLevels is the closed set of valid logging level strings.
var allowedLogLevels = []string{"debug", "info", "warn", "error"}

// allowedLogFormats is the closed set of valid logging format strings.
var allowedLogFormats = []string{"json", "text"}

// allowedLogOutputs is the closed set of valid logging output sinks.
var allowedLogOutputs = []string{"stdout", "file"}

// LoadGlobal reads and validates the global config YAML located at the supplied
// path. It returns a fully populated *Global or a *ConfigError that scopes the
// failure to the originating file/field.
func LoadGlobal(path string) (*Global, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigError{
			File:   path,
			Field:  "",
			Reason: "failed to read global config file",
			Cause:  err,
		}
	}

	var g Global
	g.ConfigPath = path
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(false)
	if err := dec.Decode(&g); err != nil {
		return nil, &ConfigError{
			File:  path,
			Field: "",
			Reason: "failed to parse global config YAML",
			Cause: err,
		}
	}

	if err := validateGlobal(&g, path); err != nil {
		return nil, err
	}

	applyGlobalDefaults(&g)
	return &g, nil
}

// validateGlobal enforces every invariant documented in the global config
// reference. Fields are validated independently — a failure on one short-circuits
// to return immediately, matching the spec's "each proxy config is isolated"
// requirement applied at the global level too.
func validateGlobal(g *Global, path string) error {
	if g.API.Enabled {
		if g.API.Bind == "" {
			return cfgErr(path, "api.bind", "bind address must be set when api.enabled is true")
		}
		if _, err := net.ResolveTCPAddr("tcp", g.API.Bind); err != nil {
			return wrap(path, "api.bind", "bind is not a valid host:port", err)
		}
		if len(g.API.APIKeys) == 0 {
			return cfgErr(path, "api.api_keys", "at least one API key is required when API is enabled")
		}
		for i, k := range g.API.APIKeys {
			field := fmt.Sprintf("api.api_keys[%d]", i)
			if strings.TrimSpace(k.Key) == "" {
				return cfgErr(path, field+".key", "key must be non-empty")
			}
			if k.Label == "" {
				return cfgErr(path, field+".label", "label must be set")
			}
			if len(k.Permissions) == 0 {
				return cfgErr(path, field+".permissions", "at least one permission is required")
			}
			for j, p := range k.Permissions {
				if strings.TrimSpace(p) == "" {
					return cfgErr(path, fmt.Sprintf("%s.permissions[%d]", field, j), "permission must not be empty")
				}
			}
		}
		if g.API.TLS.Enabled {
			if g.API.TLS.Cert == "" || g.API.TLS.Key == "" {
				return cfgErr(path, "api.tls", "both cert and key paths are required when tls.enabled is true")
			}
		}
	} else {
		g.API.allowAll = true
	}

	if g.Metrics.Enabled {
		if g.Metrics.RetentionHours <= 0 {
			return cfgErr(path, "metrics.retention_hours", "must be positive when metrics are enabled")
		}
		if g.Metrics.FlushIntervalSeconds <= 0 {
			return cfgErr(path, "metrics.flush_interval_seconds", "must be positive when metrics are enabled")
		}
		if strings.TrimSpace(g.Metrics.SqlitePath) == "" {
			return cfgErr(path, "metrics.sqlite_path", "must be set when metrics are enabled")
		}
		if len(g.Metrics.Formats) == 0 {
			return cfgErr(path, "metrics.formats", "at least one output format is required")
		}
		for i, f := range g.Metrics.Formats {
			if !contains(allowedMetricsFormats, f) {
				return cfgErr(path, fmt.Sprintf("metrics.formats[%d]", i), fmt.Sprintf("unsupported format %q (allowed: %s)", f, strings.Join(allowedMetricsFormats, ", ")))
			}
		}
	}

	if g.ICMP.PingRateLimit < 0 {
		return cfgErr(path, "icmp.ping_rate_limit", "must be >= 0 (0 = unlimited)")
	}

	nw := g.Network
	if nw.SocketBufferSize < 0 {
		return cfgErr(path, "network.socket_buffer_size", "must be >= 0")
	}
	if nw.TCPKeepaliveInterval < 0 {
		return cfgErr(path, "network.tcp_keepalive_interval", "must be >= 0")
	}
	if nw.UDPReadBuffer < 0 || nw.UDPWriteBuffer < 0 {
		return cfgErr(path, "network.udp_buffers", "read/write buffers must be >= 0")
	}

	d := g.Defaults
	if !d.UpstreamConnectTimeout.IsZero() && !d.UpstreamConnectTimeout.Positive() {
		return cfgErr(path, "defaults.upstream_connect_timeout", "must be a positive duration")
	}
	if !d.HealthCheckInterval.IsZero() && !d.HealthCheckInterval.Positive() {
		return cfgErr(path, "defaults.health_check_interval", "must be a positive duration")
	}
	if d.HealthCheckFailuresBeforeEject < 0 {
		return cfgErr(path, "defaults.health_check_failures_before_eject", "must be >= 0")
	}
	if d.HealthCheckPassesBeforeReadmit < 0 {
		return cfgErr(path, "defaults.health_check_passes_before_readmit", "must be >= 0")
	}

	it := g.Iptables
	if it.Enabled {
		if strings.TrimSpace(it.ChainPrefix) == "" {
			return cfgErr(path, "iptables.chain_prefix", "must be set when iptables.enabled is true")
		}
		if strings.TrimSpace(it.CommentPrefix) == "" {
			return cfgErr(path, "iptables.comment_prefix", "must be set when iptables.enabled is true")
		}
	}

	log := g.Logging
	if log.Level != "" && !contains(allowedLogLevels, log.Level) {
		return cfgErr(path, "logging.level", fmt.Sprintf("unsupported level %q (allowed: %s)", log.Level, strings.Join(allowedLogLevels, ", ")))
	}
	if log.Format != "" && !contains(allowedLogFormats, log.Format) {
		return cfgErr(path, "logging.format", fmt.Sprintf("unsupported format %q (allowed: %s)", log.Format, strings.Join(allowedLogFormats, ", ")))
	}
	if log.Output != "" && !contains(allowedLogOutputs, log.Output) {
		return cfgErr(path, "logging.output", fmt.Sprintf("unsupported output %q (allowed: %s)", log.Output, strings.Join(allowedLogOutputs, ", ")))
	}
	if log.Output == "file" && strings.TrimSpace(log.FilePath) == "" {
		return cfgErr(path, "logging.file_path", "must be set when output is file")
	}
	if log.MaxSizeMB < 0 || log.MaxBackups < 0 {
		return cfgErr(path, "logging", "max_size_mb and max_backups must be >= 0")
	}

	return nil
}

// applyGlobalDefaults fills in any zero values that have documented defaults.
// Explicit config always wins; this only patches values left unset by the user.
func applyGlobalDefaults(g *Global) {
	if g.Logging.Level == "" {
		g.Logging.Level = "info"
	}
	if g.Logging.Format == "" {
		g.Logging.Format = "json"
	}
	if g.Logging.Output == "" {
		g.Logging.Output = "stdout"
	}
	if g.Logging.MaxSizeMB == 0 {
		g.Logging.MaxSizeMB = 100
	}
	if g.Logging.MaxBackups == 0 {
		g.Logging.MaxBackups = 5
	}

	if g.Iptables.ChainPrefix == "" {
		g.Iptables.ChainPrefix = "ROUTEX"
	}
	if g.Iptables.CommentPrefix == "" {
		g.Iptables.CommentPrefix = "RouteX"
	}

	if g.Metrics.RetentionHours == 0 {
		g.Metrics.RetentionHours = 168
	}
	if g.Metrics.FlushIntervalSeconds == 0 {
		g.Metrics.FlushIntervalSeconds = 10
	}
	if g.Metrics.SqlitePath == "" {
		g.Metrics.SqlitePath = "./routex_metrics.db"
	}
	if len(g.Metrics.Formats) == 0 {
		g.Metrics.Formats = []string{"json", "prometheus", "influx", "csv"}
	}

	nw := &g.Network
	if nw.SocketBufferSize == 0 {
		nw.SocketBufferSize = 65536
	}
	if nw.TCPKeepaliveInterval == 0 && nw.TCPKeepaliveEnabled {
		nw.TCPKeepaliveInterval = 30
	}
	if nw.UDPReadBuffer == 0 {
		nw.UDPReadBuffer = 4 * 1024 * 1024
	}
	if nw.UDPWriteBuffer == 0 {
		nw.UDPWriteBuffer = 4 * 1024 * 1024
	}

	d := &g.Defaults
	if d.UpstreamConnectTimeout == 0 {
		d.UpstreamConnectTimeout = Duration(5 * time.Second)
	}
	if d.UpstreamReadTimeout == 0 {
		d.UpstreamReadTimeout = Duration(30 * time.Second)
	}
	if d.UpstreamWriteTimeout == 0 {
		d.UpstreamWriteTimeout = Duration(30 * time.Second)
	}
	if d.ClientReadTimeout == 0 {
		d.ClientReadTimeout = Duration(30 * time.Second)
	}
	if d.ClientWriteTimeout == 0 {
		d.ClientWriteTimeout = Duration(30 * time.Second)
	}
	if d.HealthCheckInterval == 0 {
		d.HealthCheckInterval = Duration(10 * time.Second)
	}
	if d.HealthCheckTimeout == 0 {
		d.HealthCheckTimeout = Duration(3 * time.Second)
	}
	if d.HealthCheckFailuresBeforeEject == 0 {
		d.HealthCheckFailuresBeforeEject = 3
	}
	if d.HealthCheckPassesBeforeReadmit == 0 {
		d.HealthCheckPassesBeforeReadmit = 2
	}
	if d.UDPSessionTimeout == 0 {
		d.UDPSessionTimeout = Duration(60 * time.Second)
	}

	if g.API.Bind == "" {
		g.API.Bind = "0.0.0.0:9000"
	}
}

// contains reports whether the slice contains the supplied value.
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// AllPermissions reports whether the supplied permission list grants wildcard
// access. Used by the API auth middleware at request time.
func AllPermissions(perms []string) bool { return contains(perms, "*") }

// HasPermission reports whether perms include the required scope or the
// wildcard "*". Empty perms means no access; callers should handle accordingly.
func HasPermission(perms []string, required string) bool {
	if len(perms) == 0 {
		return false
	}
	if AllPermissions(perms) {
		return true
	}
	return contains(perms, required)
}

// LookupAPIKey returns the API key record matching the supplied secret and
// whether such a key exists. Used by the auth middleware at request time.
func (g *Global) LookupAPIKey(secret string) (GlobalAPIKey, bool) {
	for _, k := range g.API.APIKeys {
		if k.Key == secret {
			return k, true
		}
	}
	return GlobalAPIKey{}, false
}

// APIAuthBypass reports whether the API is disabled entirely — in which case
// the server layer treats all requests as authorized for local instrument only.
func (g *Global) APIAuthBypass() bool { return g.API.allowAll }