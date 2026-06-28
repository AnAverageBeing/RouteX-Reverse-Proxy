package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
)

func TestLoadGlobal_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.yaml")
	content := `
api:
  enabled: true
  bind: "127.0.0.1:8080"
  api_keys:
    - key: "test-key"
      label: "test"
      permissions: ["*"]
metrics:
  enabled: true
  retention_hours: 168
  flush_interval_seconds: 10
  sqlite_path: "./test.db"
  formats: ["json", "prometheus"]
logging:
  level: "info"
  format: "json"
  output: "stdout"
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	g, err := config.LoadGlobal(path)
	if err != nil {
		t.Fatalf("LoadGlobal failed: %v", err)
	}
	if !g.API.Enabled {
		t.Error("API should be enabled")
	}
	if g.API.Bind != "127.0.0.1:8080" {
		t.Errorf("bind = %q, want 127.0.0.1:8080", g.API.Bind)
	}
	if len(g.API.APIKeys) != 1 {
		t.Fatalf("expected 1 API key, got %d", len(g.API.APIKeys))
	}
	if g.API.APIKeys[0].Key != "test-key" {
		t.Errorf("key = %q, want test-key", g.API.APIKeys[0].Key)
	}
	if !config.HasPermission(g.API.APIKeys[0].Permissions, "metrics:read") {
		t.Error("wildcard permission should grant metrics:read")
	}
}

func TestLoadGlobal_MissingAPIKeyFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.yaml")
	content := `
api:
  enabled: true
  bind: "127.0.0.1:8080"
  api_keys: []
metrics:
  enabled: false
logging:
  level: "info"
  format: "json"
  output: "stdout"
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	_, err := config.LoadGlobal(path)
	if err == nil {
		t.Fatal("expected error for missing API keys when API is enabled")
	}
}

func TestLoadGlobal_InvalidMetricsFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.yaml")
	content := `
api:
  enabled: false
metrics:
  enabled: true
  retention_hours: 168
  flush_interval_seconds: 10
  sqlite_path: "./test.db"
  formats: ["invalid-format"]
logging:
  level: "info"
  format: "json"
  output: "stdout"
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	_, err := config.LoadGlobal(path)
	if err == nil {
		t.Fatal("expected error for unsupported metrics format")
	}
}

func TestLoadGlobal_APIKeyLookup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.yaml")
	content := `
api:
  enabled: true
  bind: "127.0.0.1:8080"
  api_keys:
    - key: "abc"
      label: "A"
      permissions: ["metrics:read"]
    - key: "xyz"
      label: "X"
      permissions: ["*"]
metrics:
  enabled: false
logging:
  level: "info"
  format: "json"
  output: "stdout"
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	g, err := config.LoadGlobal(path)
	if err != nil {
		t.Fatalf("LoadGlobal failed: %v", err)
	}

	k, ok := g.LookupAPIKey("abc")
	if !ok {
		t.Fatal("key 'abc' not found")
	}
	if k.Label != "A" {
		t.Errorf("label = %q, want A", k.Label)
	}

	_, ok = g.LookupAPIKey("missing")
	if ok {
		t.Error("missing key should not be found")
	}
}

func TestLoadGlobal_DefaultsApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.yaml")
	content := `
api:
  enabled: false
metrics:
  enabled: false
logging:
  level: ""
  format: ""
  output: ""
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	g, err := config.LoadGlobal(path)
	if err != nil {
		t.Fatalf("LoadGlobal failed: %v", err)
	}

	if g.Logging.Level != "info" {
		t.Errorf("default logging level = %q, want info", g.Logging.Level)
	}
	if g.Logging.Format != "json" {
		t.Errorf("default logging format = %q, want json", g.Logging.Format)
	}
	if g.Logging.Output != "stdout" {
		t.Errorf("default logging output = %q, want stdout", g.Logging.Output)
	}
	if g.Iptables.ChainPrefix != "ROUTEX" {
		t.Errorf("default chain prefix = %q, want ROUTEX", g.Iptables.ChainPrefix)
	}
	if g.Iptables.CommentPrefix != "RouteX" {
		t.Errorf("default comment prefix = %q, want RouteX", g.Iptables.CommentPrefix)
	}
	if g.Defaults.UpstreamConnectTimeout == 0 {
		t.Error("upstream connect timeout should have default")
	}
}

func TestLoadProxy_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `
name: "test-proxy"
enabled: true
origin-ip: "0.0.0.0"
origin-port: "8080:8085"
dest-ip: "10.0.0.1, 10.0.0.2"
dest-port: "9090:9095"
one-to-one: true
protocol: "tcp"
load_balancing:
  algorithm: "round-robin"
  sticky_sessions: false
  sticky_ttl: 0
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	p, err := config.LoadProxy(path)
	if err != nil {
		t.Fatalf("LoadProxy failed: %v", err)
	}
	if p.Name != "test-proxy" {
		t.Errorf("name = %q, want test-proxy", p.Name)
	}
	if p.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", p.Protocol)
	}
	if !p.OneToOne {
		t.Error("one-to-one should be true")
	}
	ports := p.ResolveOriginPorts()
	if len(ports) == 0 {
		t.Error("expected non-empty origin ports")
	}
	dports := p.ResolveDestPorts()
	if len(dports) == 0 {
		t.Error("expected non-empty dest ports")
	}
	ips := p.ResolveDestIPs()
	if len(ips) < 2 {
		t.Errorf("expected at least 2 dest IPs, got %d", len(ips))
	}
}

func TestLoadProxy_OneToOneRangeMismatchFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `
name: "bad-proxy"
enabled: true
origin-ip: "0.0.0.0"
origin-port: "8080:8089"
dest-ip: "10.0.0.1"
dest-port: "9090:9092"
one-to-one: true
protocol: "tcp"
load_balancing:
  algorithm: "round-robin"
  sticky_sessions: false
  sticky_ttl: 0
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	_, err := config.LoadProxy(path)
	if err == nil {
		t.Fatal("expected error for one-to-one range size mismatch")
	}
}

func TestLoadProxy_InvalidProtocol(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `
name: "bad-proto"
enabled: true
origin-ip: "0.0.0.0"
origin-port: "8080"
dest-ip: "10.0.0.1"
dest-port: "9090"
one-to-one: true
protocol: "invalid"
load_balancing:
  algorithm: "round-robin"
  sticky_sessions: false
  sticky_ttl: 0
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	_, err := config.LoadProxy(path)
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestLoadProxy_InvalidAlgorithm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `
name: "bad-algo"
enabled: true
origin-ip: "0.0.0.0"
origin-port: "8080"
dest-ip: "10.0.0.1"
dest-port: "9090"
one-to-one: false
protocol: "tcp"
load_balancing:
  algorithm: "magic-hash"
  sticky_sessions: false
  sticky_ttl: 0
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	_, err := config.LoadProxy(path)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestLoadProxy_L7InspectionMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `
name: "l7-proxy"
enabled: true
origin-ip: "0.0.0.0"
origin-port: "8080"
dest-ip: "10.0.0.1"
dest-port: "9090"
one-to-one: false
protocol: "tcp"
load_balancing:
  algorithm: "round-robin"
  sticky_sessions: false
  sticky_ttl: 0
l7_protection:
  enabled: true
  payload_inspection:
    enabled: true
    mode: "invalid-mode"
`
	_ = os.WriteFile(path, []byte(content), 0o644)

	_, err := config.LoadProxy(path)
	if err == nil {
		t.Fatal("expected error for unsupported inspection mode")
	}
}
