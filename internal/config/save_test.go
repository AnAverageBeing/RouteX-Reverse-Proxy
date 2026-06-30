package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProxyFromYAML_ValidAndInvalid(t *testing.T) {
	good := []byte(`
name: "api-proxy"
enabled: true
origin-ip: "127.0.0.1"
origin-port: 19000
dest-ip: "10.0.0.1, 10.0.0.2"
dest-port: 29000
protocol: "tcp"
load_balancing:
  algorithm: "least-conn"
`)
	p, err := LoadProxyFromYAML(good)
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if p.Name != "api-proxy" || p.Protocol != "tcp" {
		t.Fatalf("parsed config wrong: %+v", p)
	}

	// Missing protocol must fail validation (same rules as file loading).
	bad := []byte(`
name: "broken"
origin-ip: "127.0.0.1"
origin-port: 19000
dest-ip: "10.0.0.1"
dest-port: 29000
`)
	if _, err := LoadProxyFromYAML(bad); err == nil {
		t.Fatal("expected validation error for config missing protocol")
	}
}

// TestSaveLoadRoundTrip verifies a config saved to disk reloads identically and
// that the canonical filename is derived from the proxy name.
func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p, err := LoadProxyFromYAML([]byte(`
name: "Round Trip!"
enabled: true
origin-ip: "127.0.0.1"
origin-port: "25565:25567"
dest-ip: "10.0.0.1"
dest-port: "35565:35567"
one-to-one: true
protocol: "tcp-udp"
load_balancing:
  algorithm: "round-robin"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	path, err := SaveProxy(p, dir)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	wantName := "round-trip.yaml" // sanitized from "Round Trip!"
	if filepath.Base(path) != wantName {
		t.Errorf("filename = %q, want %q", filepath.Base(path), wantName)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved file missing: %v", err)
	}

	reloaded, err := LoadProxy(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Name != p.Name || reloaded.OriginPort != p.OriginPort ||
		reloaded.DestPort != p.DestPort || reloaded.OneToOne != p.OneToOne ||
		reloaded.Protocol != p.Protocol {
		t.Fatalf("round-trip mismatch:\n original=%+v\n reloaded=%+v", p, reloaded)
	}

	// FindProxyConfigPath should locate it by name.
	if got := FindProxyConfigPath(dir, "Round Trip!"); got != path {
		t.Errorf("FindProxyConfigPath = %q, want %q", got, path)
	}

	// DeleteProxyFile is idempotent.
	if err := DeleteProxyFile(path); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := DeleteProxyFile(path); err != nil {
		t.Fatalf("second delete should be a no-op, got: %v", err)
	}
}

func TestProxyToMap_UsesYAMLNames(t *testing.T) {
	p, err := LoadProxyFromYAML([]byte(`
name: "m"
origin-ip: "127.0.0.1"
origin-port: 1
dest-ip: "10.0.0.1"
dest-port: 2
protocol: "tcp"
`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ProxyToMap(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["origin-ip"]; !ok {
		t.Errorf("expected yaml field name 'origin-ip' in map, got keys: %v", keysOf(m))
	}
	if _, ok := m["origin-port"]; !ok {
		t.Errorf("expected 'origin-port' in map")
	}
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
