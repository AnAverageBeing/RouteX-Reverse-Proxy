package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// MarshalProxyYAML serializes a proxy config back to YAML bytes. The output is
// a valid per-proxy config file that round-trips through LoadProxyFromYAML.
func MarshalProxyYAML(p *Proxy) ([]byte, error) {
	return yaml.Marshal(p)
}

// ProxyToMap converts a proxy config into a generic JSON-friendly map keyed by
// the YAML field names (origin-ip, dest-port, ...). This lets the REST API
// return structured JSON without duplicating json tags on every config struct.
func ProxyToMap(p *Proxy) (map[string]interface{}, error) {
	raw, err := yaml.Marshal(p)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// LoadProxyFromYAML parses and validates a proxy config from raw YAML bytes
// (e.g. a REST API request body). It performs the exact same validation as
// LoadProxy so an API-created proxy can never differ from a file-loaded one.
func LoadProxyFromYAML(raw []byte) (*Proxy, error) {
	var p Proxy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(false)
	if err := dec.Decode(&p); err != nil {
		return nil, &ConfigError{Field: "", Reason: "failed to parse proxy config YAML", Cause: err}
	}
	if err := validateProxy(&p, "<api>"); err != nil {
		return nil, err
	}
	return &p, nil
}

// ValidateProxyConfig validates an already-parsed proxy config in place,
// applying the same normalization (defaults) that LoadProxy applies.
func ValidateProxyConfig(p *Proxy) error {
	return validateProxy(p, "<api>")
}

// ProxyFileName returns the canonical config file name for a proxy: the proxy
// name lowercased with any character outside [a-z0-9-_] replaced by '-', plus
// a .yaml extension. Used so API-created proxies land in predictable files.
func ProxyFileName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	fn := strings.Trim(b.String(), "-")
	if fn == "" {
		fn = "proxy"
	}
	return fn + ".yaml"
}

// SaveProxy writes a proxy config to the proxies directory and returns the path
// it was written to. If the proxy already carries a ConfigPath (it was loaded
// from disk) that exact file is overwritten so we don't orphan the original;
// otherwise a canonical {dir}/{name}.yaml file is created.
//
// NOTE: this rewrites the file from the parsed struct, so YAML comments and
// custom field ordering in a hand-edited file are not preserved. API-managed
// proxies are expected to be owned by the API.
func SaveProxy(p *Proxy, dir string) (string, error) {
	raw, err := MarshalProxyYAML(p)
	if err != nil {
		return "", fmt.Errorf("marshal proxy %q: %w", p.Name, err)
	}
	path := p.ConfigPath
	if path == "" {
		path = filepath.Join(dir, ProxyFileName(p.Name))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create proxies dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return "", fmt.Errorf("write proxy config: %w", err)
	}
	// Atomic replace so the watcher never observes a half-written file.
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("commit proxy config: %w", err)
	}
	p.ConfigPath = path
	return path, nil
}

// DeleteProxyFile removes a proxy's config file from disk. A missing file is not
// treated as an error so delete is idempotent.
func DeleteProxyFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// FindProxyConfigPath scans the proxies directory for a config whose proxy name
// matches the supplied name and returns its file path (or "" if not found).
func FindProxyConfigPath(dir, name string) string {
	for _, res := range LoadProxyDir(dir) {
		if res.Err == nil && res.Proxy != nil && res.Proxy.Name == name {
			return res.Path
		}
	}
	return ""
}
