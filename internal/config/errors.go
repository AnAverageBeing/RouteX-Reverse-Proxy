package config

import (
	"errors"
	"strings"
)

// ConfigError carries structured context about a config problem: which file
// the error originated in, which field (dotted path) was rejected, and the
// underlying reason. Callers receive a *ConfigError so the proxy manager can
// scope failure reports per file without losing the diagnostic detail.
type ConfigError struct {
	File   string
	Field  string
	Reason string
	Cause  error
}

// Error renders a single-line human-readable description suitable for logs.
func (e *ConfigError) Error() string {
	if e == nil {
		return "config error"
	}
	var b strings.Builder
	if e.File != "" {
		b.WriteString(e.File)
		b.WriteString(": ")
	}
	if e.Field != "" {
		b.WriteString(e.Field)
		b.WriteString(": ")
	}
	b.WriteString(e.Reason)
	if e.Cause != nil {
		b.WriteString(" (")
		b.WriteString(e.Cause.Error())
		b.WriteString(")")
	}
	return b.String()
}

// Unwrap enables errors.Is / errors.As traversal of the underlying cause.
func (e *ConfigError) Unwrap() error { return e.Cause }

// wrap lifts the supplied plain error into a *ConfigError tagged with the
// current scope, taking care to avoid double-wrapping already scoped errors.
func wrap(file, field, reason string, cause error) *ConfigError {
	if cause != nil {
		var ce *ConfigError
		if errors.As(cause, &ce) {
			return ce
		}
	}
	return &ConfigError{File: file, Field: field, Reason: reason, Cause: cause}
}

// cfgErr constructs a *ConfigError with a plain message string. Callers that
// need formatting must use fmt.Sprintf themselves — keeping this helper
// non-printf-style avoids vet's "non-constant format string" warning on the
// many call sites that pass message variables (e.g. validation closures).
func cfgErr(file, field, message string) *ConfigError {
	return &ConfigError{File: file, Field: field, Reason: message}
}