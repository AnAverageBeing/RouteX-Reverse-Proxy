package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that unmarshals from Go's duration string format
// ("5s", "30s", "1m", "1h30m"). It also accepts a bare integer interpreted as
// nanoseconds to remain compatible with yaml.v3's default scalar handling when
// a numeric value is provided without a unit suffix.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler. The value may be supplied as a
// string (parsed via time.ParseDuration) or as a plain integer (seconds).
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw interface{}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", v, err)
		}
		*d = Duration(parsed)
	case int:
		*d = Duration(time.Duration(v) * time.Second)
	case int64:
		*d = Duration(time.Duration(v) * time.Second)
	case float64:
		*d = Duration(time.Duration(v) * time.Second)
	case uint64:
		*d = Duration(time.Duration(v) * time.Second)
	case nil:
		*d = 0
	default:
		return fmt.Errorf("invalid duration value of type %T", raw)
	}
	return nil
}

// MarshalYAML emits the duration as a canonical Go duration string so round-trip
// writes preserve the original representation.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// D returns the underlying time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// IsZero reports whether the duration is zero.
func (d Duration) IsZero() bool { return d == 0 }

// Positive reports whether the duration is strictly greater than zero.
func (d Duration) Positive() bool { return d > 0 }

// Or returns d when it is non-zero, otherwise the supplied fallback.
func (d Duration) Or(fallback Duration) Duration {
	if d != 0 {
		return d
	}
	return fallback
}

// DurationPtr wraps a *time.Duration pointer for callers that want to keep the
// raw time.Duration type after parsing. Helper used by proxy code.
func (d Duration) DurationPtr() *time.Duration {
	v := time.Duration(d)
	return &v
}

// Seconds returns the duration in seconds as a float.
func (d Duration) Seconds() float64 { return time.Duration(d).Seconds() }

// String renders the duration using time.Duration's canonical formatter.
func (d Duration) String() string { return time.Duration(d).String() }

// parseScalarInt accepts a YAML scalar that might be a string ("10") or a bare
// integer and returns an int. Used by sub-schema parsers that need flexible
// numeric inputs.
func parseScalarInt(raw any) (int, error) {
	switch v := raw.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		clean := strings.TrimSpace(v)
		if clean == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(clean)
		if err != nil {
			return 0, fmt.Errorf("invalid integer %q", v)
		}
		return n, nil
	}
	return 0, fmt.Errorf("unsupported numeric scalar %T", raw)
}