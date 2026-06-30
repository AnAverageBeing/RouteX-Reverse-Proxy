package proxy

// suspendChecker is implemented by the bandwidth tracker. We probe the
// BytesRecorder for it via type assertion so the proxy can enforce bandwidth
// suspension without coupling its constructor signature to the bandwidth package.
type suspendChecker interface {
	Suspended() bool
}

// isSuspended reports whether the supplied recorder (if any) has tripped its
// bandwidth quota. A nil recorder or one without quota support is never suspended.
func isSuspended(rec BytesRecorder) bool {
	if sc, ok := rec.(suspendChecker); ok {
		return sc.Suspended()
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func parsePort(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			return 0
		}
	}
	return n
}
