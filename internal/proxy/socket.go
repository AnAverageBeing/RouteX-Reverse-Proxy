package proxy

import (
	"syscall"
)

func setSocketBuffer(size int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var setErr error
		err := c.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
		})
		if err != nil {
			return err
		}
		return setErr
	}
}
