package memberlist

import (
	"fmt"
	"net"
)

// LogAddress ...
func LogAddress(addr net.Addr) string {
	if addr == nil {
		return "from=<unknown address>"
	}

	return fmt.Sprintf("from=%s", addr.String())
}

// LogConn ...
func LogConn(conn net.Conn) string {
	if conn == nil {
		return LogAddress(nil)
	}

	return LogAddress(conn.RemoteAddr())
}
