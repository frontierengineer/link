package relay

import (
	"crypto/tls"
	"net"
	"syscall"
)

// unsentLimit is the most the kernel holds of what the relay wrote to a connection and has not
// sent yet (section 9). Without it the send buffer grows to megabytes behind a member that
// reads slowly, and the relay's own messages, written ahead of routed frames in the relay's
// queue, would still wait behind those megabytes in the kernel's. It bounds only what waits
// unsent, not what is in flight, so it costs no throughput on a long path.
const unsentLimit = 64 << 10

// limitUnsent sets TCP_NOTSENT_LOWAT on the connection's socket, where the system has it.
func limitUnsent(nc net.Conn) {
	if tcpNotSentLowat == 0 {
		return
	}
	if tc, ok := nc.(*tls.Conn); ok {
		nc = tc.NetConn()
	}
	tc, ok := nc.(*net.TCPConn)
	if !ok {
		return
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	rc.Control(func(fd uintptr) {
		setsockoptInt(fd, syscall.IPPROTO_TCP, tcpNotSentLowat, unsentLimit)
	})
}
