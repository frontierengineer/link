//go:build !unix

package relay

import (
	"net"
	"syscall"
)

// rawConnOf: no non-blocking socket access here (Windows sockets are overlapped); the writer
// goroutine writes and the reader goroutine reads.
func rawConnOf(net.Conn) syscall.RawConn { return nil }

func rawIO(syscall.RawConn, []byte, bool) (int, error) { return 0, syscall.EAGAIN }
