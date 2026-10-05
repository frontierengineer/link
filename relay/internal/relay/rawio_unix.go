//go:build unix

package relay

import (
	"net"
	"sync"
	"syscall"
)

// rawConnOf gives the socket for non-blocking reads and writes: a plain TCP connection's.
// Behind the relay's own TLS there is none, and the writer goroutine does the writing.
func rawConnOf(nc net.Conn) syscall.RawConn {
	tc, ok := nc.(*net.TCPConn)
	if !ok {
		return nil
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return nil
	}
	return rc
}

// rawOp is one non-blocking read or write through a RawConn. Its callbacks are made once per
// pooled op, not per call, so the per-frame path allocates nothing for them.
type rawOp struct {
	p       []byte
	n       int
	err     error
	readFn  func(fd uintptr) bool
	writeFn func(fd uintptr) bool
}

var rawOps = sync.Pool{New: func() any {
	o := &rawOp{}
	o.readFn = func(fd uintptr) bool {
		o.n, o.err = syscall.Read(int(fd), o.p)
		return true // one attempt: never wait
	}
	o.writeFn = func(fd uintptr) bool {
		o.n, o.err = syscall.Write(int(fd), o.p)
		return true
	}
	return o
}}

// rawIO makes one non-blocking attempt to read into p or write p. A socket with nothing to
// read, or no room to write, answers syscall.EAGAIN.
func rawIO(rc syscall.RawConn, p []byte, write bool) (int, error) {
	o := rawOps.Get().(*rawOp)
	o.p = p
	var cerr error
	if write {
		cerr = rc.Write(o.writeFn)
	} else {
		cerr = rc.Read(o.readFn)
	}
	n, err := max(o.n, 0), o.err
	o.p, o.n, o.err = nil, 0, nil
	rawOps.Put(o)
	if cerr != nil {
		return 0, cerr
	}
	return n, err
}
