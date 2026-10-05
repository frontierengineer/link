package relay

import (
	"errors"
	"sync"
	"syscall"
)

// errNoPoller: the platform has no poller; not worth a log line.
var errNoPoller = errors.New("no poller on this platform")

// poller lets a registered connection that has nothing to read give its goroutine up: its
// socket is armed, one-shot, in an epoll set, and the wait loop starts a reader for it when
// it is readable. An idle connection then costs its conn and its socket, no stack.
//
// Events carry the connection's key, never its descriptor, so an event for a connection
// that has since closed (and whose descriptor number a new socket reuses) finds nothing.
type poller struct {
	s      *Server
	epfd   int
	wake   [2]int // a pipe: the wait loop's way out at shutdown
	closed sync.Once
}

const wakeKey = 0 // connection keys start at 1

func newPoller(s *Server) (*poller, error) {
	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	p := &poller{s: s, epfd: epfd}
	if err := syscall.Pipe2(p.wake[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		syscall.Close(epfd)
		return nil, err
	}
	ev := syscall.EpollEvent{Events: syscall.EPOLLIN}
	setKey(&ev, wakeKey)
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, p.wake[0], &ev); err != nil {
		syscall.Close(p.wake[0])
		syscall.Close(p.wake[1])
		syscall.Close(epfd)
		return nil, err
	}
	go p.loop()
	return p, nil
}

func setKey(ev *syscall.EpollEvent, key uint64) {
	ev.Fd, ev.Pad = int32(uint32(key)), int32(uint32(key>>32))
}

func keyOf(ev *syscall.EpollEvent) uint64 {
	return uint64(uint32(ev.Fd)) | uint64(uint32(ev.Pad))<<32
}

// arm asks for one wake-up when c's socket is readable (or hung up): add puts it in the set
// the first time, later calls re-arm it. Called by c's parking reader; once it succeeds, a
// new reader may already own c, so it reads only what never changes.
func (p *poller) arm(c *conn, add bool) bool {
	ev := syscall.EpollEvent{Events: syscall.EPOLLIN | syscall.EPOLLRDHUP | syscall.EPOLLONESHOT}
	setKey(&ev, c.key)
	op := syscall.EPOLL_CTL_MOD
	if add {
		op = syscall.EPOLL_CTL_ADD
	}
	var err error
	// Inside Control the descriptor cannot be closed (and reused) under us.
	cerr := c.rc.Control(func(fd uintptr) { err = syscall.EpollCtl(p.epfd, op, int(fd), &ev) })
	return cerr == nil && err == nil
}

func (p *poller) loop() {
	events := make([]syscall.EpollEvent, 256)
	for {
		n, err := syscall.EpollWait(p.epfd, events, -1)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return
		}
		for i := range events[:n] {
			key := keyOf(&events[i])
			if key == wakeKey {
				syscall.Close(p.wake[0])
				syscall.Close(p.epfd)
				return
			}
			if c := p.s.lookup(key); c != nil {
				c.wake()
			}
		}
	}
}

// close stops the wait loop. A closed socket leaves the epoll set by itself.
func (p *poller) close() {
	if p == nil {
		return
	}
	p.closed.Do(func() {
		syscall.Write(p.wake[1], []byte{0})
		syscall.Close(p.wake[1])
	})
}
