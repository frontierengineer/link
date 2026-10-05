//go:build !linux

package relay

import "errors"

// errNoPoller: the platform has no poller; not worth a log line.
var errNoPoller = errors.New("no poller on this platform")

// poller is Linux-only (poll_linux.go). Elsewhere every connection keeps its reader goroutine.
type poller struct{}

func newPoller(*Server) (*poller, error) { return nil, errNoPoller }

func (*poller) arm(*conn, bool) bool { return false }

func (*poller) close() {}
