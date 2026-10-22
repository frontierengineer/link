//go:build !linux && !darwin

package relay

// tcpNotSentLowat: the system has no TCP_NOTSENT_LOWAT, and the kernel's send buffer is left
// to itself.
const tcpNotSentLowat = 0
