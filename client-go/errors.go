package link

import (
	"errors"
	"fmt"
)

// ErrorCode is the stable code of every error this package returns, so callers can branch
// without parsing messages. The values are the TypeScript client's.
type ErrorCode string

const (
	CodeUnreachable ErrorCode = "unreachable"  // the relay reports the peer is not connected; nothing is queued
	CodeRefused     ErrorCode = "refused"      // the peer will not talk to this node (reason 1: not on its roster)
	CodeRevoked     ErrorCode = "revoked"      // this node is no longer a member (4008); terminal
	CodeReplaced    ErrorCode = "replaced"     // a newer connection for this node took over (4005); terminal
	CodeTimeout     ErrorCode = "timeout"      // an operation timed out
	CodeClosed      ErrorCode = "closed"       // the member was closed, or the session ended first
	CodePairing     ErrorCode = "pairing"      // pairing failed
	CodeRosterFull  ErrorCode = "roster-full"  // another member would take the roster over 65000 bytes
	CodeRateLimited ErrorCode = "rate-limited" // the relay refused a request over its budget
	CodeInvalid     ErrorCode = "invalid"      // a caller error: bad argument, unknown peer, message too large
)

// Error is the error type of this package. Peer is set for unreachable and refused, Reason
// for refused, Bytes for roster-full.
type Error struct {
	Code    ErrorCode
	Message string
	Peer    string
	Reason  int
	Bytes   int
}

func (e *Error) Error() string { return e.Message }

// Is matches a sentinel of the same code: errors.Is(err, link.ErrUnreachable).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Message == "" && t.Code == e.Code
}

// Sentinels for errors.Is.
var (
	ErrUnreachable = &Error{Code: CodeUnreachable}
	ErrRefused     = &Error{Code: CodeRefused}
	ErrRevoked     = &Error{Code: CodeRevoked}
	ErrReplaced    = &Error{Code: CodeReplaced}
	ErrTimeout     = &Error{Code: CodeTimeout}
	ErrClosed      = &Error{Code: CodeClosed}
	ErrPairing     = &Error{Code: CodePairing}
	ErrRosterFull  = &Error{Code: CodeRosterFull}
	ErrRateLimited = &Error{Code: CodeRateLimited}
	ErrInvalid     = &Error{Code: CodeInvalid}
)

// CodeOf returns the code of a link error, or "" for any other error.
func CodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func unreachableError(peer string) *Error {
	return &Error{Code: CodeUnreachable, Message: fmt.Sprintf("peer %s is not connected", peer), Peer: peer}
}

func refusedError(peer string, reason int) *Error {
	return &Error{Code: CodeRefused, Message: fmt.Sprintf("peer %s refused the session (reason %d)", peer, reason), Peer: peer, Reason: reason}
}

func revokedError() *Error {
	return &Error{Code: CodeRevoked, Message: "this node is not a member of the network"}
}

func replacedError() *Error {
	return &Error{Code: CodeReplaced, Message: "a newer connection for this node replaced this one"}
}

func timeoutError(what string) *Error {
	return &Error{Code: CodeTimeout, Message: what + " timed out"}
}

func closedError(what string) *Error {
	if what == "" {
		what = "the member is closed"
	}
	return &Error{Code: CodeClosed, Message: what}
}

func pairingError(msg string) *Error { return &Error{Code: CodePairing, Message: msg} }

func rosterFullError(bytes int) *Error {
	return &Error{Code: CodeRosterFull, Message: fmt.Sprintf("the roster would be %d bytes, over the 65000-byte limit", bytes), Bytes: bytes}
}

func rateLimitedError(what string) *Error {
	return &Error{Code: CodeRateLimited, Message: what + " refused: over the relay's budget"}
}

func invalidError(msg string) *Error { return &Error{Code: CodeInvalid, Message: msg} }
