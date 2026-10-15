//! Typed errors. Every error this crate returns is a [`LinkError`] with a stable [`ErrorCode`],
//! so callers can branch without parsing messages. The codes and their spellings are the
//! TypeScript client's.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The relay reports the peer is not connected. Nothing is queued for it.
    Unreachable,
    /// The peer will not talk to this node (reason 1: this node is not on its roster).
    Refused,
    /// This node is no longer a member (registration closed 4008). Terminal.
    Revoked,
    /// A newer connection for this node took over (close 4005). Terminal.
    Replaced,
    Timeout,
    /// The member was closed, or the session ended before the operation finished.
    Closed,
    Pairing,
    /// Adding a member would take the roster's JCS encoding over 65000 bytes (section 3).
    RosterFull,
    /// The relay refused a request over its budget (section 4.3); nothing was queued.
    RateLimited,
    /// A caller error: bad argument, unknown peer, message too large.
    Invalid,
}

impl ErrorCode {
    /// The code as the TypeScript client and the driver protocol spell it.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unreachable => "unreachable",
            ErrorCode::Refused => "refused",
            ErrorCode::Revoked => "revoked",
            ErrorCode::Replaced => "replaced",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Closed => "closed",
            ErrorCode::Pairing => "pairing",
            ErrorCode::RosterFull => "roster-full",
            ErrorCode::RateLimited => "rate-limited",
            ErrorCode::Invalid => "invalid",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkError {
    code: ErrorCode,
    message: String,
    /// For `Unreachable` and `Refused`: the peer.
    peer: Option<String>,
    /// For `Refused`: the reason byte of the `refused` frame.
    reason: Option<u8>,
}

impl LinkError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> LinkError {
        LinkError { code, message: message.into(), peer: None, reason: None }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn peer(&self) -> Option<&str> {
        self.peer.as_deref()
    }

    pub fn reason(&self) -> Option<u8> {
        self.reason
    }

    pub(crate) fn unreachable(peer: &str) -> LinkError {
        LinkError {
            peer: Some(peer.to_owned()),
            ..LinkError::new(ErrorCode::Unreachable, format!("peer {peer} is not connected"))
        }
    }

    pub(crate) fn refused(peer: &str, reason: u8) -> LinkError {
        LinkError {
            peer: Some(peer.to_owned()),
            reason: Some(reason),
            ..LinkError::new(ErrorCode::Refused, format!("peer {peer} refused the session (reason {reason})"))
        }
    }

    pub(crate) fn revoked() -> LinkError {
        LinkError::new(ErrorCode::Revoked, "this node is not a member of the network")
    }

    pub(crate) fn replaced() -> LinkError {
        LinkError::new(ErrorCode::Replaced, "a newer connection for this node replaced this one")
    }

    pub(crate) fn timeout(what: &str) -> LinkError {
        LinkError::new(ErrorCode::Timeout, format!("{what} timed out"))
    }

    pub(crate) fn closed(what: impl Into<String>) -> LinkError {
        LinkError::new(ErrorCode::Closed, what)
    }

    pub(crate) fn member_closed() -> LinkError {
        LinkError::closed("the member is closed")
    }

    pub(crate) fn pairing(message: impl Into<String>) -> LinkError {
        LinkError::new(ErrorCode::Pairing, message)
    }

    pub(crate) fn roster_full(bytes: usize) -> LinkError {
        LinkError::new(ErrorCode::RosterFull, format!("the roster would be {bytes} bytes, over the 65000-byte limit"))
    }

    pub(crate) fn rate_limited(what: &str) -> LinkError {
        LinkError::new(ErrorCode::RateLimited, format!("{what} refused: over the relay's budget"))
    }

    pub(crate) fn invalid(message: impl Into<String>) -> LinkError {
        LinkError::new(ErrorCode::Invalid, message)
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LinkError {}
