//! The public values a member hands out: its state, events, inbound messages, traffic counts,
//! usage reports, pairing codes, and the protocol timers.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use bytes::Bytes;

use crate::roster::{MemberKind, Roster, RosterMember};

/// Every message larger than this is refused (section 7.3).
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;
/// One transport plaintext: a Noise message is at most 65535 bytes, 16 of them the tag.
pub const MAX_PLAINTEXT: usize = 65535 - 16;
/// The `bytes` of one `message` fragment (section 7.3).
pub const MAX_FRAGMENT: usize = MAX_PLAINTEXT - 2;
/// Credit every session starts with, in each direction (section 7.3).
pub const INITIAL_CREDIT: u64 = 1024 * 1024;
pub const DEFAULT_CREDIT_WINDOW: u64 = INITIAL_CREDIT;
/// Owed credit is returned at once from this much (section 7.3)...
pub const CREDIT_BATCH_BYTES: u64 = 65536;
/// ...and otherwise this long after it began to be owed.
pub const CREDIT_DELAY_MS: u64 = 250;
/// A session may have at least this many message bytes un-credited, or one and a half times
/// what was credited back over the last second if more.
pub const PACE_FLOOR_BYTES: u64 = 65536;
/// The smallest fragment the pace cuts a message into.
pub const PACE_MIN_FRAGMENT: u64 = 16384;
/// Control (text) messages are at most 128 KiB (section 4).
pub const MAX_CONTROL_BYTES: usize = 131_072;
/// Data is handed to the socket only while at most this much waits in it.
pub const SOCKET_LOW_WATER: usize = 65536;
/// A pairing code admits one node for this long (section 5.1).
pub const CODE_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// Five failed confirmations burn a code.
pub const CODE_ATTEMPTS: u32 = 5;
/// The relay's budget for usage asks per network (section 4.3): this many at once...
pub const USAGE_BURST: u32 = 3;
/// ...then one per this long.
pub const USAGE_INTERVAL: Duration = Duration::from_secs(10);

/// A member's connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemberState {
    Connecting,
    Connected,
    Disconnected,
    /// Not a member (4008, or a roster that no longer lists it). Terminal.
    Revoked,
    /// Another copy of the identity connected (4005). Terminal.
    Replaced,
    /// Closed by the application. Terminal.
    Closed,
}

impl MemberState {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberState::Connecting => "connecting",
            MemberState::Connected => "connected",
            MemberState::Disconnected => "disconnected",
            MemberState::Revoked => "revoked",
            MemberState::Replaced => "replaced",
            MemberState::Closed => "closed",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, MemberState::Revoked | MemberState::Replaced | MemberState::Closed)
    }
}

impl fmt::Display for MemberState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A whole message from a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundMessage {
    pub from: String,
    pub bytes: Bytes,
}

/// What a member reports as it runs, in the order it happens.
#[derive(Clone, Debug)]
pub enum Event {
    State(MemberState),
    /// A newer roster was accepted. Persist it.
    Roster(Roster),
    /// The relay connection closed (any code).
    Disconnect {
        code: u16,
        reason: String,
    },
    /// 4009: the network moved to another relay node.
    Moved {
        network: String,
    },
    /// A non-fatal `error` control message from the relay.
    RelayError {
        code: String,
        message: Option<String>,
        id: Option<String>,
    },
    /// Primary only: a newcomer completed pairing and is on the published roster.
    Paired {
        member: RosterMember,
        roster: Roster,
    },
    /// Primary only: a pairing attempt ended without a new member. `message` says it in words.
    PairingFailed {
        code_id: String,
        reason: PairingFailure,
        message: String,
    },
}

/// Why a pairing attempt ended without a new member. `as_str` spells it as the driver protocol
/// does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PairingFailure {
    /// The newcomer's confirmation did not verify (a failed attempt; five burn the code).
    WrongCode,
    /// A pairing message was malformed (a failed attempt, section 5.1).
    Malformed,
    /// No open code has that id: never opened, expired, cancelled, used or burned.
    UnknownCode,
    /// Another newcomer has already confirmed this code.
    Used,
    /// The code is open, but its five attempts are all failed or in flight.
    NoAttempts,
    /// The relay ended the channel (`pairEnd`): the newcomer left or the relay timed out.
    NewcomerLeft,
    /// The primary's own 60-second limit on the channel ran out.
    Timeout,
    /// The primary's relay connection dropped mid-pairing.
    RelayLost,
    /// The newcomer's key is already on the roster.
    AlreadyMember,
    /// The roster has no room for the newcomer.
    RosterFull,
}

impl PairingFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            PairingFailure::WrongCode => "wrong-code",
            PairingFailure::Malformed => "malformed",
            PairingFailure::UnknownCode => "unknown-code",
            PairingFailure::Used => "used",
            PairingFailure::NoAttempts => "no-attempts",
            PairingFailure::NewcomerLeft => "newcomer-left",
            PairingFailure::Timeout => "timeout",
            PairingFailure::RelayLost => "relay-lost",
            PairingFailure::AlreadyMember => "already-member",
            PairingFailure::RosterFull => "roster-full",
        }
    }
}

impl fmt::Display for PairingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A function that sees everything a member reports, synchronously and in order, as it
/// happens. It runs while the member's state is locked: it must be quick and must not call back
/// into the member.
pub type Observer = std::sync::Arc<dyn Fn(&Observed) + Send + Sync>;

/// Everything a member reports, in one ordered stream: its events, and each message as it
/// arrives (the message stays for `recv`; observing it does not take it).
#[derive(Clone, Debug)]
pub enum Observed {
    Event(Event),
    Message(InboundMessage),
    /// Only in an [`Observation`](crate::Observation) stream: this many items were dropped, the
    /// oldest first, because the stream fell more than 1024 behind.
    Lagged(u64),
}

/// The protocol timers. The defaults are the spec's; tests shorten them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// Handshake timeout per message (10 s); also how long a send waits for the relay.
    pub handshake_timeout: Duration,
    /// The initiator rekeys after this long (10 min)...
    pub rekey_interval: Duration,
    /// ...or after this many messages in either direction (2^32).
    pub rekey_messages: u64,
    /// The previous session's keys are kept this long after a rekey (30 s); a responder also
    /// treats a session older than `rekey_interval + retire_grace` as expired.
    pub retire_grace: Duration,
    /// A session with no frame in either direction this long is forgotten (10 min).
    pub idle: Duration,
    /// First reconnect delay (500 ms), doubling...
    pub backoff_initial: Duration,
    /// ...to at most this (10 s).
    pub backoff_max: Duration,
    /// How long relay requests (usage, roster sync, resign) wait for an answer (10 s).
    pub request_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            handshake_timeout: Duration::from_secs(10),
            rekey_interval: Duration::from_secs(600),
            rekey_messages: 1 << 32,
            retire_grace: Duration::from_secs(30),
            idle: Duration::from_secs(600),
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// Counts in one direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    /// Whole application messages...
    pub messages: u64,
    /// ...and their payload bytes.
    pub bytes: u64,
    /// Routed frames of every type (handshakes, credit and control included)...
    pub frames: u64,
    /// ...at their full size, header included: what the relay charges. Pairing frames are not
    /// counted.
    pub frame_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerTraffic {
    pub sent: Traffic,
    pub received: Traffic,
}

/// UTF-8 bytes of control messages exchanged with the relay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayTraffic {
    pub sent: u64,
    pub received: u64,
}

/// What a member sent and received since `since`, per peer and in total.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrafficReport {
    /// Unix milliseconds the counts start from (creation, or the last `reset_traffic`).
    pub since: u64,
    pub total: PeerTraffic,
    pub relay: RelayTraffic,
    /// Per roster member.
    pub peers: BTreeMap<String, PeerTraffic>,
}

/// The relay's limits for a network (section 4.3).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct UsageLimits {
    pub rate_bps: f64,
    pub quota_bytes_hour: f64,
    pub trickle_bps: f64,
}

/// The relay's answer to a usage ask (section 4.3).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct UsageReport {
    /// Bytes charged to the network over the last hour, in five-minute steps.
    pub bytes_hour: f64,
    /// Connected members.
    pub connections: f64,
    pub limits: UsageLimits,
    /// `bytes_hour / quota_bytes_hour`; 0 without a quota.
    pub quota_used: f64,
    /// The trickle rate is in effect: send less.
    pub slowed: bool,
}

/// An open pairing code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingCode {
    /// Display form, `XXXX-XXXX`.
    pub code: String,
    /// b64u of the 8-byte code id.
    pub code_id: String,
    pub kind: MemberKind,
    /// The `frontier://pair?...` link carrying network, code, code id and relay.
    pub link: String,
    /// Unix milliseconds.
    pub expires_at: u64,
}
