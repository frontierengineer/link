//! Sessions (section 7): Noise IK handshakes keyed by roster X25519 keys, transport with
//! receiver indices, rekeying, idle expiry, and the session message layer (fragmentation and
//! credit flow control). The behaviour is the TypeScript client's `SessionManager`.
//!
//! Two lanes share the relay socket. Control (handshakes, refused, reset and session messages
//! other than `message`) is encrypted and handed over at once. Message fragments wait in a gate
//! until the socket is short, the session's un-credited bytes are within its window, credit
//! allows, and, while the relay shapes the network (section 11, pacing), the connection's pace
//! allows; only then is a fragment encrypted, in the same step that hands it to the socket.
//! Wire order is therefore nonce order, and control can pass queued data without breaking
//! Noise's implicit counter. Paced at the rate the relay reads, little lies in the socket in
//! front of control, so control arrives quickly however much data waits.
//!
//! Credit and reassembly belong to one session, and a message is never split across two
//! sessions: a rekey switches at a message boundary, and a retired session lives past its grace
//! while a message still uses it.
//!
//! What a peer can make this node hold is bounded, beyond what the TypeScript client does:
//! - a peer that sends message bytes beyond the credit it was given ends its session;
//! - a message in reassembly is at most 64 MiB (section 7.3);
//! - per peer, messages waiting for the application plus messages in reassembly are at most
//!   `2 × 64 MiB + 4 × creditWindow` bytes and `PEER_HELD_MESSAGES` messages; beyond either,
//!   the session that would exceed it ends (the message is lost: delivery is at most once);
//! - per peer, at most `MAX_SESSIONS_PER_PEER` sessions live at once; adopting one more ends
//!   the oldest that is not current.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use tokio::sync::oneshot;

use super::{Node, SessionControl};
use crate::bytes::{read_u32be, read_u64be, u32be, u64be};
use crate::errors::LinkError;
use crate::frames::{
    REFUSED_NOT_ON_ROSTER, SessionMessage, data_body, frame_type, handshake_init_body, handshake_resp_body,
    init_payload, parse_data, parse_handshake_init, parse_handshake_resp, parse_init_payload,
};
use crate::noise::{CipherState, HandshakeOptions, HandshakeState, IK, KeyPair, MAX_MESSAGE as MAX_NOISE, Transport};
use crate::types::{
    CREDIT_BATCH_BYTES, CREDIT_DELAY_MS, FRAGMENT_FRAME_OVERHEAD, INITIAL_CREDIT, MAX_MESSAGE, MAX_PLAINTEXT,
    PACE_FLOOR_BYTES, PACE_MIN_FRAGMENT, paced_fragment,
};

/// At most this many sessions with one peer live at once.
pub(crate) const MAX_SESSIONS_PER_PEER: usize = 8;
/// At most this many whole messages from one peer wait for the application.
pub(crate) const PEER_HELD_MESSAGES: u64 = 65536;

pub fn session_prologue(network: &str) -> Vec<u8> {
    format!("frontier-link/1/session{network}").into_bytes()
}

/// A session message this node originates other than `message` and `credit`.
#[derive(Clone, Debug)]
pub(crate) enum Ctl {
    RosterRequest,
    /// The roster's JCS and its version.
    Roster(String, u64),
    Resign(String),
}

impl Ctl {
    fn message(&self) -> SessionMessage<'_> {
        match self {
            Ctl::RosterRequest => SessionMessage::RosterRequest,
            Ctl::Roster(json, _) => SessionMessage::Roster(json),
            Ctl::Resign(json) => SessionMessage::Resign(json),
        }
    }
}

/// What to do when a control message cannot be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailAction {
    Ignore,
    /// Ask the primary for its roster instead (a peer that showed a newer roster but cannot be
    /// reached).
    AskPrimary,
    /// A roster the primary pushed: tried again later, with backoff, until it goes.
    RetryRoster,
}

type Done = oneshot::Sender<Result<(), LinkError>>;

fn reply(done: Option<Done>, r: Result<(), LinkError>) {
    if let Some(d) = done {
        // The caller may have gone away; nothing to do then.
        let _ = d.send(r);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CoreStats {
    pub credits_sent: u64,
    pub messages_received: u64,
    pub inflight_max_bytes: u64,
    pub socket_backlog_max_bytes: usize,
    pub control_backlog_max_bytes: usize,
}

pub(crate) struct Session {
    peer: String,
    local_index: u32,
    remote_index: u32,
    initiator: bool,
    send: CipherState,
    recv: CipherState,
    created_at: u64,
    last_activity: u64,
    sent: u64,
    received: u64,
    retired: bool,
    /// Outbound messages bound to this session (0 or 1: messages to a peer go one at a time).
    active_sends: u32,
    /// Message bytes this side may still send.
    send_credit: u64,
    /// Message bytes sent and not yet credited back.
    inflight: u64,
    /// Credit applied to `inflight`, in one-second buckets: the receiver's take rate.
    rate_at: u64,
    rate_cur: u64,
    rate_prev: u64,
    credit_due: Option<u64>,
    // Receive side.
    /// Message bytes the peer may still send under the credit this side gave it.
    recv_allowance: u64,
    partial: Vec<u8>,
    partial_credited: u64,
    /// Complete messages handed to the application and not yet taken.
    held: u64,
    owed: u64,
}

struct PendingInit {
    local_index: u32,
    hs: HandshakeState,
    deadline: u64,
    waiters: Vec<Waiter>,
}

enum Waiter {
    /// The peer's oldest outbound message waits for this handshake.
    SendHead,
    Control {
        ctl: Ctl,
        done: Option<Done>,
        on_fail: FailAction,
    },
}

struct OutMsg {
    token: u64,
    bytes: Bytes,
    off: usize,
    session: Option<u64>,
    done: Option<Done>,
}

#[derive(Default)]
struct PeerState {
    current: Option<u64>,
    sessions: Vec<u64>,
    pending: Option<PendingInit>,
    /// Outbound messages, oldest first; only the head is ever bound to a session.
    queue: VecDeque<OutMsg>,
    held_bytes: u64,
    held_count: u64,
    /// The last roster queued to this peer: its version, the connection, and the queue position
    /// just after it. While that position is unwritten, no roster as old is queued again.
    roster_queued: Option<(u64, u64, u64)>,
    /// When this side last answered the peer's roster-request, and a deferred answer.
    roster_answered_at: Option<u64>,
    roster_answer_due: Option<u64>,
    /// Handshake-inits this peer may still have processed, inits in its name that may still fail,
    /// and resets it may still be sent.
    inits: Bucket,
    failures: Bucket,
    resets: Bucket,
}

/// The budgets of an id off the roster (a member this node does not know of yet, or an id a
/// relay forged), kept in a bounded table.
#[derive(Clone, Copy, Debug, Default)]
struct Stranger {
    inits: Bucket,
    resets: Bucket,
    used: u64,
}

/// A token bucket in milli-tokens: `rate` tokens a second, at most `burst` at once.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Bucket {
    spent: u64,
    at: u64,
}

impl Bucket {
    /// Takes one token if there is one.
    pub(crate) fn take(&mut self, now: u64, rate: u64, burst: u64) -> bool {
        if !self.has(now, rate, burst) {
            return false;
        }
        self.spent += 1000;
        true
    }

    /// Whether a token is there, without taking it.
    pub(crate) fn has(&mut self, now: u64, rate: u64, burst: u64) -> bool {
        let elapsed = now.saturating_sub(self.at);
        self.at = self.at.max(now);
        self.spent = self.spent.saturating_sub(elapsed.saturating_mul(rate));
        self.spent + 1000 <= burst * 1000
    }
}

/// A peer's roster-requests are answered at most once per this long; repeats within it are
/// coalesced into one answer at its end. The roster is the largest thing a member sends on
/// demand (up to 65000 bytes for a 41-byte request).
pub(crate) const ROSTER_ANSWER_INTERVAL_MS: u64 = 250;
/// A `reset` for the same peer and index is sent at most once per this long...
pub(crate) const RESET_REPEAT_MS: u64 = 1000;
/// ...and to one peer at most this many a second, this many at once. Each peer has its own
/// budget, so a peer flooding bad indices spends only its own.
pub(crate) const RESET_RATE: u64 = 32;
pub(crate) const RESET_BURST: u64 = 64;
/// Handshake-inits processed per roster member: this many a second, this many at once (each
/// costs two X25519 operations and a key pair before anything is known of the sender)...
pub(crate) const INIT_RATE: u64 = 16;
pub(crate) const INIT_BURST: u64 = 32;
/// ...per id off the roster...
pub(crate) const STRANGER_INIT_RATE: u64 = 4;
pub(crate) const STRANGER_INIT_BURST: u64 = 8;
/// ...and from all ids off the roster together, a ceiling only a relay forging ids can reach
/// (a member always arrives under its own id).
pub(crate) const STRANGERS_INIT_RATE: u64 = 128;
pub(crate) const STRANGERS_INIT_BURST: u64 = 256;
/// Handshake-inits named as from a roster member that fail (a key that is not the member's, or a
/// message that does not read), per member id: while that id's budget is spent, its inits are
/// dropped before any DH work. Whoever sends them (the member itself, or a relay naming it)
/// starves only that id, never another member.
pub(crate) const MEMBER_FAILURE_RATE: u64 = 2;
pub(crate) const MEMBER_FAILURE_BURST: u64 = 4;
/// Resets to ids off the roster, all of them together (each id has its own budget besides).
pub(crate) const STRANGERS_RESET_RATE: u64 = 128;
pub(crate) const STRANGERS_RESET_BURST: u64 = 256;
/// Ids off the roster whose budgets are kept; past it, the least recently used is forgotten.
pub(crate) const STRANGERS: usize = 256;
/// An init from an id off the roster is a hint that a newer roster lists it: the primary is
/// asked for its roster, at most once per this long...
pub(crate) const ROSTER_HINT_INTERVAL_MS: u64 = 1000;
/// ...and after each hint that brought no newer roster, the wait before the next doubles, up to
/// this long. A newer roster puts it back to ROSTER_HINT_INTERVAL_MS.
pub(crate) const ROSTER_HINT_MAX_INTERVAL_MS: u64 = 300_000;
/// The stamp window W: an init stamped further than this ahead of this node's wall clock is
/// refused, and with no stamp kept for a member, one stamped this long before this node started
/// or the member joined its roster is still taken (clocks differ a little).
pub(crate) const STAMP_WINDOW_MS: u64 = 600_000;
/// Stamps kept for ids that left the roster.
pub(crate) const DEPARTED_STAMPS: usize = 1024;
/// The `(peer, index)` pairs remembered for coalescing resets.
const RECENT_RESETS: usize = 1024;

#[derive(Clone, Debug)]
enum Slot {
    Session(u64),
    Pending(String),
}

/// Introspection of one session, for tests and the driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub peer: String,
    pub local_index: u32,
    pub remote_index: u32,
    pub initiator: bool,
    pub current: bool,
    pub sent: u64,
    pub received: u64,
    pub send_credit: u64,
    pub inflight: u64,
}

pub(crate) struct Sessions {
    peers: HashMap<String, PeerState>,
    by_index: HashMap<u32, Slot>,
    sessions: HashMap<u64, Session>,
    next_uid: u64,
    next_token: u64,
    gate: VecDeque<(String, u64)>,
    pumping: bool,
    repump: bool,
    awaiting_drain: bool,
    /// The rate in force from the relay's `shaping` notice (0: none), when the connection's next
    /// fragment may go at its pace (monotonic microseconds), and whether the gate waits for it.
    rate_bps: u64,
    pace_due_us: u64,
    awaiting_pace: bool,
    next_sweep: u64,
    sweep_period: u64,
    closed: bool,
    credit_window: u64,
    /// Per peer: bytes waiting for the application or in reassembly, and whole messages waiting.
    peer_cap: u64,
    held_max: u64,
    /// Resets sent lately, by peer and index, and the bucket all resets draw from.
    recent_resets: HashMap<(String, u32), u64>,
    /// Budgets of ids off the roster, and the ceiling on their handshake-inits together.
    strangers: HashMap<String, Stranger>,
    strangers_inits: Bucket,
    strangers_resets: Bucket,
    /// When the primary was last asked for its roster on a stranger's hint, the roster version
    /// then, and the wait before that ask.
    roster_hint: Option<Hint>,
    /// The stamp of this node's last handshake-init (Unix milliseconds, strictly increasing).
    last_stamp: u64,
    /// Per roster member, the greatest stamp of an init from it that was accepted: an init
    /// stamped no later is a replay. Kept apart from `peers` (whose entries go when idle) and
    /// pruned to the roster, so it is bounded by the roster.
    stamps: HashMap<String, u64>,
    /// The stamps of ids that left the roster, most recent last, at most DEPARTED_STAMPS: an id
    /// re-added gets its stamp back, so inits from before it left stay refused.
    departed: VecDeque<(String, u64)>,
    /// Per roster member, when this node started or the member joined its roster, whichever is
    /// later, on the monotonic clock (so a wall clock set right after the start moves the floor
    /// with it): with no stamp kept, an init must be stamped after this, in wall time, less
    /// STAMP_WINDOW_MS, so inits recorded before then cannot be replayed. Bounded by the roster.
    member_since: HashMap<String, u64>,
    /// A hint came while the wait was running: the primary is asked when it ends (one ask,
    /// however many hints), so a hint is deferred, never lost.
    hint_deferred: bool,
    /// How often the primary has been asked on a hint, and asked at all.
    #[cfg(test)]
    pub(crate) hints: u64,
    #[cfg(test)]
    pub(crate) primary_asks: u64,
    pub(crate) stats: CoreStats,
}

impl Sessions {
    pub(crate) fn new(t: &super::TimingMs, credit_window: u64, now: u64, roster: &crate::roster::Roster) -> Sessions {
        let sweep_period = (t.idle.min(t.rekey_interval).min(t.retire_grace) / 4).max(20);
        Sessions {
            peers: HashMap::new(),
            by_index: HashMap::new(),
            sessions: HashMap::new(),
            next_uid: 1,
            next_token: 1,
            gate: VecDeque::new(),
            pumping: false,
            repump: false,
            awaiting_drain: false,
            rate_bps: 0,
            pace_due_us: 0,
            awaiting_pace: false,
            next_sweep: now.saturating_add(sweep_period),
            sweep_period,
            closed: false,
            credit_window,
            peer_cap: 2 * MAX_MESSAGE as u64 + 4 * credit_window,
            held_max: PEER_HELD_MESSAGES,
            recent_resets: HashMap::new(),
            strangers: HashMap::new(),
            strangers_inits: Bucket::default(),
            strangers_resets: Bucket::default(),
            roster_hint: None,
            last_stamp: 0,
            stamps: HashMap::new(),
            departed: VecDeque::new(),
            member_since: roster.members().iter().map(|m| (m.id().to_owned(), now)).collect(),
            hint_deferred: false,
            #[cfg(test)]
            hints: 0,
            #[cfg(test)]
            primary_asks: 0,
            stats: CoreStats::default(),
        }
    }

    /// The bytes in reassembly from `peer` and the heap they take, over its sessions.
    #[cfg(test)]
    pub(crate) fn reassembly(&self, peer: &str) -> (usize, usize) {
        let Some(ps) = self.peers.get(peer) else {
            return (0, 0);
        };
        ps.sessions
            .iter()
            .filter_map(|u| self.sessions.get(u))
            .fold((0, 0), |(l, c), s| (l + s.partial.len(), c + s.partial.capacity()))
    }

    /// Whether anything is under way with `peer`: a handshake pending, a session, a roster queued
    /// for it, or control messages waiting for a session.
    #[cfg(test)]
    pub(crate) fn engaged(&self, peer: &str) -> bool {
        self.peers.get(peer).is_some_and(|ps| {
            ps.pending.is_some() || !ps.sessions.is_empty() || ps.roster_queued.is_some() || !ps.queue.is_empty()
        })
    }

    /// The stamp kept for `peer`, if any.
    #[cfg(test)]
    pub(crate) fn stamp_of(&self, peer: &str) -> Option<u64> {
        self.stamps.get(peer).copied()
    }

    /// How many departed ids' stamps are kept.
    #[cfg(test)]
    pub(crate) fn departed_len(&self) -> usize {
        self.departed.len()
    }

    /// The members with a stamp kept.
    #[cfg(test)]
    pub(crate) fn stamped(&self) -> Vec<String> {
        self.stamps.keys().cloned().collect()
    }

    /// Lowers the per-peer bounds, so tests can reach them without moving 132 MiB.
    #[cfg(test)]
    pub(crate) fn set_limits(&mut self, peer_cap: u64, held_max: u64) {
        self.peer_cap = peer_cap;
        self.held_max = held_max;
    }

    /// The live sessions with `peer`.
    pub(crate) fn info(&self, peer: &str) -> Vec<SessionInfo> {
        let Some(ps) = self.peers.get(peer) else {
            return Vec::new();
        };
        ps.sessions
            .iter()
            .filter_map(|uid| self.sessions.get(uid).map(|s| (uid, s)))
            .map(|(uid, s)| SessionInfo {
                peer: peer.to_owned(),
                local_index: s.local_index,
                remote_index: s.remote_index,
                initiator: s.initiator,
                current: ps.current == Some(*uid),
                sent: s.sent,
                received: s.received,
                send_credit: s.send_credit,
                inflight: s.inflight,
            })
            .collect()
    }

    /// The live sessions with every peer.
    pub(crate) fn all_info(&self) -> Vec<SessionInfo> {
        self.peers.keys().flat_map(|p| self.info(p)).collect()
    }

    fn peer_buffered(&self, peer: &str) -> u64 {
        let Some(ps) = self.peers.get(peer) else {
            return 0;
        };
        let partial: u64 =
            ps.sessions.iter().filter_map(|u| self.sessions.get(u)).map(|s| s.partial.len() as u64).sum();
        ps.held_bytes + partial
    }
}

// ── Public operations ──

/// Sends one application message, fragmenting and waiting for credit as needed.
pub(crate) fn send(node: &mut Node, peer: &str, bytes: Bytes, done: Done) {
    if node.sessions.closed {
        return reply(Some(done), Err(LinkError::member_closed()));
    }
    if bytes.len() > MAX_MESSAGE {
        return reply(Some(done), Err(LinkError::invalid("message exceeds 64 MiB")));
    }
    if peer == node.id() {
        return reply(Some(done), Err(LinkError::invalid("cannot send to self")));
    }
    if node.roster().member(peer).is_none() {
        return reply(Some(done), Err(LinkError::invalid(format!("{peer} is not on the roster"))));
    }
    let token = node.sessions.next_token;
    node.sessions.next_token += 1;
    let ps = node.sessions.peers.entry(peer.to_owned()).or_default();
    ps.queue.push_back(OutMsg { token, bytes, off: 0, session: None, done: Some(done) });
    if ps.queue.len() == 1 {
        start_head(node, peer);
    }
}

/// Sends a control session message (roster-request, roster, resign).
pub(crate) fn send_control(node: &mut Node, peer: &str, ctl: Ctl, done: Option<Done>, on_fail: FailAction) {
    if node.sessions.closed {
        return reply(done, Err(LinkError::member_closed()));
    }
    match ensure_session(node, peer) {
        Ensure::Ready(uid) => {
            let sent = transmit_ctl(node, uid, &ctl);
            control_done(node, peer, done, on_fail, sent);
        }
        Ensure::Pending => {
            if let Some(p) = node.sessions.peers.get_mut(peer).and_then(|ps| ps.pending.as_mut()) {
                p.waiters.push(Waiter::Control { ctl, done, on_fail });
            }
        }
        Ensure::Failed(e) => fail_control(node, peer, done, on_fail, e),
    }
}

/// A control message was handed to a session (`Ok(true)`), could not be (`Ok(false)`, the
/// connection being gone), or failed.
fn control_done(node: &mut Node, peer: &str, done: Option<Done>, on_fail: FailAction, sent: Result<bool, LinkError>) {
    match sent {
        Ok(true) => {
            reply(done, Ok(()));
            if on_fail == FailAction::RetryRoster {
                super::primary::push_delivered(node, peer);
            }
        }
        // Not handed over: as before, the caller is told it went (the connection is gone, and
        // a send waits for it); a pushed roster is tried again.
        Ok(false) if on_fail == FailAction::RetryRoster => {
            reply(done, Ok(()));
            super::primary::push_failed(node, peer);
        }
        Ok(false) => reply(done, Ok(())),
        Err(e) => fail_control(node, peer, done, on_fail, e),
    }
}

/// Transmits a control message. A roster is not queued to a peer while one at least as new is
/// still unsent to it: the one on its way already says as much.
fn transmit_ctl(node: &mut Node, uid: u64, ctl: &Ctl) -> Result<bool, LinkError> {
    let Ctl::Roster(_, version) = ctl else {
        return transmit(node, uid, &ctl.message());
    };
    let Some(peer) = node.sessions.sessions.get(&uid).map(|s| s.peer.clone()) else {
        return Ok(false);
    };
    let conn = node.conn_id();
    let (_, written) = node.wire_totals();
    let unsent = node
        .sessions
        .peers
        .get(&peer)
        .and_then(|ps| ps.roster_queued)
        .is_some_and(|(v, c, pos)| v >= *version && c == conn && written < pos);
    if unsent {
        return Ok(true);
    }
    let sent = transmit(node, uid, &ctl.message())?;
    if sent {
        let (queued, _) = node.wire_totals();
        if let Some(ps) = node.sessions.peers.get_mut(&peer) {
            ps.roster_queued = Some((*version, conn, queued));
        }
    }
    Ok(sent)
}

/// Hands `peer` this member's roster: at once, or, within ROSTER_ANSWER_INTERVAL_MS of the last
/// roster sent to it this way, once at the end of that interval however often it was asked for.
/// Answers to `roster-request` and rosters handed to a peer seen to be behind both go this way.
pub(crate) fn offer_roster(node: &mut Node, peer: &str) {
    let now = node.now();
    let Some(ps) = node.sessions.peers.get_mut(peer) else {
        return;
    };
    if ps.roster_answer_due.is_some() {
        return;
    }
    if let Some(at) = ps.roster_answered_at
        && now < at.saturating_add(ROSTER_ANSWER_INTERVAL_MS)
    {
        ps.roster_answer_due = Some(at + ROSTER_ANSWER_INTERVAL_MS);
        return;
    }
    ps.roster_answered_at = Some(now);
    send_roster(node, peer);
}

fn send_roster(node: &mut Node, peer: &str) {
    let ctl = Ctl::Roster(node.roster().to_jcs(), node.roster().version());
    // From the primary, a roster answered or offered is a push like any other: once it goes,
    // none is owed; if it fails, it is made again.
    let on_fail = if node.primary.is_some() { FailAction::RetryRoster } else { FailAction::Ignore };
    send_control(node, peer, ctl, None, on_fail);
}

/// The budgets of `peer`, an id off the roster, made if need be; the table is bounded.
fn stranger<'a>(s: &'a mut Sessions, peer: &str, now: u64) -> &'a mut Stranger {
    if !s.strangers.contains_key(peer) && s.strangers.len() >= STRANGERS {
        let oldest = s.strangers.iter().min_by_key(|(_, x)| x.used).map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            s.strangers.remove(&k);
        }
    }
    let st = s.strangers.entry(peer.to_owned()).or_default();
    st.used = now;
    st
}

/// Whether a `reset` may go to `peer` for `index` now: not twice for one peer and index within
/// RESET_REPEAT_MS, and within that peer's own reset budget. A flood of bad indices is answered
/// at a bounded rate, and spends only the flooding peer's budget.
fn reset_allowed(node: &mut Node, peer: &str, index: u32, now: u64) -> bool {
    let member = node.roster().member(peer).is_some();
    let s = &mut node.sessions;
    let key = (peer.to_owned(), index);
    if s.recent_resets.get(&key).is_some_and(|t| now.saturating_sub(*t) < RESET_REPEAT_MS) {
        return false;
    }
    let allowed = if member {
        s.peers.entry(peer.to_owned()).or_default().resets.take(now, RESET_RATE, RESET_BURST)
    } else {
        // An id off the roster is one a relay may have made up: its own budget, and a ceiling
        // on all of them together.
        stranger(s, peer, now).resets.take(now, RESET_RATE, RESET_BURST)
            && s.strangers_resets.take(now, STRANGERS_RESET_RATE, STRANGERS_RESET_BURST)
    };
    if !allowed {
        return false;
    }
    if s.recent_resets.len() >= RECENT_RESETS {
        s.recent_resets.retain(|_, t| now.saturating_sub(*t) < RESET_REPEAT_MS);
        if s.recent_resets.len() >= RECENT_RESETS {
            s.recent_resets.clear();
        }
    }
    s.recent_resets.insert(key, now);
    true
}

/// Whether a handshake-init from `peer` may be processed now (its DH work done): within the
/// peer's own budget, and for an id off the roster within the ceiling on all of them too.
fn init_allowed(node: &mut Node, peer: &str, now: u64) -> bool {
    if node.roster().member(peer).is_some() {
        let ps = node.sessions.peers.entry(peer.to_owned()).or_default();
        return ps.failures.has(now, MEMBER_FAILURE_RATE, MEMBER_FAILURE_BURST)
            && ps.inits.take(now, INIT_RATE, INIT_BURST);
    }
    let s = &mut node.sessions;
    stranger(s, peer, now).inits.take(now, STRANGER_INIT_RATE, STRANGER_INIT_BURST)
        && s.strangers_inits.take(now, STRANGERS_INIT_RATE, STRANGERS_INIT_BURST)
}

/// A handshake-init named as from `peer` failed: charged to that member id's failure budget.
fn member_init_failed(node: &mut Node, peer: &str, now: u64) {
    if node.roster().member(peer).is_some()
        && let Some(ps) = node.sessions.peers.get_mut(peer)
    {
        ps.failures.take(now, MEMBER_FAILURE_RATE, MEMBER_FAILURE_BURST);
    }
}

#[derive(Clone, Copy)]
struct Hint {
    at: u64,
    version: u64,
    wait: u64,
}

/// When the next hint may ask the primary, and the wait that ends then: double the last wait if
/// no newer roster came since the last ask, ROSTER_HINT_INTERVAL_MS if one did.
fn hint_due(node: &Node) -> Option<(u64, u64)> {
    let h = node.sessions.roster_hint?;
    let wait = if node.roster().version() > h.version {
        ROSTER_HINT_INTERVAL_MS
    } else {
        h.wait.saturating_mul(2).min(ROSTER_HINT_MAX_INTERVAL_MS)
    };
    Some((h.at.saturating_add(wait), wait))
}

/// An id off the roster wants a session: perhaps a roster this node has not seen lists it. The
/// primary is asked for its roster, at most once per ROSTER_HINT_INTERVAL_MS, and less often
/// while hints bring nothing: a relay making up ids could otherwise have every member fetch the
/// whole roster from the primary every second.
fn roster_hint(node: &mut Node, now: u64) {
    let wait = match hint_due(node) {
        None => ROSTER_HINT_INTERVAL_MS,
        Some((due, _)) if now < due => {
            node.sessions.hint_deferred = true;
            return;
        }
        Some((_, wait)) => wait,
    };
    node.sessions.hint_deferred = false;
    let version = node.roster().version();
    node.sessions.roster_hint = Some(Hint { at: now, version, wait });
    #[cfg(test)]
    {
        node.sessions.hints += 1;
    }
    node.ask_primary();
}

fn fail_control(node: &mut Node, peer: &str, done: Option<Done>, on_fail: FailAction, e: LinkError) {
    reply(done, Err(e));
    if node.sessions.closed {
        return;
    }
    match on_fail {
        FailAction::AskPrimary => node.ask_primary(),
        FailAction::RetryRoster => super::primary::push_failed(node, peer),
        FailAction::Ignore => {}
    }
}

/// Ends every session with peers no longer on the roster.
pub(crate) fn roster_changed(node: &mut Node) {
    let s = &mut node.sessions;
    let left: Vec<(String, u64)> =
        s.stamps.iter().filter(|(id, _)| node.roster.member(id).is_none()).map(|(id, t)| (id.clone(), *t)).collect();
    for (id, stamp) in left {
        s.stamps.remove(&id);
        s.departed.retain(|(d, _)| *d != id);
        if s.departed.len() >= DEPARTED_STAMPS {
            s.departed.pop_front();
        }
        s.departed.push_back((id, stamp));
    }
    s.member_since.retain(|id, _| node.roster.member(id).is_some());
    let now = node.clock.now_ms();
    for m in node.roster.members() {
        let id = m.id();
        if s.member_since.contains_key(id) {
            continue;
        }
        s.member_since.insert(id.to_owned(), now);
        // Re-added: its stamp from before it left comes back.
        if let Some(at) = s.departed.iter().position(|(d, _)| d == id)
            && let Some((_, stamp)) = s.departed.remove(at)
        {
            s.stamps.insert(id.to_owned(), stamp);
        }
    }
    let gone: Vec<String> =
        node.sessions.peers.keys().filter(|id| node.roster().member(id).is_none()).cloned().collect();
    for id in &gone {
        let err = LinkError::invalid(format!("{id} is no longer on the roster"));
        end_peer(node, id, &err);
    }
    for id in &gone {
        let idle = node.sessions.peers.get(id).is_some_and(|ps| {
            ps.queue.is_empty() && ps.pending.is_none() && ps.sessions.is_empty() && ps.held_count == 0
        });
        if idle {
            node.sessions.peers.remove(id);
        }
    }
}

/// Ends all sessions, e.g. when the relay connection drops.
pub(crate) fn drop_all(node: &mut Node, err: &LinkError) {
    let peers: Vec<String> = node.sessions.peers.keys().cloned().collect();
    for p in peers {
        end_peer(node, &p, err);
    }
}

fn end_peer(node: &mut Node, peer: &str, err: &LinkError) {
    fail_pending(node, peer, err);
    let uids: Vec<u64> = node.sessions.peers.get(peer).map(|ps| ps.sessions.clone()).unwrap_or_default();
    for uid in uids {
        end_session(node, uid, err);
    }
}

pub(crate) fn close(node: &mut Node) {
    if node.sessions.closed {
        return;
    }
    node.sessions.closed = true;
    drop_all(node, &LinkError::member_closed());
}

// ── Frames from the relay ──

pub(crate) fn handle_frame(node: &mut Node, kind: u8, body: &[u8], from: &str) {
    if node.sessions.closed {
        return;
    }
    // A malformed frame is dropped; it never takes the member down.
    match kind {
        frame_type::HANDSHAKE_INIT => on_init(node, from, body),
        frame_type::HANDSHAKE_RESP => on_resp(node, from, body),
        frame_type::DATA | frame_type::CONTROL => on_data(node, from, body),
        frame_type::UNREACHABLE => on_unreachable(node, from),
        frame_type::REFUSED => on_refused(node, from, body.first().copied().unwrap_or(0)),
        frame_type::RESET => {
            if let Some(index) = read_u32be(body, 0) {
                on_reset(node, from, index);
            }
        }
        _ => {}
    }
}

fn my_keypair(node: &Node) -> KeyPair {
    KeyPair::from_private(node.identity.x25519_private_ref())
}

fn on_init(node: &mut Node, from: &str, body: &[u8]) {
    let Some((sender_index, noise)) = parse_handshake_init(body) else {
        return;
    };
    if sender_index == 0 {
        return;
    }
    let now = node.now();
    if !init_allowed(node, from, now) {
        if node.roster().member(from).is_none() {
            roster_hint(node, now);
        }
        return;
    }
    let prologue = session_prologue(node.network());
    let Ok(mut hs) = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: false,
        prologue: &prologue,
        s: Some(my_keypair(node)),
        rs: None,
        fixed_ephemeral: None,
    }) else {
        return;
    };
    let Ok((payload, _)) = hs.read_message(noise) else {
        // Named as a member but unreadable: it cost a DH all the same.
        member_init_failed(node, from, now);
        return;
    };
    let claimed = parse_init_payload(&payload);
    let version = claimed.map(|(v, _)| v);
    let member = node.roster().member(from).is_some();
    let known = match (node.roster().member(from), hs.remote_static()) {
        (Some(m), Some(rs)) => m.x25519() == rs,
        _ => false,
    };
    if !known {
        // Named as a member, but not on that member's key.
        member_init_failed(node, from, now);
        node.send_frame(frame_type::REFUSED, from, &[REFUSED_NOT_ON_ROSTER]);
        // The version a failed init claims says nothing about the member it names: it is ignored,
        // never a roster pushed to that member, asked of it, or asked of the primary (a member
        // sending these to every other could have each fetch the whole roster, N² a second). An
        // id off the roster claiming a newer one may be a newcomer: the primary is asked.
        if !member && version.is_some_and(|v| v > node.roster().version()) {
            roster_hint(node, now);
        }
        return;
    }
    let Some((version, stamp)) = claimed else {
        // On the member's key, but not a 16-byte version and stamp: malformed, a failed init.
        member_init_failed(node, from, now);
        return;
    };
    if stamp <= stamp_floor(node, from) || stamp > node.unix_now().saturating_add(STAMP_WINDOW_MS) {
        // A replay, a stale init, or one stamped too far ahead (kept, it would shut the member
        // out; capped, it could be replayed): dropped unanswered, charged to the member, its
        // version ignored, no session or stamp changed.
        member_init_failed(node, from, now);
        return;
    }
    let local = new_index(node);
    let mine = u64be(node.roster().version());
    let Ok((message, Some(transport))) = hs.write_message(&mine) else {
        return;
    };
    if !node.send_frame(frame_type::HANDSHAKE_RESP, from, &handshake_resp_body(local, sender_index, &message)) {
        return;
    }
    node.sessions.stamps.insert(from.to_owned(), stamp);
    let uid = new_session(node, from, local, sender_index, false, transport);
    adopt(node, uid);
    node.on_peer_version(from, version);
}

fn on_resp(node: &mut Node, from: &str, body: &[u8]) {
    let Some((sender_index, receiver_index, noise)) = parse_handshake_resp(body) else {
        return;
    };
    match node.sessions.by_index.get(&receiver_index) {
        Some(Slot::Pending(p)) if p == from && sender_index != 0 => {}
        _ => return,
    }
    let Some(pending) = node.sessions.peers.get_mut(from).and_then(|ps| ps.pending.as_mut()) else {
        return;
    };
    if pending.local_index != receiver_index {
        return;
    }
    let (payload, transport) = match pending.hs.read_message(noise) {
        Ok((payload, Some(transport))) if payload.len() == 8 => (payload, transport),
        _ => {
            fail_pending(node, from, &LinkError::closed(format!("handshake with {from} failed")));
            return;
        }
    };
    let rs = pending.hs.remote_static().copied();
    // The responder's key must still be on the current roster.
    let known = match (node.roster().member(from), rs) {
        (Some(m), Some(rs)) => *m.x25519() == rs,
        _ => false,
    };
    if !known {
        fail_pending(node, from, &LinkError::invalid(format!("{from} is no longer on the roster")));
        return;
    }
    let Some(p) = node.sessions.peers.get_mut(from).and_then(|ps| ps.pending.take()) else {
        return;
    };
    let uid = new_session(node, from, p.local_index, sender_index, true, transport);
    adopt(node, uid);
    let mut start = false;
    for w in p.waiters {
        match w {
            Waiter::SendHead => start = true,
            Waiter::Control { ctl, done, on_fail } => {
                let sent = transmit_ctl(node, uid, &ctl);
                control_done(node, from, done, on_fail, sent);
            }
        }
    }
    if start {
        start_head(node, from);
    }
    if let Some(v) = read_u64be(&payload, 0) {
        node.on_peer_version(from, v);
    }
}

fn on_data(node: &mut Node, from: &str, body: &[u8]) {
    let Some((receiver_index, ciphertext)) = parse_data(body) else {
        return;
    };
    let now = node.now();
    let slot = node.sessions.by_index.get(&receiver_index).cloned();
    let valid = match &slot {
        Some(Slot::Session(uid)) => node
            .sessions
            .sessions
            .get(uid)
            .filter(|s| s.peer == from && !(expired(&node.timing, s, now) && !crossing(s)))
            .map(|_| *uid),
        _ => None,
    };
    let Some(uid) = valid else {
        // Section 7.2: a receiver index this side does not hold (or a responder session past
        // its lifetime, unless a message is still crossing it) is answered with reset.
        if let Some(Slot::Session(uid)) = slot
            && node.sessions.sessions.get(&uid).is_some_and(|s| s.peer == from)
        {
            end_session(node, uid, &LinkError::closed(format!("session with {from} expired")));
        }
        if reset_allowed(node, from, receiver_index, now) {
            node.send_frame(frame_type::RESET, from, &u32be(receiver_index));
        }
        return;
    };
    let plaintext = match node.sessions.sessions.get_mut(&uid) {
        // A Noise message is at most 65535 bytes (section 7.2); a longer one is malformed.
        Some(s) if ciphertext.len() <= MAX_NOISE => s.recv.decrypt_with_ad(&[], ciphertext).ok(),
        _ => None,
    };
    let Some(plaintext) = plaintext else {
        // Frames for one pair arrive in order, so a frame that fails ends the session.
        end_session(node, uid, &LinkError::closed(format!("session with {from} lost a frame")));
        return;
    };
    if let Some(s) = node.sessions.sessions.get_mut(&uid) {
        s.received += 1;
        s.last_activity = now;
    }
    match SessionMessage::decode(&plaintext) {
        Err(_) => {
            end_session(node, uid, &LinkError::closed(format!("session with {from} carried a malformed message")));
            return;
        }
        Ok(SessionMessage::Message { more, bytes }) => on_fragment(node, uid, more, bytes),
        Ok(SessionMessage::Credit(n)) => on_credit(node, uid, n),
        Ok(SessionMessage::RosterRequest) => node.on_session_control(from, SessionControl::RosterRequest),
        Ok(SessionMessage::Roster(json)) => node.on_session_control(from, SessionControl::Roster(json.to_owned())),
        Ok(SessionMessage::Resign(json)) => node.on_session_control(from, SessionControl::Resign(json.to_owned())),
    }
    maybe_rekey(node, uid);
}

fn on_credit(node: &mut Node, uid: u64, n: u32) {
    let now = node.now();
    let Some(s) = node.sessions.sessions.get_mut(&uid) else {
        return;
    };
    let n = u64::from(n);
    s.send_credit = s.send_credit.saturating_add(n);
    let took = s.inflight.min(n);
    s.inflight -= took;
    roll_rate(s, now);
    s.rate_cur = s.rate_cur.saturating_add(took);
    pump(node);
}

fn on_fragment(node: &mut Node, uid: u64, more: bool, bytes: &[u8]) {
    let cap = node.sessions.peer_cap;
    let Some(s) = node.sessions.sessions.get(&uid) else {
        return;
    };
    let peer = s.peer.clone();
    let len = bytes.len() as u64;
    // A fragment saying more follow carries at least one byte (spec section 7.3).
    if more && bytes.is_empty() {
        end_session(node, uid, &LinkError::closed(format!("{peer} sent an empty fragment saying more follow")));
        return;
    }
    if len > s.recv_allowance {
        end_session(node, uid, &LinkError::closed(format!("{peer} sent message bytes beyond its credit")));
        return;
    }
    if s.partial.len() as u64 + len > MAX_MESSAGE as u64 {
        end_session(node, uid, &LinkError::closed(format!("{peer} sent a message over 64 MiB")));
        return;
    }
    if node.sessions.peer_buffered(&peer) + len > cap {
        end_session(node, uid, &LinkError::closed(format!("{peer} has more waiting than this member holds")));
        return;
    }
    let held_count = node.sessions.peers.get(&peer).map_or(0, |ps| ps.held_count);
    if !more && held_count >= node.sessions.held_max {
        end_session(node, uid, &LinkError::closed(format!("{peer} has too many messages waiting")));
        return;
    }
    let Some(s) = node.sessions.sessions.get_mut(&uid) else {
        return;
    };
    s.recv_allowance -= len;
    s.partial.extend_from_slice(bytes);
    if more {
        // Fragments of a message in progress are taken at once while the application keeps
        // up, so a message larger than the window can finish.
        if s.held == 0 {
            s.owed += len;
            s.partial_credited += len;
            flush_credit(node, uid, false);
        }
        return;
    }
    let whole = Bytes::from(std::mem::take(&mut s.partial));
    let uncredited = whole.len() as u64 - s.partial_credited;
    s.partial_credited = 0;
    s.held += 1;
    node.sessions.stats.messages_received += 1;
    if let Some(ps) = node.sessions.peers.get_mut(&peer) {
        ps.held_bytes += whole.len() as u64;
        ps.held_count += 1;
    }
    node.deliver(&peer, whole, uid, uncredited);
}

/// The application took a message: credit it back to its sender.
pub(crate) fn release(node: &mut Node, from: &str, len: u64, uid: u64, uncredited: u64) {
    if let Some(ps) = node.sessions.peers.get_mut(from) {
        ps.held_bytes = ps.held_bytes.saturating_sub(len);
        ps.held_count = ps.held_count.saturating_sub(1);
    }
    let Some(s) = node.sessions.sessions.get_mut(&uid) else {
        return;
    };
    s.held = s.held.saturating_sub(1);
    s.owed += uncredited;
    let partial = s.partial.len() as u64;
    if s.held == 0 && partial > s.partial_credited {
        s.owed += partial - s.partial_credited;
        s.partial_credited = partial;
    }
    flush_credit(node, uid, false);
}

/// Returns owed credit in batches: at once from CREDIT_BATCH_BYTES, else CREDIT_DELAY_MS after
/// it began to be owed.
fn flush_credit(node: &mut Node, uid: u64, now_flag: bool) {
    let now = node.now();
    let Some(s) = node.sessions.sessions.get_mut(&uid) else {
        return;
    };
    if s.owed == 0 {
        return;
    }
    if !now_flag && s.owed < CREDIT_BATCH_BYTES {
        if s.credit_due.is_none() {
            s.credit_due = Some(now + CREDIT_DELAY_MS);
        }
        return;
    }
    s.credit_due = None;
    loop {
        let Some(s) = node.sessions.sessions.get_mut(&uid) else {
            return;
        };
        if s.owed == 0 {
            return;
        }
        let n = s.owed.min(u64::from(u32::MAX));
        s.owed -= n;
        node.sessions.stats.credits_sent += 1;
        // `n` fits a u32 by the line above.
        match transmit(node, uid, &SessionMessage::Credit(n as u32)) {
            Ok(true) => {
                if let Some(s) = node.sessions.sessions.get_mut(&uid) {
                    s.recv_allowance = s.recv_allowance.saturating_add(n);
                }
            }
            _ => return,
        }
    }
}

fn on_unreachable(node: &mut Node, peer: &str) {
    if node.sessions.peers.contains_key(peer) {
        end_peer(node, peer, &LinkError::unreachable(peer));
    }
}

/// The peer holds no session for `index` (our remote index): drop ours; the next send
/// handshakes again.
fn on_reset(node: &mut Node, peer: &str, index: u32) {
    let Some(ps) = node.sessions.peers.get(peer) else {
        return;
    };
    let hit: Vec<u64> = ps
        .sessions
        .iter()
        .copied()
        .filter(|u| node.sessions.sessions.get(u).is_some_and(|s| s.remote_index == index))
        .collect();
    for uid in hit {
        end_session(node, uid, &LinkError::closed(format!("{peer} reset the session")));
    }
}

fn on_refused(node: &mut Node, peer: &str, reason: u8) {
    if node.sessions.peers.contains_key(peer) {
        end_peer(node, peer, &LinkError::refused(peer, reason));
    }
}

// ── Session lifecycle ──

fn new_index(node: &Node) -> u32 {
    loop {
        let i = u32::from_be_bytes(crate::crypto::random_array::<4>());
        if i != 0 && !node.sessions.by_index.contains_key(&i) {
            return i;
        }
    }
}

fn new_session(node: &mut Node, peer: &str, local: u32, remote: u32, initiator: bool, t: Transport) -> u64 {
    let now = node.now();
    let uid = node.sessions.next_uid;
    node.sessions.next_uid += 1;
    node.sessions.sessions.insert(
        uid,
        Session {
            peer: peer.to_owned(),
            local_index: local,
            remote_index: remote,
            initiator,
            send: t.send,
            recv: t.recv,
            created_at: now,
            last_activity: now,
            sent: 0,
            received: 0,
            retired: false,
            active_sends: 0,
            send_credit: INITIAL_CREDIT,
            inflight: 0,
            rate_at: now,
            rate_cur: 0,
            rate_prev: 0,
            credit_due: None,
            recv_allowance: INITIAL_CREDIT,
            partial: Vec::new(),
            partial_credited: 0,
            held: 0,
            owed: 0,
        },
    );
    uid
}

/// Makes a newly established session the one new messages use.
fn adopt(node: &mut Node, uid: u64) {
    let now = node.now();
    let Some(s) = node.sessions.sessions.get_mut(&uid) else {
        return;
    };
    let peer = s.peer.clone();
    let local = s.local_index;
    // A window beyond the initial 1 MiB is granted as extra credit at once.
    let extra = node.sessions.credit_window.saturating_sub(INITIAL_CREDIT);
    if extra > 0 {
        s.owed += extra;
    }
    node.sessions.by_index.insert(local, Slot::Session(uid));
    let ps = node.sessions.peers.entry(peer.clone()).or_default();
    ps.sessions.push(uid);
    let prev = ps.current.replace(uid);
    if extra > 0 {
        flush_credit(node, uid, false);
    }
    if let Some(prev) = prev.filter(|p| *p != uid)
        && let Some(p) = node.sessions.sessions.get_mut(&prev)
    {
        p.retired = true;
        p.last_activity = p.last_activity.max(now);
    }
    // Bounded: the oldest sessions that are not current go first.
    loop {
        let Some(ps) = node.sessions.peers.get(&peer) else {
            return;
        };
        if ps.sessions.len() <= MAX_SESSIONS_PER_PEER {
            return;
        }
        let Some(oldest) = ps.sessions.iter().copied().find(|u| Some(*u) != ps.current) else {
            return;
        };
        end_session(node, oldest, &LinkError::closed(format!("too many sessions with {peer}")));
    }
}

enum Ensure {
    Ready(u64),
    /// A handshake is pending; the caller joins its waiters.
    Pending,
    Failed(LinkError),
}

fn ensure_session(node: &mut Node, peer: &str) -> Ensure {
    let now = node.now();
    let t = node.timing;
    let cur = node.sessions.peers.get(peer).and_then(|ps| ps.current);
    if let Some(uid) = cur {
        let Some(s) = node.sessions.sessions.get_mut(&uid) else {
            return initiate_ensure(node, peer);
        };
        if expired(&t, s, now) {
            // Expiry yields to a message in flight (section 7.2): one still crossing finishes
            // on the old session, which is retired; this send takes a new one.
            if crossing(s) {
                s.retired = true;
            } else {
                end_session(node, uid, &LinkError::closed(format!("session with {peer} expired")));
            }
            return initiate_ensure(node, peer);
        }
        maybe_rekey(node, uid);
        return Ensure::Ready(uid);
    }
    initiate_ensure(node, peer)
}

fn initiate_ensure(node: &mut Node, peer: &str) -> Ensure {
    match initiate(node, peer) {
        Ok(()) => Ensure::Pending,
        Err(e) => Ensure::Failed(e),
    }
}

fn initiate(node: &mut Node, peer: &str) -> Result<(), LinkError> {
    // A send queued before close() runs after it: it must not start a handshake.
    if node.sessions.closed {
        return Err(LinkError::member_closed());
    }
    if node.sessions.peers.get(peer).is_some_and(|ps| ps.pending.is_some()) {
        return Ok(());
    }
    let Some(member) = node.roster().member(peer) else {
        return Err(LinkError::invalid(format!("{peer} is not on the roster")));
    };
    let rs = *member.x25519();
    let prologue = session_prologue(node.network());
    let mut hs = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: true,
        prologue: &prologue,
        s: Some(my_keypair(node)),
        rs: Some(rs),
        fixed_ephemeral: None,
    })
    .map_err(|e| LinkError::closed(format!("handshake with {peer} failed: {e}")))?;
    // Wall clock, not monotonic: the stamp must keep increasing across restarts.
    let stamp = next_stamp(node.unix_now(), node.sessions.last_stamp);
    node.sessions.last_stamp = stamp;
    let (message, _) = hs
        .write_message(&init_payload(node.roster().version(), stamp))
        .map_err(|e| LinkError::closed(format!("handshake with {peer} failed: {e}")))?;
    let local = new_index(node);
    let deadline = node.now().saturating_add(node.timing.handshake_timeout);
    node.sessions.by_index.insert(local, Slot::Pending(peer.to_owned()));
    let ps = node.sessions.peers.entry(peer.to_owned()).or_default();
    ps.pending = Some(PendingInit { local_index: local, hs, deadline, waiters: Vec::new() });
    if !node.send_frame(frame_type::HANDSHAKE_INIT, peer, &handshake_init_body(local, &message)) {
        let err = LinkError::closed("not connected to the relay");
        fail_pending(node, peer, &err);
        return Err(err);
    }
    Ok(())
}

/// The stamp an init from `peer` must be later than: the last one accepted from it (kept, or
/// restored when it was re-added), and STAMP_WINDOW_MS before this node started or `peer`
/// joined its roster, whichever is later. That moment is kept on the monotonic clock and read in
/// wall time now: `wall_now - (mono_now - since)`. For a member present all along the time floor
/// is below any stamp accepted from it; for one re-added it also refuses inits recorded, and
/// never delivered, before it left.
fn stamp_floor(node: &Node, peer: &str) -> u64 {
    let s = &node.sessions;
    let Some(since) = s.member_since.get(peer) else {
        return u64::MAX;
    };
    let elapsed = node.now().saturating_sub(*since);
    let floor = node.unix_now().saturating_sub(elapsed).saturating_sub(STAMP_WINDOW_MS);
    s.stamps.get(peer).map_or(floor, |last| floor.max(*last))
}

/// A handshake-init's stamp: the wall clock's Unix milliseconds, or one more than the last stamp
/// when the clock has not moved past it.
pub(crate) fn next_stamp(wall_now_ms: u64, last_stamp: u64) -> u64 {
    wall_now_ms.max(last_stamp.saturating_add(1))
}

fn fail_pending(node: &mut Node, peer: &str, err: &LinkError) {
    let Some(p) = node.sessions.peers.get_mut(peer).and_then(|ps| ps.pending.take()) else {
        return;
    };
    node.sessions.by_index.remove(&p.local_index);
    let mut head = false;
    let mut ask = false;
    let mut retry = false;
    for w in p.waiters {
        match w {
            Waiter::SendHead => head = true,
            Waiter::Control { done, on_fail, .. } => {
                reply(done, Err(err.clone()));
                ask |= on_fail == FailAction::AskPrimary;
                retry |= on_fail == FailAction::RetryRoster;
            }
        }
    }
    if head {
        finish_head(node, peer, Err(err.clone()));
        start_head(node, peer);
    }
    if ask && !node.sessions.closed {
        node.ask_primary();
    }
    if retry && !node.sessions.closed {
        super::primary::push_failed(node, peer);
    }
}

fn end_session(node: &mut Node, uid: u64, err: &LinkError) {
    let Some(s) = node.sessions.sessions.remove(&uid) else {
        return;
    };
    if matches!(node.sessions.by_index.get(&s.local_index), Some(Slot::Session(u)) if *u == uid) {
        node.sessions.by_index.remove(&s.local_index);
    }
    let mut head_failed = false;
    if let Some(ps) = node.sessions.peers.get_mut(&s.peer) {
        ps.sessions.retain(|u| *u != uid);
        if ps.current == Some(uid) {
            ps.current = None;
        }
        head_failed = ps.queue.front().is_some_and(|m| m.session == Some(uid));
    }
    // The message bound to this session fails with it.
    if head_failed {
        finish_head(node, &s.peer, Err(err.clone()));
        start_head(node, &s.peer);
    }
    pump(node);
}

/// A responder session older than the rekey interval plus the grace has expired.
fn expired(t: &super::TimingMs, s: &Session, now: u64) -> bool {
    !s.initiator && now.saturating_sub(s.created_at) > t.rekey_interval.saturating_add(t.retire_grace)
}

/// A message is part-way across the session: one being received, or one this side is sending.
fn crossing(s: &Session) -> bool {
    !s.partial.is_empty() || s.active_sends > 0
}

fn maybe_rekey(node: &mut Node, uid: u64) {
    let now = node.now();
    let t = node.timing;
    let Some(s) = node.sessions.sessions.get(&uid) else {
        return;
    };
    if !s.initiator || s.retired {
        return;
    }
    let due = now.saturating_sub(s.created_at) >= t.rekey_interval
        || s.sent >= t.rekey_messages
        || s.received >= t.rekey_messages;
    let peer = s.peer.clone();
    if due && !node.sessions.peers.get(&peer).is_some_and(|ps| ps.pending.is_some()) {
        let _ = initiate(node, &peer);
    }
}

fn sweep(node: &mut Node, now: u64) {
    let t = node.timing;
    let uids: Vec<u64> = node.sessions.sessions.keys().copied().collect();
    for uid in uids {
        let Some(s) = node.sessions.sessions.get(&uid) else {
            continue;
        };
        let quiet = now.saturating_sub(s.last_activity);
        let idle = s.active_sends == 0 && s.partial.is_empty() && s.held == 0;
        let peer = s.peer.clone();
        if quiet >= t.idle {
            end_session(node, uid, &LinkError::closed(format!("session with {peer} went idle")));
        } else if expired(&t, s, now) && idle {
            end_session(node, uid, &LinkError::closed(format!("session with {peer} expired")));
        } else if s.retired && quiet >= t.retire_grace && idle {
            end_session(node, uid, &LinkError::closed(format!("session with {peer} was replaced")));
        } else if s.sent + s.received > 0 {
            // A session that never carried a frame is left to expire, not rekeyed.
            maybe_rekey(node, uid);
        }
    }
}

/// Runs the session timers that are due.
pub(crate) fn poll(node: &mut Node, now: u64) {
    if now >= node.sessions.next_sweep {
        node.sessions.next_sweep = now.saturating_add(node.sessions.sweep_period);
        sweep(node, now);
    }
    let due: Vec<u64> = node
        .sessions
        .sessions
        .iter()
        .filter(|(_, s)| s.credit_due.is_some_and(|t| now >= t))
        .map(|(u, _)| *u)
        .collect();
    for uid in due {
        if let Some(s) = node.sessions.sessions.get_mut(&uid) {
            s.credit_due = None;
        }
        flush_credit(node, uid, true);
    }
    let timed_out: Vec<String> = node
        .sessions
        .peers
        .iter()
        .filter(|(_, ps)| ps.pending.as_ref().is_some_and(|p| now >= p.deadline))
        .map(|(id, _)| id.clone())
        .collect();
    for peer in timed_out {
        fail_pending(node, &peer, &LinkError::timeout(&format!("handshake with {peer}")));
    }
    let answers: Vec<String> = node
        .sessions
        .peers
        .iter()
        .filter(|(_, ps)| ps.roster_answer_due.is_some_and(|t| now >= t))
        .map(|(id, _)| id.clone())
        .collect();
    for peer in answers {
        if let Some(ps) = node.sessions.peers.get_mut(&peer) {
            ps.roster_answer_due = None;
            ps.roster_answered_at = Some(now);
        }
        send_roster(node, &peer);
    }
    if node.sessions.hint_deferred && !node.sessions.closed && hint_due(node).is_none_or(|(due, _)| now >= due) {
        roster_hint(node, now);
    }
    if node.sessions.awaiting_pace && now.saturating_mul(1000) >= node.sessions.pace_due_us {
        node.sessions.awaiting_pace = false;
        pump(node);
    }
    on_drain(node);
}

pub(crate) fn next_deadline(node: &Node) -> Option<u64> {
    let s = &node.sessions;
    let mut d = if s.closed { None } else { Some(s.next_sweep) };
    let mut min = |t: u64| d = Some(d.map_or(t, |x: u64| x.min(t)));
    for sess in s.sessions.values() {
        if let Some(t) = sess.credit_due {
            min(t);
        }
    }
    for ps in s.peers.values() {
        if let Some(p) = &ps.pending {
            min(p.deadline);
        }
        if let Some(t) = ps.roster_answer_due {
            min(t);
        }
    }
    if s.hint_deferred
        && !s.closed
        && let Some((due, _)) = hint_due(node)
    {
        min(due);
    }
    if s.awaiting_pace && !s.closed {
        min(s.pace_due_us.div_ceil(1000));
    }
    d
}

pub(crate) fn on_drain(node: &mut Node) {
    if node.sessions.awaiting_drain && node.writable() {
        node.sessions.awaiting_drain = false;
        pump(node);
    }
}

// ── Sending ──

/// Encrypts and hands over one session message. `Ok(false)` when it could not be handed to the
/// relay; `Err` for a control message too large for one transport message.
fn transmit(node: &mut Node, uid: u64, msg: &SessionMessage<'_>) -> Result<bool, LinkError> {
    let plaintext = msg.encode();
    // Checked before encrypting, so a refused message does not spend a nonce.
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(LinkError::invalid(format!("a session message exceeds {MAX_PLAINTEXT} bytes")));
    }
    let backlog = node.buffered();
    let data = msg.is_message();
    let stats = &mut node.sessions.stats;
    if data {
        stats.socket_backlog_max_bytes = stats.socket_backlog_max_bytes.max(backlog);
    } else {
        stats.control_backlog_max_bytes = stats.control_backlog_max_bytes.max(backlog);
    }
    let now = node.now();
    let Some(s) = node.sessions.sessions.get_mut(&uid) else {
        return Ok(false);
    };
    // Encrypted and handed over in one step: the frame's nonce is its place on the wire.
    let ciphertext = match s.send.encrypt_with_ad(&[], &plaintext) {
        Ok(c) => c,
        Err(_) => {
            end_session(node, uid, &LinkError::closed("session nonces exhausted"));
            return Ok(false);
        }
    };
    s.sent += 1;
    s.last_activity = now;
    let (peer, remote) = (s.peer.clone(), s.remote_index);
    let kind = if data { frame_type::DATA } else { frame_type::CONTROL };
    Ok(node.send_frame(kind, &peer, &data_body(remote, &ciphertext)))
}

/// Starts the peer's oldest outbound message: binds it to a session (handshaking first if
/// needed), or fails it and moves on to the next.
fn start_head(node: &mut Node, peer: &str) {
    loop {
        let Some(ps) = node.sessions.peers.get(peer) else {
            return;
        };
        let Some(head) = ps.queue.front() else {
            return;
        };
        if head.session.is_some() {
            return;
        }
        if ps.pending.as_ref().is_some_and(|p| p.waiters.iter().any(|w| matches!(w, Waiter::SendHead))) {
            return;
        }
        match ensure_session(node, peer) {
            Ensure::Ready(uid) => {
                bind_head(node, peer, uid);
                return;
            }
            Ensure::Pending => {
                if let Some(p) = node.sessions.peers.get_mut(peer).and_then(|ps| ps.pending.as_mut()) {
                    p.waiters.push(Waiter::SendHead);
                }
                return;
            }
            Ensure::Failed(e) => finish_head(node, peer, Err(e)),
        }
    }
}

fn bind_head(node: &mut Node, peer: &str, uid: u64) {
    let Some(head) = node.sessions.peers.get_mut(peer).and_then(|ps| ps.queue.front_mut()) else {
        return;
    };
    if head.session.is_some() {
        return;
    }
    head.session = Some(uid);
    let token = head.token;
    if let Some(s) = node.sessions.sessions.get_mut(&uid) {
        s.active_sends += 1;
    }
    node.sessions.gate.push_back((peer.to_owned(), token));
    pump(node);
}

/// Completes the peer's oldest outbound message.
fn finish_head(node: &mut Node, peer: &str, r: Result<(), LinkError>) {
    let Some(mut m) = node.sessions.peers.get_mut(peer).and_then(|ps| ps.queue.pop_front()) else {
        return;
    };
    if let Some(uid) = m.session {
        if let Some(s) = node.sessions.sessions.get_mut(&uid) {
            s.active_sends = s.active_sends.saturating_sub(1);
        }
        maybe_rekey(node, uid);
    }
    if r.is_ok() {
        node.count_message(peer, m.bytes.len() as u64, true);
    }
    reply(m.done.take(), r);
}

/// Message bytes `s` may have un-credited, its window: about a second and a half of what its
/// receiver takes; while shaped at `rate` bytes a second, about a second of it, and never more
/// than half a second of the rate, so that members sending at once each keep about a second of
/// their share behind their control (section 11).
fn pace(s: &mut Session, now: u64, rate: u64) -> u64 {
    roll_rate(s, now);
    // A second's worth of credit: the larger of the last whole second and the one under way.
    let credited = s.rate_prev.max(s.rate_cur);
    if rate > 0 {
        return paced_fragment(rate).max(credited.min(rate / 2));
    }
    PACE_FLOOR_BYTES.max(credited.saturating_mul(3) / 2)
}

/// The rate the relay shapes the network at (section 9's `shaping`; 0: none). Fragments are
/// paced to it from now on; what was handed over already is the relay's grace to read.
pub(crate) fn set_rate(node: &mut Node, rate_bps: u64) {
    if node.sessions.rate_bps == rate_bps {
        return;
    }
    node.sessions.rate_bps = rate_bps;
    if rate_bps == 0 {
        node.sessions.awaiting_pace = false;
    }
    pump(node);
}

/// Microseconds a frame carrying `n` message bytes takes at 7/8 of `rate`.
fn pace_cost_us(n: u64, rate: u64) -> u64 {
    (n + FRAGMENT_FRAME_OVERHEAD).saturating_mul(8_000_000) / (7 * rate)
}

fn roll_rate(s: &mut Session, now: u64) {
    if now < s.rate_at || now - s.rate_at >= 2000 {
        s.rate_prev = 0;
        s.rate_cur = 0;
        s.rate_at = now;
    } else if now - s.rate_at >= 1000 {
        s.rate_prev = s.rate_cur;
        s.rate_cur = 0;
        s.rate_at += 1000;
    }
}

/// Hands waiting fragments to the socket, oldest first, skipping a session that is out of
/// credit or over its window (its next credit wakes it) so one slow receiver never holds up
/// another. Stops while the socket is backed up, and resumes once it drains; and, while shaped,
/// until the connection's pace allows the next fragment.
fn pump(node: &mut Node) {
    if node.sessions.pumping {
        node.sessions.repump = true;
        return;
    }
    node.sessions.pumping = true;
    loop {
        node.sessions.repump = false;
        let more = pump_pass(node);
        if !more && !node.sessions.repump {
            break;
        }
    }
    node.sessions.pumping = false;
}

/// One pass over the gate. True when it made progress worth another pass.
fn pump_pass(node: &mut Node) -> bool {
    let now = node.now();
    let mut requeue: Vec<(String, u64)> = Vec::new();
    let mut finished: Vec<(String, Result<(), LinkError>)> = Vec::new();
    let mut stopped = false;
    let mut i = 0;
    while let Some((peer, token)) = node.sessions.gate.get(i).cloned() {
        let head = node
            .sessions
            .peers
            .get(&peer)
            .and_then(|ps| ps.queue.front())
            .filter(|m| m.token == token && m.off <= m.bytes.len())
            .and_then(|m| m.session.map(|uid| (uid, m.bytes.is_empty())));
        let Some((uid, empty)) = head else {
            node.sessions.gate.remove(i);
            continue;
        };
        let Some(s) = node.sessions.sessions.get_mut(&uid) else {
            node.sessions.gate.remove(i);
            continue;
        };
        let rate = node.sessions.rate_bps;
        if (!empty && s.send_credit == 0) || s.inflight >= pace(s, now, rate) {
            i += 1;
            continue;
        }
        if !node.writable() {
            node.sessions.awaiting_drain = true;
            stopped = true;
            break;
        }
        if rate > 0 && now.saturating_mul(1000) < node.sessions.pace_due_us {
            node.sessions.awaiting_pace = true;
            stopped = true;
            break;
        }
        node.sessions.gate.remove(i);
        match run_fragment(node, &peer, uid, now) {
            Ok(false) => requeue.push((peer, token)),
            Ok(true) => finished.push((peer, Ok(()))),
            Err(e) => finished.push((peer, Err(e))),
        }
    }
    let progressed = !requeue.is_empty() || !finished.is_empty();
    node.sessions.gate.extend(requeue);
    for (peer, r) in finished {
        finish_head(node, &peer, r);
        start_head(node, &peer);
    }
    !stopped && progressed
}

/// Sends the head message's next fragment. `Ok(true)` once the whole message is handed over.
fn run_fragment(node: &mut Node, peer: &str, uid: u64, now: u64) -> Result<bool, LinkError> {
    let (bytes, off) = match node.sessions.peers.get(peer).and_then(|ps| ps.queue.front()) {
        Some(m) => (m.bytes.clone(), m.off),
        None => return Err(LinkError::closed("the message is gone")),
    };
    let Some(s) = node.sessions.sessions.get_mut(&uid) else {
        return Err(LinkError::closed("the session ended"));
    };
    // Never more than the room left under the window (but not below the smallest fragment), so
    // the socket holds about the window and no more: on a slow link fragments shrink, and control
    // behind them waits a fraction of a second rather than a whole fragment.
    let rate = node.sessions.rate_bps;
    let largest = paced_fragment(rate);
    let room = PACE_MIN_FRAGMENT.min(largest).max(pace(s, now, rate).saturating_sub(s.inflight));
    let remaining = (bytes.len() - off) as u64;
    let n = remaining.min(largest).min(s.send_credit).min(room) as usize;
    let end = off + n;
    let more = end < bytes.len();
    let Some(chunk) = bytes.get(off..end) else {
        return Err(LinkError::closed("the message is gone"));
    };
    if !transmit(node, uid, &SessionMessage::Message { more, bytes: chunk })? {
        return Err(LinkError::closed("not connected to the relay"));
    }
    if rate > 0 {
        let due = node.sessions.pace_due_us.max(now.saturating_mul(1000));
        node.sessions.pace_due_us = due.saturating_add(pace_cost_us(n as u64, rate));
    }
    if let Some(s) = node.sessions.sessions.get_mut(&uid) {
        s.send_credit -= n as u64;
        s.inflight += n as u64;
        node.sessions.stats.inflight_max_bytes = node.sessions.stats.inflight_max_bytes.max(s.inflight);
    }
    if let Some(m) = node.sessions.peers.get_mut(peer).and_then(|ps| ps.queue.front_mut()) {
        m.off = end;
    }
    Ok(!more)
}
