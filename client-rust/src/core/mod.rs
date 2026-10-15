//! The node core: everything a member (or the primary) does, as one synchronous state machine
//! with no I/O and no clock of its own. The async shell (`member.rs`, `socket.rs`) feeds it
//! socket events and the time, and performs the dials it asks for; tests feed it a fake relay
//! and a fake clock. Its structure follows the TypeScript client: `RelayConnection` and
//! `Member` here, `SessionManager` in `sessions.rs`, `Primary` in `primary.rs`.
//!
//! Every byte from the relay or a peer is hostile: frames, control messages and session
//! messages are parsed strictly, every length is checked before it is used, and what a peer can
//! make this node hold is bounded (see `sessions.rs`).

pub(crate) mod primary;
pub(crate) mod sessions;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Notify, broadcast, oneshot, watch};

use crate::bytes::{b64u, from_b64u_array};
use crate::errors::LinkError;
use crate::frames::{FRAME_HEADER, decode_frame, encode_frame, frame_type};
use crate::identity::{Identity, node_id_from_bytes, node_id_to_bytes};
use crate::json::Json;
use crate::roster::{Roster, acceptance_problem};
use crate::signed::{origin_of, register_signing_bytes};
use crate::types::{
    Event, InboundMessage, MAX_CONTROL_BYTES, MemberState, Observed, Observer, PeerTraffic, RelayTraffic, Timing,
    TrafficReport,
};

use self::primary::PrimaryState;
use self::sessions::{Ctl, FailAction, Sessions};

/// Close codes (section 10).
pub mod close_code {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    pub const ABNORMAL: u16 = 1006;
    pub const BAD_REQUEST: u16 = 4000;
    pub const RATE_LIMITED: u16 = 4002;
    pub const REPLACED: u16 = 4005;
    pub const SLOW_PEER: u16 = 4006;
    pub const REGISTRATION_FAILED: u16 = 4007;
    pub const NOT_MEMBER: u16 = 4008;
    pub const MOVED: u16 = 4009;
}

/// Monotonic milliseconds for timers, Unix milliseconds for what is signed or shown.
pub(crate) trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
    fn unix_ms(&self) -> u64;
}

/// One live WebSocket connection, as the core sees it.
pub(crate) trait Wire: Send {
    /// Queues a text message; false once the connection is gone.
    fn send_text(&mut self, text: String) -> bool;
    /// Queues a binary message; false once the connection is gone.
    fn send_binary(&mut self, bytes: Vec<u8>) -> bool;
    /// Bytes queued and not yet written to the network.
    fn buffered(&self) -> usize;
    /// Bytes queued since the connection began.
    fn queued_total(&self) -> u64;
    /// Bytes written to the network since the connection began: a message queued when
    /// `queued_total` was `q` is unsent while this is below `q`.
    fn written_total(&self) -> u64;
    /// The queue passed its bound and refuses everything: the connection must be dropped.
    fn overflowed(&self) -> bool;
    /// Sends a close frame after what is queued. The core forgets the connection at once.
    fn close(&mut self, code: u16, reason: &str);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayState {
    Connecting,
    Registered,
    Disconnected,
    Revoked,
    Replaced,
    Closed,
}

impl RelayState {
    fn member_state(self) -> MemberState {
        match self {
            RelayState::Connecting => MemberState::Connecting,
            RelayState::Registered => MemberState::Connected,
            RelayState::Disconnected => MemberState::Disconnected,
            RelayState::Revoked => MemberState::Revoked,
            RelayState::Replaced => MemberState::Replaced,
            RelayState::Closed => MemberState::Closed,
        }
    }

    fn terminal(self) -> bool {
        matches!(self, RelayState::Revoked | RelayState::Replaced | RelayState::Closed)
    }
}

/// The timers, in milliseconds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TimingMs {
    pub handshake_timeout: u64,
    pub rekey_interval: u64,
    pub rekey_messages: u64,
    pub retire_grace: u64,
    pub idle: u64,
    pub backoff_initial: u64,
    pub backoff_max: u64,
    pub request_timeout: u64,
}

impl From<Timing> for TimingMs {
    fn from(t: Timing) -> TimingMs {
        let ms = |d: std::time::Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        TimingMs {
            handshake_timeout: ms(t.handshake_timeout),
            rekey_interval: ms(t.rekey_interval),
            rekey_messages: t.rekey_messages,
            retire_grace: ms(t.retire_grace),
            idle: ms(t.idle),
            backoff_initial: ms(t.backoff_initial).max(1),
            backoff_max: ms(t.backoff_max).max(1),
            request_timeout: ms(t.request_timeout),
        }
    }
}

/// Where the core's observable effects go. The shell creates these and hands out receivers.
pub(crate) struct Outputs {
    pub events: broadcast::Sender<Event>,
    pub state: watch::Sender<MemberState>,
    /// Counts `roster` session messages received, accepted or not (syncRoster waits on it).
    pub rosters_seen: watch::Sender<u64>,
    /// Woken whenever a message is delivered or the member turns terminal.
    pub inbox: Arc<Notify>,
}

pub(crate) struct NodeConfig {
    pub identity: Identity,
    pub roster: Roster,
    pub pinned_primary: Option<String>,
    pub relay_url: Option<String>,
    pub credit_window: u64,
    pub timing: Timing,
    pub primary: bool,
    pub has_resolver: bool,
    pub clock: Arc<dyn Clock>,
    /// Sees every event and arrival from the start.
    pub observer: Option<Observer>,
}

struct Conn {
    conn_id: u64,
    /// `None` while the dial is in progress.
    wire: Option<Box<dyn Wire>>,
    challenge: Option<[u8; 32]>,
}

/// A message delivered to the inbox and not yet taken.
struct Delivered {
    msg: InboundMessage,
    session: u64,
    uncredited: u64,
}

/// `RelayError` events: at most this many a second, this many at once.
const RELAY_ERROR_RATE: u64 = 16;
const RELAY_ERROR_BURST: u64 = 64;

/// Distinct peers counted separately in `traffic()` before ids off the roster go to `total` only.
const MAX_TRAFFIC_PEERS: usize = 4096;

pub(crate) struct Node {
    pub(crate) identity: Identity,
    roster: Roster,
    pinned_primary: String,
    pub(crate) timing: TimingMs,
    clock: Arc<dyn Clock>,
    out: Outputs,

    // The relay connection (sections 4.1, 10, 11).
    state: RelayState,
    url: String,
    backoff: u64,
    control_feature: bool,
    conn_id: u64,
    conn: Option<Conn>,
    reconnect_at: Option<u64>,
    dial_request: Option<(u64, String)>,
    resolve_request: Option<String>,
    has_resolver: bool,
    text_sent: u64,
    text_received: u64,
    ask_primary_after_register: bool,
    /// The outbound queue overflowed; `poll` drops the connection.
    overflow_pending: bool,
    /// `error` control messages raised as events.
    relay_errors: sessions::Bucket,

    pub(crate) sessions: Sessions,
    primary: Option<PrimaryState>,

    // Delivery.
    inbox: VecDeque<Delivered>,
    observers: Vec<Watcher>,

    // Traffic.
    traffic_since: u64,
    traffic_total: PeerTraffic,
    traffic_peers: BTreeMap<String, PeerTraffic>,
    relay_base: (u64, u64),
}

impl Node {
    pub(crate) fn new(cfg: NodeConfig, out: Outputs) -> Result<Node, LinkError> {
        let roster = cfg.roster;
        if roster.member(cfg.identity.id()).is_none() {
            return Err(LinkError::invalid("this identity is not on the roster"));
        }
        let pinned_primary = cfg.pinned_primary.unwrap_or_else(|| roster.primary_ed25519());
        if pinned_primary != roster.primary_ed25519() {
            return Err(LinkError::invalid("the roster is not signed by the pinned primary"));
        }
        if !(crate::types::INITIAL_CREDIT..=u64::from(u32::MAX)).contains(&cfg.credit_window) {
            return Err(LinkError::invalid("creditWindow must be an integer from 1 MiB to 2^32 - 1"));
        }
        if cfg.primary && cfg.identity.id() != roster.network() {
            return Err(LinkError::invalid("this identity is not the network primary"));
        }
        let url = cfg.relay_url.unwrap_or_else(|| roster.relay().to_owned());
        let timing = TimingMs::from(cfg.timing);
        let now = cfg.clock.now_ms();
        let unix = cfg.clock.unix_ms();
        Ok(Node {
            sessions: Sessions::new(&timing, cfg.credit_window, now, &roster),
            identity: cfg.identity,
            roster,
            pinned_primary,
            timing,
            clock: cfg.clock,
            out,
            state: RelayState::Disconnected,
            url,
            backoff: timing.backoff_initial,
            control_feature: false,
            conn_id: 0,
            conn: None,
            reconnect_at: None,
            dial_request: None,
            resolve_request: None,
            has_resolver: cfg.has_resolver,
            text_sent: 0,
            text_received: 0,
            ask_primary_after_register: false,
            overflow_pending: false,
            relay_errors: sessions::Bucket::default(),
            primary: cfg.primary.then(PrimaryState::default),
            inbox: VecDeque::new(),
            observers: cfg.observer.into_iter().map(Watcher::Call).collect(),
            traffic_since: unix,
            traffic_total: PeerTraffic::default(),
            traffic_peers: BTreeMap::new(),
            relay_base: (0, 0),
        })
    }

    pub(crate) fn now(&self) -> u64 {
        self.clock.now_ms()
    }

    pub(crate) fn unix_now(&self) -> u64 {
        self.clock.unix_ms()
    }

    pub(crate) fn emit(&mut self, e: Event) {
        if !self.observers.is_empty() {
            let o = Observed::Event(e.clone());
            self.observers.retain(|w| w.see(&o));
        }
        // No subscriber is not an error.
        let _ = self.out.events.send(e);
    }

    // ── Accessors ──

    pub(crate) fn roster(&self) -> &Roster {
        &self.roster
    }

    pub(crate) fn network(&self) -> &str {
        self.roster.network()
    }

    pub(crate) fn id(&self) -> &str {
        self.identity.id()
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.state.terminal()
    }

    pub(crate) fn relay_url(&self) -> &str {
        &self.url
    }

    // ── The relay connection ──

    /// Starts connecting, once.
    pub(crate) fn start(&mut self) {
        if self.state == RelayState::Disconnected && self.reconnect_at.is_none() && self.conn.is_none() {
            self.dial();
        }
    }

    /// The dial the shell must perform: `(generation, url)`.
    pub(crate) fn take_dial(&mut self) -> Option<(u64, String)> {
        self.dial_request.take()
    }

    /// The network whose new relay the shell must resolve (close code 4009).
    pub(crate) fn take_resolve(&mut self) -> Option<String> {
        self.resolve_request.take()
    }

    /// The application's answer to a 4009 lookup.
    pub(crate) fn on_resolved(&mut self, url: Option<String>) {
        if let Some(u) = url {
            self.url = u;
        }
        self.schedule();
    }

    fn set_state(&mut self, s: RelayState) {
        if self.state == s {
            return;
        }
        self.state = s;
        if s != RelayState::Registered {
            let err = match s {
                RelayState::Revoked => LinkError::revoked(),
                RelayState::Replaced => LinkError::replaced(),
                RelayState::Closed => LinkError::member_closed(),
                _ => LinkError::closed("relay connection lost"),
            };
            sessions::drop_all(self, &err);
        }
        if s.terminal() {
            sessions::close(self);
        }
        if s != RelayState::Registered {
            primary::on_connection_lost(self);
        }
        let ms = s.member_state();
        self.out.state.send_replace(ms);
        self.emit(Event::State(ms));
        if s.terminal() {
            self.out.inbox.notify_waiters();
        }
    }

    fn dial(&mut self) {
        self.set_state(RelayState::Connecting);
        self.control_feature = false;
        self.conn_id += 1;
        self.conn = Some(Conn { conn_id: self.conn_id, wire: None, challenge: None });
        self.dial_request = Some((self.conn_id, self.url.clone()));
    }

    fn is_current(&self, conn_id: u64) -> bool {
        self.conn.as_ref().is_some_and(|c| c.conn_id == conn_id)
    }

    /// The dial for `conn_id` connected. False when the core no longer wants it (close it).
    pub(crate) fn on_open(&mut self, conn_id: u64, wire: Box<dyn Wire>) -> bool {
        match &mut self.conn {
            Some(c) if c.conn_id == conn_id && c.wire.is_none() => {
                c.wire = Some(wire);
                true
            }
            _ => false,
        }
    }

    /// The connection `conn_id` ended (or never opened: 1006).
    pub(crate) fn on_close(&mut self, conn_id: u64, code: u16, reason: &str) {
        if !self.is_current(conn_id) {
            return;
        }
        self.conn = None;
        self.emit(Event::Disconnect { code, reason: reason.to_owned() });
        self.after_close(code);
    }

    /// Closes the current connection from this side and reports it as the TypeScript client's
    /// channel does: a `disconnect` event with `code` at once.
    fn close_conn(&mut self, code: u16) {
        if let Some(mut c) = self.conn.take() {
            if let Some(w) = c.wire.as_mut() {
                w.close(code, "");
            }
            self.emit(Event::Disconnect { code, reason: String::new() });
            self.after_close(code);
        }
    }

    fn after_close(&mut self, code: u16) {
        if self.state.terminal() {
            return;
        }
        match code {
            close_code::NOT_MEMBER => return self.set_state(RelayState::Revoked),
            // Section 11: a newer copy of this identity holds the connection; stop rather
            // than fight it.
            close_code::REPLACED => return self.set_state(RelayState::Replaced),
            _ => {}
        }
        self.set_state(RelayState::Disconnected);
        if code == close_code::MOVED {
            let network = self.network().to_owned();
            self.emit(Event::Moved { network: network.clone() });
            if self.has_resolver {
                self.resolve_request = Some(network);
                return;
            }
        }
        self.schedule();
    }

    fn schedule(&mut self) {
        if self.state != RelayState::Disconnected {
            return;
        }
        let delay = self.backoff;
        self.backoff = self.backoff.saturating_mul(2).min(self.timing.backoff_max);
        self.reconnect_at = Some(self.now().saturating_add(delay));
    }

    /// Closes the member for good.
    pub(crate) fn close(&mut self) {
        if self.state == RelayState::Closed {
            return;
        }
        self.reconnect_at = None;
        self.resolve_request = None;
        self.set_state(RelayState::Closed);
        self.close_conn(close_code::NORMAL);
    }

    /// Enters the terminal revoked state (also when an accepted roster drops this node).
    pub(crate) fn revoke_self(&mut self) {
        if self.state.terminal() {
            return;
        }
        self.reconnect_at = None;
        self.set_state(RelayState::Revoked);
        self.close_conn(close_code::NORMAL);
    }

    /// Sends a control message once registered; false otherwise.
    pub(crate) fn send_control_text(&mut self, msg: &Json) -> bool {
        if self.state != RelayState::Registered {
            return false;
        }
        self.send_text_now(msg)
    }

    fn send_text_now(&mut self, msg: &Json) -> bool {
        let Ok(text) = msg.to_json_string() else {
            return false;
        };
        if text.len() > MAX_CONTROL_BYTES {
            return false;
        }
        let n = text.len() as u64;
        let Some(w) = self.conn.as_mut().and_then(|c| c.wire.as_mut()) else {
            return false;
        };
        if w.send_text(text) {
            self.text_sent += n;
            true
        } else {
            self.note_overflow();
            false
        }
    }

    /// A send was refused: if the queue overflowed, the connection is dropped at the next poll
    /// (not here, deep inside whatever was sending).
    fn note_overflow(&mut self) {
        if self.conn.as_ref().and_then(|c| c.wire.as_ref()).is_some_and(|w| w.overflowed()) {
            self.overflow_pending = true;
        }
    }

    /// Bytes queued and written on the current connection (`(0, 0)` without one).
    pub(crate) fn wire_totals(&self) -> (u64, u64) {
        self.conn.as_ref().and_then(|c| c.wire.as_ref()).map_or((0, 0), |w| (w.queued_total(), w.written_total()))
    }

    /// The current connection's id, to tell whether a recorded queue position is still its own.
    pub(crate) fn conn_id(&self) -> u64 {
        self.conn.as_ref().map_or(0, |c| c.conn_id)
    }

    /// Hands a binary frame to the relay; only once registered.
    pub(crate) fn send_binary(&mut self, bytes: Vec<u8>) -> bool {
        if self.state != RelayState::Registered {
            return false;
        }
        let sent = self.conn.as_mut().and_then(|c| c.wire.as_mut()).is_some_and(|w| w.send_binary(bytes));
        if !sent {
            self.note_overflow();
        }
        sent
    }

    /// Data may be handed to the socket: little waits in it, or there is no socket (a send
    /// then fails at once).
    pub(crate) fn writable(&self) -> bool {
        match self.conn.as_ref().and_then(|c| c.wire.as_ref()) {
            Some(w) => w.buffered() <= crate::types::SOCKET_LOW_WATER,
            None => true,
        }
    }

    pub(crate) fn buffered(&self) -> usize {
        self.conn.as_ref().and_then(|c| c.wire.as_ref()).map_or(0, |w| w.buffered())
    }

    /// A routed frame to a member. Control (0x08) goes as data (0x03) to a relay without the
    /// `control` feature (section 6). Counted as traffic once handed over.
    pub(crate) fn send_frame(&mut self, kind: u8, peer: &str, body: &[u8]) -> bool {
        let kind = if kind == frame_type::CONTROL && !self.control_feature { frame_type::DATA } else { kind };
        let Some(peer_bytes) = node_id_to_bytes(peer) else {
            return false;
        };
        let Ok(frame) = encode_frame(kind, &peer_bytes, body) else {
            return false;
        };
        if !self.send_binary(frame) {
            return false;
        }
        let size = (FRAME_HEADER + body.len()) as u64;
        self.count_frame(peer, size, true);
        true
    }

    fn count_frame(&mut self, peer: &str, size: u64, sent: bool) {
        let bump = |t: &mut PeerTraffic| {
            let d = if sent { &mut t.sent } else { &mut t.received };
            d.frames += 1;
            d.frame_bytes += size;
        };
        bump(&mut self.traffic_total);
        // Per-peer counts only for roster members, so a relay cannot grow the map at will.
        if let Some(p) = self.peer_traffic(peer) {
            bump(p);
        }
    }

    /// The counts for `peer`. Every id a frame names gets its own, so `total` is the sum over
    /// `peers`; past `MAX_TRAFFIC_PEERS` ids (a roster holds about 400) a new id that is not on
    /// the roster is counted in `total` only, so a relay cannot grow the map without bound.
    fn peer_traffic(&mut self, peer: &str) -> Option<&mut PeerTraffic> {
        if !self.traffic_peers.contains_key(peer)
            && self.traffic_peers.len() >= MAX_TRAFFIC_PEERS
            && self.roster.member(peer).is_none()
        {
            return None;
        }
        Some(self.traffic_peers.entry(peer.to_owned()).or_default())
    }

    pub(crate) fn count_message(&mut self, peer: &str, bytes: u64, sent: bool) {
        let bump = |t: &mut PeerTraffic| {
            let d = if sent { &mut t.sent } else { &mut t.received };
            d.messages += 1;
            d.bytes += bytes;
        };
        bump(&mut self.traffic_total);
        if let Some(p) = self.peer_traffic(peer) {
            bump(p);
        }
    }

    pub(crate) fn on_text(&mut self, conn_id: u64, text: &str) {
        if !self.is_current(conn_id) {
            return;
        }
        self.text_received += text.len() as u64;
        if text.len() > MAX_CONTROL_BYTES {
            return;
        }
        let Ok(msg) = Json::parse(text) else {
            return;
        };
        let Some(kind) = msg.get("type").and_then(Json::as_str) else {
            return;
        };
        let has_challenge = self.conn.as_ref().is_some_and(|c| c.challenge.is_some());
        if kind == "hello" && !has_challenge {
            match self.on_hello(&msg) {
                Ok(()) => {}
                Err(()) => self.close_conn(close_code::BAD_REQUEST),
            }
            return;
        }
        if kind == "registered" && has_challenge && self.state == RelayState::Connecting {
            self.backoff = self.timing.backoff_initial;
            // Section 4.1: the relay returns its newer roster when this member presented an
            // older one; it is applied before anything is sent under it.
            match msg.get("roster") {
                Some(r) => {
                    self.offer_roster(r);
                }
                None => {
                    // A relay that keeps only a compact record of a newer roster says so without
                    // sending it; the primary, or the first up-to-date peer met, hands it over.
                    if msg.get("rosterVersion").and_then(Json::as_safe_uint).is_some_and(|v| v > self.roster.version())
                    {
                        self.ask_primary_after_register = true;
                    }
                }
            }
            if self.state == RelayState::Connecting {
                self.set_state(RelayState::Registered);
            }
            if std::mem::take(&mut self.ask_primary_after_register) && self.state == RelayState::Registered {
                self.ask_primary();
            }
            return;
        }
        if self.state == RelayState::Registered || kind == "error" {
            self.on_control(kind, &msg);
        }
    }

    fn on_hello(&mut self, msg: &Json) -> Result<(), ()> {
        if msg.get("version").and_then(Json::as_safe_uint) != Some(1) {
            return Err(());
        }
        let challenge = msg.get("challenge").and_then(Json::as_str).and_then(from_b64u_array::<32>).ok_or(())?;
        // Names this client does not know are ignored; a missing list is empty.
        self.control_feature = msg
            .get("features")
            .and_then(Json::as_array)
            .is_some_and(|f| f.iter().any(|x| x.as_str() == Some("control")));
        let register = self.register_message(&challenge).ok_or(())?;
        if let Some(c) = self.conn.as_mut() {
            c.challenge = Some(challenge);
        }
        if !self.send_text_now(&register) {
            return Err(());
        }
        Ok(())
    }

    fn register_message(&self, challenge: &[u8; 32]) -> Option<Json> {
        let origin = origin_of(&self.url).ok()?;
        let ts = self.unix_now();
        let network = self.network();
        let node = self.id();
        let sig = self.identity.sign(&register_signing_bytes(network, node, challenge, ts, &origin));
        Some(Json::object([
            ("type", Json::str("register")),
            ("network", Json::str(network)),
            ("node", Json::str(node)),
            ("ed25519", Json::str(b64u(&self.identity.ed25519_public()))),
            ("ts", Json::int(ts)),
            ("sig", Json::str(b64u(&sig))),
            ("roster", self.roster.json().clone()),
        ]))
    }

    fn on_control(&mut self, kind: &str, msg: &Json) {
        if self.primary.is_some() && primary::on_control(self, kind, msg) {
            return;
        }
        // A relay can send errors as fast as it likes: they are raised as events at a bounded rate.
        if kind == "error" && self.relay_errors.take(self.clock.now_ms(), RELAY_ERROR_RATE, RELAY_ERROR_BURST) {
            // Short fields, cut short: a relay's error may be up to 128 KiB of text.
            self.emit(Event::RelayError {
                code: clip(&relay_error_code(msg)),
                message: msg.get("message").and_then(Json::as_str).map(clip),
                id: msg.get("id").and_then(Json::as_str).map(clip),
            });
        }
    }

    pub(crate) fn on_binary(&mut self, conn_id: u64, bytes: &[u8]) {
        if !self.is_current(conn_id) || self.state != RelayState::Registered {
            return;
        }
        let Ok(f) = decode_frame(bytes) else {
            return;
        };
        if f.kind == frame_type::PAIR {
            if self.primary.is_some() {
                primary::on_pair_frame(self, &f.peer, f.body);
            }
            return;
        }
        let from = node_id_from_bytes(&f.peer);
        self.count_frame(&from, bytes.len() as u64, false);
        sessions::handle_frame(self, f.kind, f.body, &from);
    }

    // ── Timers ──

    /// Runs every timer that is due.
    pub(crate) fn poll(&mut self) {
        let now = self.now();
        if std::mem::take(&mut self.overflow_pending) {
            // The outbound queue hit its bound: drop the connection and redial (with backoff).
            self.close_conn(close_code::ABNORMAL);
        }
        if self.reconnect_at.is_some_and(|t| now >= t) {
            self.reconnect_at = None;
            if self.state == RelayState::Disconnected {
                self.dial();
            }
        }
        sessions::poll(self, now);
        if self.primary.is_some() {
            primary::poll(self, now);
        }
    }

    /// The earliest time `poll` has work, if any.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        if self.overflow_pending {
            return Some(self.now());
        }
        let mut d = self.reconnect_at;
        let mut min = |t: Option<u64>| {
            if let Some(t) = t {
                d = Some(d.map_or(t, |x| x.min(t)));
            }
        };
        min(sessions::next_deadline(self));
        min(self.primary.as_ref().and_then(PrimaryState::next_deadline));
        d
    }

    // ── Rosters ──

    /// Applies section 3 acceptance. True when the roster was taken.
    pub(crate) fn offer_roster(&mut self, candidate: &Json) -> bool {
        if acceptance_problem(candidate, &self.pinned_primary, self.roster.version()).is_some() {
            return false;
        }
        match Roster::from_json(candidate.clone()) {
            Ok(r) => {
                self.adopt_roster(r);
                true
            }
            Err(_) => false,
        }
    }

    pub(crate) fn adopt_roster(&mut self, r: Roster) {
        self.roster = r.clone();
        sessions::roster_changed(self);
        let still_member = r.member(self.id()).is_some();
        self.emit(Event::Roster(r));
        if !still_member {
            self.revoke_self();
        }
    }

    /// A session message other than `message` from a peer.
    pub(crate) fn on_session_control(&mut self, from: &str, kind: SessionControl) {
        match kind {
            SessionControl::RosterRequest => sessions::offer_roster(self, from),
            SessionControl::Roster(text) => {
                // A roster that is not JSON is dropped without a word, as in the TypeScript client.
                let Ok(candidate) = Json::parse(&text) else {
                    return;
                };
                self.offer_roster(&candidate);
                self.out.rosters_seen.send_modify(|n| *n += 1);
            }
            SessionControl::Resign(text) => {
                if self.primary.is_some() {
                    primary::on_resign(self, from, &text);
                }
            }
        }
    }

    /// Rosters spread member to member (section 7.1). A peer holding a newer roster is asked for
    /// it; a peer that is behind, and still on this member's roster, is handed this one. A
    /// roster is taken only if the pinned primary signed it, so the peer need not be trusted.
    pub(crate) fn on_peer_version(&mut self, from: &str, version: u64) {
        let mine = self.roster.version();
        if version > mine {
            // The primary is the fallback, for a peer this member cannot open a session to.
            sessions::send_control(self, from, Ctl::RosterRequest, None, FailAction::AskPrimary);
        } else if version < mine && from != self.id() && self.roster.member(from).is_some() {
            // Coalesced with roster-request answers: one roster per peer per interval.
            sessions::offer_roster(self, from);
        } else if version == mine && self.primary.is_some() {
            // The member already holds this roster: no push of it is owed.
            primary::push_delivered(self, from);
        }
    }

    pub(crate) fn ask_primary(&mut self) {
        if self.id() == self.network() {
            return;
        }
        #[cfg(test)]
        {
            self.sessions.primary_asks += 1;
        }
        let primary = self.network().to_owned();
        sessions::send_control(self, &primary, Ctl::RosterRequest, None, FailAction::Ignore);
    }

    // ── Delivery ──

    pub(crate) fn deliver(&mut self, from: &str, bytes: Bytes, session: u64, uncredited: u64) {
        self.count_message(from, bytes.len() as u64, false);
        let msg = InboundMessage { from: from.to_owned(), bytes };
        if !self.observers.is_empty() {
            let o = Observed::Message(msg.clone());
            self.observers.retain(|w| w.see(&o));
        }
        self.inbox.push_back(Delivered { msg, session, uncredited });
        self.out.inbox.notify_waiters();
    }

    /// Takes the oldest waiting message, crediting it back to its sender.
    pub(crate) fn take_message(&mut self) -> Option<InboundMessage> {
        let d = self.inbox.pop_front()?;
        sessions::release(self, &d.msg.from, d.msg.bytes.len() as u64, d.session, d.uncredited);
        Some(d.msg)
    }

    /// Takes the `n` oldest waiting messages, or none when fewer than `n` wait.
    pub(crate) fn take_messages(&mut self, n: usize) -> Option<Vec<InboundMessage>> {
        if self.inbox.len() < n {
            return None;
        }
        Some((0..n).filter_map(|_| self.take_message()).collect())
    }

    pub(crate) fn waiting_messages(&self) -> usize {
        self.inbox.len()
    }

    /// Every event and arrival from now on, in order, without taking anything.
    pub(crate) fn observe(&mut self) -> Observation {
        let queue = Arc::new(ObserveQueue::default());
        self.observers.push(Watcher::Queue(QueueEnd(queue.clone())));
        Observation { queue }
    }

    // ── Traffic ──

    pub(crate) fn traffic(&self) -> TrafficReport {
        TrafficReport {
            since: self.traffic_since,
            total: self.traffic_total,
            relay: RelayTraffic {
                sent: self.text_sent - self.relay_base.0,
                received: self.text_received - self.relay_base.1,
            },
            peers: self.traffic_peers.clone(),
        }
    }

    pub(crate) fn reset_traffic(&mut self) {
        self.traffic_since = self.unix_now();
        self.traffic_total = PeerTraffic::default();
        self.traffic_peers.clear();
        self.relay_base = (self.text_sent, self.text_received);
    }

    // ── Sends ──

    /// One application message; `done` resolves once every fragment is handed to the relay.
    pub(crate) fn send(&mut self, peer: &str, bytes: Bytes, done: oneshot::Sender<Result<(), LinkError>>) {
        sessions::send(self, peer, bytes, done);
    }

    /// A control session message (roster-request, resign) with its completion.
    pub(crate) fn send_control(&mut self, peer: &str, ctl: Ctl, done: oneshot::Sender<Result<(), LinkError>>) {
        sessions::send_control(self, peer, ctl, Some(done), FailAction::Ignore);
    }
}

/// Who sees events and arrivals as they happen.
enum Watcher {
    Call(Observer),
    Queue(QueueEnd),
}

/// What an `observe()` stream holds before it drops its oldest items.
pub(crate) const OBSERVE_CAPACITY: usize = 1024;

impl Watcher {
    /// False once the watcher is gone (an `Observation` that was dropped).
    fn see(&self, o: &Observed) -> bool {
        match self {
            Watcher::Call(f) => {
                f(o);
                true
            }
            Watcher::Queue(q) => q.push(o),
        }
    }
}

#[derive(Default)]
struct ObserveState {
    items: VecDeque<Observed>,
    dropped: u64,
    ended: bool,
}

#[derive(Default)]
pub(crate) struct ObserveQueue {
    state: std::sync::Mutex<ObserveState>,
    ready: Notify,
}

impl ObserveQueue {
    fn lock(&self) -> std::sync::MutexGuard<'_, ObserveState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The member's end of an `observe()` stream: a ring of OBSERVE_CAPACITY items that drops its
/// oldest rather than grow, and ends the stream when the member goes.
pub(crate) struct QueueEnd(Arc<ObserveQueue>);

impl QueueEnd {
    /// False once the `Observation` was dropped.
    fn push(&self, o: &Observed) -> bool {
        if Arc::strong_count(&self.0) < 2 {
            return false;
        }
        {
            let mut st = self.0.lock();
            if st.items.len() >= OBSERVE_CAPACITY {
                st.items.pop_front();
                st.dropped += 1;
            }
            st.items.push_back(o.clone());
        }
        self.0.ready.notify_one();
        true
    }
}

impl Drop for QueueEnd {
    fn drop(&mut self) {
        self.0.lock().ended = true;
        self.0.ready.notify_one();
    }
}

/// Every event and every arriving message of a member, in order, from when it was asked for.
/// It holds at most 1024 items: one that falls further behind drops its oldest, and says how
/// many with an [`Observed::Lagged`] before the next item.
pub struct Observation {
    queue: Arc<ObserveQueue>,
}

impl Observation {
    /// The next item, if one is waiting.
    pub fn try_recv(&mut self) -> Option<Observed> {
        let mut st = self.queue.lock();
        if st.dropped > 0 {
            return Some(Observed::Lagged(std::mem::take(&mut st.dropped)));
        }
        st.items.pop_front()
    }

    /// The next item, waiting for one; `None` once the member is gone and nothing is left.
    pub async fn recv(&mut self) -> Option<Observed> {
        let queue = self.queue.clone();
        loop {
            // Each push stores a wake-up even with nobody waiting, so none is missed.
            let ready = queue.ready.notified();
            if let Some(o) = self.try_recv() {
                return Some(o);
            }
            if self.queue.lock().ended {
                return None;
            }
            ready.await;
        }
    }
}

/// The session messages a member handles beyond `message` and `credit`.
pub(crate) enum SessionControl {
    RosterRequest,
    Roster(String),
    Resign(String),
}

/// The most of a relay error's `code`, `message` or `id` an event carries.
pub(crate) const RELAY_ERROR_TEXT: usize = 1024;

/// `s`, cut to at most RELAY_ERROR_TEXT bytes on a character boundary.
fn clip(s: &str) -> String {
    let mut end = s.len().min(RELAY_ERROR_TEXT);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// The `code` of an `error` control message, as the TypeScript client stringifies it.
fn relay_error_code(msg: &Json) -> String {
    match msg.get("code") {
        Some(Json::String(s)) => s.clone(),
        Some(other) => other.to_json_string().unwrap_or_default(),
        None => "undefined".into(),
    }
}
