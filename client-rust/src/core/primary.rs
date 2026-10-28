//! The primary: the member that holds the network seed and signs the roster with the network
//! key. It opens pairing codes and runs the B side of pairing (section 5), revokes (section 8),
//! accepts resignations (section 7.3), pushes every new roster to the relay and the members, and
//! asks the relay for usage (section 4.3). Being primary is a trait of a member (section 3.1):
//! this state comes and goes on the same member, its connection untouched. The behaviour is the
//! TypeScript client's.

use std::collections::{HashMap, VecDeque};

use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::Node;
use super::sessions::{self, Bucket, Ctl, FailAction};
use crate::bytes::{b64u, from_b64u_array};
use crate::code::{
    DEFAULT_CODE_ID, PairingLink, build_pairing_link, format_code, generate_code, generate_code_id, normalize_code,
};
use crate::errors::{ErrorCode, LinkError};
use crate::frames::{encode_frame, frame_type};
use crate::identity::node_id_from_ed25519;
use crate::json::Json;
use crate::pairing::PrimaryExchange;
use crate::roster::{MAX_ROSTER_BYTES, Roster, RosterMember, UnsignedRoster, sign_roster, signed_size};
use crate::signed::Resignation;
use crate::types::{CODE_ATTEMPTS, Event, PairingCode, PairingFailure, UsageLimits, UsageReport};

/// The relay ends a pairing channel after 60 seconds (section 5.2).
pub(crate) const PAIRING_CHANNEL_MS: u64 = 60_000;
/// A resignation is accepted with `ts` within 5 minutes of the primary's clock.
const RESIGN_SKEW_MS: u64 = 300_000;

struct OpenCode {
    /// The code itself is the secret SPAKE2 proves: wiped when the code goes.
    code: Zeroizing<String>,
    code_id: [u8; 8],
    /// Which opening of `code_id` this is: the default code's id names each default code in
    /// turn, and a channel acts only on the code it was opened for.
    serial: u64,
    /// The same moment on the monotonic clock, which is what is checked: `expires_at` (Unix
    /// milliseconds) is only shown.
    deadline: u64,
    /// Channel setups this code may still have (each is a SPAKE2 setup, and a channel ended
    /// without a failed attempt refunds its slot, so the five attempts do not bound them).
    setups: Bucket,
    failed: u32,
    in_flight: u32,
    claimed: bool,
    burned: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    P1,
    P3,
    P5,
}

struct PairChannel {
    channel: [u8; 16],
    code_id: String,
    /// The `serial` of the code this channel was opened for.
    serial: u64,
    exchange: PrimaryExchange,
    stage: Stage,
    claimed: bool,
    deadline: u64,
}

/// A roster push to a member that failed, to be tried again.
struct Push {
    /// The roster version that failed to go.
    version: u64,
    /// The wait before the latest try, doubling with each failure.
    wait: u64,
    /// When to try again; `None` while a try is under way.
    due: Option<u64>,
}

/// A failed roster push is tried again after this long, doubling with each failure up to
/// PUSH_RETRY_MAX_MS, until it goes, the member leaves the roster, or a newer roster replaces it.
pub(crate) const PUSH_RETRY_MS: u64 = 1000;
pub(crate) const PUSH_RETRY_MAX_MS: u64 = 600_000;

struct UsageRequest {
    done: oneshot::Sender<Result<UsageReport, LinkError>>,
    deadline: u64,
}

#[derive(Default)]
pub(crate) struct PrimaryState {
    codes: HashMap<String, OpenCode>,
    channels: HashMap<String, PairChannel>,
    usage: HashMap<String, UsageRequest>,
    /// Members a roster push failed to reach, bounded by the roster.
    pushes: HashMap<String, Push>,
    /// Ids of codes this primary opened that are closed now (expired, cancelled, burned or
    /// used), newest last, at most CLOSED_CODES: a `pairing` for one is refused with an event.
    /// A `pairing` for an id never opened here (which only a relay can make up) raises none.
    closed_codes: VecDeque<String>,
    /// Whether a default code has been opened: from then on its id counts as issued, and a
    /// `pairing` for it while none is open is refused as for a closed code.
    default_opened: bool,
    /// The `serial` of the next code opened.
    next_serial: u64,
    /// When a refusal event was last raised, by code id and reason (at most one a second).
    refusal_events: HashMap<(String, PairingFailure), u64>,
    /// The `pairEnd` answers to refused `pairing`s for code ids this primary never issued, all
    /// of them together...
    refusal_replies: Bucket,
    /// ...and, apart from that budget, when one was last sent for a code it did issue, by code
    /// and channel: the first refusal on each channel is always answered.
    code_replies: HashMap<(String, String), u64>,
}

/// Closed code ids remembered, so their refusals still say `unknown-code`.
const CLOSED_CODES: usize = 1024;
/// A refusal event for one code and reason is raised at most once per this long.
const REFUSAL_EVENT_MS: u64 = 1000;
/// A `pairEnd` answer to a refused `pairing` for a code this primary issued goes at most once per
/// this long per code, apart from the shared budget, so newcomers with made-up ids cannot use up
/// the answer an honest newcomer with a mistyped or expired code is owed.
const CODE_REPLY_MS: u64 = 1000;
/// `pairEnd` answers to refused `pairing`s for ids never issued: this many a second, this many at
/// once.
const REFUSAL_REPLY_RATE: u64 = 32;
const REFUSAL_REPLY_BURST: u64 = 64;
/// Pairing channels set up per open code: this many a second, this many at once. Beyond it, a
/// `pairing` is refused as for a code out of attempts.
pub(crate) const CHANNEL_SETUP_RATE: u64 = 4;
pub(crate) const CHANNEL_SETUP_BURST: u64 = 8;

impl PrimaryState {
    /// Remembers that the code `id` is closed.
    fn close_code(&mut self, id: &str) {
        self.codes.remove(id);
        if !self.closed_codes.iter().any(|c| c == id) {
            if self.closed_codes.len() >= CLOSED_CODES {
                self.closed_codes.pop_front();
            }
            self.closed_codes.push_back(id.to_owned());
        }
    }

    /// Whether a `pairEnd` answering a refusal for `code_id`, a code this primary issued, may go
    /// now. The table holds only issued codes, so it is bounded as they are.
    /// The first refusal on a channel is answered; repeats on the same code and channel at most
    /// once per CODE_REPLY_MS. So someone holding the code id cannot use up the answer a newcomer
    /// on another channel is owed.
    fn code_reply(&mut self, code_id: &str, channel: &str, now: u64) -> bool {
        let key = (code_id.to_owned(), channel.to_owned());
        if self.code_replies.get(&key).is_some_and(|t| now.saturating_sub(*t) < CODE_REPLY_MS) {
            return false;
        }
        if self.code_replies.len() >= 2 * CLOSED_CODES {
            self.code_replies.retain(|_, t| now.saturating_sub(*t) < CODE_REPLY_MS);
            if self.code_replies.len() >= 2 * CLOSED_CODES {
                self.code_replies.clear();
            }
        }
        self.code_replies.insert(key, now);
        true
    }

    /// Whether a refusal event for `code_id` and `reason` may be raised now.
    fn refusal_event(&mut self, code_id: &str, reason: PairingFailure, now: u64) -> bool {
        let key = (code_id.to_owned(), reason);
        if self.refusal_events.get(&key).is_some_and(|t| now.saturating_sub(*t) < REFUSAL_EVENT_MS) {
            return false;
        }
        if self.refusal_events.len() >= CLOSED_CODES {
            self.refusal_events.retain(|_, t| now.saturating_sub(*t) < REFUSAL_EVENT_MS);
            if self.refusal_events.len() >= CLOSED_CODES {
                return false;
            }
        }
        self.refusal_events.insert(key, now);
        true
    }

    /// The open code a channel was opened for: `None` once it is closed, even while another
    /// code (a newer default code) is open under the same id.
    fn code_of(&mut self, code_id: &str, serial: u64) -> Option<&mut OpenCode> {
        self.codes.get_mut(code_id).filter(|e| e.serial == serial)
    }

    /// Closes the code a channel was opened for, if it is still the one open under its id.
    fn close_code_of(&mut self, code_id: &str, serial: u64) {
        if self.code_of(code_id, serial).is_some() {
            self.close_code(code_id);
        }
    }

    /// Whether `code_id` is a code this primary issued, open or closed.
    fn issued(&self, code_id: &str) -> bool {
        self.codes.contains_key(code_id)
            || (self.default_opened && code_id == DEFAULT_CODE_ID)
            || self.closed_codes.iter().any(|c| c == code_id)
    }

    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.channels
            .values()
            .map(|c| c.deadline)
            .chain(self.usage.values().map(|u| u.deadline))
            .chain(self.pushes.values().filter_map(|p| p.due))
            .min()
    }
}

fn state(node: &mut Node) -> Option<&mut PrimaryState> {
    node.primary.as_mut()
}

fn not_primary() -> LinkError {
    LinkError::invalid("this member is not the network primary")
}

/// This node stops being the primary (section 3.1): its pairing channels end (`pairEnd`, and
/// `Demoted`), its usage asks fail, and its codes and pushes go with the state the
/// caller drops.
pub(crate) fn stop(node: &mut Node) {
    let Some(st) = state(node) else {
        return;
    };
    let keys: Vec<String> = st.channels.keys().cloned().collect();
    let asks: Vec<String> = st.usage.keys().cloned().collect();
    for k in keys {
        end_channel(node, &k, PairingFailure::Demoted, "this node is no longer the primary", true);
    }
    for id in asks {
        usage_finish(node, &id, Err(not_primary()));
    }
}

// ── Pairing codes ──

/// Opens a code that admits one node for `lifetime_ms` (15 minutes by default). The
/// code is random unless `code` gives one (any spelling `normalize_code` accepts). Unless
/// `separate`, it is the default code (section 5.1), and the default code open before it closes,
/// its pairing channels ended; a separate code has a random id of its own.
pub(crate) fn open_pairing_code(
    node: &mut Node,
    lifetime_ms: Option<u64>,
    code: Option<&str>,
    separate: bool,
) -> Result<PairingCode, LinkError> {
    if node.primary.is_none() {
        return Err(not_primary());
    }
    let chosen = match code {
        Some(c) => Some(normalize_code(c).map_err(LinkError::invalid)?),
        None => None,
    };
    // Every entry has the same shape, so a placeholder measures the next roster.
    let mut members = node.roster().members().to_vec();
    members.push(RosterMember::new([0; 32], [0; 32]));
    let room = signed_size(&next_unsigned(node, members));
    if room > MAX_ROSTER_BYTES {
        return Err(LinkError::roster_full(room));
    }
    let now = node.unix_now();
    let mono = node.now();
    let network = node.network().to_owned();
    // A network not placed yet names no relay: the link names the one this primary dials.
    let relay = if node.roster().is_placed() { node.roster().relay().to_owned() } else { node.url.clone() };
    let lifetime = lifetime_ms.unwrap_or(crate::types::CODE_LIFETIME.as_millis() as u64);
    let st = state(node).ok_or_else(not_primary)?;
    let closed: Vec<String> =
        st.codes.iter().filter(|(_, c)| c.burned || c.deadline <= mono).map(|(k, _)| k.clone()).collect();
    for id in closed {
        st.close_code(&id);
    }
    let code = chosen.unwrap_or_else(generate_code);
    let code_id_bytes = if separate { generate_code_id() } else { [0; 8] };
    let code_id = b64u(&code_id_bytes);
    let expires_at = now.saturating_add(lifetime);
    let link = build_pairing_link(&PairingLink { network, code: code.clone(), code_id: code_id.clone(), relay })
        .map_err(LinkError::invalid)?;
    let display = format_code(&code).map_err(LinkError::invalid)?;
    if !separate {
        // The default code before this one admits nobody from now on: a channel opened for it
        // must not go on to claim this one, which has the same id.
        st.default_opened = true;
        withdraw(node, DEFAULT_CODE_ID);
    }
    let st = state(node).ok_or_else(not_primary)?;
    let serial = st.next_serial;
    st.next_serial += 1;
    st.codes.insert(
        code_id.clone(),
        OpenCode {
            code: Zeroizing::new(code),
            code_id: code_id_bytes,
            serial,
            deadline: mono.saturating_add(lifetime),
            setups: Bucket::default(),
            failed: 0,
            in_flight: 0,
            claimed: false,
            burned: false,
        },
    );
    Ok(PairingCode { code: display, code_id, link, expires_at })
}

/// Withdraws an open code: the default code when `code_id` is `DEFAULT_CODE_ID`.
pub(crate) fn cancel_pairing_code(node: &mut Node, code_id: &str) {
    withdraw(node, code_id);
}

/// Closes the code `code_id` before its time (cancelled, or a default code opened after it): it
/// admits nobody from then on, so the pairing channels opened for it end too.
fn withdraw(node: &mut Node, code_id: &str) {
    let Some(st) = state(node) else {
        return;
    };
    if st.codes.contains_key(code_id) {
        st.close_code(code_id);
    }
    let keys: Vec<String> = st.channels.iter().filter(|(_, c)| c.code_id == code_id).map(|(k, _)| k.clone()).collect();
    for k in keys {
        end_channel(node, &k, PairingFailure::UnknownCode, "unknown or expired code", true);
    }
}

// ── Rosters ──

/// The next roster version with `members`, unsigned, the primary unchanged.
fn next_unsigned(node: &Node, members: Vec<RosterMember>) -> UnsignedRoster {
    next_unsigned_naming(node, members, node.roster().primary_id())
}

/// The next roster version with `members` and `primary`, unsigned.
fn next_unsigned_naming(node: &Node, members: Vec<RosterMember>, primary: &str) -> UnsignedRoster {
    let prev = node.roster();
    UnsignedRoster {
        network: prev.network().to_owned(),
        version: prev.version() + 1,
        issued_at: node.unix_now().max(prev.issued_at()),
        relay: prev.relay().to_owned(),
        network_key: *prev.network_key(),
        primary: primary.to_owned(),
        members,
    }
}

/// The next roster version with `members`, signed with the network key. RosterFull over 65000
/// bytes; invalid without the network seed.
pub(crate) fn next_roster(node: &Node, members: Vec<RosterMember>) -> Result<Roster, LinkError> {
    sign_next(node, next_unsigned(node, members))
}

/// The next roster version naming `primary`, the members unchanged, signed with the network key.
pub(crate) fn next_roster_naming(node: &Node, primary: &str) -> Result<Roster, LinkError> {
    sign_next(node, next_unsigned_naming(node, node.roster().members().to_vec(), primary))
}

fn sign_next(node: &Node, unsigned: UnsignedRoster) -> Result<Roster, LinkError> {
    let Some(key) = node.network_key() else {
        return Err(LinkError::invalid("this node does not hold the network seed"));
    };
    let size = signed_size(&unsigned);
    if size > MAX_ROSTER_BYTES {
        return Err(LinkError::roster_full(size));
    }
    sign_roster(&unsigned, key).map_err(LinkError::invalid)
}

/// Adopts a roster this primary signed and pushes it to the relay and every member.
pub(crate) fn publish(node: &mut Node, roster: Roster) {
    publish_except(node, roster, None);
}

/// Publishes `roster`, pushing it to every member but this node and `except` (a newcomer the
/// roster was just sealed for in P6: it holds it, and is not connected yet, so a push would only
/// fail and land later, in the middle of other traffic; spec section 5.3).
fn publish_except(node: &mut Node, roster: Roster, except: Option<&str>) {
    node.adopt_roster(roster.clone());
    node.send_control_text(&Json::object([("type", Json::str("roster")), ("roster", roster.json().clone())]));
    // A newer roster replaces any push still waiting to be tried again.
    if let Some(st) = state(node) {
        st.pushes.clear();
    }
    let me = node.id().to_owned();
    for m in roster.members() {
        if m.id() != me && Some(m.id()) != except {
            push(node, m.id());
        }
    }
}

/// The members a roster push is waiting to be tried again for.
#[cfg(test)]
pub(crate) fn pushes_waiting(node: &mut Node) -> Vec<String> {
    state(node).map(|st| st.pushes.keys().cloned().collect()).unwrap_or_default()
}

/// Publishes `roster` as the primary does after any change.
#[cfg(test)]
pub(crate) fn publish_for_test(node: &mut Node, roster: Roster) {
    publish(node, roster);
}

/// Pushes the current roster to `member`; a failure is tried again (`push_failed`).
fn push(node: &mut Node, member: &str) {
    let roster = node.roster();
    let ctl = Ctl::Roster(roster.to_jcs(), roster.version());
    sessions::send_control(node, member, ctl, None, FailAction::RetryRoster);
}

/// The current roster was handed to a session with `member`.
pub(crate) fn push_delivered(node: &mut Node, member: &str) {
    if let Some(st) = state(node) {
        st.pushes.remove(member);
    }
}

/// A push of the current roster to `member` failed: it is tried again after the next wait in
/// its backoff, unless the member has left the roster.
pub(crate) fn push_failed(node: &mut Node, member: &str) {
    let now = node.now();
    let version = node.roster().version();
    let on_roster = node.roster().member(member).is_some() && member != node.id();
    let Some(st) = state(node) else {
        return;
    };
    if !on_roster {
        st.pushes.remove(member);
        return;
    }
    let p = st.pushes.entry(member.to_owned()).or_insert(Push { version, wait: 0, due: None });
    if p.version != version {
        *p = Push { version, wait: 0, due: None };
    }
    p.wait = if p.wait == 0 { PUSH_RETRY_MS } else { p.wait.saturating_mul(2).min(PUSH_RETRY_MAX_MS) };
    p.due = Some(now.saturating_add(p.wait));
}

/// Pushes whose wait has ended go again; those for a member gone, or a roster since replaced,
/// are dropped.
fn retry_pushes(node: &mut Node, now: u64) {
    let roster = &node.roster;
    let Some(st) = node.primary.as_mut() else {
        return;
    };
    if st.pushes.is_empty() {
        return;
    }
    st.pushes.retain(|id, p| p.version == roster.version() && roster.member(id).is_some());
    let due: Vec<String> =
        st.pushes.iter().filter(|(_, p)| p.due.is_some_and(|t| now >= t)).map(|(k, _)| k.clone()).collect();
    for id in &due {
        if let Some(p) = st.pushes.get_mut(id) {
            p.due = None;
        }
    }
    for id in due {
        push(node, &id);
    }
}

/// Removes a member and publishes the roster. Returns the new roster.
pub(crate) fn revoke(node: &mut Node, id: &str) -> Result<Roster, LinkError> {
    if node.primary.is_none() {
        return Err(not_primary());
    }
    if id == node.id() {
        return Err(LinkError::invalid("the primary cannot revoke itself"));
    }
    if node.roster().member(id).is_none() {
        return Err(LinkError::invalid(format!("{id} is not on the roster")));
    }
    let members = node.roster().members().iter().filter(|m| m.id() != id).cloned().collect();
    let next = next_roster(node, members)?;
    publish(node, next.clone());
    Ok(next)
}

pub(crate) fn on_resign(node: &mut Node, from: &str, json: &str) {
    let Ok(v) = Json::parse(json) else {
        return;
    };
    let Some(r) = Resignation::from_json(&v) else {
        return;
    };
    if r.node != from || node.unix_now().abs_diff(r.ts) > RESIGN_SKEW_MS {
        return;
    }
    let Some(member) = node.roster().member(from).cloned() else {
        return;
    };
    if from == node.roster().primary_id() || !r.verify(node.network(), member.ed25519()) {
        return;
    }
    let members = node.roster().members().iter().filter(|m| m.id() != from).cloned().collect();
    if let Ok(next) = next_roster(node, members) {
        publish(node, next);
    }
}

// ── Usage ──

/// Registers a usage ask with its timeout. The shell sends it once the member is online.
pub(crate) fn usage_begin(node: &mut Node, id: &str, done: oneshot::Sender<Result<UsageReport, LinkError>>) {
    let deadline = node.now().saturating_add(node.timing.request_timeout);
    match state(node) {
        Some(st) => {
            st.usage.insert(id.to_owned(), UsageRequest { done, deadline });
        }
        None => {
            let _ = done.send(Err(not_primary()));
        }
    }
}

/// Sends a registered ask; fails it when the relay connection is not there.
pub(crate) fn usage_send(node: &mut Node, id: &str) {
    let sent = node.send_control_text(&Json::object([("type", Json::str("usage")), ("id", Json::str(id))]));
    if !sent {
        usage_finish(node, id, Err(LinkError::closed("not connected to the relay")));
    }
}

/// Fails a registered ask (the member never came online).
pub(crate) fn usage_finish(node: &mut Node, id: &str, r: Result<UsageReport, LinkError>) {
    if let Some(req) = state(node).and_then(|st| st.usage.remove(id)) {
        let _ = req.done.send(r);
    }
}

fn usage_report(v: Option<&Json>) -> UsageReport {
    let num = |o: Option<&Json>, k: &str| o.and_then(|o| o.get(k)).and_then(Json::as_f64).unwrap_or(0.0);
    let limits = v.and_then(|v| v.get("limits"));
    UsageReport {
        bytes_hour: num(v, "bytesHour"),
        connections: num(v, "connections"),
        limits: UsageLimits {
            rate_bps: num(limits, "rateBps"),
            quota_bytes_hour: num(limits, "quotaBytesHour"),
            trickle_bps: num(limits, "trickleBps"),
        },
        quota_used: num(v, "quotaUsed"),
        slowed: v.and_then(|v| v.get("slowed")).and_then(Json::as_bool).unwrap_or(false),
    }
}

// ── Relay control ──

/// Control messages the primary handles; true when handled.
pub(crate) fn on_control(node: &mut Node, kind: &str, msg: &Json) -> bool {
    match kind {
        "usage" => {
            if let Some(id) = msg.get("id").and_then(Json::as_str) {
                usage_finish(node, id, Ok(usage_report(msg.get("network"))));
            }
            true
        }
        "pairing" => {
            on_pairing(node, msg);
            true
        }
        "pairEnd" => {
            if let Some(ch) = msg.get("channel").and_then(Json::as_str) {
                end_channel(node, ch, PairingFailure::NewcomerLeft, "the newcomer left", false);
            }
            true
        }
        "error" => {
            let id = msg.get("id").and_then(Json::as_str);
            let Some(id) = id.filter(|id| node.primary.as_ref().is_some_and(|st| st.usage.contains_key(*id))) else {
                return false;
            };
            let code = msg.get("code").and_then(Json::as_str).unwrap_or("undefined");
            let err = match code {
                "rate_limited" => LinkError::rate_limited("usage request"),
                "forbidden" => LinkError::new(ErrorCode::Refused, format!("relay answered {code}")),
                _ => LinkError::new(ErrorCode::Invalid, format!("relay answered {code}")),
            };
            let id = id.to_owned();
            usage_finish(node, &id, Err(err));
            true
        }
        _ => false,
    }
}

/// The relay connection is gone: pairing channels end (their slots are refunded) and usage asks
/// fail.
pub(crate) fn on_connection_lost(node: &mut Node) {
    let Some(st) = state(node) else {
        return;
    };
    let keys: Vec<String> = st.channels.keys().cloned().collect();
    let asks: Vec<String> = st.usage.keys().cloned().collect();
    for k in keys {
        end_channel(node, &k, PairingFailure::RelayLost, "the relay connection dropped", false);
    }
    for id in asks {
        usage_finish(node, &id, Err(LinkError::closed("relay connection lost")));
    }
}

pub(crate) fn poll(node: &mut Node, now: u64) {
    let Some(st) = state(node) else {
        return;
    };
    let channels: Vec<String> = st.channels.iter().filter(|(_, c)| now >= c.deadline).map(|(k, _)| k.clone()).collect();
    let asks: Vec<String> = st.usage.iter().filter(|(_, u)| now >= u.deadline).map(|(k, _)| k.clone()).collect();
    for k in channels {
        end_channel(node, &k, PairingFailure::Timeout, "pairing timed out", true);
    }
    for id in asks {
        usage_finish(node, &id, Err(LinkError::timeout("usage request")));
    }
    retry_pushes(node, now);
}

// ── Pairing, B side ──

fn on_pairing(node: &mut Node, msg: &Json) {
    let (Some(key), Some(code_id)) =
        (msg.get("channel").and_then(Json::as_str), msg.get("code").and_then(Json::as_str))
    else {
        return;
    };
    let Some(channel) = from_b64u_array::<16>(key) else {
        return;
    };
    let mono = node.now();
    let deadline = mono.saturating_add(PAIRING_CHANNEL_MS);
    let Some(st) = state(node) else {
        return;
    };
    if st.channels.contains_key(key) {
        return;
    }
    let refusal = match st.codes.get_mut(code_id) {
        None => Some((PairingFailure::UnknownCode, "unknown or expired code")),
        Some(e) if e.burned || e.deadline <= mono => Some((PairingFailure::UnknownCode, "unknown or expired code")),
        Some(e) if e.claimed => Some((PairingFailure::Used, "code already used")),
        // Reserve a slot: attempts in flight plus failures never exceed five, and setups stay
        // within the code's own budget.
        Some(e) if e.failed + e.in_flight >= CODE_ATTEMPTS => Some((PairingFailure::NoAttempts, "no attempts left")),
        Some(e) => (!e.setups.take(mono, CHANNEL_SETUP_RATE, CHANNEL_SETUP_BURST))
            .then_some((PairingFailure::NoAttempts, "too many attempts at once; try again")),
    };
    let exchange = match (refusal, st.codes.get(code_id)) {
        (None, Some(e)) => PrimaryExchange::new(&e.code, &e.code_id, None).ok().map(|x| (x, e.serial)),
        _ => None,
    };
    let Some((exchange, serial)) = exchange else {
        // Refused. A relay can send these as fast as it likes, so the answers are rate-limited
        // and the events are too: none for a code id this primary never opened, and at most one
        // a second per code and reason otherwise.
        let (reason, message) = refusal.unwrap_or((PairingFailure::UnknownCode, "unknown or expired code"));
        let ours = st.issued(code_id);
        let event = ours && st.refusal_event(code_id, reason, mono);
        let reply = if ours {
            st.code_reply(code_id, key, mono)
        } else {
            st.refusal_replies.take(mono, REFUSAL_REPLY_RATE, REFUSAL_REPLY_BURST)
        };
        if reply {
            node.send_control_text(&Json::object([("type", Json::str("pairEnd")), ("channel", Json::str(key))]));
        }
        if event {
            node.emit(Event::PairingFailed { code_id: code_id.to_owned(), reason, message: message.to_owned() });
        }
        return;
    };
    if let Some(e) = st.codes.get_mut(code_id) {
        e.in_flight += 1;
    }
    st.channels.insert(
        key.to_owned(),
        PairChannel {
            channel,
            code_id: code_id.to_owned(),
            serial,
            exchange,
            stage: Stage::P1,
            claimed: false,
            deadline,
        },
    );
}

pub(crate) fn on_pair_frame(node: &mut Node, channel: &[u8; 16], body: &[u8]) {
    let key = b64u(channel);
    let Some(st) = state(node) else {
        return;
    };
    let Some(ch) = st.channels.get_mut(&key) else {
        return;
    };
    match ch.stage {
        Stage::P1 => match ch.exchange.on_p1(body) {
            Ok(p2) => {
                ch.stage = Stage::P3;
                let c = ch.channel;
                send_pair(node, &c, &p2);
            }
            // A malformed message counts as a failed attempt.
            Err(e) => fail_attempt(node, &key, PairingFailure::Malformed, &format!("malformed pairing message: {e}")),
        },
        Stage::P3 => match ch.exchange.on_p3(body) {
            Ok(false) => fail_attempt(node, &key, PairingFailure::WrongCode, "wrong code"),
            Ok(true) => {
                let (code_id, serial) = (ch.code_id.clone(), ch.serial);
                // `ch` holds `st.channels`, so the code is looked up through `st.codes` directly.
                let gone = st.codes.get(&code_id).filter(|e| e.serial == serial).is_none_or(|e| e.claimed || e.burned);
                if gone {
                    return end_channel(node, &key, PairingFailure::Used, "code already used", true);
                }
                let Ok(p4) = ch.exchange.p4() else {
                    return fail_attempt(node, &key, PairingFailure::Malformed, "malformed pairing message");
                };
                ch.claimed = true;
                ch.stage = Stage::P5;
                let c = ch.channel;
                if let Some(e) = st.codes.get_mut(&code_id).filter(|e| e.serial == serial) {
                    e.claimed = true;
                }
                send_pair(node, &c, &p4);
            }
            Err(e) => fail_attempt(node, &key, PairingFailure::Malformed, &format!("malformed pairing message: {e}")),
        },
        Stage::P5 => complete_pairing(node, &key, body),
    }
}

fn complete_pairing(node: &mut Node, key: &str, body: &[u8]) {
    let Some(ch) = state(node).and_then(|st| st.channels.get_mut(key)) else {
        return;
    };
    let keys = match ch.exchange.on_p5(body) {
        Ok(k) => k,
        Err(e) => {
            return fail_attempt(node, key, PairingFailure::Malformed, &format!("malformed pairing message: {e}"));
        }
    };
    let id = node_id_from_ed25519(&keys.ed25519);
    if node.roster().member(&id).is_some() {
        return end_channel(node, key, PairingFailure::AlreadyMember, &format!("{id} is already a member"), true);
    }
    let member = RosterMember::new(keys.ed25519, keys.x25519);
    let mut members = node.roster().members().to_vec();
    members.push(member.clone());
    let next = match next_roster(node, members) {
        Ok(r) => r,
        Err(e) => return end_channel(node, key, PairingFailure::RosterFull, e.message(), true),
    };
    let Some(st) = state(node) else {
        return;
    };
    let Some(mut ch) = st.channels.remove(key) else {
        return;
    };
    if let Some(e) = st.code_of(&ch.code_id, ch.serial) {
        e.in_flight = e.in_flight.saturating_sub(1);
        e.burned = true;
    }
    st.close_code_of(&ch.code_id, ch.serial);
    match ch.exchange.p6(next.json()) {
        Ok(p6) => send_pair(node, &ch.channel, &p6),
        Err(e) => {
            node.emit(Event::PairingFailed { code_id: ch.code_id, reason: PairingFailure::Malformed, message: e });
            return;
        }
    }
    publish_except(node, next.clone(), Some(&id));
    node.send_control_text(&Json::object([("type", Json::str("pairEnd")), ("channel", Json::str(key))]));
    node.emit(Event::Paired { member, code_id: ch.code_id, roster: next });
}

fn send_pair(node: &mut Node, channel: &[u8; 16], body: &[u8]) {
    if let Ok(frame) = encode_frame(frame_type::PAIR, channel, body) {
        node.send_binary(frame);
    }
}

/// A failed confirmation: the slot stays used; five burn the code.
fn fail_attempt(node: &mut Node, key: &str, reason: PairingFailure, message: &str) {
    let Some(st) = state(node) else {
        return;
    };
    let Some(ch) = st.channels.remove(key) else {
        return;
    };
    if let Some(e) = st.code_of(&ch.code_id, ch.serial) {
        e.in_flight = e.in_flight.saturating_sub(1);
        e.failed += 1;
        if ch.claimed {
            e.claimed = false;
        }
        if e.failed >= CODE_ATTEMPTS {
            e.burned = true;
        }
    }
    if st.code_of(&ch.code_id, ch.serial).is_some_and(|e| e.burned) {
        st.close_code(&ch.code_id);
    }
    node.send_control_text(&Json::object([("type", Json::str("pairEnd")), ("channel", Json::str(key))]));
    node.emit(Event::PairingFailed { code_id: ch.code_id, reason, message: message.to_owned() });
}

/// A timeout or a dropped connection: the slot is refunded.
fn end_channel(node: &mut Node, key: &str, reason: PairingFailure, message: &str, tell_relay: bool) {
    let Some(st) = state(node) else {
        return;
    };
    let Some(ch) = st.channels.remove(key) else {
        return;
    };
    if let Some(e) = st.code_of(&ch.code_id, ch.serial) {
        e.in_flight = e.in_flight.saturating_sub(1);
        if ch.claimed {
            e.claimed = false;
        }
    }
    if tell_relay {
        node.send_control_text(&Json::object([("type", Json::str("pairEnd")), ("channel", Json::str(key))]));
    }
    // A channel ended without a failed attempt costs whoever ended it nothing, so it tells the
    // application at most once a second per code and reason, as a refusal does.
    let now = node.now();
    if state(node).is_some_and(|st| st.refusal_event(&ch.code_id, reason, now)) {
        node.emit(Event::PairingFailed { code_id: ch.code_id, reason, message: message.to_owned() });
    }
}
