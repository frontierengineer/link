//! The node core driven by a fake relay and a fake clock: nothing here touches a socket or
//! waits on real time. A rogue peer, built from the Noise engine directly, sends what a correct
//! client never would: replayed, reordered, oversized and malformed frames, bytes beyond its
//! credit, and handshakes in bulk.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot::error::TryRecvError;

use super::sessions::{PEER_HELD_MESSAGES, session_prologue};
use super::*;
use crate::bytes::u32be;
use crate::errors::ErrorCode;
use crate::frames::{MAX_FRAME, SessionMessage, data_body, handshake_init_body, parse_handshake_resp, session_type};
use crate::noise::{HandshakeOptions, HandshakeState, IK, KeyPair, Transport};
use crate::roster::{RosterMember, UnsignedRoster, sign_roster};
use crate::types::{INITIAL_CREDIT, MAX_FRAGMENT, MAX_MESSAGE, SOCKET_LOW_WATER, paced_fragment};

// ── The fakes ──

struct FakeClock {
    now: AtomicU64,
    unix: AtomicU64,
}

impl FakeClock {
    fn new() -> Arc<FakeClock> {
        Arc::new(FakeClock { now: AtomicU64::new(1_000), unix: AtomicU64::new(1_790_000_000_000) })
    }

    fn advance(&self, ms: u64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
        self.unix.fetch_add(ms, Ordering::SeqCst);
    }

    /// Sets the wall clock alone; monotonic time is untouched.
    fn set_wall(&self, ms: u64) {
        self.unix.store(ms, Ordering::SeqCst);
    }

    /// Steps the wall clock alone (NTP, a restored virtual machine); monotonic time is untouched.
    fn step_wall_back(&self, ms: u64) {
        self.unix.fetch_sub(ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn unix_ms(&self) -> u64 {
        self.unix.load(Ordering::SeqCst)
    }
}

/// A handshake-init payload: the roster version and a stamp later than any before it.
fn payload(version: u64) -> [u8; 16] {
    static STAMP: AtomicU64 = AtomicU64::new(1_790_000_000_000);
    crate::frames::init_payload(version, STAMP.fetch_add(1, Ordering::SeqCst))
}

#[derive(Debug)]
enum Sent {
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Clone, Default)]
struct WireLog {
    out: Arc<Mutex<Vec<Sent>>>,
    /// Bytes not yet "written": tests raise it to model a socket that does not drain.
    buffered: Arc<AtomicUsize>,
    /// Every byte ever queued.
    queued: Arc<AtomicU64>,
    /// Refuse everything, as an overflowed queue does.
    overflowed: Arc<std::sync::atomic::AtomicBool>,
    closed: Arc<Mutex<Option<u16>>>,
}

struct FakeWire(WireLog);

impl Wire for FakeWire {
    fn send_text(&mut self, text: String) -> bool {
        if self.overflowed() {
            return false;
        }
        self.0.queued.fetch_add(text.len() as u64, Ordering::SeqCst);
        self.0.out.lock().unwrap().push(Sent::Text(text));
        true
    }

    fn send_binary(&mut self, bytes: Vec<u8>) -> bool {
        if self.overflowed() {
            return false;
        }
        self.0.queued.fetch_add(bytes.len() as u64, Ordering::SeqCst);
        self.0.out.lock().unwrap().push(Sent::Binary(bytes));
        true
    }

    fn buffered(&self) -> usize {
        self.0.buffered.load(Ordering::SeqCst)
    }

    fn queued_total(&self) -> u64 {
        self.0.queued.load(Ordering::SeqCst)
    }

    /// Everything is written but the last `buffered` bytes.
    fn written_total(&self) -> u64 {
        self.queued_total().saturating_sub(self.buffered() as u64)
    }

    fn overflowed(&self) -> bool {
        self.0.overflowed.load(Ordering::SeqCst)
    }

    fn close(&mut self, code: u16, _reason: &str) {
        *self.0.closed.lock().unwrap() = Some(code);
    }
}

/// A node on the fake relay.
struct T {
    node: Node,
    log: WireLog,
    conn: u64,
    events: broadcast::Receiver<Event>,
    identity: Identity,
}

fn timing() -> Timing {
    Timing::default()
}

/// The network seed of the network `creator` made, in these tests: apart from its node seed.
fn net_seed(creator: &Identity) -> [u8; 32] {
    let mut s = *creator.seed();
    for b in &mut s {
        *b ^= 0x80;
    }
    s
}

fn net_key(creator: &Identity) -> NetworkKey {
    NetworkKey::from_seed(&net_seed(creator))
}

fn make(identity: &Identity, roster: &Roster, primary: bool, clock: &Arc<FakeClock>, t: Timing, resolver: bool) -> T {
    let seed = primary.then(|| net_seed(identity));
    make_with(identity, roster, primary, seed, clock, t, resolver)
}

fn make_with(
    identity: &Identity,
    roster: &Roster,
    primary: bool,
    network_seed: Option<[u8; 32]>,
    clock: &Arc<FakeClock>,
    t: Timing,
    resolver: bool,
) -> T {
    let (events, rx) = broadcast::channel(65536);
    let (state, _) = watch::channel(MemberState::Disconnected);
    let (seen, _) = watch::channel(0);
    let node = Node::new(
        NodeConfig {
            identity: identity.clone(),
            roster: roster.clone(),
            pinned_network_key: None,
            network_seed,
            relay_url: Some("ws://127.0.0.1:9/v1".into()),
            credit_window: INITIAL_CREDIT,
            timing: t,
            primary,
            has_resolver: resolver,
            clock: clock.clone(),
            observer: None,
        },
        Outputs { events, state, rosters_seen: seen, inbox: Arc::new(Notify::new()) },
    )
    .unwrap();
    T { node, log: WireLog::default(), conn: 0, events: rx, identity: identity.clone() }
}

impl T {
    /// Dials, opens, says hello and registers, as a relay with the `control` feature would.
    fn connect(&mut self) {
        self.node.start();
        self.open_and_register(None);
    }

    fn open_and_register(&mut self, registered: Option<Json>) {
        self.open_and_register_with(r#"["control","later"]"#, registered);
    }

    /// As `open_and_register`, with the relay's `hello` listing `features` (a JSON array).
    fn open_and_register_with(&mut self, features: &str, registered: Option<Json>) {
        let (conn, _url) = self.node.take_dial().expect("a dial");
        self.conn = conn;
        self.log = WireLog::default();
        assert!(self.node.on_open(conn, Box::new(FakeWire(self.log.clone()))));
        let hello = format!(
            r#"{{"type":"hello","version":1,"challenge":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","features":{features}}}"#
        );
        self.node.on_text(conn, &hello);
        let reg = self.texts().into_iter().find(|t| t.get("type").and_then(Json::as_str) == Some("register"));
        let reg = reg.expect("register sent after hello");
        assert_eq!(reg.get("node").and_then(Json::as_str), Some(self.identity.id()));
        let msg = registered.unwrap_or_else(|| {
            Json::object([
                ("type", Json::str("registered")),
                ("node", Json::str(self.identity.id())),
                ("rosterVersion", Json::int(self.node.roster().version())),
            ])
        });
        self.node.on_text(conn, &msg.to_json_string().unwrap());
    }

    fn take(&self) -> Vec<Sent> {
        std::mem::take(&mut *self.log.out.lock().unwrap())
    }

    fn texts(&self) -> Vec<Json> {
        self.take()
            .into_iter()
            .filter_map(|s| match s {
                Sent::Text(t) => Some(Json::parse(&t).unwrap()),
                Sent::Binary(_) => None,
            })
            .collect()
    }

    fn binaries(&self) -> Vec<Vec<u8>> {
        self.take()
            .into_iter()
            .filter_map(|s| match s {
                Sent::Binary(b) => Some(b),
                Sent::Text(_) => None,
            })
            .collect()
    }

    /// The kinds of the frames this node sent since last asked.
    fn sent_kinds(&self) -> Vec<u8> {
        self.binaries().iter().map(|f| f[1]).collect()
    }

    fn send(&mut self, peer: &str, bytes: &[u8]) -> oneshot::Receiver<Result<(), LinkError>> {
        let (tx, rx) = oneshot::channel();
        self.node.send(peer, Bytes::copy_from_slice(bytes), tx);
        rx
    }

    fn events(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        while let Ok(e) = self.events.try_recv() {
            out.push(e);
        }
        out
    }

    fn take_all(&mut self) -> Vec<InboundMessage> {
        std::iter::from_fn(|| self.node.take_message()).collect()
    }

    fn id_bytes(&self) -> [u8; 16] {
        node_id_to_bytes(self.identity.id()).unwrap()
    }

    fn deliver_from(&mut self, from: &Identity, kind: u8, body: &[u8]) {
        let f = encode_frame(kind, &node_id_to_bytes(from.id()).unwrap(), body).unwrap();
        let conn = self.conn;
        self.node.on_binary(conn, &f);
    }

    fn deliver_pair(&mut self, channel: &[u8; 16], body: &[u8]) {
        let f = encode_frame(frame_type::PAIR, channel, body).unwrap();
        let conn = self.conn;
        self.node.on_binary(conn, &f);
    }

    fn state(&self) -> MemberState {
        self.node.state.member_state()
    }
}

fn done(rx: &mut oneshot::Receiver<Result<(), LinkError>>) -> Option<Result<(), LinkError>> {
    match rx.try_recv() {
        Ok(r) => Some(r),
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Closed) => panic!("completion dropped"),
    }
}

/// Moves binary frames between the nodes as the relay does (peer rewritten to the sender,
/// control delivered as data), and answers `unreachable` for an absent peer, until quiet.
fn route(nodes: &mut [&mut T]) {
    loop {
        let mut any = false;
        for i in 0..nodes.len() {
            let frames = nodes[i].binaries();
            let from = nodes[i].id_bytes();
            for mut f in frames {
                any = true;
                let to: [u8; 16] = f[2..18].try_into().unwrap();
                f[2..18].copy_from_slice(&from);
                if f[1] == frame_type::CONTROL {
                    f[1] = frame_type::DATA;
                }
                match nodes.iter().position(|n| n.id_bytes() == to) {
                    Some(j) => {
                        let conn = nodes[j].conn;
                        nodes[j].node.on_binary(conn, &f);
                    }
                    None => {
                        let back = encode_frame(frame_type::UNREACHABLE, &to, &[]).unwrap();
                        let conn = nodes[i].conn;
                        nodes[i].node.on_binary(conn, &back);
                    }
                }
            }
        }
        if !any {
            return;
        }
    }
}

struct World {
    clock: Arc<FakeClock>,
    p: Identity,
    a: Identity,
    b: Identity,
    roster: Roster,
    /// The network id: derived from the network's own seed, not the primary's node id.
    net: String,
}

fn roster_with(p: &Identity, version: u64, others: &[&Identity]) -> Roster {
    let mut members = vec![RosterMember::from_identity(p)];
    members.extend(others.iter().map(|i| RosterMember::from_identity(i)));
    roster_of(&net_key(p), version, p, members)
}

/// A roster of the network `key` names, with exactly these members, `primary` its primary.
fn roster_of(key: &NetworkKey, version: u64, primary: &Identity, members: Vec<RosterMember>) -> Roster {
    sign_roster(
        &UnsignedRoster {
            network: key.id().into(),
            version,
            issued_at: 1_790_000_000_000,
            relay: "ws://127.0.0.1:9/v1".into(),
            network_key: key.ed25519_public(),
            primary: primary.id().into(),
            members,
        },
        key,
    )
    .unwrap()
}

fn world() -> World {
    let (p, a, b) = (Identity::from_seed(&[1; 32]), Identity::from_seed(&[2; 32]), Identity::from_seed(&[3; 32]));
    let roster = roster_with(&p, 3, &[&a, &b]);
    let net = roster.network().to_owned();
    World { clock: FakeClock::new(), p, a, b, roster, net }
}

fn connected(w: &World, id: &Identity, roster: &Roster, t: Timing) -> T {
    let mut n = make(id, roster, false, &w.clock, t, false);
    n.connect();
    n.take();
    n
}

fn pair_ab(w: &World, t: Timing) -> (T, T) {
    (connected(w, &w.a, &w.roster, t), connected(w, &w.b, &w.roster, t))
}

fn bodies(msgs: Vec<InboundMessage>) -> Vec<Bytes> {
    msgs.into_iter().map(|m| m.bytes).collect()
}

// ── Sessions between two correct nodes ──

#[test]
fn a_message_is_fragmented_handed_over_and_reassembled() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let big: Vec<u8> = (0..3 * MAX_FRAGMENT + 5).map(|i| (i * 7) as u8).collect();
    let mut rx = a.send(w.b.id(), &big);
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    let got = b.take_all();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].from, w.a.id());
    assert!(got[0].bytes == big);
    assert_eq!(a.node.sessions.info(w.b.id())[0].sent, 4, "four fragments");
    let mut empty = a.send(w.b.id(), &[]);
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut empty), Some(Ok(())));
    assert!(b.take_all()[0].bytes.is_empty(), "an empty message arrives as one");
    let t = a.node.traffic();
    assert_eq!(t.peers[w.b.id()].sent.messages, 2);
    assert_eq!(t.peers[w.b.id()].sent.bytes, big.len() as u64);
    assert_eq!(b.node.traffic().peers[w.a.id()].received.frame_bytes, t.peers[w.b.id()].sent.frame_bytes);
}

#[test]
fn messages_to_one_peer_go_one_at_a_time_in_order() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let mut rxs: Vec<_> = (0..20u8).map(|i| a.send(w.b.id(), &vec![i; 100_000])).collect();
    route(&mut [&mut a, &mut b]);
    for _ in 0..20 {
        for m in b.take_all() {
            assert!(m.bytes.iter().all(|x| *x == m.bytes[0]));
        }
        route(&mut [&mut a, &mut b]);
        w.clock.advance(250);
        b.node.poll();
        route(&mut [&mut a, &mut b]);
    }
    assert!(rxs.iter_mut().all(|rx| done(rx) == Some(Ok(()))));
}

#[test]
fn credit_runs_out_and_refills_as_the_application_takes() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let msg = vec![9u8; 700 * 1024];
    let mut r1 = a.send(w.b.id(), &msg);
    route(&mut [&mut a, &mut b]);
    let mut r2 = a.send(w.b.id(), &msg);
    route(&mut [&mut a, &mut b]);
    let mut r3 = a.send(w.b.id(), &msg);
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut r1), Some(Ok(())));
    assert_eq!(done(&mut r2), Some(Ok(())));
    assert_eq!(done(&mut r3), None, "the third waits for credit");
    let s = &a.node.sessions.info(w.b.id())[0];
    assert!(s.inflight <= INITIAL_CREDIT);
    assert_eq!(b.node.waiting_messages(), 2);
    assert!(b.node.take_message().is_some());
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut r3), None, "one message is still unread");
    assert!(b.node.take_message().is_some());
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut r3), Some(Ok(())));
    assert!(b.node.take_message().is_some());
    // Below the batch size, the last credit waits for the 250 ms timer.
    route(&mut [&mut a, &mut b]);
    w.clock.advance(250);
    b.node.poll();
    route(&mut [&mut a, &mut b]);
    let s = &a.node.sessions.info(w.b.id())[0];
    assert_eq!((s.send_credit, s.inflight), (INITIAL_CREDIT, 0), "the full window is back");
}

#[test]
fn credit_is_batched_for_many_small_messages() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    for i in 0..500u32 {
        let mut rx = a.send(w.b.id(), &i.to_be_bytes());
        route(&mut [&mut a, &mut b]);
        assert_eq!(done(&mut rx), Some(Ok(())));
        assert_eq!(b.node.take_message().unwrap().bytes, Bytes::copy_from_slice(&i.to_be_bytes()));
    }
    // 2000 bytes owed in all, never 64 KiB at once: no credit frame until the timer.
    assert_eq!(b.node.sessions.stats.credits_sent, 0);
    w.clock.advance(250);
    b.node.poll();
    assert_eq!(b.node.sessions.stats.credits_sent, 1);
}

#[test]
fn the_pace_holds_a_sender_whose_receiver_does_not_take() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    // 200-byte messages, never taken: the sender stops at the 64 KiB pace, well inside the
    // 1 MiB window, so the socket never holds more than about the pace.
    let mut rxs: Vec<_> = (0..1000).map(|_| a.send(w.b.id(), &[0u8; 200])).collect();
    route(&mut [&mut a, &mut b]);
    let mut sent = 0;
    for rx in rxs.iter_mut() {
        if done(rx).is_some() {
            sent += 1;
        }
    }
    assert_eq!(sent, 65536usize.div_ceil(200));
    assert!(a.node.sessions.info(w.b.id())[0].inflight >= 65536);
    // Taken, the credit comes back and the rest goes.
    for _ in 0..20 {
        b.take_all();
        w.clock.advance(250);
        b.node.poll();
        route(&mut [&mut a, &mut b]);
    }
    assert_eq!(b.node.traffic().total.received.messages, 1000);
}

#[test]
fn a_full_socket_holds_data_but_not_control() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let mut rx = a.send(w.b.id(), b"open");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    a.log.buffered.store(SOCKET_LOW_WATER + 1, Ordering::SeqCst);
    let mut rx = a.send(w.b.id(), b"waits");
    assert!(a.binaries().is_empty(), "data waits for the socket to drain");
    sessions::send_control(&mut a.node, w.b.id(), Ctl::RosterRequest, None, FailAction::Ignore);
    assert_eq!(a.sent_kinds(), [frame_type::CONTROL], "control goes at once, as 0x08");
    a.log.buffered.store(0, Ordering::SeqCst);
    a.node.poll();
    assert_eq!(a.sent_kinds(), [frame_type::DATA]);
    assert_eq!(done(&mut rx), Some(Ok(())));
}

#[test]
fn rekey_by_time_overlaps_then_retires_the_old_session() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let mut rx = a.send(w.b.id(), b"one");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    let first = a.node.sessions.info(w.b.id())[0].clone();
    assert!(first.initiator && first.current);
    // Ten minutes on: the initiator's next send starts a rekey; the message itself goes on
    // the session it has.
    w.clock.advance(600_000);
    let mut rx = a.send(w.b.id(), b"two");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    let sessions = a.node.sessions.info(w.b.id());
    assert_eq!(sessions.len(), 2, "old and new overlap");
    let current: Vec<_> = sessions.iter().filter(|s| s.current).collect();
    assert_eq!(current.len(), 1);
    assert_ne!(current[0].local_index, first.local_index);
    let mut rx = a.send(w.b.id(), b"three");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    assert_eq!(bodies(b.take_all()), [&b"one"[..], b"two", b"three"]);
    // A frame still in flight on the retired session is accepted within the grace.
    let old = b.node.sessions.info(w.a.id()).into_iter().find(|s| !s.current).unwrap();
    assert!(old.local_index != 0);
    // Past the 30 s grace, with nothing crossing, the retired session is forgotten by both.
    w.clock.advance(31_000);
    a.node.poll();
    b.node.poll();
    w.clock.advance(10_000);
    a.node.poll();
    b.node.poll();
    assert_eq!(a.node.sessions.info(w.b.id()).len(), 1);
    assert_eq!(b.node.sessions.info(w.a.id()).len(), 1);
}

#[test]
fn rekey_by_message_count() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, Timing { rekey_messages: 3, ..timing() });
    let mut indices = std::collections::HashSet::new();
    for i in 0..12u8 {
        let mut rx = a.send(w.b.id(), &[i]);
        route(&mut [&mut a, &mut b]);
        assert_eq!(done(&mut rx), Some(Ok(())));
        indices.insert(a.node.sessions.info(w.b.id()).iter().find(|s| s.current).unwrap().local_index);
    }
    let got: Vec<u8> = b.take_all().into_iter().map(|m| m.bytes[0]).collect();
    assert_eq!(got, (0..12).collect::<Vec<_>>());
    assert!(indices.len() >= 3, "{indices:?}");
}

#[test]
fn a_message_crossing_a_rekey_is_never_split() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, Timing { rekey_interval: std::time::Duration::from_secs(60), ..timing() });
    // An unread message makes the receiver stop crediting, so the big one stalls part-way.
    let mut rx = a.send(w.b.id(), b"unread");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    let big = vec![5u8; 3 * 1024 * 1024];
    let mut rx = a.send(w.b.id(), &big);
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), None, "stalled on credit");
    let old = a.node.sessions.info(w.b.id())[0].clone();
    // The rekey falls due, and completes, while the message is part-way.
    w.clock.advance(60_000);
    a.node.poll();
    route(&mut [&mut a, &mut b]);
    let sessions = a.node.sessions.info(w.b.id());
    assert_eq!(sessions.len(), 2);
    let new = sessions.iter().find(|s| s.current).unwrap().clone();
    assert_ne!(new.local_index, old.local_index);
    // Taken, the unread message frees the credit; the big one finishes on the old session.
    assert_eq!(&b.node.take_message().unwrap().bytes[..], b"unread");
    let mut result = None;
    for _ in 0..100 {
        route(&mut [&mut a, &mut b]);
        result = done(&mut rx);
        if result.is_some() {
            break;
        }
        w.clock.advance(250);
        a.node.poll();
        b.node.poll();
    }
    assert_eq!(result, Some(Ok(())));
    let got = b.take_all();
    assert_eq!(got.len(), 1);
    assert!(got[0].bytes == big);
    let sessions = a.node.sessions.info(w.b.id());
    let new_now = sessions.iter().find(|s| s.local_index == new.local_index).unwrap();
    assert_eq!(new_now.sent, 0, "not one fragment on the new session: {sessions:?}");
    // The next message goes on the new session.
    let mut rx = a.send(w.b.id(), b"after");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    assert_eq!(bodies(b.take_all()), [&b"after"[..]]);
    let sessions = a.node.sessions.info(w.b.id());
    assert_eq!(sessions.iter().find(|s| s.current).unwrap().sent, 1, "{sessions:?}");
    // Once nothing crosses it, the old session is retired for good after the grace.
    w.clock.advance(31_000);
    a.node.poll();
    w.clock.advance(8_000);
    a.node.poll();
    assert_eq!(a.node.sessions.info(w.b.id()).len(), 1);
}

#[test]
fn reset_when_the_peer_lost_its_state() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let mut rx = a.send(w.b.id(), b"one");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    drop(b);
    // B restarts: same identity, no sessions.
    let mut b2 = connected(&w, &w.b, &w.roster, timing());
    let mut rx = a.send(w.b.id(), b"lost");
    route(&mut [&mut a, &mut b2]);
    assert_eq!(done(&mut rx), Some(Ok(())), "handed to the relay: delivery is at most once");
    assert!(a.node.sessions.info(w.b.id()).is_empty(), "the reset ended A's session");
    let mut rx = a.send(w.b.id(), b"two");
    route(&mut [&mut a, &mut b2]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    assert_eq!(bodies(b2.take_all()), [&b"two"[..]]);
}

#[test]
fn idle_sessions_are_forgotten() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let mut rx = a.send(w.b.id(), b"one");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    b.take_all();
    w.clock.advance(250);
    b.node.poll();
    route(&mut [&mut a, &mut b]);
    w.clock.advance(599_000);
    a.node.poll();
    assert_eq!(a.node.sessions.info(w.b.id()).len(), 1, "not yet");
    // The sweep runs every quarter of the shortest timer (7.5 s here), as the TypeScript
    // client's interval does.
    w.clock.advance(8_000);
    a.node.poll();
    b.node.poll();
    assert!(a.node.sessions.info(w.b.id()).is_empty());
    assert!(b.node.sessions.info(w.a.id()).is_empty());
}

#[test]
fn a_responder_answers_reset_past_its_session_lifetime() {
    let w = world();
    let mut a =
        connected(&w, &w.a, &w.roster, Timing { rekey_interval: std::time::Duration::from_secs(3600), ..timing() });
    let mut b = connected(&w, &w.b, &w.roster, timing());
    let mut rx = a.send(w.b.id(), b"fresh");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    b.take_all();
    // Keep the session from going idle, then pass 10 min 30 s for B (the responder) but not
    // for A, which keeps using its session.
    for _ in 0..7 {
        w.clock.advance(90_000);
        let mut rx = a.send(w.b.id(), b"keepalive");
        route(&mut [&mut a, &mut b]);
        assert_eq!(done(&mut rx), Some(Ok(())));
        b.take_all();
    }
    assert!(!a.node.sessions.info(w.b.id()).is_empty());
    w.clock.advance(1);
    let first = a.node.sessions.info(w.b.id())[0].local_index;
    let mut rx = a.send(w.b.id(), b"expired");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    assert!(b.take_all().is_empty(), "lost to the reset");
    assert!(a.node.sessions.info(w.b.id()).is_empty(), "reset");
    let mut rx = a.send(w.b.id(), b"renewed");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    assert_eq!(bodies(b.take_all()), [&b"renewed"[..]]);
    assert_ne!(a.node.sessions.info(w.b.id())[0].local_index, first);
}

#[test]
fn a_handshake_with_no_answer_times_out() {
    let w = world();
    let (mut a, _b) = pair_ab(&w, timing());
    let mut rx = a.send(w.b.id(), b"x");
    a.take(); // the relay loses the handshake
    w.clock.advance(9_999);
    a.node.poll();
    assert_eq!(done(&mut rx), None);
    w.clock.advance(1);
    a.node.poll();
    assert_eq!(done(&mut rx).unwrap().unwrap_err().code(), ErrorCode::Timeout);
}

#[test]
fn unreachable_and_refused_fail_the_send() {
    let w = world();
    let mut a = connected(&w, &w.a, &w.roster, timing());
    let mut rx = a.send(w.b.id(), b"x");
    route(&mut [&mut a]); // B is not connected
    assert_eq!(done(&mut rx).unwrap().unwrap_err().code(), ErrorCode::Unreachable);
    // B holds a roster without A: it refuses.
    let without_a = roster_with(&w.p, 2, &[&w.b]);
    let mut b = connected(&w, &w.b, &without_a, timing());
    let mut rx = a.send(w.b.id(), b"x");
    route(&mut [&mut a, &mut b]);
    let err = done(&mut rx).unwrap().unwrap_err();
    assert_eq!((err.code(), err.reason()), (ErrorCode::Refused, Some(1)));
    assert_eq!(b.node.roster().version(), 2);
    // Sends that are not even attempted.
    let mut rx = a.send(w.a.id(), b"x");
    assert_eq!(done(&mut rx).unwrap().unwrap_err().code(), ErrorCode::Invalid);
    let mut rx = a.send(Identity::from_seed(&[7; 32]).id(), b"x");
    assert_eq!(done(&mut rx).unwrap().unwrap_err().code(), ErrorCode::Invalid);
    let mut rx = a.send(w.b.id(), &vec![0; MAX_MESSAGE + 1]);
    assert_eq!(done(&mut rx).unwrap().unwrap_err().code(), ErrorCode::Invalid);
}

#[test]
fn rosters_spread_member_to_member_over_a_handshake() {
    let w = world();
    let older = roster_with(&w.p, 2, &[&w.a, &w.b]);
    let mut a = connected(&w, &w.a, &w.roster, timing()); // v3
    let mut b = connected(&w, &w.b, &older, timing()); // v2
    b.events();
    let mut rx = b.send(w.a.id(), b"hi");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    assert_eq!(b.node.roster().version(), 3, "A saw B behind and handed it v3");
    assert!(b.events().iter().any(|e| matches!(e, Event::Roster(r) if r.version() == 3)));
}

#[test]
fn a_roster_from_a_peer_is_taken_only_if_the_pinned_network_key_signed_it_and_it_is_newer() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let mut rx = a.send(w.b.id(), b"x");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    // A forged roster (signed by A, not the primary) and an older one: B keeps v3.
    let forged = roster_with(&w.a, 9, &[]);
    let older = roster_with(&w.p, 2, &[&w.a, &w.b]);
    for r in [&forged, &older] {
        sessions::send_control(&mut a.node, w.b.id(), Ctl::Roster(r.to_jcs(), r.version()), None, FailAction::Ignore);
        route(&mut [&mut a, &mut b]);
    }
    sessions::send_control(&mut a.node, w.b.id(), Ctl::Roster("not json".into(), 99), None, FailAction::Ignore);
    route(&mut [&mut a, &mut b]);
    assert_eq!(b.node.roster().version(), 3);
    // A newer one that drops A: B takes it and drops its sessions with A.
    let v4 = roster_with(&w.p, 4, &[&w.b]);
    sessions::send_control(&mut a.node, w.b.id(), Ctl::Roster(v4.to_jcs(), v4.version()), None, FailAction::Ignore);
    route(&mut [&mut a, &mut b]);
    assert_eq!(b.node.roster().version(), 4);
    assert!(b.node.sessions.info(w.a.id()).is_empty());
    let mut rx = b.send(w.a.id(), b"to the revoked");
    assert_eq!(done(&mut rx).unwrap().unwrap_err().code(), ErrorCode::Invalid);
    // A roster that drops this node itself makes it revoked, for good.
    assert!(a.node.offer_roster(v4.json()));
    assert_eq!(a.state(), MemberState::Revoked);
    w.clock.advance(60_000);
    a.node.poll();
    assert!(a.node.take_dial().is_none());
}

// ── The relay connection ──

#[test]
fn reconnect_backs_off_doubling_to_ten_seconds_and_resets_after_registered() {
    let w = world();
    let mut a = make(&w.a, &w.roster, false, &w.clock, timing(), false);
    a.node.start();
    let wait_for_dial = |a: &mut T| {
        let mut waited = 0;
        while a.node.dial_request.is_none() {
            w.clock.advance(100);
            waited += 100;
            a.node.poll();
        }
        waited
    };
    let mut delays = Vec::new();
    for _ in 0..7 {
        let (conn, _) = a.node.take_dial().expect("a dial");
        a.node.on_close(conn, close_code::ABNORMAL, "");
        delays.push(wait_for_dial(&mut a));
    }
    assert_eq!(delays, [500, 1000, 2000, 4000, 8000, 10000, 10000]);
    a.open_and_register(None);
    assert_eq!(a.state(), MemberState::Connected);
    let conn = a.conn;
    a.node.on_close(conn, close_code::GOING_AWAY, "");
    assert_eq!(wait_for_dial(&mut a), 500, "the backoff starts over after registered");
}

#[test]
fn close_codes_4008_and_4005_are_terminal_and_4009_asks_where_the_network_went() {
    let w = world();
    for (code, state) in [(close_code::NOT_MEMBER, MemberState::Revoked), (close_code::REPLACED, MemberState::Replaced)]
    {
        let mut a = connected(&w, &w.a, &w.roster, timing());
        a.events();
        let conn = a.conn;
        let mut rx = a.send(w.b.id(), b"x");
        a.node.on_close(conn, code, "");
        assert_eq!(a.state(), state);
        assert!(done(&mut rx).unwrap().is_err(), "pending sends fail");
        w.clock.advance(60_000);
        a.node.poll();
        assert!(a.node.take_dial().is_none(), "never redialled");
        let codes: Vec<u16> = a
            .events()
            .iter()
            .filter_map(|e| if let Event::Disconnect { code, .. } = e { Some(*code) } else { None })
            .collect();
        assert_eq!(codes, [code]);
        assert!(a.take_all().is_empty());
    }
    let mut a = make(&w.a, &w.roster, false, &w.clock, timing(), true);
    a.connect();
    a.events();
    let conn = a.conn;
    a.node.on_close(conn, close_code::MOVED, "moved");
    assert!(a.events().iter().any(|e| matches!(e, Event::Moved { network } if *network == w.net)));
    assert_eq!(a.node.take_resolve().as_deref(), Some(w.net.as_str()));
    w.clock.advance(5_000);
    a.node.poll();
    assert!(a.node.take_dial().is_none(), "nothing until the lookup answers");
    a.node.on_resolved(Some("ws://127.0.0.2:9/v1".into()));
    w.clock.advance(500);
    a.node.poll();
    assert_eq!(a.node.take_dial().map(|d| d.1).as_deref(), Some("ws://127.0.0.2:9/v1"));
}

#[test]
fn a_bad_hello_closes_4000_and_reconnects() {
    let w = world();
    for hello in [
        r#"{"type":"hello","version":2,"challenge":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}"#,
        r#"{"type":"hello","version":1,"challenge":"AQID"}"#,
        r#"{"type":"hello","version":1}"#,
        // An integer is written as an integer literal (spec section 1).
        r#"{"type":"hello","version":1.0,"challenge":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}"#,
    ] {
        let mut a = make(&w.a, &w.roster, false, &w.clock, timing(), false);
        a.node.start();
        let (conn, _) = a.node.take_dial().unwrap();
        let log = WireLog::default();
        assert!(a.node.on_open(conn, Box::new(FakeWire(log.clone()))));
        a.node.on_text(conn, hello);
        assert_eq!(*log.closed.lock().unwrap(), Some(close_code::BAD_REQUEST));
        assert_eq!(a.state(), MemberState::Disconnected);
        w.clock.advance(500);
        a.node.poll();
        assert!(a.node.take_dial().is_some());
    }
}

#[test]
fn nothing_but_register_goes_out_before_registered() {
    let w = world();
    let mut a = make(&w.a, &w.roster, false, &w.clock, timing(), false);
    a.node.start();
    let (conn, _) = a.node.take_dial().unwrap();
    let log = WireLog::default();
    assert!(a.node.on_open(conn, Box::new(FakeWire(log.clone()))));
    a.log = log;
    a.conn = conn;
    let mut rx = a.send(w.b.id(), b"too early");
    assert_eq!(done(&mut rx).unwrap().unwrap_err().code(), ErrorCode::Closed);
    a.node.on_text(conn, r#"{"type":"hello","version":1,"challenge":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}"#);
    let sent = a.take();
    assert_eq!(sent.len(), 1);
    let Sent::Text(reg) = &sent[0] else { panic!("register is text") };
    let reg = Json::parse(reg).unwrap();
    // The registration signature verifies over the origin dialled and the challenge.
    let sig: [u8; 64] = crate::bytes::from_b64u_array(reg.get("sig").and_then(Json::as_str).unwrap()).unwrap();
    let ts = reg.get("ts").and_then(Json::as_safe_uint).unwrap();
    assert_eq!(ts, w.clock.unix_ms());
    let challenge: [u8; 32] = crate::bytes::from_b64u_array("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA").unwrap();
    let msg = register_signing_bytes(&w.net, w.a.id(), &challenge, ts, "127.0.0.1:9");
    assert!(crate::crypto::ed25519_verify(&w.a.ed25519_public(), &msg, &sig));
    assert_eq!(reg.get("roster"), Some(w.roster.json()));
}

#[test]
fn registered_with_a_newer_roster_applies_it_before_connected() {
    let w = world();
    let older = roster_with(&w.p, 2, &[&w.a]);
    let mut a = make(&w.a, &older, false, &w.clock, timing(), false);
    a.node.start();
    let registered = Json::object([
        ("type", Json::str("registered")),
        ("node", Json::str(w.a.id())),
        ("rosterVersion", Json::int(3)),
        ("roster", w.roster.json().clone()),
    ]);
    a.open_and_register(Some(registered));
    let order: Vec<String> = a
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Roster(r) => Some(format!("roster {}", r.version())),
            Event::State(s) => Some(format!("state {s}")),
            _ => None,
        })
        .collect();
    assert_eq!(order, ["state connecting", "roster 3", "state connected"]);
    // A compact record: a newer version without the roster. The member asks the primary.
    let mut b = make(&w.b, &w.roster, false, &w.clock, timing(), false);
    b.node.start();
    let registered = Json::object([
        ("type", Json::str("registered")),
        ("node", Json::str(w.b.id())),
        ("rosterVersion", Json::int(7)),
    ]);
    b.open_and_register(Some(registered));
    let inits = b.binaries();
    assert_eq!(inits.len(), 1);
    assert_eq!(inits[0][1], frame_type::HANDSHAKE_INIT);
    assert_eq!(&inits[0][2..18], &node_id_to_bytes(w.p.id()).unwrap());
}

#[test]
fn relay_errors_are_events_and_unknown_messages_are_ignored() {
    let w = world();
    let mut a = connected(&w, &w.a, &w.roster, timing());
    a.events();
    let conn = a.conn;
    for junk in
        ["", "[]", "{}", r#"{"type":5}"#, "not json", r#"{"type":"surprise"}"#, r#"{"type":"hello","version":1}"#]
    {
        a.node.on_text(conn, junk);
    }
    a.node.on_text(conn, &format!(r#"{{"type":"error","code":"x","pad":"{}"}}"#, "x".repeat(MAX_CONTROL_BYTES)));
    a.node.on_text(conn, r#"{"type":"error","code":"forbidden","message":"no","id":"u1"}"#);
    let ev = a.events();
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert!(matches!(&ev[0], Event::RelayError { code, message, id }
        if code == "forbidden" && message.as_deref() == Some("no") && id.as_deref() == Some("u1")));
    assert_eq!(a.state(), MemberState::Connected);
    // Frames for an old connection are ignored.
    a.node.on_text(conn + 1, r#"{"type":"error","code":"late"}"#);
    assert!(a.events().is_empty());
}

// ── A rogue peer: hostile frames ──

/// A peer driven by hand: it handshakes with `target` as `me` and sends whatever it likes.
struct Rogue {
    me: Identity,
    t: Transport,
    their_index: u32,
}

impl Rogue {
    fn handshake(me: &Identity, target: &mut T, network: &str, version: u64) -> Option<Rogue> {
        let prologue = session_prologue(network);
        let mut hs = HandshakeState::new(HandshakeOptions {
            pattern: &IK,
            initiator: true,
            prologue: &prologue,
            s: Some(KeyPair::from_private(&me.x25519_private())),
            rs: Some(target.identity.x25519_public()),
            fixed_ephemeral: None,
        })
        .unwrap();
        let (m1, _) = hs.write_message(&payload(version)).unwrap();
        let mine = u32::from_be_bytes(crate::crypto::random_array::<4>()) | 1;
        target.deliver_from(me, frame_type::HANDSHAKE_INIT, &handshake_init_body(mine, &m1));
        let resp = target.binaries().into_iter().find(|f| f[1] == frame_type::HANDSHAKE_RESP)?;
        let (theirs, to_me, m2) = parse_handshake_resp(&resp[18..]).unwrap();
        assert_eq!(to_me, mine);
        let (_, t) = hs.read_message(m2).unwrap();
        Some(Rogue { me: me.clone(), t: t.unwrap(), their_index: theirs })
    }

    fn frame(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ct = self.t.send.encrypt_with_ad(&[], plaintext).unwrap();
        data_body(self.their_index, &ct)
    }

    fn send(&mut self, target: &mut T, plaintext: &[u8]) {
        let body = self.frame(plaintext);
        let me = self.me.clone();
        target.deliver_from(&me, frame_type::DATA, &body);
    }

    fn fragment(&mut self, target: &mut T, more: bool, bytes: &[u8]) {
        let p = SessionMessage::Message { more, bytes }.encode();
        self.send(target, &p);
    }
}

fn target(w: &World) -> T {
    connected(w, &w.b, &w.roster, timing())
}

#[test]
fn a_replayed_frame_ends_the_session_and_the_next_one_is_reset() {
    let w = world();
    let mut b = target(&w);
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    let body = r.frame(&SessionMessage::Message { more: false, bytes: b"once" }.encode());
    b.deliver_from(&w.a, frame_type::DATA, &body);
    assert_eq!(b.take_all().len(), 1);
    b.deliver_from(&w.a, frame_type::DATA, &body);
    assert!(b.take_all().is_empty(), "a replay is not delivered");
    assert!(b.node.sessions.info(w.a.id()).is_empty(), "it ended the session");
    b.take();
    r.fragment(&mut b, false, b"after");
    assert!(b.sent_kinds().contains(&frame_type::RESET));
    assert!(b.take_all().is_empty());
}

#[test]
fn an_out_of_order_frame_ends_the_session() {
    let w = world();
    let mut b = target(&w);
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    let first = r.frame(&SessionMessage::Message { more: false, bytes: b"1" }.encode());
    let second = r.frame(&SessionMessage::Message { more: false, bytes: b"2" }.encode());
    b.deliver_from(&w.a, frame_type::DATA, &second);
    b.deliver_from(&w.a, frame_type::DATA, &first);
    assert!(b.take_all().is_empty());
    assert!(b.node.sessions.info(w.a.id()).is_empty());
}

#[test]
fn malformed_frames_are_dropped_or_end_the_session_never_panic() {
    let w = world();
    let mut b = target(&w);
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    let conn = b.conn;
    // Frames that do not parse: dropped.
    for f in [vec![], vec![1], vec![2; 18], vec![1, 1], vec![1, 3, 0], vec![1; MAX_FRAME + 1]] {
        b.node.on_binary(conn, &f);
    }
    let from = node_id_to_bytes(w.a.id()).unwrap();
    for (kind, body) in [
        (frame_type::HANDSHAKE_INIT, vec![0, 0, 0]),
        (frame_type::HANDSHAKE_INIT, vec![0, 0, 0, 0, 1, 2, 3]),
        (frame_type::HANDSHAKE_INIT, vec![0, 0, 0, 1, 1, 2, 3]),
        (frame_type::HANDSHAKE_RESP, vec![0; 7]),
        (frame_type::HANDSHAKE_RESP, vec![0; 100]),
        (frame_type::RESET, vec![0, 0]),
        (frame_type::DATA, vec![0, 0, 0]),
        (frame_type::PAIR, vec![0; 65]),
        (0x09, vec![]),
        (0xff, vec![1; 10]),
    ] {
        b.node.on_binary(conn, &encode_frame(kind, &from, &body).unwrap());
    }
    assert_eq!(b.node.sessions.info(w.a.id()).len(), 1, "the session survived");
    // A session message that does not decode ends the session.
    r.send(&mut b, &[0x42, 1, 2]);
    assert!(b.node.sessions.info(w.a.id()).is_empty());
    for bad in [
        vec![],
        vec![session_type::CREDIT, 0, 0],
        vec![session_type::ROSTER_REQUEST, 1],
        vec![session_type::ROSTER, 0xff],
    ] {
        let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
        r.send(&mut b, &bad);
        assert!(b.node.sessions.info(w.a.id()).is_empty(), "{bad:?}");
    }
    // A ciphertext longer than a Noise message ends the session before any decryption.
    let r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    let mut body = u32be(r.their_index).to_vec();
    body.extend(vec![0u8; 65536]);
    b.deliver_from(&w.a, frame_type::DATA, &body);
    assert!(b.node.sessions.info(w.a.id()).is_empty());
    assert!(b.take_all().is_empty());
    assert_eq!(b.state(), MemberState::Connected);
}

#[test]
fn a_handshake_from_a_non_member_or_with_the_wrong_key_is_refused() {
    let w = world();
    let mut b = target(&w);
    let stranger = Identity::from_seed(&[9; 32]);
    assert!(Rogue::handshake(&stranger, &mut b, &w.net, 3).is_none());
    // The relay named a member, but the handshake carried another key.
    let mut b2 = target(&w);
    let prologue = session_prologue(&w.net);
    let mut hs = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: true,
        prologue: &prologue,
        s: Some(KeyPair::from_private(&stranger.x25519_private())),
        rs: Some(w.b.x25519_public()),
        fixed_ephemeral: None,
    })
    .unwrap();
    let (m1, _) = hs.write_message(&payload(3)).unwrap();
    b2.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &handshake_init_body(7, &m1));
    let sent = b2.binaries();
    assert!(sent.iter().any(|f| f[1] == frame_type::REFUSED && f[18..] == [1]));
    assert!(b2.node.sessions.info(w.a.id()).is_empty());
    // A handshake for another network's prologue does not even complete.
    assert!(Rogue::handshake(&w.a, &mut b2, w.a.id(), 3).is_none());
}

#[test]
fn data_for_an_unknown_index_is_answered_reset() {
    let w = world();
    let mut b = target(&w);
    b.deliver_from(&w.a, frame_type::DATA, &data_body(0xdead_beef, &[0; 40]));
    let sent = b.binaries();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0][1], frame_type::RESET);
    assert_eq!(&sent[0][18..], &0xdead_beefu32.to_be_bytes());
}

#[test]
fn message_bytes_beyond_the_credit_given_end_the_session() {
    let w = world();
    let mut b = target(&w);
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    // A whole message is held until taken, so its bytes stay charged against the window.
    let chunk = vec![1u8; MAX_FRAGMENT];
    let mut sent = 0usize;
    while sent + MAX_FRAGMENT <= INITIAL_CREDIT as usize {
        r.fragment(&mut b, false, &chunk);
        sent += MAX_FRAGMENT;
    }
    let left = INITIAL_CREDIT as usize - sent;
    r.fragment(&mut b, false, &vec![2u8; left]);
    assert_eq!(b.node.sessions.info(w.a.id()).len(), 1, "exactly the window is fine");
    r.fragment(&mut b, false, b"x");
    assert!(b.node.sessions.info(w.a.id()).is_empty(), "one byte more is not");
    assert_eq!(b.node.waiting_messages(), sent / MAX_FRAGMENT + 1);
}

#[test]
fn a_message_over_64_mib_ends_the_session() {
    let w = world();
    let mut b = target(&w);
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    // Fragments of a message in progress are credited at once (nothing is held), so the
    // window never stops it: the 64 MiB rule does.
    let chunk = vec![3u8; MAX_FRAGMENT];
    let mut total = 0;
    while total + MAX_FRAGMENT <= MAX_MESSAGE {
        r.fragment(&mut b, true, &chunk);
        total += MAX_FRAGMENT;
    }
    r.fragment(&mut b, true, &vec![3u8; MAX_MESSAGE - total]);
    assert_eq!(b.node.sessions.info(w.a.id()).len(), 1, "exactly 64 MiB so far");
    r.fragment(&mut b, false, b"!");
    assert!(b.node.sessions.info(w.a.id()).is_empty());
    assert!(b.take_all().is_empty());
}

#[test]
fn what_one_peer_can_make_this_node_hold_is_bounded() {
    let w = world();
    let mut b = target(&w);
    b.node.sessions.set_limits(3 * INITIAL_CREDIT, PEER_HELD_MESSAGES);
    // Each new session brings a fresh window; untaken messages pile up across sessions until
    // the per-peer bound ends the session that would pass it.
    let chunk = vec![4u8; MAX_FRAGMENT];
    let mut ended = false;
    for _ in 0..5 {
        let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
        for _ in 0..(INITIAL_CREDIT as usize / MAX_FRAGMENT) {
            r.fragment(&mut b, false, &chunk);
            if b.node.sessions.info(w.a.id()).iter().all(|s| !s.current) {
                ended = true;
                break;
            }
        }
    }
    assert!(ended, "the bound was reached");
    let held = (b.node.waiting_messages() * MAX_FRAGMENT) as u64;
    assert!(held <= 3 * INITIAL_CREDIT, "{held} bytes held");

    // Empty messages need no credit; their count is bounded too.
    let mut c = target(&w);
    c.node.sessions.set_limits(u64::MAX, 100);
    let mut r = Rogue::handshake(&w.a, &mut c, &w.net, 3).unwrap();
    for _ in 0..150 {
        r.fragment(&mut c, false, &[]);
    }
    assert_eq!(c.node.waiting_messages(), 100);
    assert!(c.node.sessions.info(w.a.id()).is_empty());
    // Taking them frees the room again.
    c.take_all();
    let mut r = Rogue::handshake(&w.a, &mut c, &w.net, 3).unwrap();
    r.fragment(&mut c, false, b"room again");
    assert_eq!(c.take_all().len(), 1);
}

#[test]
fn sessions_per_peer_are_bounded() {
    let w = world();
    let mut b = target(&w);
    let mut rogues: Vec<Rogue> = (0..20).map(|_| Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap()).collect();
    assert_eq!(b.node.sessions.info(w.a.id()).len(), sessions::MAX_SESSIONS_PER_PEER);
    // The newest still works; the oldest was dropped and is answered reset.
    let last = rogues.len() - 1;
    rogues[last].fragment(&mut b, false, b"newest");
    assert_eq!(b.take_all().len(), 1);
    b.take();
    rogues[0].fragment(&mut b, false, b"oldest");
    assert!(b.sent_kinds().contains(&frame_type::RESET));
}

#[test]
fn resignations_are_checked_before_the_primary_publishes() {
    let w = world();
    let mut p = make(&w.p, &w.roster, true, &w.clock, timing(), false);
    p.connect();
    p.take();
    let mut r = Rogue::handshake(&w.a, &mut p, &w.net, 3).unwrap();
    let now = w.clock.unix_ms();
    let resign = |id: &Identity, network: &str, ts: u64| {
        crate::signed::Resignation::sign(id, network, ts).to_json().to_json_string().unwrap().into_bytes()
    };
    let msg = |json: Vec<u8>| [vec![session_type::RESIGN], json].concat();
    // Signed by another member, for another network, too old, tampered, malformed.
    r.send(&mut p, &msg(resign(&w.b, &w.net, now)));
    r.send(&mut p, &msg(resign(&w.a, w.b.id(), now)));
    r.send(&mut p, &msg(resign(&w.a, &w.net, now - 300_001)));
    let mut bad_sig = crate::signed::Resignation::sign(&w.a, &w.net, now);
    bad_sig.ts += 1;
    r.send(&mut p, &msg(bad_sig.to_json().to_json_string().unwrap().into_bytes()));
    r.send(&mut p, &msg(b"{\"node\":1}".to_vec()));
    assert_eq!(p.node.roster().version(), 3);
    r.send(&mut p, &msg(resign(&w.a, &w.net, now - 299_000)));
    assert_eq!(p.node.roster().version(), 4);
    assert!(p.node.roster().member(w.a.id()).is_none());
    let pushed = p.texts();
    assert!(pushed.iter().any(|t| t.get("type").and_then(Json::as_str) == Some("roster")), "pushed to the relay");
}

// ── The primary's side of pairing ──

fn failures(p: &mut T) -> Vec<String> {
    p.events()
        .into_iter()
        .filter_map(
            |e| if let Event::PairingFailed { reason, .. } = e { Some(reason.as_str().to_owned()) } else { None },
        )
        .collect()
}

fn pairing_msg(channel: &[u8; 16], code_id: &str) -> String {
    format!(r#"{{"type":"pairing","channel":"{}","code":"{code_id}"}}"#, crate::bytes::b64u(channel))
}

/// A newcomer through P1..P6; `None` where the primary stops answering.
fn attempt(p: &mut T, n: u8, code_text: &str, code_id: &str) -> Option<Json> {
    let id: [u8; 8] = crate::bytes::from_b64u_array(code_id).unwrap();
    let channel = [n; 16];
    let conn = p.conn;
    p.node.on_text(conn, &pairing_msg(&channel, code_id));
    let mut a = crate::pairing::NewcomerExchange::new(code_text, &id, None).unwrap();
    p.deliver_pair(&channel, &a.p1());
    let p2 = p.binaries().pop()?;
    p.deliver_pair(&channel, &a.on_p2(&p2[18..]).unwrap());
    let p4 = p.binaries().pop()?;
    let newcomer = Identity::from_seed(&[n; 32]);
    let keys = crate::pairing::NewcomerKeys { ed25519: newcomer.ed25519_public(), x25519: newcomer.x25519_public() };
    p.deliver_pair(&channel, &a.on_p4(&p4[18..], &keys).ok()?);
    let p6 = p.binaries().into_iter().find(|f| f[1] == frame_type::PAIR)?;
    a.on_p6(&p6[18..]).ok()
}

#[test]
fn the_primary_runs_pairing_and_burns_a_code_after_five_failures() {
    let w = world();
    let mut p = make(&w.p, &w.roster, true, &w.clock, timing(), false);
    p.connect();
    p.take();
    p.events();
    let code = primary::open_pairing_code(&mut p.node, None, None, false).unwrap();
    let wrong = if code.code == "AAAA-AAAA" { "BBBBBBBB" } else { "AAAAAAAA" };
    for n in 1..=4 {
        assert!(attempt(&mut p, n, wrong, &code.code_id).is_none());
    }
    assert_eq!(failures(&mut p), vec!["wrong-code"; 4]);
    // A newcomer that sends a malformed P1 is the fifth failure: the code burns.
    let channel = [5u8; 16];
    let conn = p.conn;
    p.node.on_text(conn, &pairing_msg(&channel, &code.code_id));
    p.deliver_pair(&channel, &[4u8; 65]);
    assert!(attempt(&mut p, 6, &code.code.replace('-', ""), &code.code_id).is_none(), "burned");
    let reasons = failures(&mut p);
    assert_eq!(reasons[0], "malformed", "{reasons:?}");
    assert_eq!(reasons[1], "unknown-code");
    assert_eq!(p.node.roster().version(), 3);
}

#[test]
fn a_pairing_channel_left_hanging_times_out_and_refunds_its_slot() {
    let w = world();
    let mut p = make(&w.p, &w.roster, true, &w.clock, timing(), false);
    p.connect();
    p.take();
    p.events();
    let code = primary::open_pairing_code(&mut p.node, None, None, false).unwrap();
    let wrong = if code.code == "AAAA-AAAA" { "BBBBBBBB" } else { "AAAAAAAA" };
    for n in 1..=4 {
        assert!(attempt(&mut p, n, wrong, &code.code_id).is_none());
    }
    let conn = p.conn;
    p.node.on_text(conn, &pairing_msg(&[9; 16], &code.code_id));
    // The fifth slot is held: the right code is turned away for now.
    assert!(attempt(&mut p, 10, &code.code.replace('-', ""), &code.code_id).is_none());
    w.clock.advance(60_000);
    p.node.poll();
    let reasons = failures(&mut p);
    assert_eq!(&reasons[4..], ["no-attempts", "timeout"]);
    let roster = Roster::from_json(attempt(&mut p, 11, &code.code.replace('-', ""), &code.code_id).unwrap()).unwrap();
    assert_eq!(roster.version(), 4);
    let newcomer = Identity::from_seed(&[11; 32]);
    assert!(roster.member(newcomer.id()).is_some());
    assert_eq!(p.node.roster(), &roster);
    assert!(p.events().iter().any(
        |e| matches!(e, Event::Paired { member, code_id, .. } if member.id() == newcomer.id() && *code_id == code.code_id)
    ));
    // Used: the code admits no one else.
    assert!(attempt(&mut p, 12, &code.code.replace('-', ""), &code.code_id).is_none());
}

#[test]
fn usage_answers_refusals_and_timeouts() {
    let w = world();
    let mut p = make(&w.p, &w.roster, true, &w.clock, timing(), false);
    p.connect();
    p.take();
    p.events();
    let conn = p.conn;
    let ask = |p: &mut T, id: &str| {
        let (tx, rx) = oneshot::channel();
        primary::usage_begin(&mut p.node, id, tx);
        primary::usage_send(&mut p.node, id);
        rx
    };
    let mut ok = ask(&mut p, "a");
    p.node.on_text(
        conn,
        r#"{"type":"usage","id":"a","network":{"bytesHour":10,"connections":3,"limits":{"rateBps":1,"quotaBytesHour":2,"trickleBps":3},"quotaUsed":0.5,"slowed":true}}"#,
    );
    let r = ok.try_recv().unwrap().unwrap();
    assert_eq!((r.bytes_hour, r.connections, r.quota_used, r.slowed), (10.0, 3.0, 0.5, true));
    assert_eq!((r.limits.rate_bps, r.limits.quota_bytes_hour, r.limits.trickle_bps), (1.0, 2.0, 3.0));
    let mut limited = ask(&mut p, "b");
    p.node.on_text(conn, r#"{"type":"error","code":"rate_limited","id":"b"}"#);
    assert_eq!(limited.try_recv().unwrap().unwrap_err().code(), ErrorCode::RateLimited);
    let mut forbidden = ask(&mut p, "c");
    p.node.on_text(conn, r#"{"type":"error","code":"forbidden","id":"c"}"#);
    assert_eq!(forbidden.try_recv().unwrap().unwrap_err().code(), ErrorCode::Refused);
    let mut slow = ask(&mut p, "d");
    w.clock.advance(10_000);
    p.node.poll();
    assert_eq!(slow.try_recv().unwrap().unwrap_err().code(), ErrorCode::Timeout);
    assert!(p.events().iter().all(|e| !matches!(e, Event::RelayError { .. })), "answers to asks are not relay errors");
    let mut lost = ask(&mut p, "e");
    p.node.on_close(conn, close_code::ABNORMAL, "");
    assert_eq!(lost.try_recv().unwrap().unwrap_err().code(), ErrorCode::Closed);
}

// ── Delivery and traffic ──

#[test]
fn several_messages_are_taken_together_or_not_at_all() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    for i in 0..3u8 {
        let mut rx = a.send(w.b.id(), &[i]);
        route(&mut [&mut a, &mut b]);
        assert_eq!(done(&mut rx), Some(Ok(())));
    }
    assert!(b.node.take_messages(4).is_none(), "fewer than asked: nothing taken");
    assert_eq!(b.node.waiting_messages(), 3);
    let two = b.node.take_messages(2).unwrap();
    assert_eq!(two.iter().map(|m| m.bytes[0]).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(b.node.waiting_messages(), 1);
}

#[test]
fn total_traffic_is_the_sum_over_peers() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let p = connected(&w, &w.p, &w.roster, timing());
    let mut rx = a.send(w.b.id(), &vec![1u8; 100_000]);
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    // The primary is not connected through the fake relay: an unreachable for it is counted
    // under the peer it names.
    drop(p);
    let mut rx = a.send(w.p.id(), b"x");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx).unwrap().unwrap_err().code(), ErrorCode::Unreachable);
    // A frame naming an id off the roster is counted too.
    let stranger = Identity::from_seed(&[9; 32]);
    a.deliver_from(&stranger, frame_type::DATA, &data_body(5, &[0; 20]));
    for t in [a.node.traffic(), b.node.traffic()] {
        let mut sum = PeerTraffic::default();
        for p in t.peers.values() {
            for (s, x) in [(&mut sum.sent, &p.sent), (&mut sum.received, &p.received)] {
                s.messages += x.messages;
                s.bytes += x.bytes;
                s.frames += x.frames;
                s.frame_bytes += x.frame_bytes;
            }
        }
        assert_eq!(sum, t.total);
    }
    let t = a.node.traffic();
    assert_eq!(t.peers[w.p.id()].received.frames, 1, "the unreachable");
    assert_eq!(t.peers[w.p.id()].received.frame_bytes, 18);
    assert_eq!(t.peers[stranger.id()].received.frame_bytes, 18 + 24);
    assert_eq!(t.peers[stranger.id()].sent.frame_bytes, 22, "the reset it was answered");
    // Frame sizes as the driver protocol tabulates them.
    let init = 126;
    let resp = 82;
    assert!(b.node.traffic().peers[w.a.id()].received.frame_bytes >= init);
    assert!(a.node.traffic().peers[w.b.id()].received.frame_bytes >= resp);
}

// ── What a peer or the relay can make this node send (security review H1, L1) ──

/// Roster frames `t` sent: the only frames this large.
fn roster_frames(t: &T) -> usize {
    t.binaries().iter().filter(|f| f.len() > 500).count()
}

#[test]
fn a_roster_request_flood_gets_one_answer_while_it_is_unsent_then_one_per_interval() {
    let w = world();
    let mut b = target(&w);
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    b.take();
    // The socket stops draining: nothing B queues is written.
    b.log.buffered.store(usize::MAX / 2, Ordering::SeqCst);
    for _ in 0..10_000 {
        r.send(&mut b, &[session_type::ROSTER_REQUEST]);
    }
    assert_eq!(roster_frames(&b), 1, "one answer, the rest coalesced");
    for _ in 0..20 {
        w.clock.advance(250);
        b.node.poll();
        r.send(&mut b, &[session_type::ROSTER_REQUEST]);
    }
    assert_eq!(roster_frames(&b), 0, "never a second roster while the first is unsent");
    // Drained: the coalesced answer goes, and from then on at most one per interval.
    b.log.buffered.store(0, Ordering::SeqCst);
    w.clock.advance(250);
    b.node.poll();
    assert_eq!(roster_frames(&b), 1);
    let mut answers = 0;
    for _ in 0..100 {
        for _ in 0..50 {
            r.send(&mut b, &[session_type::ROSTER_REQUEST]);
        }
        w.clock.advance(10);
        b.node.poll();
        answers += roster_frames(&b);
    }
    assert!((3..=5).contains(&answers), "{answers} answers in one second at one per 250 ms");
    assert_eq!(b.node.sessions.info(w.a.id()).len(), 1, "an honest-looking session is not ended");
}

#[test]
fn a_newer_roster_is_queued_even_while_an_older_one_is_unsent() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let mut rx = a.send(w.b.id(), b"x");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    a.log.buffered.store(usize::MAX / 2, Ordering::SeqCst);
    let v4 = roster_with(&w.p, 4, &[&w.a, &w.b]);
    let v5 = roster_with(&w.p, 5, &[&w.a, &w.b]);
    for r in [&v4, &v4, &v5, &v4] {
        sessions::send_control(&mut a.node, w.b.id(), Ctl::Roster(r.to_jcs(), r.version()), None, FailAction::Ignore);
    }
    assert_eq!(roster_frames(&a), 2, "v4 once, then v5; the repeats and the older one are dropped");
}

#[test]
fn a_reset_flood_is_answered_at_a_bounded_rate() {
    let w = world();
    let mut b = target(&w);
    // Distinct bad indices, as a relay can forge them: resets stop at the budget.
    for i in 0..10_000u32 {
        b.deliver_from(&w.a, frame_type::DATA, &data_body(0x1000_0000 + i, &[0; 20]));
    }
    let resets = b.sent_kinds().iter().filter(|k| **k == frame_type::RESET).count();
    assert_eq!(resets, sessions::RESET_BURST as usize);
    w.clock.advance(1000);
    for i in 0..10_000u32 {
        b.deliver_from(&w.a, frame_type::DATA, &data_body(0x2000_0000 + i, &[0; 20]));
    }
    let resets = b.sent_kinds().iter().filter(|k| **k == frame_type::RESET).count();
    assert_eq!(resets, sessions::RESET_RATE as usize, "one second refills one second's worth");
    // One bad index, many frames: one reset per index per second.
    w.clock.advance(10_000);
    for _ in 0..1000 {
        b.deliver_from(&w.a, frame_type::DATA, &data_body(0xdead_beef, &[0; 20]));
    }
    assert_eq!(b.sent_kinds(), [frame_type::RESET]);
    w.clock.advance(sessions::RESET_REPEAT_MS);
    b.deliver_from(&w.a, frame_type::DATA, &data_body(0xdead_beef, &[0; 20]));
    assert_eq!(b.sent_kinds(), [frame_type::RESET]);
}

#[test]
fn an_overflowing_outbound_queue_drops_the_connection_and_redials() {
    let w = world();
    let (mut a, _b) = pair_ab(&w, timing());
    a.events();
    a.log.overflowed.store(true, Ordering::SeqCst);
    let mut rx = a.send(w.b.id(), b"x");
    assert_eq!(done(&mut rx).unwrap().unwrap_err().code(), ErrorCode::Closed, "refused at once, not queued");
    assert_eq!(a.state(), MemberState::Connected, "dropped at the next poll, not mid-send");
    a.node.poll();
    assert_eq!(a.state(), MemberState::Disconnected);
    let codes: Vec<u16> = a
        .events()
        .iter()
        .filter_map(|e| if let Event::Disconnect { code, .. } = e { Some(*code) } else { None })
        .collect();
    assert_eq!(codes, [close_code::ABNORMAL]);
    assert_eq!(*a.log.closed.lock().unwrap(), Some(close_code::ABNORMAL));
    w.clock.advance(500);
    a.node.poll();
    assert!(a.node.take_dial().is_some(), "redialled with backoff");
}

#[test]
fn handshake_inits_are_limited_per_peer_and_for_strangers() {
    let w = world();
    let mut b = target(&w);
    let answered = (0..100).filter(|_| Rogue::handshake(&w.a, &mut b, &w.net, 3).is_some()).count();
    assert_eq!(answered, sessions::INIT_BURST as usize);
    w.clock.advance(1000);
    let answered = (0..100).filter(|_| Rogue::handshake(&w.a, &mut b, &w.net, 3).is_some()).count();
    assert_eq!(answered, sessions::INIT_RATE as usize, "one second refills one second's worth");
    // Another member is not held back by the first one's flood.
    assert!(Rogue::handshake(&w.p, &mut b, &w.net, 3).is_some());
    // Ids off the roster: each its own budget (an init processed is answered `refused`).
    b.take();
    let refused_from = |b: &mut T, who: &Identity, n: usize| {
        for _ in 0..n {
            deliver_init(b, who, &w);
        }
        b.sent_kinds().iter().filter(|k| **k == frame_type::REFUSED).count()
    };
    let stranger = Identity::from_seed(&[200; 32]);
    assert_eq!(refused_from(&mut b, &stranger, 100), sessions::STRANGER_INIT_BURST as usize);
}

/// A handshake-init from `who` (with the roster version 3) delivered to `b`.
fn deliver_init(b: &mut T, who: &Identity, w: &World) {
    deliver_init_v(b, who, w, 3);
}

fn deliver_init_v(b: &mut T, who: &Identity, w: &World, version: u64) {
    let prologue = session_prologue(&w.net);
    let mut hs = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: true,
        prologue: &prologue,
        s: Some(KeyPair::from_private(&who.x25519_private())),
        rs: Some(b.identity.x25519_public()),
        fixed_ephemeral: None,
    })
    .unwrap();
    let (m1, _) = hs.write_message(&payload(version)).unwrap();
    b.deliver_from(who, frame_type::HANDSHAKE_INIT, &handshake_init_body(7, &m1));
}

/// Review M1: one member flooding bad indices must not use up the resets owed to another. With
/// a budget shared by all peers, the honest peer here got almost none of its resets.
#[test]
fn one_peers_reset_flood_does_not_starve_another_peers_resets() {
    let w = world();
    let mut b = target(&w);
    let mut honest = 0;
    for round in 0..30u32 {
        // The attacker: 2000 frames naming fresh unknown indices every 100 ms.
        for i in 0..2000u32 {
            b.deliver_from(&w.a, frame_type::DATA, &data_body(0x1000_0000 + round * 2000 + i, &[0; 20]));
        }
        b.take();
        // The honest peer (the primary): one frame on a session B no longer holds.
        b.deliver_from(&w.p, frame_type::DATA, &data_body(0xa000_0000 + round, &[0; 20]));
        honest += b
            .binaries()
            .iter()
            .filter(|f| f[1] == frame_type::RESET && f[2..18] == node_id_to_bytes(w.p.id()).unwrap())
            .count();
        w.clock.advance(100);
    }
    assert_eq!(honest, 30, "every reset owed to the honest peer was sent");
}

/// Review L3: a stranger flooding inits does not drain another stranger's budget, and an init
/// from an id off the roster has the primary asked for a newer roster, at most once a second.
#[test]
fn one_strangers_init_flood_does_not_block_another_and_hints_a_roster_fetch() {
    let w = world();
    // A primary-connected member: the hint asks the primary (a handshake-init to it).
    let mut b = target(&w);
    let flooder = Identity::from_seed(&[201; 32]);
    let newcomer = Identity::from_seed(&[202; 32]);
    for _ in 0..500 {
        deliver_init(&mut b, &flooder, &w);
    }
    let sent = b.binaries();
    let refused = sent.iter().filter(|f| f[1] == frame_type::REFUSED).count();
    assert_eq!(refused, sessions::STRANGER_INIT_BURST as usize, "the flooder spends its own budget only");
    let asks = sent
        .iter()
        .filter(|f| f[1] == frame_type::HANDSHAKE_INIT && f[2..18] == node_id_to_bytes(w.p.id()).unwrap())
        .count();
    assert_eq!(asks, 1, "one roster fetch from the primary, however many hints");
    deliver_init(&mut b, &newcomer, &w);
    assert_eq!(b.sent_kinds(), [frame_type::REFUSED], "the newcomer's init is still processed");
}

/// Review L2: a peer that keeps showing an old roster version in its handshakes is handed this
/// member's roster at most once per interval, and never twice while one is unsent.
#[test]
fn rosters_handed_to_a_peer_behind_are_coalesced() {
    let w = world();
    let mut b = target(&w);
    b.take();
    for _ in 0..20 {
        deliver_init_v(&mut b, &w.a, &w, 2);
    }
    assert_eq!(roster_frames(&b), 1, "one roster for 20 handshakes within 250 ms");
    w.clock.advance(250);
    b.node.poll();
    assert_eq!(roster_frames(&b), 1, "and the coalesced one at the end of the interval");
}

#[test]
fn budgets_carry_across_a_new_connection() {
    // A relay that forces reconnects does not get budgets back in full: they refill with time.
    let w = world();
    let mut b = target(&w);
    let answered = (0..100).filter(|_| Rogue::handshake(&w.a, &mut b, &w.net, 3).is_some()).count();
    assert_eq!(answered, sessions::INIT_BURST as usize);
    let conn = b.conn;
    b.node.on_close(conn, close_code::GOING_AWAY, "");
    w.clock.advance(500);
    b.node.poll();
    b.open_and_register(None);
    b.take();
    let after = (0..100).filter(|_| Rogue::handshake(&w.a, &mut b, &w.net, 3).is_some()).count();
    assert_eq!(after, (sessions::INIT_RATE / 2) as usize, "half a second's refill, not a full budget");
}

// ── What a relay can make a node raise as events ──

fn primary_node(w: &World) -> T {
    let mut p = make(&w.p, &w.roster, true, &w.clock, timing(), false);
    p.connect();
    p.take();
    p.events();
    p
}

fn pair_ends(p: &T) -> usize {
    p.texts().iter().filter(|t| t.get("type").and_then(Json::as_str) == Some("pairEnd")).count()
}

#[test]
fn a_relay_streaming_pairings_for_unknown_codes_raises_no_events_and_few_answers() {
    let w = world();
    let mut p = primary_node(&w);
    let mut seen = p.node.observe();
    let conn = p.conn;
    for i in 0..10_000u32 {
        let channel: [u8; 16] = crate::crypto::random_array();
        let code: [u8; 8] = (u64::from(i) << 8).to_be_bytes();
        p.node.on_text(conn, &pairing_msg(&channel, &crate::bytes::b64u(&code)));
    }
    assert!(p.events().is_empty(), "no event for a code id this primary never opened");
    assert!(seen.try_recv().is_none(), "nothing queued for an observer either");
    assert_eq!(pair_ends(&p), 64, "pairEnd answers stop at their budget");
    w.clock.advance(1000);
    let channel: [u8; 16] = crate::crypto::random_array();
    p.node.on_text(conn, &pairing_msg(&channel, "AAAAAAAAAAA"));
    assert_eq!(pair_ends(&p), 1, "and refill");
}

#[test]
fn refusals_for_a_closed_code_raise_one_event_a_second() {
    let w = world();
    let mut p = primary_node(&w);
    let code = primary::open_pairing_code(&mut p.node, None, None, true).unwrap();
    primary::cancel_pairing_code(&mut p.node, &code.code_id);
    let conn = p.conn;
    for _ in 0..1000 {
        let channel: [u8; 16] = crate::crypto::random_array();
        p.node.on_text(conn, &pairing_msg(&channel, &code.code_id));
    }
    assert_eq!(failures(&mut p), ["unknown-code"], "one event, not one each");
    w.clock.advance(1000);
    let channel: [u8; 16] = crate::crypto::random_array();
    p.node.on_text(conn, &pairing_msg(&channel, &code.code_id));
    assert_eq!(failures(&mut p), ["unknown-code"]);
    // An expired code is refused with its event too.
    let short = primary::open_pairing_code(&mut p.node, Some(10), None, true).unwrap();
    w.clock.advance(20);
    p.node.on_text(conn, &pairing_msg(&[3; 16], &short.code_id));
    assert_eq!(failures(&mut p), ["unknown-code"]);
}

#[test]
fn a_relay_streaming_errors_raises_events_at_a_bounded_rate() {
    let w = world();
    let mut a = connected(&w, &w.a, &w.roster, timing());
    a.events();
    let conn = a.conn;
    for _ in 0..10_000 {
        a.node.on_text(conn, r#"{"type":"error","code":"bad_request"}"#);
    }
    assert_eq!(a.events().len(), 64);
    w.clock.advance(1000);
    for _ in 0..100 {
        a.node.on_text(conn, r#"{"type":"error","code":"bad_request"}"#);
    }
    assert_eq!(a.events().len(), 16);
}

#[test]
fn an_observer_that_falls_behind_drops_its_oldest_and_says_how_many() {
    let w = world();
    let mut b = target(&w);
    let mut seen = b.node.observe();
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    for i in 0..3000u32 {
        r.fragment(&mut b, false, &i.to_be_bytes());
    }
    // The marker first, then the newest 1024, in order.
    assert!(matches!(seen.try_recv(), Some(Observed::Lagged(1976))));
    let mut got = Vec::new();
    while let Some(o) = seen.try_recv() {
        let Observed::Message(m) = o else { panic!("{o:?}") };
        got.push(u32::from_be_bytes(m.bytes[..].try_into().unwrap()));
    }
    assert_eq!(got, (1976..3000).collect::<Vec<_>>());
    assert_eq!(b.node.waiting_messages(), 3000, "the messages themselves are still there to take");
    // It goes on observing after the gap.
    r.fragment(&mut b, false, b"next");
    assert!(matches!(seen.try_recv(), Some(Observed::Message(m)) if &m.bytes[..] == b"next"));
}

#[tokio::test]
async fn an_observation_ends_when_the_member_goes() {
    let w = world();
    let mut a = connected(&w, &w.a, &w.roster, timing());
    let mut seen = a.node.observe();
    a.node.close();
    assert!(matches!(seen.recv().await, Some(Observed::Event(Event::State(MemberState::Closed)))));
    assert!(matches!(seen.recv().await, Some(Observed::Event(Event::Disconnect { .. }))));
    drop(a);
    assert!(seen.recv().await.is_none());
    // A dropped observation is forgotten by the member.
    let mut b = target(&w);
    drop(b.node.observe());
    b.node.on_text(b.conn, r#"{"type":"error","code":"x"}"#);
    assert!(b.node.observers.is_empty());
}

#[test]
fn relay_error_events_carry_short_fields() {
    let w = world();
    let mut a = connected(&w, &w.a, &w.roster, timing());
    a.events();
    let conn = a.conn;
    let long = "é".repeat(20_000); // 40 KB a field, under the 128 KiB control limit in all
    a.node.on_text(conn, &format!(r#"{{"type":"error","code":"{long}","message":"{long}","id":"{long}"}}"#));
    let ev = a.events();
    let Some(Event::RelayError { code, message, id }) = ev.first() else { panic!("{ev:?}") };
    for f in [code, message.as_ref().unwrap(), id.as_ref().unwrap()] {
        assert!(f.len() <= RELAY_ERROR_TEXT && f.len() >= RELAY_ERROR_TEXT - 1, "{}", f.len());
        assert!(f.chars().all(|c| c == 'é'), "cut on a character boundary");
    }
}

#[test]
fn an_empty_fragment_saying_more_follow_ends_the_session() {
    let w = world();
    let mut b = target(&w);
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    r.fragment(&mut b, false, &[]);
    assert_eq!(b.take_all().len(), 1, "an empty last fragment is an empty message");
    r.fragment(&mut b, true, &[]);
    assert!(b.node.sessions.info(w.a.id()).is_empty(), "an empty one saying more follow is not");
}

#[test]
fn refusals_for_issued_codes_are_answered_whatever_made_up_ids_used() {
    let w = world();
    let mut p = primary_node(&w);
    let expired = primary::open_pairing_code(&mut p.node, Some(10), None, true).unwrap();
    let cancelled = primary::open_pairing_code(&mut p.node, None, None, true).unwrap();
    primary::cancel_pairing_code(&mut p.node, &cancelled.code_id);
    w.clock.advance(20);
    let conn = p.conn;
    // Newcomers with made-up code ids use up the shared answers.
    for i in 0..1000u64 {
        let channel: [u8; 16] = crate::crypto::random_array();
        p.node.on_text(conn, &pairing_msg(&channel, &crate::bytes::b64u(&(i << 8).to_be_bytes())));
    }
    assert_eq!(pair_ends(&p), 64);
    // An honest newcomer with an expired or a cancelled code is still answered at once.
    p.node.on_text(conn, &pairing_msg(&[1; 16], &expired.code_id));
    p.node.on_text(conn, &pairing_msg(&[2; 16], &cancelled.code_id));
    assert_eq!(pair_ends(&p), 2);
    // Repeats on the same code and channel at most once a second.
    p.node.on_text(conn, &pairing_msg(&[1; 16], &expired.code_id));
    assert_eq!(pair_ends(&p), 0);
    w.clock.advance(1000);
    p.node.on_text(conn, &pairing_msg(&[1; 16], &expired.code_id));
    assert_eq!(pair_ends(&p), 1);
}

#[test]
fn someone_holding_a_code_id_cannot_use_up_another_newcomers_answer() {
    let w = world();
    let mut p = primary_node(&w);
    let code = primary::open_pairing_code(&mut p.node, None, None, true).unwrap();
    primary::cancel_pairing_code(&mut p.node, &code.code_id);
    let conn = p.conn;
    // Someone with the code id refuses itself over and over on its channel...
    for _ in 0..100 {
        p.node.on_text(conn, &pairing_msg(&[7; 16], &code.code_id));
    }
    assert_eq!(pair_ends(&p), 1);
    // ...and the newcomer on its own channel is answered at once all the same.
    p.node.on_text(conn, &pairing_msg(&[8; 16], &code.code_id));
    assert_eq!(pair_ends(&p), 1);
}

#[test]
fn a_newer_default_code_closes_the_one_before_it_and_separate_codes_sit_beside_it() {
    use crate::code::DEFAULT_CODE_ID;
    let w = world();
    let mut p = primary_node(&w);
    let conn = p.conn;
    // Until a default code is opened its id is one never issued: refused with no event.
    p.node.on_text(conn, &pairing_msg(&[1; 16], DEFAULT_CODE_ID));
    assert_eq!(pair_ends(&p), 1);
    assert!(failures(&mut p).is_empty());
    let first = primary::open_pairing_code(&mut p.node, None, Some("AAAAAAAA"), false).unwrap();
    assert_eq!(first.code_id, DEFAULT_CODE_ID);
    assert!(!first.link.contains("&i="), "no i for the default code: {}", first.link);
    let beside = primary::open_pairing_code(&mut p.node, None, None, true).unwrap();
    assert_ne!(beside.code_id, DEFAULT_CODE_ID);
    assert!(beside.link.contains(&format!("&i={}&", beside.code_id)));
    // A newcomer is midway through the first default code when a second one opens: its
    // channel ends, and the first code admits nobody from then on.
    p.node.on_text(conn, &pairing_msg(&[2; 16], DEFAULT_CODE_ID));
    let mut a = crate::pairing::NewcomerExchange::new("AAAAAAAA", &[0; 8], None).unwrap();
    p.deliver_pair(&[2; 16], &a.p1());
    let p2 = p.binaries().pop().unwrap();
    let second = primary::open_pairing_code(&mut p.node, None, Some("BBBBBBBB"), false).unwrap();
    assert_eq!(second.code_id, DEFAULT_CODE_ID);
    assert_eq!(pair_ends(&p), 1, "the first default code's channel ends");
    assert_eq!(failures(&mut p), ["unknown-code"]);
    p.deliver_pair(&[2; 16], &a.on_p2(&p2[18..]).unwrap());
    assert!(p.binaries().is_empty(), "nothing answers on the ended channel");
    assert!(attempt(&mut p, 3, "AAAAAAAA", DEFAULT_CODE_ID).is_none());
    assert_eq!(failures(&mut p), ["wrong-code"], "the default code is the second one now");
    // The separate code and the default code each admit one node, and say which they were.
    assert!(attempt(&mut p, 4, &beside.code.replace('-', ""), &beside.code_id).is_some());
    assert!(attempt(&mut p, 5, "BBBBBBBB", DEFAULT_CODE_ID).is_some());
    let paired: Vec<String> = p
        .events()
        .into_iter()
        .filter_map(|e| if let Event::Paired { code_id, .. } = e { Some(code_id) } else { None })
        .collect();
    assert_eq!(paired, [beside.code_id.clone(), DEFAULT_CODE_ID.to_owned()]);
    // A cancelled code's channels end with it.
    let third = primary::open_pairing_code(&mut p.node, None, None, false).unwrap();
    p.texts();
    p.node.on_text(conn, &pairing_msg(&[7; 16], DEFAULT_CODE_ID));
    assert_eq!(pair_ends(&p), 0);
    w.clock.advance(1000);
    primary::cancel_pairing_code(&mut p.node, &third.code_id);
    assert_eq!(pair_ends(&p), 1, "the cancelled code's channel ends");
    assert_eq!(failures(&mut p), ["unknown-code"]);
    // With no default code open, its id is refused as a closed code: answered, with an event.
    w.clock.advance(1000);
    p.node.on_text(conn, &pairing_msg(&[6; 16], DEFAULT_CODE_ID));
    assert_eq!(pair_ends(&p), 1);
    assert_eq!(failures(&mut p), ["unknown-code"]);
}

/// A newcomer on channel `[n; 16]` that has sent P1 and holds P2, ready to send P3.
fn midway(p: &mut T, n: u8, code_text: &str, code_id: &str) -> (crate::pairing::NewcomerExchange, Vec<u8>) {
    let id: [u8; 8] = crate::bytes::from_b64u_array(code_id).unwrap();
    let conn = p.conn;
    p.node.on_text(conn, &pairing_msg(&[n; 16], code_id));
    let a = crate::pairing::NewcomerExchange::new(code_text, &id, None).unwrap();
    p.deliver_pair(&[n; 16], &a.p1());
    let p2 = p.binaries().pop().expect("P2");
    (a, p2)
}

#[test]
fn a_cancelled_code_ends_its_pairing_channels_at_once() {
    let w = world();
    let mut p = primary_node(&w);
    let code = primary::open_pairing_code(&mut p.node, None, Some("CCCCCCCC"), true).unwrap();
    let (mut a, p2) = midway(&mut p, 1, "CCCCCCCC", &code.code_id);
    primary::cancel_pairing_code(&mut p.node, &code.code_id);
    let ends: Vec<String> = p
        .texts()
        .iter()
        .filter(|t| t.get("type").and_then(Json::as_str) == Some("pairEnd"))
        .filter_map(|t| t.get("channel").and_then(Json::as_str).map(str::to_owned))
        .collect();
    assert_eq!(ends, [crate::bytes::b64u(&[1; 16])]);
    assert_eq!(failures(&mut p), ["unknown-code"]);
    // The right code on that channel goes unanswered, and the roster is unchanged.
    let version = p.node.roster().version();
    p.deliver_pair(&[1; 16], &a.on_p2(&p2[18..]).unwrap());
    assert!(p.binaries().is_empty());
    assert_eq!(p.node.roster().version(), version);
}

#[test]
fn a_stale_channel_on_an_expired_default_code_never_touches_the_default_code_after_it() {
    use crate::code::DEFAULT_CODE_ID;
    let w = world();
    let mut p = primary_node(&w);
    // The first default code: four wrong attempts, then two newcomers midway, one with the
    // right code and one with a wrong one (its last attempt).
    primary::open_pairing_code(&mut p.node, Some(10_000), Some("AAAAAAAA"), false).unwrap();
    for n in 1..=3 {
        assert!(attempt(&mut p, n, "ZZZZZZZZ", DEFAULT_CODE_ID).is_none());
    }
    let (mut right, right_p2) = midway(&mut p, 4, "AAAAAAAA", DEFAULT_CODE_ID);
    let (mut wrong, wrong_p2) = midway(&mut p, 5, "ZZZZZZZZ", DEFAULT_CODE_ID);
    // It expires, and a second default code opens under the same id.
    w.clock.advance(10_000);
    primary::open_pairing_code(&mut p.node, None, Some("BBBBBBBB"), false).unwrap();
    assert_eq!(pair_ends(&p), 2, "both stale channels end");
    p.events();
    // Whatever the stale channels send now, the second code neither closes nor burns...
    p.deliver_pair(&[5; 16], &wrong.on_p2(&wrong_p2[18..]).unwrap());
    p.deliver_pair(&[4; 16], &right.on_p2(&right_p2[18..]).unwrap());
    assert!(p.binaries().is_empty(), "no P4 for a stale channel");
    assert!(p.events().iter().all(|e| !matches!(e, Event::Paired { .. })));
    // ...and still admits one node, with its own five attempts.
    for n in 6..=9 {
        assert!(attempt(&mut p, n, "ZZZZZZZZ", DEFAULT_CODE_ID).is_none());
    }
    let roster = Roster::from_json(attempt(&mut p, 10, "BBBBBBBB", DEFAULT_CODE_ID).unwrap()).unwrap();
    assert!(roster.member(Identity::from_seed(&[10; 32]).id()).is_some());
}

/// An init in `named`'s name, on a static key that is not `named`'s (as a relay could forge, or
/// `named` itself could send).
fn bogus_init(w: &World, b: &mut T, named: &Identity) {
    bogus_init_v(w, b, named, 3);
}

fn bogus_init_v(w: &World, b: &mut T, named: &Identity, version: u64) {
    let prologue = session_prologue(&w.net);
    let mut hs = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: true,
        prologue: &prologue,
        s: Some(KeyPair::from_private(&[0x5a; 32])),
        rs: Some(b.identity.x25519_public()),
        fixed_ephemeral: None,
    })
    .unwrap();
    let (m1, _) = hs.write_message(&payload(version)).unwrap();
    b.deliver_from(named, frame_type::HANDSHAKE_INIT, &handshake_init_body(7, &m1));
}

#[test]
fn inits_that_fail_in_a_members_name_starve_only_that_member() {
    let w = world();
    let mut b = target(&w);
    b.take();
    // Inits in A's name on a key that is not A's: each fails the key check and is refused, until
    // A's failure budget is spent; then A's inits are dropped before any DH.
    for _ in 0..200 {
        bogus_init(&w, &mut b, &w.a);
        w.clock.advance(1);
    }
    let refused = b.sent_kinds().iter().filter(|k| **k == frame_type::REFUSED).count();
    assert_eq!(refused, sessions::MEMBER_FAILURE_BURST as usize);
    // A's own genuine init waits for its budget to refill...
    assert!(Rogue::handshake(&w.a, &mut b, &w.net, 3).is_none());
    // ...while another member's goes through at once.
    assert!(Rogue::handshake(&w.p, &mut b, &w.net, 3).is_some());
    w.clock.advance(500);
    assert!(Rogue::handshake(&w.a, &mut b, &w.net, 3).is_some());
}

/// Re-review 4, L4 (`forged_version_push.rs`): an init in A's name on a key that is not A's, claiming
/// an older roster, had the victim open a session to A and push it the roster; claiming a newer
/// one, ask A for it. Re-review 5, M3: nor may it ask the primary (a member sending these to every
/// other would have each fetch the whole roster, N² a second). The version is ignored.
#[test]
fn a_version_claimed_by_an_init_that_fails_the_key_check_is_not_acted_on() {
    let w = world();
    let mut b = target(&w);
    b.take();
    let peer_of = |f: &Vec<u8>| decode_frame(f).unwrap().peer;
    let a = node_id_to_bytes(w.a.id()).unwrap();
    bogus_init_v(&w, &mut b, &w.a, 0);
    let sent = b.binaries();
    assert_eq!(sent.iter().map(|f| (f[1], peer_of(f))).collect::<Vec<_>>(), [(frame_type::REFUSED, a)]);
    assert!(!b.node.sessions.engaged(w.a.id()), "no session opened to A, no roster queued for it");
    bogus_init_v(&w, &mut b, &w.a, 9);
    let sent: Vec<_> = b.binaries().iter().map(|f| (f[1], peer_of(f))).collect();
    assert_eq!(sent, [(frame_type::REFUSED, a)], "nothing asked of A or of the primary");
    assert!(!b.node.sessions.engaged(w.a.id()), "nothing asked of A");
    assert!(!b.node.sessions.engaged(w.p.id()), "nothing asked of the primary");
    assert_eq!(b.node.sessions.hints, 0);
}

#[test]
fn unreadable_inits_in_a_members_name_are_charged_to_that_member() {
    let w = world();
    let mut b = target(&w);
    b.take();
    // Well-formed frames in A's name whose Noise message does not decrypt.
    for i in 0..200u32 {
        let mut junk = vec![0u8; 96];
        junk[..4].copy_from_slice(&i.to_be_bytes());
        junk[0] = 9; // a non-zero ephemeral key
        b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &handshake_init_body(7, &junk));
    }
    assert!(b.binaries().is_empty(), "unreadable inits get no answer");
    // A's budget is spent: its genuine init waits for it to refill; P's never did.
    assert!(Rogue::handshake(&w.a, &mut b, &w.net, 3).is_none());
    assert!(Rogue::handshake(&w.p, &mut b, &w.net, 3).is_some());
    w.clock.advance(500);
    assert!(Rogue::handshake(&w.a, &mut b, &w.net, 3).is_some());
}

/// Re-review 4, M2 (`member_init_ceiling.rs`): eight members stream inits in their own names on a
/// bogus key. With one failure ceiling shared by all members, an honest member's handshakes were
/// all dropped (0 of 28 against the real relay); each member's own budget leaves it untouched.
#[test]
fn members_failing_their_own_inits_cannot_block_an_honest_member() {
    let w = world();
    let attackers: Vec<Identity> = (0..8u8).map(|i| Identity::from_seed(&[40 + i; 32])).collect();
    let honest = Identity::from_seed(&[60; 32]);
    let mut others: Vec<&Identity> = attackers.iter().collect();
    others.push(&honest);
    others.push(&w.b);
    let roster = roster_with(&w.p, 3, &others);
    let mut b = connected(&w, &w.b, &roster, timing());
    // One bogus init per attacker, replayed: each copy costs the victim a DH if it is processed.
    let prologue = session_prologue(&w.net);
    let floods: Vec<Vec<u8>> = attackers
        .iter()
        .map(|_| {
            let mut hs = HandshakeState::new(HandshakeOptions {
                pattern: &IK,
                initiator: true,
                prologue: &prologue,
                s: Some(KeyPair::from_private(&[0x5a; 32])),
                rs: Some(w.b.x25519_public()),
                fixed_ephemeral: None,
            })
            .unwrap();
            handshake_init_body(7, &hs.write_message(&payload(3)).unwrap().0)
        })
        .collect();
    let (mut attempts, mut completed) = (0, 0);
    // 3 s of 64 inits per attacker every 20 ms, the honest member handshaking every 100 ms.
    for tick in 0..150 {
        for (a, init) in attackers.iter().zip(&floods) {
            for _ in 0..64 {
                b.deliver_from(a, frame_type::HANDSHAKE_INIT, init);
            }
        }
        if tick % 5 == 4 {
            attempts += 1;
            completed += usize::from(Rogue::handshake(&honest, &mut b, &w.net, 3).is_some());
        }
        w.clock.advance(20);
    }
    assert_eq!(completed, attempts, "{completed} of {attempts} honest handshakes completed");
}

#[test]
fn resets_to_made_up_ids_have_a_ceiling_together() {
    let w = world();
    let mut b = target(&w);
    b.take();
    for i in 0..2000u32 {
        let fake: [u8; 16] = crate::crypto::random_array();
        let f = encode_frame(frame_type::DATA, &fake, &data_body(i + 1, &[0; 20])).unwrap();
        let conn = b.conn;
        b.node.on_binary(conn, &f);
    }
    let resets = b.sent_kinds().iter().filter(|k| **k == frame_type::RESET).count();
    assert_eq!(resets, sessions::STRANGERS_RESET_BURST as usize);
    // A member still gets its own resets.
    b.deliver_from(&w.a, frame_type::DATA, &data_body(0xdead_beef, &[0; 20]));
    assert_eq!(b.sent_kinds(), [frame_type::RESET]);
}

#[test]
fn tiny_fragments_cost_no_more_heap_than_the_caps_count() {
    let w = world();
    let mut b = target(&w);
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    for _ in 0..100_000 {
        r.fragment(&mut b, true, &[1]);
    }
    let (len, capacity) = b.node.sessions.reassembly(w.a.id());
    assert_eq!(len, 100_000);
    // One contiguous buffer: at most double what is counted, never per fragment.
    assert!(capacity <= 2 * len, "{capacity} bytes of heap for {len} counted");
    assert_eq!(b.node.sessions.info(w.a.id()).len(), 1);
}

#[test]
fn an_init_on_a_members_key_without_a_roster_version_is_a_failed_init() {
    let w = world();
    let mut b = target(&w);
    b.take();
    let prologue = session_prologue(&w.net);
    // Nothing, a bare roster version (the old 8 bytes), and one byte too many.
    for payload in [&[][..], &[0; 8], &[0; 17]].iter().cycle().take(6) {
        let mut hs = HandshakeState::new(HandshakeOptions {
            pattern: &IK,
            initiator: true,
            prologue: &prologue,
            s: Some(KeyPair::from_private(&w.a.x25519_private())),
            rs: Some(w.b.x25519_public()),
            fixed_ephemeral: None,
        })
        .unwrap();
        let (m1, _) = hs.write_message(payload).unwrap();
        b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &handshake_init_body(7, &m1));
    }
    assert!(b.binaries().is_empty(), "malformed inits are dropped unanswered");
    assert!(!b.node.sessions.engaged(w.a.id()));
    // They spent A's failure budget: A's next init waits for it, P's does not.
    assert!(Rogue::handshake(&w.a, &mut b, &w.net, 3).is_none());
    assert!(Rogue::handshake(&w.p, &mut b, &w.net, 3).is_some());
    w.clock.advance(500);
    assert!(Rogue::handshake(&w.a, &mut b, &w.net, 3).is_some());
}

/// Re-review 5, M3: hints that bring no newer roster double the wait before the next, from 1 s to
/// 5 minutes, so a relay making up ids cannot have every member fetch the roster every second; a
/// newer roster puts the wait back to 1 s.
#[test]
fn hints_that_bring_no_newer_roster_back_off_to_five_minutes() {
    let w = world();
    let mut b = target(&w);
    b.take();
    // An id off the roster whose init is read and refused, claiming a newer roster: a hint.
    let stranger = Identity::from_seed(&[90; 32]);
    let prologue = session_prologue(&w.net);
    let init = |b: &mut T| {
        let mut hs = HandshakeState::new(HandshakeOptions {
            pattern: &IK,
            initiator: true,
            prologue: &prologue,
            s: Some(KeyPair::from_private(&stranger.x25519_private())),
            rs: Some(w.b.x25519_public()),
            fixed_ephemeral: None,
        })
        .unwrap();
        let (m1, _) = hs.write_message(&payload(9)).unwrap();
        b.deliver_from(&stranger, frame_type::HANDSHAKE_INIT, &handshake_init_body(7, &m1));
        b.take();
    };
    // One a second: the seconds at which the primary was asked.
    let hints_over = |b: &mut T, secs: u64| {
        let mut at = Vec::new();
        for t in 0..secs {
            let before = b.node.sessions.hints;
            init(b);
            if b.node.sessions.hints > before {
                at.push(t);
            }
            w.clock.advance(1000);
        }
        at
    };
    let gaps = |at: &[u64]| at.windows(2).map(|p| p[1] - p[0]).collect::<Vec<_>>();
    let at = hints_over(&mut b, 20 * 60);
    assert_eq!(at[0], 0, "the first hint goes at once");
    let g = gaps(&at);
    assert_eq!(g[..10], [2, 4, 8, 16, 32, 64, 128, 256, 300, 300]);
    assert!(g[10..].iter().all(|g| *g == 300), "{g:?}");
    // A newer roster arrives (at least 1 s after the last hint): the next goes at once, and the
    // back-off starts over.
    let newer = roster_with(&w.p, 4, &[&w.a, &w.b]);
    b.node.adopt_roster(newer);
    let at = hints_over(&mut b, 8);
    assert_eq!(at[0], 0, "a hint after a newer roster waits only 1 s");
    assert_eq!(gaps(&at), [2, 4]);
}

#[test]
fn pairing_channel_setups_per_code_have_a_budget_and_ended_channels_few_events() {
    let w = world();
    let mut p = primary_node(&w);
    let code = primary::open_pairing_code(&mut p.node, None, None, false).unwrap();
    let conn = p.conn;
    // A relay sets channels up on an open code and ends each at once: the ending refunds the
    // attempt, so only the setup budget stops it.
    let mut set_up = 0;
    for i in 0..100u8 {
        let channel = [i; 16];
        p.node.on_text(conn, &pairing_msg(&channel, &code.code_id));
        if pair_ends(&p) == 0 {
            set_up += 1;
        }
        let end = format!(r#"{{"type":"pairEnd","channel":"{}"}}"#, crate::bytes::b64u(&channel));
        p.node.on_text(conn, &end);
    }
    assert_eq!(set_up, primary::CHANNEL_SETUP_BURST);
    let mut seen: Vec<(String, String)> = p
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::PairingFailed { reason, message, .. } => Some((reason.as_str().to_owned(), message)),
            _ => None,
        })
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        [
            ("newcomer-left".to_owned(), "the newcomer left".to_owned()),
            ("no-attempts".to_owned(), "too many attempts at once; try again".to_owned()),
        ],
        "one event per code and reason a second, the setup budget saying so"
    );
    // The budget refills at its rate; the code itself was never used up.
    w.clock.advance(1000);
    let mut set_up = 0;
    for i in 100..120u8 {
        p.node.on_text(conn, &pairing_msg(&[i; 16], &code.code_id));
        if pair_ends(&p) == 0 {
            set_up += 1;
        }
        let end = format!(r#"{{"type":"pairEnd","channel":"{}"}}"#, crate::bytes::b64u(&[i; 16]));
        p.node.on_text(conn, &end);
    }
    assert_eq!(set_up, primary::CHANNEL_SETUP_RATE);
    // An honest newcomer, once the budget has refilled, pairs with the code.
    w.clock.advance(1000);
    assert!(attempt(&mut p, 200, &code.code.replace('-', ""), &code.code_id).is_some());
}

#[test]
fn a_wall_clock_stepped_back_strands_no_budget_and_extends_no_code() {
    let w = world();
    let mut p = primary_node(&w);
    let code = primary::open_pairing_code(&mut p.node, Some(10_000), None, true).unwrap();
    let mut b = target(&w);
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    b.take();
    // Spend A's init budget, and have B answer A's roster-request.
    for _ in 0..64 {
        deliver_init(&mut b, &w.a, &w);
    }
    r.send(&mut b, &[session_type::ROSTER_REQUEST]);
    b.take();
    // The wall clock goes back 5 minutes while 11 s pass (within the stamp window, so stamps
    // are not what is tested here).
    w.clock.step_wall_back(300_000);
    w.clock.advance(11_000);
    // The code has expired all the same...
    let conn = p.conn;
    p.node.on_text(conn, &pairing_msg(&[1; 16], &code.code_id));
    assert_eq!(pair_ends(&p), 1);
    assert_eq!(failures(&mut p), ["unknown-code"]);
    // ...A's init budget has refilled...
    assert!(Rogue::handshake(&w.a, &mut b, &w.net, 3).is_some());
    // ...and a roster-request is answered again.
    let mut r = Rogue::handshake(&w.a, &mut b, &w.net, 3).unwrap();
    b.take();
    r.send(&mut b, &[session_type::ROSTER_REQUEST]);
    assert_eq!(roster_frames(&b), 1);
}

/// An init from an id off the roster, read and refused, claiming a newer roster: a hint.
fn stranger_hint(w: &World, b: &mut T) {
    let stranger = Identity::from_seed(&[90; 32]);
    let mut hs = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: true,
        prologue: &session_prologue(&w.net),
        s: Some(KeyPair::from_private(&stranger.x25519_private())),
        rs: Some(w.b.x25519_public()),
        fixed_ephemeral: None,
    })
    .unwrap();
    let (m1, _) = hs.write_message(&payload(9)).unwrap();
    b.deliver_from(&stranger, frame_type::HANDSHAKE_INIT, &handshake_init_body(7, &m1));
    b.take();
}

/// Go confirming review: a hint the back-off holds back must not be lost. With the wait at its
/// 5 minutes (the primary offline through earlier asks, say), a hint is deferred to the end of the
/// wait, one ask however many hints; and a newer version seen in `registered` asks at once.
#[test]
fn a_hint_held_back_by_the_wait_is_asked_when_the_wait_ends() {
    let w = world();
    let mut b = target(&w);
    b.take();
    // Fruitless hints, each as the last wait ends, until the wait is at its maximum.
    for _ in 0..12 {
        stranger_hint(&w, &mut b);
        w.clock.advance(sessions::ROSTER_HINT_MAX_INTERVAL_MS);
        b.node.poll();
        b.take();
    }
    stranger_hint(&w, &mut b);
    let asked = b.node.sessions.hints;
    // Hints during the wait ask nothing now...
    for _ in 0..5 {
        w.clock.advance(1000);
        stranger_hint(&w, &mut b);
    }
    assert_eq!(b.node.sessions.hints, asked);
    let due = b.node.next_deadline().unwrap();
    assert!(due <= b.node.now() + sessions::ROSTER_HINT_MAX_INTERVAL_MS, "the end of the wait is a deadline");
    w.clock.advance(sessions::ROSTER_HINT_MAX_INTERVAL_MS - 6000);
    b.node.poll();
    assert_eq!(b.node.sessions.hints, asked, "not before the wait ends");
    // ...and one ask goes when it ends, with no further hint.
    w.clock.advance(1000);
    b.node.poll();
    assert_eq!(b.node.sessions.hints, asked + 1);
    w.clock.advance(2 * sessions::ROSTER_HINT_MAX_INTERVAL_MS);
    b.node.poll();
    assert_eq!(b.node.sessions.hints, asked + 1, "one ask for all the hints held back");
    // With the wait at its maximum, a newer version in `registered` asks the primary at once.
    stranger_hint(&w, &mut b);
    w.clock.advance(1000);
    stranger_hint(&w, &mut b);
    let asks = b.node.sessions.primary_asks;
    let conn = b.conn;
    b.node.on_close(conn, close_code::ABNORMAL, "");
    while b.node.dial_request.is_none() {
        w.clock.advance(100);
        b.node.poll();
    }
    let registered = Json::object([
        ("type", Json::str("registered")),
        ("node", Json::str(w.b.id())),
        ("rosterVersion", Json::int(7)),
    ]);
    b.open_and_register(Some(registered));
    assert_eq!(b.node.sessions.primary_asks, asks + 1);
}

/// Message 1 of a handshake from `who` to `b`, carrying `version` and `stamp`.
fn stamped_init(w: &World, b: &T, who: &Identity, version: u64, stamp: u64) -> Vec<u8> {
    let mut hs = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: true,
        prologue: &session_prologue(&w.net),
        s: Some(KeyPair::from_private(&who.x25519_private())),
        rs: Some(b.identity.x25519_public()),
        fixed_ephemeral: None,
    })
    .unwrap();
    let (m1, _) = hs.write_message(&crate::frames::init_payload(version, stamp)).unwrap();
    handshake_init_body(u32::from_be_bytes(crate::crypto::random_array::<4>()) | 1, &m1)
}

fn sessions_with(b: &T, peer: &Identity) -> Vec<(u32, bool)> {
    b.node.sessions.info(peer.id()).iter().map(|s| (s.local_index, s.current)).collect()
}

#[test]
fn a_replayed_init_is_dropped_and_evicts_no_session() {
    let w = world();
    let mut b = target(&w);
    b.take();
    let init = stamped_init(&w, &b, &w.a, 3, 1_790_000_000_000);
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &init);
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    let before = sessions_with(&b, &w.a);
    assert_eq!(before.len(), 1);
    // The same bytes again, as a relay could replay them: nothing answered, nothing changed.
    for _ in 0..sessions::MEMBER_FAILURE_BURST {
        b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &init);
    }
    assert!(b.binaries().is_empty(), "a replay is dropped unanswered");
    assert_eq!(sessions_with(&b, &w.a), before, "no session made, none evicted");
    // Each replay was charged to A: its failure budget is spent, so even a fresh init waits.
    let fresh = stamped_init(&w, &b, &w.a, 3, 1_790_000_000_001);
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &fresh);
    assert!(b.binaries().is_empty());
    w.clock.advance(500);
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &fresh);
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
}

#[test]
fn an_init_stamped_no_later_than_the_last_accepted_is_refused_and_a_later_one_accepted() {
    let w = world();
    let mut b = target(&w);
    b.take();
    let t = 1_790_000_000_000;
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 3, t));
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    let before = sessions_with(&b, &w.a);
    // Fresh messages (new ephemeral keys), stamped earlier or the same: refused, version ignored
    // (an older one would otherwise draw a roster push).
    for stamp in [t - 1, t, 1] {
        b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 2, stamp));
    }
    assert!(b.binaries().is_empty());
    assert_eq!(sessions_with(&b, &w.a), before);
    // A later stamp is accepted, and becomes the one to beat.
    w.clock.advance(1000);
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 3, t + 1));
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 3, t + 1));
    assert!(b.binaries().is_empty());
    // Each member's stamps are its own.
    b.deliver_from(&w.p, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.p, 3, t - 5));
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    // The table holds roster members only: A off the roster, its entry goes.
    let without_a = roster_with(&w.p, 4, &[&w.b]);
    b.node.adopt_roster(without_a);
    assert_eq!(b.node.sessions.stamped(), [w.p.id().to_owned()]);
}

#[test]
fn inits_in_the_same_millisecond_get_increasing_stamps() {
    let w = world();
    let mut b = target(&w);
    b.take();
    // The stamp a peer reads from B's message 1.
    let stamp_to = |b: &mut T, peer: &Identity| {
        let _sent = b.send(peer.id(), b"x");
        let f = b.binaries().into_iter().find(|f| f[1] == frame_type::HANDSHAKE_INIT).unwrap();
        let (_, noise) = crate::frames::parse_handshake_init(&f[18..]).unwrap();
        let mut hs = HandshakeState::new(HandshakeOptions {
            pattern: &IK,
            initiator: false,
            prologue: &session_prologue(&w.net),
            s: Some(KeyPair::from_private(&peer.x25519_private())),
            rs: None,
            fixed_ephemeral: None,
        })
        .unwrap();
        let (payload, _) = hs.read_message(noise).unwrap();
        crate::frames::parse_init_payload(&payload).unwrap()
    };
    let wall = w.clock.unix_ms();
    let (version, first) = stamp_to(&mut b, &w.a);
    assert_eq!((version, first), (3, wall), "Unix milliseconds, and the roster version");
    let (_, second) = stamp_to(&mut b, &w.p);
    assert_eq!(second, first + 1, "same millisecond, next stamp");
    // The handshake with A times out while the wall clock goes back a minute: the next init
    // still stamps later than before.
    let timeout = b.node.timing.handshake_timeout;
    w.clock.advance(timeout + 1);
    w.clock.step_wall_back(timeout + 60_000);
    b.node.poll();
    b.take();
    let (_, third) = stamp_to(&mut b, &w.a);
    assert_eq!(third, second + 1);
}

fn client_vectors() -> Json {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors/client.json");
    Json::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// `spec/vectors/client.json` `handshakeStamps`: how a stamp is chosen, and a real responder
/// taking each message 1 of the steps in order.
#[test]
fn handshake_stamp_vectors() {
    let v = client_vectors();
    let hs = v.get("handshakeStamps").unwrap();
    let num = |j: &Json, k: &str| j.get(k).and_then(Json::as_safe_uint).unwrap_or_else(|| panic!("{k}"));
    let text = |j: &Json, k: &str| j.get(k).and_then(Json::as_str).unwrap_or_else(|| panic!("{k}")).to_owned();
    let hex = |j: &Json, k: &str| crate::bytes::from_hex(&text(j, k)).unwrap();
    let encoding = hs.get("encoding").and_then(Json::as_array).unwrap();
    assert!(!encoding.is_empty());
    for case in encoding {
        let stamp = sessions::next_stamp(num(case, "wallNowMs"), num(case, "lastStamp"));
        assert_eq!(stamp, num(case, "stamp"), "{}", case.to_json_string().unwrap());
    }

    // The identities are the key vectors', the network the Noise vector's.
    let keys = v.get("keys").and_then(Json::as_array).unwrap();
    let identity = |id: &str| {
        let k = keys.iter().find(|k| k.get("nodeId").and_then(Json::as_str) == Some(id)).unwrap();
        Identity::from_seed(&hex(k, "seed").try_into().unwrap())
    };
    let initiator = identity(&text(hs, "initiator"));
    let responder = identity(&text(hs, "responder"));
    let network = text(v.get("noise").unwrap(), "network");
    let nets = v.get("networkKeys").and_then(Json::as_array).unwrap();
    let net = nets.iter().find(|n| n.get("networkId").and_then(Json::as_str) == Some(network.as_str())).unwrap();
    let key = NetworkKey::from_seed(&hex(net, "networkSeed").try_into().unwrap());
    let primary = identity(keys[0].get("nodeId").and_then(Json::as_str).unwrap());
    assert_eq!(num(hs, "windowMs"), sessions::STAMP_WINDOW_MS);
    // The responder starts at responderStartedMs; each step runs at its own responderWallNowMs,
    // the monotonic clock moving with the wall clock (so the start, kept on the monotonic clock,
    // reads back as responderStartedMs).
    let clock = FakeClock::new();
    clock.set_wall(num(hs, "responderStartedMs"));
    let roster = roster_of(
        &key,
        12,
        &primary,
        vec![
            RosterMember::from_identity(&primary),
            RosterMember::from_identity(&initiator),
            RosterMember::from_identity(&responder),
        ],
    );
    let mut node = make(&responder, &roster, false, &clock, timing(), false);
    node.connect();
    node.take();

    let steps = hs.get("steps").and_then(Json::as_array).unwrap();
    assert_eq!(steps.len(), 15);
    let mut version = 12;
    let mut events = 0;
    for (n, step) in steps.iter().enumerate() {
        let wall = num(step, "responderWallNowMs");
        clock.advance(wall.checked_sub(clock.unix_ms()).expect("the steps move forward in time"));
        let what = format!("step {n}: {}", text(step, "description"));
        // A roster change, applied as any roster is (adopt_roster, then roster_changed).
        if let Some(event) = step.get("event").and_then(Json::as_str) {
            events += 1;
            version += 1;
            let others: &[&Identity] = match event {
                "removed" => &[&responder],
                "readmitted" => &[&initiator, &responder],
                other => panic!("{what}: unknown event {other}"),
            };
            let mut members = vec![RosterMember::from_identity(&primary)];
            members.extend(others.iter().map(|i| RosterMember::from_identity(i)));
            node.node.adopt_roster(roster_of(&key, version, &primary, members));
            node.take();
            let stored = node.node.sessions.stamp_of(initiator.id());
            match (event, step.get("stored").and_then(Json::as_safe_uint)) {
                ("removed", _) => assert_eq!(stored, None, "{what}: no stamp while off the roster"),
                (_, expected) => assert_eq!(stored, expected, "{what}: the stamp restored"),
            }
            continue;
        }
        let payload = hex(step, "payload");
        let stamp = step.get("stamp").and_then(Json::as_safe_uint);
        match stamp {
            Some(stamp) => assert_eq!(&payload[8..], stamp.to_be_bytes(), "{what}"),
            None => assert_eq!(payload.len(), 8, "{what}"),
        }
        let (sessions_before, stored_before) =
            (node.node.sessions.info(initiator.id()).len(), node.node.sessions.stamp_of(initiator.id()));
        node.deliver_from(
            &initiator,
            frame_type::HANDSHAKE_INIT,
            &handshake_init_body(n as u32 + 1, &hex(step, "noise")),
        );
        // After the roster events the initiator claims an older roster than the responder's, so
        // a roster may follow the answer.
        let sent = node.sent_kinds();
        let answered = sent.first() == Some(&frame_type::HANDSHAKE_RESP);
        assert!(answered || sent.is_empty(), "{what}: a refusal sends nothing, got {sent:?}");
        let accepted = step.get("accepted") == Some(&Json::Bool(true));
        assert_eq!(answered, accepted, "{what}");
        assert_eq!(
            node.node.sessions.info(initiator.id()).len(),
            sessions_before + usize::from(accepted),
            "{what}: a session only when accepted"
        );
        // The stamp kept after the step: as the vector says, or else unchanged by a refusal.
        let stored = node.node.sessions.stamp_of(initiator.id());
        match step.get("stored").and_then(Json::as_safe_uint) {
            Some(expected) => assert_eq!(stored, Some(expected), "{what}: the stamp kept"),
            None if accepted => assert_eq!(stored, stamp, "{what}: the stamp kept"),
            None => assert_eq!(stored, stored_before, "{what}: a refusal keeps the stamp"),
        }
    }
    assert_eq!(events, 2, "removed, then readmitted");
}

/// TS confirming review: an init stamped more than W = 10 minutes ahead of the responder's wall
/// clock is refused and nothing is kept (kept, it would shut the member out; capped, as before,
/// the same bytes could be replayed again and again). One within W is taken as stamped.
#[test]
fn an_init_stamped_too_far_ahead_is_refused_and_keeps_nothing() {
    let w = world();
    let mut b = target(&w);
    b.take();
    let wall = w.clock.unix_ms();
    for ahead in [86_400_000, sessions::STAMP_WINDOW_MS + 1] {
        let far = stamped_init(&w, &b, &w.a, 3, wall + ahead);
        for _ in 0..2 {
            w.clock.advance(1000);
            w.clock.step_wall_back(1000);
            b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &far);
            assert!(b.binaries().is_empty(), "{ahead} ms ahead is refused, replayed or not");
        }
        assert_eq!(b.node.sessions.stamp_of(w.a.id()), None, "nothing kept");
    }
    // Within W: accepted, and kept as stamped.
    w.clock.advance(1000);
    w.clock.step_wall_back(1000);
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 3, wall + sessions::STAMP_WINDOW_MS));
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    assert_eq!(b.node.sessions.stamp_of(w.a.id()), Some(wall + sessions::STAMP_WINDOW_MS));
}

/// The floor's moment (this node's start, a member's joining) is kept on the monotonic clock: a
/// wall clock set right after the start moves the floor with it, rather than leaving it a day
/// ahead and every honest init below it.
#[test]
fn a_wall_clock_set_right_after_the_start_does_not_freeze_the_floor() {
    let w = world();
    let real = w.clock.unix_ms();
    // B starts with its wall clock a day ahead; a minute later it is set right.
    w.clock.set_wall(real + 86_400_000);
    let mut b = target(&w);
    b.take();
    w.clock.advance(60_000);
    w.clock.set_wall(real + 60_000);
    // An honest init stamped by the real time is taken...
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 3, real + 60_000));
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    // ...and one recorded well before the start is still refused.
    b.deliver_from(
        &w.p,
        frame_type::HANDSHAKE_INIT,
        &stamped_init(&w, &b, &w.p, 3, real - 2 * sessions::STAMP_WINDOW_MS),
    );
    assert!(b.binaries().is_empty());
}

/// With no stamp kept for a member (this node just started, or the member just joined its
/// roster), an init must be stamped after that moment less 5 minutes: inits a relay recorded
/// before then cannot be replayed into a session.
#[test]
fn inits_recorded_before_a_restart_or_a_re_add_are_refused() {
    let w = world();
    let b = target(&w);
    let recorded = stamped_init(&w, &b, &w.a, 3, w.clock.unix_ms());
    w.clock.advance(15 * 60_000);
    // B restarts: a recorded init from 15 minutes ago is refused, a fresh one accepted.
    let mut b = target(&w);
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &recorded);
    assert!(b.binaries().is_empty(), "a recorded init is not taken after a restart");
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 3, w.clock.unix_ms()));
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    // Within 10 minutes before the start is allowed (clocks differ a little).
    let skewed = stamped_init(&w, &b, &w.p, 3, w.clock.unix_ms() - 9 * 60_000);
    b.deliver_from(&w.p, frame_type::HANDSHAKE_INIT, &skewed);
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    // A leaves the roster and comes back 15 minutes later: what was recorded before is refused.
    let recorded = stamped_init(&w, &b, &w.a, 5, w.clock.unix_ms() + 1);
    b.node.adopt_roster(roster_with(&w.p, 4, &[&w.b]));
    w.clock.advance(15 * 60_000);
    b.node.adopt_roster(roster_with(&w.p, 5, &[&w.a, &w.b]));
    b.take();
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &recorded);
    assert!(b.binaries().is_empty(), "a recorded init is not taken after a re-add");
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 5, w.clock.unix_ms()));
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
}

/// Go review: the stamps of ids that leave the roster are kept (1,024 at most) and restored when
/// an id is re-added, so an init accepted before it left stays refused however soon it returns;
/// the time floor alone would take one 2 minutes old.
#[test]
fn a_member_re_added_soon_after_leaving_gets_its_stamp_back() {
    let w = world();
    let mut b = target(&w);
    b.take();
    let before = stamped_init(&w, &b, &w.a, 3, w.clock.unix_ms());
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &before);
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    b.node.adopt_roster(roster_with(&w.p, 4, &[&w.b]));
    w.clock.advance(2 * 60_000);
    b.node.adopt_roster(roster_with(&w.p, 5, &[&w.a, &w.b]));
    b.take();
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &before);
    assert!(b.binaries().is_empty(), "an init from before A left is refused when A is back");
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 5, w.clock.unix_ms()));
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
}

#[test]
fn departed_stamps_are_bounded() {
    let w = world();
    let mut b = target(&w);
    b.take();
    // 1,100 members come, each is accepted once, and they all leave.
    let ids: Vec<Identity> = (0..1100u32)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_be_bytes());
            seed[31] = 0xee;
            Identity::from_seed(&seed)
        })
        .collect();
    for chunk in ids.chunks(100) {
        let mut others: Vec<&Identity> = chunk.iter().collect();
        others.push(&w.b);
        let v = b.node.roster().version() + 1;
        b.node.adopt_roster(roster_with(&w.p, v, &others));
        for id in chunk {
            b.deliver_from(id, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, id, v, w.clock.unix_ms()));
        }
        b.take();
    }
    let v = b.node.roster().version() + 1;
    b.node.adopt_roster(roster_with(&w.p, v, &[&w.b]));
    assert_eq!(b.node.sessions.departed_len(), sessions::DEPARTED_STAMPS);
}

/// W = 10 minutes: a member up to that slow is accepted right after this node starts.
#[test]
fn a_member_nine_minutes_slow_is_accepted_right_after_a_restart() {
    let w = world();
    w.clock.advance(60 * 60_000);
    let mut b = target(&w);
    b.take();
    let slow = w.clock.unix_ms() - 9 * 60_000;
    b.deliver_from(&w.a, frame_type::HANDSHAKE_INIT, &stamped_init(&w, &b, &w.a, 3, slow));
    assert_eq!(b.sent_kinds(), [frame_type::HANDSHAKE_RESP]);
    assert_eq!(b.node.sessions.stamp_of(w.a.id()), Some(slow));
}

/// A roster push the primary could not make (the member unreachable) is made again later: an idle
/// member, which sends nothing and so would never ask, still learns of a revocation.
#[test]
fn a_failed_roster_push_is_made_again_and_an_idle_member_learns_of_a_revocation() {
    let w = world();
    let mut p = primary_node(&w);
    // B is revoked while A is away: the push of v4 to A fails.
    primary::revoke(&mut p.node, w.b.id()).unwrap();
    route(&mut [&mut p]);
    // A comes back on v3, which still lists B, and sends nothing.
    let mut a = connected(&w, &w.a, &w.roster, timing());
    assert_eq!(a.node.roster().version(), 3);
    w.clock.advance(primary::PUSH_RETRY_MS - 1);
    p.node.poll();
    route(&mut [&mut p, &mut a]);
    assert_eq!(a.node.roster().version(), 3, "not before the wait ends");
    w.clock.advance(1);
    p.node.poll();
    route(&mut [&mut p, &mut a]);
    assert_eq!(a.node.roster().version(), 4, "the push went again, and A took it");
    assert!(a.node.roster().member(w.b.id()).is_none(), "A knows B is revoked");
    // Delivered: nothing is left to try again (a roster offer coalesced from the handshake, A
    // having shown v3 in it, may still go; that is not a retry).
    assert!(primary::pushes_waiting(&mut p.node).is_empty());
    w.clock.advance(10 * primary::PUSH_RETRY_MAX_MS);
    p.node.poll();
    route(&mut [&mut p, &mut a]);
    assert!(primary::pushes_waiting(&mut p.node).is_empty());
}

/// The waits between tries double from 1 s to 10 minutes; a newer roster replaces the push, and a
/// member that leaves is no longer tried.
#[test]
fn roster_push_retries_back_off_and_stop_when_replaced_or_the_member_leaves() {
    let w = world();
    let mut p = primary_node(&w);
    let a = node_id_to_bytes(w.a.id()).unwrap();
    // Each second, the tries at A, every one answered unreachable.
    let tries = |p: &mut T, secs: u64| {
        let mut at = Vec::new();
        for t in 0..=secs {
            p.node.poll();
            for f in p.binaries() {
                if f[1] == frame_type::HANDSHAKE_INIT && f[2..18] == a {
                    at.push(t);
                    let back = encode_frame(frame_type::UNREACHABLE, &a, &[]).unwrap();
                    let conn = p.conn;
                    p.node.on_binary(conn, &back);
                }
            }
            w.clock.advance(1000);
        }
        at
    };
    let c = Identity::from_seed(&[50; 32]);
    let v4 = roster_with(&w.p, 4, &[&w.a, &w.b, &c]);
    primary::publish_for_test(&mut p.node, v4);
    let at = tries(&mut p, 50 * 60);
    let gaps: Vec<u64> = at.windows(2).map(|x| x[1] - x[0]).collect();
    assert_eq!(at[0], 0);
    assert_eq!(gaps[..12], [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 600, 600], "{gaps:?}");
    assert!(gaps[12..].iter().all(|g| *g == 600));
    // A newer roster: pushed at once, and its retries start over at 1 s.
    let v5 = roster_with(&w.p, 5, &[&w.a, &w.b]);
    primary::publish_for_test(&mut p.node, v5);
    assert_eq!(tries(&mut p, 4), [0, 1, 3]);
    // A leaves the roster: no more tries at it.
    primary::revoke(&mut p.node, w.a.id()).unwrap();
    assert!(tries(&mut p, 30 * 60).is_empty());
}

/// A push owed to a member is no longer owed once the member is seen to hold that roster: it
/// handshakes showing the version (it got the roster elsewhere, from the relay, say), or it is
/// handed the roster some other way (an answer, an offer).
#[test]
fn a_push_owed_ends_when_the_member_shows_it_holds_the_roster() {
    let w = world();
    let mut p = primary_node(&w);
    primary::revoke(&mut p.node, w.b.id()).unwrap();
    route(&mut [&mut p]);
    assert_eq!(primary::pushes_waiting(&mut p.node), [w.a.id().to_owned()]);
    // A comes back already holding v4 and sends: its handshake shows v4.
    let v4 = p.node.roster().clone();
    let mut a = connected(&w, &w.a, &v4, timing());
    let _sent = a.send(w.p.id(), b"hi");
    route(&mut [&mut p, &mut a]);
    assert!(primary::pushes_waiting(&mut p.node).is_empty(), "nothing owed to a member that holds it");
    // Another network: A comes back on v3 and sends, and the offer that answers its older
    // version is the push.
    let w2 = world();
    let mut p = primary_node(&w2);
    primary::revoke(&mut p.node, w2.b.id()).unwrap();
    route(&mut [&mut p]);
    let mut a = connected(&w2, &w2.a, &w2.roster, timing());
    let _sent = a.send(w2.p.id(), b"hi");
    route(&mut [&mut p, &mut a]);
    w2.clock.advance(300);
    p.node.poll();
    route(&mut [&mut p, &mut a]);
    assert_eq!(a.node.roster().version(), 4);
    assert!(primary::pushes_waiting(&mut p.node).is_empty());
}

/// Spec section 5.3: after P6 the primary pushes the new roster to every member but the newcomer
/// it just sealed it for, which holds it already and is not connected yet (a push would fail, and
/// its retry land later in the middle of other traffic).
#[test]
fn the_roster_made_by_a_pairing_is_pushed_to_the_others_not_the_newcomer() {
    let w = world();
    let mut p = primary_node(&w);
    let code = primary::open_pairing_code(&mut p.node, None, None, false).unwrap();
    assert!(attempt(&mut p, 33, &code.code.replace('-', ""), &code.code_id).is_some());
    let newcomer = Identity::from_seed(&[33; 32]);
    assert!(p.node.roster().member(newcomer.id()).is_some());
    // The pushes are under way to A and B (handshakes pending), none to the newcomer...
    assert!(p.node.sessions.engaged(w.a.id()) && p.node.sessions.engaged(w.b.id()));
    assert!(!p.node.sessions.engaged(newcomer.id()), "nothing pushed to the newcomer");
    // ...and when they fail, only A and B are owed one.
    w.clock.advance(p.node.timing.handshake_timeout + 1);
    p.node.poll();
    let mut owed = primary::pushes_waiting(&mut p.node);
    owed.sort();
    let mut expected = vec![w.a.id().to_owned(), w.b.id().to_owned()];
    expected.sort();
    assert_eq!(owed, expected);
}

// ── Becoming the primary (section 3.1) ──

/// The roster of `world()`'s network naming alice primary, at `version`.
fn worker_primary_roster(w: &World, version: u64) -> Roster {
    roster_of(
        &net_key(&w.p),
        version,
        &w.a,
        vec![RosterMember::from_identity(&w.p), RosterMember::from_identity(&w.a), RosterMember::from_identity(&w.b)],
    )
}

/// The text messages a node sent since last asked; its binary frames stay to be routed.
fn texts_keeping_binaries(n: &T) -> Vec<Json> {
    let mut out = n.log.out.lock().unwrap();
    let mut texts = Vec::new();
    out.retain(|s| match s {
        Sent::Text(t) => {
            texts.push(Json::parse(t).unwrap());
            false
        }
        Sent::Binary(_) => true,
    });
    texts
}

fn rosters_pushed(texts: &[Json]) -> Vec<Roster> {
    texts
        .iter()
        .filter(|t| t.get("type").and_then(Json::as_str) == Some("roster"))
        .map(|t| Roster::from_json(t.get("roster").unwrap().clone()).unwrap())
        .collect()
}

#[test]
fn a_node_started_with_the_seed_claims_the_network_at_its_first_registration() {
    let w = world();
    let named = worker_primary_roster(&w, 4);
    // The seed's custody is the caller's: it starts this node with it, under a roster naming
    // alice primary.
    let mut p = make_with(&w.p, &named, true, Some(net_seed(&w.p)), &w.clock, timing(), false);
    let mut a = make(&w.a, &named, false, &w.clock, timing(), false);
    assert!(!p.node.is_primary(), "not before it has claimed");
    a.connect();
    a.take();
    p.connect();
    // It signed the next roster, naming itself primary, and pushed it to the relay.
    let pushed = rosters_pushed(&texts_keeping_binaries(&p));
    assert_eq!(pushed.len(), 1);
    let claimed = &pushed[0];
    assert_eq!(claimed.version(), 5);
    assert_eq!(claimed.primary_id(), w.p.id());
    // The members unchanged: only `primary` names another node.
    assert_eq!(claimed.members(), named.members());
    assert_eq!(claimed.network(), named.network(), "the same network");
    assert_eq!(p.node.roster().version(), 5);
    assert!(p.node.is_primary());
    assert!(primary::open_pairing_code(&mut p.node, None, None, false).is_ok());
    // And to every member: alice takes it, and is not the primary.
    p.node.poll();
    route(&mut [&mut p, &mut a]);
    assert_eq!(a.node.roster().version(), 5);
    assert!(!a.node.is_primary());
}

#[test]
fn a_node_claims_only_at_start_and_stops_being_the_primary_in_place_after() {
    let w = world();
    let mut p = make_with(&w.p, &w.roster, true, Some(net_seed(&w.p)), &w.clock, timing(), false);
    p.connect();
    p.take();
    p.events();
    assert!(p.node.is_primary());
    let (tx, mut rx) = oneshot::channel();
    primary::usage_begin(&mut p.node, "u1", tx);
    let code = primary::open_pairing_code(&mut p.node, None, None, false).unwrap();

    // A newer roster names alice primary: this node stops being the primary in place.
    let later = worker_primary_roster(&w, 4);
    assert!(p.node.offer_roster(later.json()));
    assert!(!p.node.is_primary());
    assert!(p.node.holds_network_seed(), "the caller's seed is not touched");
    assert_eq!(rx.try_recv().unwrap().unwrap_err().code(), ErrorCode::Invalid, "the usage ask fails");
    assert!(primary::open_pairing_code(&mut p.node, None, None, false).is_err());
    let pairing = Json::object([
        ("type", Json::str("pairing")),
        ("channel", Json::str(b64u(&[7u8; 16]))),
        ("code", Json::str(&code.code_id)),
    ]);
    let conn = p.conn;
    p.node.on_text(conn, &pairing.to_json_string().unwrap());
    assert!(p.texts().is_empty(), "no claim, and no pairing served");
    // Nothing disconnected, and no claim on this roster or at a later registration.
    let events = p.events();
    assert!(!events.iter().any(|e| matches!(e, Event::Disconnect { .. } | Event::State(_))), "{events:?}");
    assert_eq!(*p.log.closed.lock().unwrap(), None);
    assert_eq!(p.state(), MemberState::Connected);
    p.node.on_close(conn, close_code::ABNORMAL, "");
    w.clock.advance(1000);
    p.node.poll();
    p.open_and_register(None);
    assert!(rosters_pushed(&p.texts()).is_empty(), "a reconnect claims nothing");
    assert!(!p.node.is_primary());
    assert_eq!(p.node.roster().version(), 4);
}

#[test]
fn a_primary_that_a_newer_roster_does_not_name_ends_its_pairing_channels() {
    let w = world();
    let mut p = make(&w.p, &w.roster, true, &w.clock, timing(), false);
    p.connect();
    p.take();
    p.events();
    let code = primary::open_pairing_code(&mut p.node, None, None, false).unwrap();
    let channel = b64u(&[7u8; 16]);
    let pairing = Json::object([
        ("type", Json::str("pairing")),
        ("channel", Json::str(&channel)),
        ("code", Json::str(&code.code_id)),
    ]);
    let conn = p.conn;
    p.node.on_text(conn, &pairing.to_json_string().unwrap());
    assert!(p.node.offer_roster(worker_primary_roster(&w, 4).json()));
    let ends: Vec<Json> =
        p.texts().into_iter().filter(|t| t.get("type").and_then(Json::as_str) == Some("pairEnd")).collect();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].get("channel").and_then(Json::as_str), Some(channel.as_str()));
    assert!(
        p.events()
            .iter()
            .any(|e| matches!(e, Event::PairingFailed { reason: crate::types::PairingFailure::Demoted, .. }))
    );
}

#[test]
fn a_seed_that_does_not_derive_the_rosters_key_is_refused_and_primary_needs_one() {
    let w = world();
    let cfg = |roster: &Roster, seed: Option<[u8; 32]>, primary: bool| {
        let (events, _) = broadcast::channel(16);
        let (state, _) = watch::channel(MemberState::Disconnected);
        let (seen, _) = watch::channel(0);
        Node::new(
            NodeConfig {
                identity: w.p.clone(),
                roster: roster.clone(),
                pinned_network_key: None,
                network_seed: seed,
                relay_url: None,
                credit_window: INITIAL_CREDIT,
                timing: timing(),
                primary,
                has_resolver: false,
                clock: w.clock.clone(),
                observer: None,
            },
            Outputs { events, state, rosters_seen: seen, inbox: Arc::new(Notify::new()) },
        )
        .map(|_| ())
        .map_err(|e| e.code())
    };
    let r = &w.roster;
    assert_eq!(cfg(r, Some(*w.p.seed()), false), Err(ErrorCode::Invalid), "the node seed is not the network seed");
    assert_eq!(cfg(r, None, true), Err(ErrorCode::Invalid), "a primary without the seed");
    assert_eq!(cfg(r, Some(net_seed(&w.p)), true), Ok(()));
    // Under a roster naming another member primary, the seed is enough: it claims.
    assert_eq!(cfg(&worker_primary_roster(&w, 4), Some(net_seed(&w.p)), true), Ok(()));
}

// ── Shaping (section 9) and pacing (section 11) ──

fn shaping_events(t: &mut T) -> Vec<Shaping> {
    t.events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Shaping(s) => Some(s),
            _ => None,
        })
        .collect()
}

fn shape(t: &mut T, rate_bps: u64, slowed: bool) {
    let conn = t.conn;
    t.node.on_text(conn, &format!(r#"{{"type":"shaping","rateBps":{rate_bps},"slowed":{slowed}}}"#));
}

#[test]
fn shaping_notices_set_the_property_and_raise_an_event_on_each_change() {
    let w = world();
    let mut a = make(&w.a, &w.roster, false, &w.clock, timing(), false);
    a.node.start();
    a.open_and_register_with(r#"["control","shaping"]"#, None);
    a.take();
    assert_eq!(a.node.shaping(), Shaping::default(), "unshaped before any notice");
    assert!(shaping_events(&mut a).is_empty());
    shape(&mut a, 1_048_576, false);
    shape(&mut a, 16384, true);
    assert_eq!(a.node.shaping(), Shaping { rate_bps: 16384, slowed: true });
    // The same again changes nothing; malformed notices are ignored.
    let conn = a.conn;
    shape(&mut a, 16384, true);
    for junk in [
        r#"{"type":"shaping","rateBps":-1,"slowed":false}"#,
        r#"{"type":"shaping","rateBps":1.5,"slowed":false}"#,
        r#"{"type":"shaping","rateBps":1e2,"slowed":false}"#,
        r#"{"type":"shaping","rateBps":5,"slowed":"no"}"#,
        r#"{"type":"shaping","slowed":false}"#,
        r#"{"type":"shaping","rateBps":5}"#,
    ] {
        a.node.on_text(conn, junk);
    }
    shape(&mut a, 0, false);
    assert_eq!(
        shaping_events(&mut a),
        [
            Shaping { rate_bps: 1_048_576, slowed: false },
            Shaping { rate_bps: 16384, slowed: true },
            Shaping { rate_bps: 0, slowed: false },
        ]
    );
    assert!(!a.events().iter().any(|e| matches!(e, Event::RelayError { .. })));
}

#[test]
fn a_relay_without_the_shaping_feature_leaves_a_member_unshaped_whatever_it_held_before() {
    let w = world();
    let mut a = connected(&w, &w.a, &w.roster, timing());
    shape(&mut a, 16384, true);
    assert!(a.node.shaping().slowed, "a notice is taken, whatever hello said");
    a.events();
    let conn = a.conn;
    a.node.on_close(conn, close_code::GOING_AWAY, "");
    w.clock.advance(timing().backoff_max.as_millis() as u64);
    a.node.poll();
    a.open_and_register(None);
    assert_eq!(a.state(), MemberState::Connected);
    assert_eq!(a.node.shaping(), Shaping::default());
    assert_eq!(shaping_events(&mut a), [Shaping::default()]);
}

#[test]
fn pacing_shaped_fragments_are_a_quarter_second_of_the_pace_and_go_no_faster_control_passes_them() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let rate = 16384;
    let largest = paced_fragment(rate);
    assert_eq!(largest, 3584);
    // A first exchange, unpaced, so the session is up and what follows is the pace alone.
    let mut rx = a.send(w.b.id(), b"open");
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    assert_eq!(b.take_all().len(), 1, "taken, so the next message's fragments are credited");
    shape(&mut a, rate, true);
    let before = a.node.traffic().peers[w.b.id()].sent;
    let mut rx = a.send(w.b.id(), &vec![7u8; 200_000]);
    let fragments = |a: &T| {
        let now = a.node.traffic().peers[w.b.id()].sent;
        (now.frames - before.frames, now.frame_bytes - before.frame_bytes)
    };
    assert_eq!(fragments(&a).0, 1, "the first goes at once, with no burst behind it");
    // Control goes at once, ahead of the fragments waiting for the pace.
    sessions::send_control(&mut a.node, w.b.id(), Ctl::RosterRequest, None, FailAction::Ignore);
    let last = |a: &T| match a.log.out.lock().unwrap().last() {
        Some(Sent::Binary(f)) => Some(f[1]),
        _ => None,
    };
    assert_eq!(last(&a), Some(frame_type::CONTROL));
    let control = (1, 39); // the roster-request: 18 + 4 + 1 + 16 bytes
    for _ in 0..30 {
        w.clock.advance(50);
        a.node.poll();
        b.node.poll();
        route(&mut [&mut a, &mut b]);
    }
    // 1.5 s: the first at once, then one a frame's size at 7R/8 (252.8 ms) after the last.
    let (frames, bytes) = fragments(&a);
    let (frames, bytes) = (frames - control.0, bytes - control.1);
    assert!((6..=8).contains(&frames), "{frames} frames in 1.5 s");
    assert!(bytes <= 7 * rate * 1500 / 8000 + 2 * (largest + 40), "{bytes} bytes in 1.5 s");
    assert_eq!(done(&mut rx), None);
    // Unshaped again: the rest goes at once.
    shape(&mut a, 0, false);
    for _ in 0..10 {
        route(&mut [&mut a, &mut b]);
        w.clock.advance(250);
        b.node.poll();
        a.node.poll();
    }
    route(&mut [&mut a, &mut b]);
    assert_eq!(done(&mut rx), Some(Ok(())));
    assert_eq!(b.take_all()[0].bytes.len(), 200_000);
}

#[test]
fn pacing_shaped_a_session_whose_receiver_takes_nothing_keeps_about_one_fragment_uncredited() {
    let w = world();
    let (mut a, mut b) = pair_ab(&w, timing());
    let rate = 16384;
    shape(&mut a, rate, true);
    let _rxs: Vec<_> = (0..20).map(|_| a.send(w.b.id(), &[0u8; 5000])).collect();
    for _ in 0..30 {
        route(&mut [&mut a, &mut b]);
        w.clock.advance(50);
        a.node.poll();
        b.node.poll();
    }
    route(&mut [&mut a, &mut b]);
    // Nothing is credited back once a message waits, so the window is max(F, min(0, R/2)) = F:
    // at most one message past it, not the 64 KiB floor.
    let inflight = a.node.sessions.info(w.b.id())[0].inflight;
    let f = paced_fragment(rate);
    assert!(inflight >= f && inflight < f + 5000, "{inflight} un-credited");
}
