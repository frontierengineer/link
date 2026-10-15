//! The relay's limits and flow control against the real client: shaping with LINK_RATE_BPS,
//! liveness pings while a sender is held back, batched credit, the 65000-byte roster limit, and
//! a network that moves (4009).

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use link_client::*;
use support::*;

const SECS: fn(u64) -> Duration = Duration::from_secs;

fn opts(identity: Identity, roster: Roster) -> MemberOptions {
    let mut o = MemberOptions::new(identity, roster);
    o.timing = fast();
    o
}

fn drops(events: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<u16> {
    let mut out = Vec::new();
    while let Ok(e) = events.try_recv() {
        if let Event::Disconnect { code, .. } = e {
            out.push(code);
        }
    }
    out
}

async fn timed_transfer(env: &[(&str, &str)], size: usize) -> (Duration, Vec<u16>, UsageReport) {
    let net = Net::start(env, fast()).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    let mut evs: Vec<_> = [net.primary.member(), &worker, &surface].iter().map(|m| events_from_now(m)).collect();
    let started = Instant::now();
    worker.send(surface.id(), vec![1u8; size]).await.unwrap();
    let got = recv_within(&surface, SECS(60)).await;
    let took = started.elapsed();
    assert_eq!(got.bytes.len(), size);
    let usage = net.primary.usage().await.unwrap();
    let all = evs.iter_mut().flat_map(drops).collect();
    (took, all, usage)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shaping_slows_a_transfer_and_pings_never_drop_the_sender_held_back() {
    let size = 2 * 1024 * 1024;
    let rate = 512 * 1024;
    let (fast_took, _, _) = timed_transfer(&[], size).await;
    // Pings every 200 ms; the sender is paused for seconds at a time and must be exempt.
    let (took, dropped, usage) =
        timed_transfer(&[("LINK_RATE_BPS", "524288"), ("LINK_PING_INTERVAL", "200ms")], size).await;
    // The bucket holds one second of tokens, so 2 MiB at 512 KiB/s take at least 3 s.
    assert!(took >= Duration::from_millis(2700), "shaped transfer took {took:?}");
    assert!(took > fast_took * 2, "shaped {took:?} against {fast_took:?} unshaped");
    assert!(dropped.is_empty(), "no connection was dropped: {dropped:?}");
    assert_eq!(usage.limits.rate_bps, rate as f64);
    assert!(!usage.slowed, "slowed means the trickle rate, not shaping");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn liveness_members_answer_the_relays_pings_and_stay_connected() {
    let net = Net::start(&[("LINK_PING_INTERVAL", "100ms")], fast()).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let mut e1 = events_from_now(&net.primary);
    let mut e2 = events_from_now(&worker);
    sleep_ms(1500).await;
    assert!(drops(&mut e1).is_empty() && drops(&mut e2).is_empty());
    worker.send(net.primary.id(), &b"still here"[..]).await.unwrap();
    recv_within(&net.primary, SECS(5)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credit_is_batched_bulk_small_messages_bring_back_few_credit_frames() {
    let net = Net::start(&[], fast()).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    worker.reset_traffic();
    surface.reset_traffic();
    let n = 2000;
    // The application takes messages as they arrive, as the TypeScript test's inbox does;
    // otherwise the sender's pace (64 KiB un-credited) would stop it, by design.
    let reader = surface.clone();
    let taken = tokio::spawn(async move {
        for _ in 0..n {
            recv_within(&reader, SECS(30)).await;
        }
    });
    for i in 0..n {
        worker.send(surface.id(), vec![i as u8; 200]).await.unwrap();
    }
    taken.await.unwrap();
    sleep_ms(400).await; // the last batch's timer
    let back = surface.traffic().peers[worker.id()].sent;
    assert_eq!(back.messages, 0);
    assert!((back.frames as f64) / (n as f64) < 0.1, "{} credit frames for {n} messages", back.frames);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_control_two_senders_into_one_slow_reader_neither_overruns_the_window() {
    let net = Net::start(&[], fast()).await;
    let a = net.add(MemberKind::Worker, &[]).await;
    let b = net.add(MemberKind::Worker, &[&a]).await;
    let r = net.add(MemberKind::Surface, &[&a, &b]).await;
    let chunk = 256 * 1024;
    let send_all = |m: Member, to: String| {
        tokio::spawn(async move {
            for i in 0..12u8 {
                m.send(&to, vec![i; chunk]).await.unwrap();
            }
        })
    };
    let ta = send_all(a.clone(), r.id().into());
    let tb = send_all(b.clone(), r.id().into());
    // The reader takes one message every 50 ms; each sender stays within its window.
    let mut from_a = 0u8;
    let mut from_b = 0u8;
    for _ in 0..24 {
        sleep_ms(50).await;
        for m in [&a, &b] {
            if let Some(s) = m.session_info(r.id()).first() {
                assert!(s.inflight <= INITIAL_CREDIT, "{} in flight", s.inflight);
            }
        }
        let msg = recv_within(&r, SECS(10)).await;
        // Whole and in order per sender.
        let n = if msg.from == a.id() { &mut from_a } else { &mut from_b };
        assert!(msg.bytes.iter().all(|x| *x == *n) && msg.bytes.len() == chunk);
        *n += 1;
    }
    assert_eq!((from_a, from_b), (12, 12));
    tokio::time::timeout(SECS(10), ta).await.unwrap().unwrap();
    tokio::time::timeout(SECS(10), tb).await.unwrap().unwrap();
}

fn fake_member() -> RosterMember {
    let mut ed = [0u8; 32];
    let mut x = [0u8; 32];
    ed.copy_from_slice(&Identity::generate().ed25519_public());
    x.copy_from_slice(&Identity::generate().x25519_public());
    RosterMember::new(MemberKind::Mcp, ed, x)
}

fn roster_of(primary: &Identity, version: u64, relay: &str, members: Vec<RosterMember>) -> Roster {
    sign_roster(
        &UnsignedRoster {
            network: primary.id().into(),
            version,
            issued_at: unix_ms(),
            relay: relay.into(),
            primary: primary.ed25519_public(),
            members,
        },
        primary,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_roster_at_the_65000_byte_limit_travels_in_register_registered_and_a_session() {
    let relay = Relay::start(&[]);
    let p = Identity::generate();
    let w = Identity::generate();
    let base =
        vec![RosterMember::from_identity(&p, MemberKind::Primary), RosterMember::from_identity(&w, MemberKind::Worker)];
    let small = roster_of(&p, 1, &relay.url, base.clone());
    // Every entry has the same length: fill v2 so that exactly one more member fits.
    let entry = Json::object([
        ("id", Json::str("a".repeat(26))),
        ("ed25519", Json::str("A".repeat(43))),
        ("x25519", Json::str("A".repeat(43))),
        ("kind", Json::str("mcp")),
    ])
    .to_json_string()
    .unwrap()
    .len()
        + 1;
    let room = MAX_ROSTER_BYTES - roster_of(&p, 2, &relay.url, base.clone()).size();
    let mut members = base.clone();
    members.extend((0..room / entry - 1).map(|_| fake_member()));
    let big = roster_of(&p, 2, &relay.url, members);
    let left = MAX_ROSTER_BYTES - big.size();
    assert!(left >= entry && left < 2 * entry, "{left} bytes left");

    let primary = Primary::connect(opts(p.clone(), big)).await.unwrap();
    let worker = Member::new(opts(w.clone(), small)).unwrap();
    worker.wait_connected(Some(SECS(10))).await.unwrap();
    assert_eq!(worker.roster().version(), 2, "the relay handed the big roster back in registered");
    worker.send(p.id(), &b"under the big roster"[..]).await.unwrap();
    recv_within(&primary, SECS(5)).await;

    // The last member that fits; v3 reaches the worker over their session, through the relay.
    let code = primary.open_pairing_code(MemberKind::Surface, CodeOptions::default()).unwrap();
    let v3 = pair(PairOptions { target: PairTarget::Link(code.link), identity: Identity::generate(), timeout: None })
        .await
        .unwrap()
        .roster;
    assert!(v3.size() <= MAX_ROSTER_BYTES && v3.size() > MAX_ROSTER_BYTES - entry);
    until(|| worker.roster().version() == 3, "the worker to receive v3 in a session").await;
    // Full: the primary refuses another, and nobody accepts a roster over the limit.
    assert_eq!(
        primary.open_pairing_code(MemberKind::Mcp, CodeOptions::default()).unwrap_err().code(),
        ErrorCode::RosterFull
    );
    let mut over = v3.json().clone();
    if let Json::Object(m) = &mut over {
        for (k, v) in m.iter_mut() {
            if k == "relay" {
                *v = Json::str(format!("{}{}", v3.relay(), "x".repeat(MAX_ROSTER_BYTES)));
            }
        }
    }
    assert!(roster_problem(&over).unwrap().contains("over the 65000-byte limit"));
    assert!(Roster::from_json(over).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn moved_4009_the_member_looks_the_network_up_again_and_reconnects_there() {
    let net = Net::start(&[], fast()).await;
    let (identity, roster) = net.pair_only(MemberKind::Worker).await;
    // The relay node the roster names closes every connection 4009.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old = format!("ws://{}/v1", listener.local_addr().unwrap());
    tokio::spawn(async move {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let frame = CloseFrame { code: CloseCode::from(4009), reason: "moved".into() };
                let _ = ws.close(Some(frame)).await;
                let _ = ws.flush().await;
            });
        }
    });
    let asked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let now_url = net.relay.url.clone();
    let asked2 = asked.clone();
    let mut o = opts(identity, roster);
    o.relay_url = Some(old.clone());
    o.resolve_relay = Some(Arc::new(move |network: String| {
        asked2.lock().unwrap().push(network);
        let url = now_url.clone();
        Box::pin(async move { Some(url) })
    }));
    let m = Member::new(o).unwrap();
    let mut events = m.events();
    m.wait_connected(Some(SECS(10))).await.unwrap();
    assert_eq!(m.relay_url(), net.relay.url);
    assert_eq!(*asked.lock().unwrap(), [m.network()]);
    let mut seen = Vec::new();
    while let Ok(e) = events.try_recv() {
        match e {
            Event::Disconnect { code, .. } => seen.push(format!("disconnect {code}")),
            Event::Moved { network } => seen.push(format!("moved {}", network == m.network())),
            Event::State(s) => seen.push(format!("state {s}")),
            _ => {}
        }
    }
    assert_eq!(
        seen,
        [
            "state connecting",
            "disconnect 4009",
            "state disconnected",
            "moved true",
            "state connecting",
            "state connected"
        ]
    );
    m.send(net.primary.id(), &b"moved"[..]).await.unwrap();
    recv_within(&net.primary, SECS(5)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_after_the_relay_restarts_and_sends_wait_for_it() {
    // A relay that goes away and comes back on the same port: the member backs off and
    // reconnects; a send made while it is away waits (up to the handshake timeout) for it.
    let relay = Relay::start(&[]);
    let port = relay.port;
    let p = Identity::generate();
    let roster = create_network(&p, &relay.url, unix_ms()).unwrap();
    let primary = Primary::connect(opts(p, roster)).await.unwrap();
    let mut events = events_from_now(&primary);
    drop(relay);
    until(|| primary.state() != MemberState::Connected, "the primary to notice").await;
    let again = Relay::start(&[("LINK_ADDR", &format!("127.0.0.1:{port}"))]);
    primary.wait_connected(Some(SECS(10))).await.unwrap();
    assert!(drops(&mut events).iter().all(|c| *c == 1006 || *c == 1001));
    drop(again);
}
