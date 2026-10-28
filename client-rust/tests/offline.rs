//! A member must never crash for want of a network: with its relay unreachable (connection
//! refused, a name that does not resolve, an address with no route), with its relay going away
//! mid-session, and on a roster with no relay yet, it keeps running and says so through its
//! states, events and the errors of the calls made on it, retrying where it retries. A panic in
//! any of its tasks is counted by a panic hook and fails the test.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use link_client::*;
use support::*;

static PANICS: AtomicUsize = AtomicUsize::new(0);

/// Counts every panic in this test binary, a spawned task's included (tokio would otherwise
/// keep it to the task's JoinHandle, which a member drops).
fn count_panics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICS.fetch_add(1, Ordering::SeqCst);
            prev(info);
        }));
    });
}

fn no_panics() {
    assert_eq!(PANICS.load(Ordering::SeqCst), 0, "a task panicked");
}

fn timing() -> Timing {
    Timing { handshake_timeout: Duration::from_secs(1), ..fast() }
}

struct Offline {
    primary: Identity,
    member: Identity,
    roster: Roster,
    seed: [u8; 32],
}

fn network(relay: &str) -> Offline {
    let primary = Identity::generate();
    let member = Identity::generate();
    let opts = NetworkOptions {
        relay: relay.into(),
        members: vec![RosterMember::from_identity(&member)],
        ..Default::default()
    };
    let (roster, key) = create_network_with_options(&primary, opts).unwrap();
    Offline { primary, member, roster, seed: *key.seed() }
}

fn refused_url() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("ws://127.0.0.1:{port}/v1")
}

/// Counts the `connecting` states raised so far.
fn connecting(events: &mut tokio::sync::broadcast::Receiver<Event>, seen: &mut usize) -> usize {
    while let Ok(e) = events.try_recv() {
        if matches!(e, Event::State(MemberState::Connecting)) {
            *seen += 1;
        }
    }
    *seen
}

async fn unreachable(url: String, hangs: bool) {
    count_panics();
    let n = network(&url);
    let mut po = MemberOptions::new(n.primary.clone(), n.roster.clone());
    po.network_seed = Some(n.seed);
    po.timing = timing();
    let primary = Primary::new(po).unwrap();
    let mut mo = MemberOptions::new(n.member.clone(), n.roster.clone());
    mo.timing = timing();
    let member = Member::new(mo).unwrap();
    let mut events = member.events();
    let e = member.wait_connected(Some(Duration::from_millis(1500))).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Timeout, "{e}");
    if !hangs {
        // It retries: dials again after each failure (an address with no route may hang in one dial).
        let mut seen = 0;
        until(|| connecting(&mut events, &mut seen) >= 2, "a second dial").await;
    }
    assert!(matches!(member.state(), MemberState::Connecting | MemberState::Disconnected), "{:?}", member.state());
    let e = tokio::time::timeout(Duration::from_secs(10), member.send(n.primary.id(), &b"x"[..]))
        .await
        .unwrap()
        .unwrap_err();
    assert!(!e.message().is_empty());
    let e = tokio::time::timeout(Duration::from_secs(10), primary.usage()).await.unwrap().unwrap_err();
    assert!(!e.message().is_empty());
    // What needs no relay still works.
    let code = primary.open_pairing_code(CodeOptions::default()).unwrap();
    assert_eq!(code.code.len(), 9);
    member.close();
    primary.close();
    assert_eq!(member.state(), MemberState::Closed);
    sleep_ms(200).await;
    no_panics();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relay_unreachable_connection_refused() {
    unreachable(refused_url(), false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relay_unreachable_a_name_that_does_not_resolve() {
    unreachable("ws://link-relay.invalid/v1".into(), false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relay_unreachable_an_address_with_no_route() {
    unreachable("ws://192.0.2.1:9/v1".into(), true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relay_going_away_mid_session_then_back() {
    count_panics();
    let relay = Relay::start(&[]);
    let port = relay.port;
    let n = network(&relay.url);
    let mut po = MemberOptions::new(n.primary.clone(), n.roster.clone());
    po.network_seed = Some(n.seed);
    po.timing = timing();
    let primary = Primary::connect(po).await.unwrap();
    let mut mo = MemberOptions::new(n.member.clone(), n.roster.clone());
    mo.timing = timing();
    let member = Member::connect(mo).await.unwrap();
    primary.send(member.id(), &b"before"[..]).await.unwrap();
    assert_eq!(&recv_within(&member, Duration::from_secs(5)).await.bytes[..], b"before");
    let mut events = member.events();
    drop(relay); // killed, as a crash or a lost network would leave it
    until(
        || member.state() != MemberState::Connected && primary.state() != MemberState::Connected,
        "both to see the relay gone",
    )
    .await;
    let e = tokio::time::timeout(Duration::from_secs(10), primary.send(member.id(), &b"lost"[..]))
        .await
        .unwrap()
        .unwrap_err();
    assert!(!e.message().is_empty());
    let mut seen = 0;
    until(|| connecting(&mut events, &mut seen) >= 2, "the member to dial again").await;
    let port_s = format!("127.0.0.1:{port}");
    let _back = Relay::start(&[("LINK_ADDR", port_s.as_str())]);
    member.wait_connected(Some(Duration::from_secs(10))).await.unwrap();
    primary.wait_connected(Some(Duration::from_secs(10))).await.unwrap();
    primary.send(member.id(), &b"after"[..]).await.unwrap();
    assert_eq!(&recv_within(&member, Duration::from_secs(5)).await.bytes[..], b"after");
    no_panics();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unplaced_roster_or_a_relay_url_that_is_not_one_is_refused_at_once() {
    count_panics();
    let n = network("");
    let mut po = MemberOptions::new(n.primary.clone(), n.roster.clone());
    po.network_seed = Some(n.seed);
    assert_eq!(Primary::new(po).err().unwrap().code(), ErrorCode::Invalid);
    let mo = MemberOptions::new(n.member.clone(), n.roster.clone());
    assert_eq!(Member::connect(mo.clone()).await.err().unwrap().code(), ErrorCode::Invalid);
    let mut bad = mo;
    bad.relay_url = Some("not a url".into());
    assert_eq!(Member::new(bad).err().unwrap().code(), ErrorCode::Invalid);
    no_panics();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lookup_after_4009_that_answers_something_not_a_url_keeps_the_relay() {
    count_panics();
    // A relay that answers every connection 4009: moved.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1", listener.local_addr().unwrap());
    tokio::spawn(async move {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await {
                    let frame = CloseFrame { code: CloseCode::from(4009), reason: "moved".into() };
                    let _ = ws.close(Some(frame)).await;
                    let _ = ws.flush().await;
                }
            });
        }
    });
    let n = network(&url);
    let asked = Arc::new(AtomicUsize::new(0));
    let asked2 = asked.clone();
    let mut mo = MemberOptions::new(n.member.clone(), n.roster.clone());
    mo.timing = timing();
    mo.resolve_relay = Some(Arc::new(move |_network: String| {
        asked2.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Some("not a url".to_owned()) })
    }));
    let member = Member::new(mo).unwrap();
    until(|| asked.load(Ordering::SeqCst) >= 3, "three lookups, each after a dial").await;
    assert_eq!(member.relay_url(), url);
    assert_ne!(member.state(), MemberState::Connected);
    member.close();
    no_panics();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pairing_with_the_relay_unreachable_fails_with_its_error() {
    count_panics();
    let n = network("");
    for relay in [refused_url(), "ws://link-relay.invalid/v1".into(), "not a url".into()] {
        let target = PairTarget::Parts {
            network: n.roster.network().into(),
            code: "7K2M9QXZ".into(),
            code_id: Some("AQIDBAUGBwg".into()),
            relay: relay.clone(),
        };
        let r =
            pair(PairOptions { target, identity: Identity::generate(), timeout: Some(Duration::from_secs(3)) }).await;
        assert!(r.is_err(), "{relay}");
    }
    no_panics();
}
