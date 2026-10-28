//! Pairing through the real relay: both sides of the SPAKE2 exchange, the roster reaching
//! everyone, codes typed by hand, wrong codes burning, slots refunded, and an absent primary.

mod support;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use link_client::*;
use support::*;
use tokio_tungstenite::tungstenite::Message;

const SECS: fn(u64) -> Duration = Duration::from_secs;

fn opts(identity: Identity, roster: Roster) -> MemberOptions {
    let mut o = MemberOptions::new(identity, roster);
    o.timing = fast();
    o
}

fn pair_failures(events: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(e) = events.try_recv() {
        if let Event::PairingFailed { reason, .. } = e {
            out.push(reason.as_str().to_owned());
        }
    }
    out
}

async fn pair_with(target: PairTarget) -> Result<PairResult, LinkError> {
    pair(PairOptions { target, identity: Identity::generate(), timeout: None }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_primary_pairs_a_worker_and_a_surface_and_sessions_run_every_way() {
    let net = Net::start(&[], fast()).await;
    let primary = &net.primary;
    let mut events = primary.events();
    let alice = net.add(&[]).await;
    assert_eq!(alice.roster().version(), 2);
    assert_eq!(alice.state(), MemberState::Connected);

    // The second node pairs from the code's parts, typed as a person might: lower case, O for
    // 0 and l for 1. It is the network's default code, so the code alone is enough.
    let sid = Identity::generate();
    let code = primary.open_pairing_code(CodeOptions::default()).unwrap();
    assert!(code.code.len() == 9 && code.code.as_bytes()[4] == b'-');
    assert_eq!(code.code_id, DEFAULT_CODE_ID);
    let typed = code.code.to_lowercase().replace('0', "o").replace('1', "l");
    let r = pair(PairOptions {
        target: PairTarget::Parts {
            network: primary.network(),
            code: typed,
            code_id: None,
            relay: net.relay.url.clone(),
        },
        identity: sid.clone(),
        timeout: None,
    })
    .await
    .unwrap();
    assert_eq!(r.roster.version(), 3);
    assert_eq!(r.pinned_network_key, primary.roster().network_key_b64u());
    let bob = Member::connect(opts(sid, r.roster)).await.unwrap();
    let mut paired = Vec::new();
    while let Ok(e) = events.try_recv() {
        if let Event::Paired { member, code_id, .. } = e {
            paired.push((member.id().to_owned(), code_id));
        }
    }
    // Each new member with the code it used: the default code, each time.
    assert_eq!(paired.len(), 2);
    assert_eq!(paired[1].0, bob.id());
    assert!(paired.iter().all(|(_, c)| c == DEFAULT_CODE_ID));
    // The primary pushed v3 to alice over their session.
    until(|| alice.roster().version() == 3, "alice to receive v3").await;
    assert!(alice.roster().member(bob.id()).is_some());

    alice.send(bob.id(), &b"alice to bob"[..]).await.unwrap();
    bob.send(alice.id(), &b"bob to alice"[..]).await.unwrap();
    primary.send(bob.id(), &b"primary to bob"[..]).await.unwrap();
    bob.send(primary.id(), &b"bob to primary"[..]).await.unwrap();
    alice.send(primary.id(), &b"alice to primary"[..]).await.unwrap();
    primary.send(alice.id(), &b"primary to alice"[..]).await.unwrap();
    let text = |m: InboundMessage| (m.from, String::from_utf8(m.bytes.to_vec()).unwrap());
    assert_eq!(text(recv_within(&bob, SECS(5)).await), (alice.id().into(), "alice to bob".into()));
    assert_eq!(text(recv_within(&bob, SECS(5)).await), (primary.id().into(), "primary to bob".into()));
    assert_eq!(text(recv_within(&alice, SECS(5)).await), (bob.id().into(), "bob to alice".into()));
    assert_eq!(text(recv_within(&alice, SECS(5)).await), (primary.id().into(), "primary to alice".into()));
    let mut p = vec![text(recv_within(primary, SECS(5)).await), text(recv_within(primary, SECS(5)).await)];
    p.sort();
    let mut want =
        vec![(bob.id().to_string(), "bob to primary".to_string()), (alice.id().into(), "alice to primary".into())];
    want.sort();
    assert_eq!(p, want);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn effective_roster_a_member_offline_during_a_pairing_is_brought_up_to_date_at_registration() {
    let net = Net::start(&[], fast()).await;
    let alice = net.add(&[]).await;
    let (identity, stale) = (alice.identity(), alice.roster());
    alice.close();
    sleep_ms(100).await;
    let bob = net.add(&[]).await;
    assert_eq!(net.primary.roster().version(), 3);
    // It presents v2; the relay holds v3 and returns it in `registered`.
    let back = Member::new(opts(identity, stale)).unwrap();
    let mut events = back.events();
    back.wait_connected(Some(SECS(10))).await.unwrap();
    assert_eq!(back.roster().version(), 3);
    // Applied before anything is sent under it: the roster event comes before `connected`.
    let mut order = Vec::new();
    while let Ok(e) = events.try_recv() {
        match e {
            Event::Roster(r) => order.push(format!("roster {}", r.version())),
            Event::State(s) => order.push(format!("state {s}")),
            _ => {}
        }
    }
    assert_eq!(order, ["state connecting", "roster 3", "state connected"]);
    back.send(bob.id(), &b"caught up"[..]).await.unwrap();
    assert_eq!(&recv_within(&bob, SECS(5)).await.bytes[..], b"caught up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_revoked_while_offline_is_closed_4008_at_registration_and_stays_revoked() {
    let net = Net::start(&[], fast()).await;
    let alice = net.add(&[]).await;
    let (identity, stale) = (alice.identity(), alice.roster());
    alice.close();
    sleep_ms(100).await;
    net.primary.revoke(identity.id()).unwrap();
    let back = Member::new(opts(identity, stale)).unwrap();
    let mut events = back.events();
    assert_eq!(back.wait_connected(Some(SECS(10))).await.unwrap_err().code(), ErrorCode::Revoked);
    sleep_ms(300).await;
    let mut codes = Vec::new();
    while let Ok(e) = events.try_recv() {
        if let Event::Disconnect { code, .. } = e {
            codes.push(code);
        }
    }
    assert_eq!(codes, [4008], "no reconnect after 4008");
    assert_eq!(back.state(), MemberState::Revoked);
}

fn wrong_parts(net: &Net, code: &PairingCode) -> PairTarget {
    let wrong = if code.code == "AAAA-AAAA" { "BBBB-BBBB" } else { "AAAA-AAAA" };
    PairTarget::Parts {
        network: net.primary.network(),
        code: wrong.into(),
        code_id: Some(code.code_id.clone()),
        relay: net.relay.url.clone(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_codes_burn_after_five_a_used_code_admits_one_node_an_absent_primary_is_unreachable() {
    let net = Net::start(&[], fast()).await;
    let mut events = net.primary.events();
    let code = net.primary.open_pairing_code(CodeOptions::default()).unwrap();
    for _ in 0..5 {
        assert_eq!(pair_with(wrong_parts(&net, &code)).await.unwrap_err().code(), ErrorCode::Pairing);
    }
    assert_eq!(pair_failures(&mut events), vec!["wrong-code"; 5]);
    assert_eq!(pair_with(PairTarget::Link(code.link.clone())).await.unwrap_err().code(), ErrorCode::Pairing);

    let once = net.primary.open_pairing_code(CodeOptions::default()).unwrap();
    assert_eq!(pair_with(PairTarget::Link(once.link.clone())).await.unwrap().roster.version(), 2);
    assert_eq!(pair_with(PairTarget::Link(once.link)).await.unwrap_err().code(), ErrorCode::Pairing);

    // A chosen code, and a cancelled one.
    let chosen = net.primary.open_pairing_code(CodeOptions { code: Some("hell-o-wor1d".into()), ..Default::default() });
    assert_eq!(chosen.unwrap_err().code(), ErrorCode::Invalid, "not 8 characters");
    let chosen = net.primary.open_pairing_code(CodeOptions { code: Some("w0rd-c0de".into()), ..Default::default() });
    let chosen = chosen.unwrap();
    assert_eq!(chosen.code, "W0RD-C0DE");
    assert_eq!(pair_with(PairTarget::Link(chosen.link)).await.unwrap().roster.version(), 3);
    let cancelled = net.primary.open_pairing_code(CodeOptions::default()).unwrap();
    net.primary.cancel_pairing_code(Some(&cancelled.code_id));
    assert_eq!(pair_with(PairTarget::Link(cancelled.link)).await.unwrap_err().code(), ErrorCode::Pairing);
    let expired =
        net.primary.open_pairing_code(CodeOptions { lifetime: Some(Duration::from_millis(1)), ..Default::default() });
    sleep_ms(20).await;
    assert_eq!(pair_with(PairTarget::Link(expired.unwrap().link)).await.unwrap_err().code(), ErrorCode::Pairing);

    let later = net.primary.open_pairing_code(CodeOptions::default()).unwrap();
    net.primary.close();
    sleep_ms(100).await;
    assert_eq!(pair_with(PairTarget::Link(later.link)).await.unwrap_err().code(), ErrorCode::Unreachable);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newer_default_code_closes_the_one_before_it_and_a_separate_code_sits_beside_them() {
    let net = Net::start(&[], fast()).await;
    let mut events = net.primary.events();
    let parts = |code: &PairingCode, code_id: Option<String>| PairTarget::Parts {
        network: net.primary.network(),
        code: code.code.clone(),
        code_id,
        relay: net.relay.url.clone(),
    };
    let beside = net.primary.open_pairing_code(CodeOptions { separate: true, ..Default::default() }).unwrap();
    assert_ne!(beside.code_id, DEFAULT_CODE_ID);
    assert_eq!(parse_pairing_link(&beside.link).unwrap().code_id, beside.code_id);
    let first = net.primary.open_pairing_code(CodeOptions::default()).unwrap();
    let second = net.primary.open_pairing_code(CodeOptions::default()).unwrap();
    assert_eq!((first.code_id.as_str(), second.code_id.as_str()), (DEFAULT_CODE_ID, DEFAULT_CODE_ID));
    assert!(!second.link.contains("&i="), "no i for the default code: {}", second.link);
    if first.code != second.code {
        let e = pair_with(PairTarget::Link(first.link)).await.unwrap_err();
        assert_eq!(e.code(), ErrorCode::Pairing, "the first default code admits nobody now");
    }
    assert_eq!(pair_with(parts(&second, None)).await.unwrap().roster.version(), 2);
    assert_eq!(pair_with(parts(&beside, Some(beside.code_id.clone()))).await.unwrap().roster.version(), 3);
    let mut paired = Vec::new();
    while let Ok(e) = events.try_recv() {
        if let Event::Paired { code_id, .. } = e {
            paired.push(code_id);
        }
    }
    assert_eq!(paired, [DEFAULT_CODE_ID.to_owned(), beside.code_id.clone()]);

    // Cancelling with no id cancels the default code, and leaves a separate one open.
    let other = net.primary.open_pairing_code(CodeOptions { separate: true, ..Default::default() }).unwrap();
    let third = net.primary.open_pairing_code(CodeOptions::default()).unwrap();
    net.primary.cancel_pairing_code(None);
    assert_eq!(pair_with(parts(&third, None)).await.unwrap_err().code(), ErrorCode::Pairing);
    assert_eq!(pair_with(PairTarget::Link(other.link)).await.unwrap().roster.version(), 4);
}

/// The generator of P-256, uncompressed: a valid point, so the primary answers it with P2.
const P256_G: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

type RawWs = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn next_json(ws: &mut RawWs) -> Json {
    loop {
        match tokio::time::timeout(SECS(5), ws.next()).await.unwrap().unwrap().unwrap() {
            Message::Text(t) => return Json::parse(t.as_str()).unwrap(),
            Message::Binary(_) => panic!("expected text"),
            _ => {}
        }
    }
}

/// A newcomer that sends a well-formed P1, receives P2, and then goes quiet.
async fn stalled_newcomer(url: &str, network: &str, code_id: &str) -> RawWs {
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    assert_eq!(next_json(&mut ws).await.get("type").and_then(Json::as_str), Some("hello"));
    let pair =
        Json::object([("type", Json::str("pair")), ("network", Json::str(network)), ("code", Json::str(code_id))]);
    ws.send(Message::text(pair.to_json_string().unwrap())).await.unwrap();
    let pairing = next_json(&mut ws).await;
    assert_eq!(pairing.get("type").and_then(Json::as_str), Some("pairing"));
    let channel = wire::from_b64u(pairing.get("channel").and_then(Json::as_str).unwrap()).unwrap();
    let mut frame = vec![1, 6];
    frame.extend_from_slice(&channel);
    frame.extend_from_slice(&wire::from_hex(P256_G).unwrap());
    ws.send(Message::binary(frame)).await.unwrap();
    match tokio::time::timeout(SECS(5), ws.next()).await.unwrap().unwrap().unwrap() {
        Message::Binary(b) => assert!(b.len() == 18 + 65 && b[1] == 6, "P2 arrives"),
        other => panic!("expected P2, got {other:?}"),
    }
    ws
}

async fn last_slot_held(net: &Net, events: &mut tokio::sync::broadcast::Receiver<Event>) -> (PairingCode, RawWs) {
    let code = net.primary.open_pairing_code(CodeOptions::default()).unwrap();
    for _ in 0..4 {
        assert_eq!(pair_with(wrong_parts(net, &code)).await.unwrap_err().code(), ErrorCode::Pairing);
    }
    let stalled = stalled_newcomer(&net.relay.url, &net.primary.network(), &code.code_id).await;
    pair_failures(events);
    // The fifth slot is in flight: the right code is turned away for now.
    assert_eq!(pair_with(PairTarget::Link(code.link.clone())).await.unwrap_err().code(), ErrorCode::Pairing);
    (code, stalled)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_end_a_newcomer_that_drops_mid_pairing_refunds_its_slot_at_the_primary() {
    let net = Net::start(&[], fast()).await;
    let mut events = net.primary.events();
    let (code, mut stalled) = last_slot_held(&net, &mut events).await;
    let mut reasons = pair_failures(&mut events);
    assert_eq!(reasons, ["no-attempts"]);
    stalled.close(None).await.unwrap();
    let deadline = tokio::time::Instant::now() + SECS(10);
    while reasons.len() < 2 && tokio::time::Instant::now() < deadline {
        sleep_ms(10).await;
        reasons.extend(pair_failures(&mut events));
    }
    assert_eq!(reasons, ["no-attempts", "newcomer-left"]);
    assert_eq!(pair_with(PairTarget::Link(code.link)).await.unwrap().roster.version(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_end_the_relay_ends_a_channel_after_its_timeout_tells_both_sides_and_the_slot_is_refunded() {
    let net = Net::start(&[("LINK_PAIR_TIMEOUT", "1s")], fast()).await;
    let mut events = net.primary.events();
    let (code, mut stalled) = last_slot_held(&net, &mut events).await;
    let mut reasons = pair_failures(&mut events);
    let end = next_json(&mut stalled).await;
    assert_eq!(end.get("type").and_then(Json::as_str), Some("pairEnd"));
    let deadline = tokio::time::Instant::now() + SECS(10);
    while reasons.len() < 2 && tokio::time::Instant::now() < deadline {
        sleep_ms(10).await;
        reasons.extend(pair_failures(&mut events));
    }
    assert_eq!(reasons, ["no-attempts", "newcomer-left"]);
    assert_eq!(pair_with(PairTarget::Link(code.link)).await.unwrap().roster.version(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_newcomer_times_out_when_the_relay_says_nothing() {
    // A listener that accepts the WebSocket and never says hello.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        sleep_ms(5000).await;
    });
    let target = PairTarget::Parts {
        network: Identity::generate().id().into(),
        code: "7K2M9QXZ".into(),
        code_id: Some("AQIDBAUGBwg".into()),
        relay: format!("ws://{addr}/v1"),
    };
    let r =
        pair(PairOptions { target, identity: Identity::generate(), timeout: Some(Duration::from_millis(300)) }).await;
    assert_eq!(r.unwrap_err().code(), ErrorCode::Timeout);
    let bad = pair(PairOptions {
        target: PairTarget::Link("frontier://pair?v=2".into()),
        identity: Identity::generate(),
        timeout: None,
    })
    .await;
    assert_eq!(bad.unwrap_err().code(), ErrorCode::Pairing);
}
