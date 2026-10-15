//! Sessions through the real relay: fragmentation and credit, rekeying, reset after a peer loses
//! its state, unreachable peers, and a copy of an identity replacing the first.

mod support;

use std::collections::HashSet;
use std::time::Duration;

use link_client::*;
use support::*;

const SECS: fn(u64) -> Duration = Duration::from_secs;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_of_several_mib_is_fragmented_relayed_and_reassembled_whole() {
    let net = Net::start(&[], fast()).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    let big = pattern(6 * 1024 * 1024 + 17, 3);
    worker.send(surface.id(), big.clone()).await.unwrap();
    let got = recv_within(&surface, SECS(60)).await;
    assert_eq!(got.from, worker.id());
    assert_eq!(got.bytes.len(), big.len());
    assert!(got.bytes == big);
    // A fragment carries at most 65517 bytes, so at least 97 data frames went through.
    let info = worker.session_info(surface.id());
    assert!(info[0].sent >= big.len().div_ceil(65517) as u64, "{info:?}");
    // And back the other way, on the same session.
    let back = pattern(3 * 1024 * 1024, 9);
    surface.send(worker.id(), back.clone()).await.unwrap();
    assert!(recv_within(&worker, SECS(60)).await.bytes == back);
    // The largest message there is.
    let max = pattern(MAX_MESSAGE, 1);
    worker.send(surface.id(), max.clone()).await.unwrap();
    assert!(recv_within(&surface, SECS(120)).await.bytes == max);
    let over = vec![0u8; MAX_MESSAGE + 1];
    assert_eq!(worker.send(surface.id(), over).await.unwrap_err().code(), ErrorCode::Invalid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credit_a_sender_waits_while_the_receiver_takes_nothing_and_resumes_as_it_reads() {
    let net = Net::start(&[], fast()).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    let msgs: Vec<Vec<u8>> = (1..=3).map(|n| vec![n as u8; 700 * 1024]).collect();
    // The first arrives while the application holds nothing, so its fragments are credited back
    // at once; the second arrives behind an unread message and is not; the third needs more
    // credit than is left and waits.
    worker.send(surface.id(), msgs[0].clone()).await.unwrap();
    worker.send(surface.id(), msgs[1].clone()).await.unwrap();
    let w = worker.clone();
    let peer = surface.id().to_owned();
    let third_msg = msgs[2].clone();
    let third = tokio::spawn(async move { w.send(&peer, third_msg).await });
    sleep_ms(500).await;
    assert!(!third.is_finished(), "the third message waits");
    let s = worker.session_info(surface.id())[0].clone();
    assert!(s.inflight <= 1024 * 1024, "{} bytes in flight", s.inflight);
    assert!(recv_within(&surface, SECS(5)).await.bytes == msgs[0]);
    sleep_ms(300).await;
    assert!(!third.is_finished(), "one message is still unread");
    assert!(recv_within(&surface, SECS(5)).await.bytes == msgs[1]);
    tokio::time::timeout(SECS(10), third).await.unwrap().unwrap().unwrap();
    assert!(recv_within(&surface, SECS(5)).await.bytes == msgs[2]);
    // Everything was taken: the full window is back with the sender.
    until(|| worker.session_info(surface.id())[0].send_credit == INITIAL_CREDIT, "all credit returned").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_larger_credit_window_is_granted_as_extra_credit_over_the_relay() {
    let net = Net::start(&[], fast()).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let surface = net.add_with(MemberKind::Surface, &[&worker], |o| o.credit_window = Some(8 * 1024 * 1024)).await;
    worker.send(surface.id(), &b"x"[..]).await.unwrap();
    recv_within(&surface, SECS(5)).await;
    until(
        || worker.session_info(surface.id()).first().is_some_and(|s| s.send_credit == 8 * 1024 * 1024),
        "an 8 MiB window",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rekey_on_a_timer_new_sessions_replace_old_ones_while_messages_keep_flowing_in_order() {
    let timing = Timing { rekey_interval: Duration::from_millis(250), retire_grace: SECS(1), ..fast() };
    let net = Net::start(&[], timing).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    let mut indices = HashSet::new();
    for i in 0..60 {
        worker.send(surface.id(), format!("w{i}").into_bytes()).await.unwrap();
        surface.send(worker.id(), format!("s{i}").into_bytes()).await.unwrap();
        if let Some(cur) = worker.session_info(surface.id()).iter().find(|s| s.current) {
            indices.insert(cur.local_index);
        }
        sleep_ms(20).await;
    }
    for i in 0..60 {
        assert_eq!(recv_within(&surface, SECS(10)).await.bytes, format!("w{i}").into_bytes());
        assert_eq!(recv_within(&worker, SECS(10)).await.bytes, format!("s{i}").into_bytes());
    }
    assert!(indices.len() >= 3, "expected at least two rekeys, saw {} sessions", indices.len());
    // A rekey in the middle of a large message never splits it.
    let big = pattern(3 * 1024 * 1024, 5);
    worker.send(surface.id(), big.clone()).await.unwrap();
    assert!(recv_within(&surface, SECS(30)).await.bytes == big);
    until_for(&mut || worker.session_info(surface.id()).len() <= 2, "retired sessions to be forgotten", SECS(15)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rekey_after_a_message_count() {
    let net = Net::start(&[], Timing { rekey_messages: 4, ..fast() }).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    let mut indices = HashSet::new();
    for i in 0..30 {
        worker.send(surface.id(), i.to_string().into_bytes()).await.unwrap();
        indices.insert(worker.session_info(surface.id()).iter().find(|s| s.current).unwrap().local_index);
        sleep_ms(5).await;
    }
    for i in 0..30 {
        assert_eq!(recv_within(&surface, SECS(10)).await.bytes, i.to_string().into_bytes());
    }
    assert!(indices.len() >= 4, "expected several rekeys, saw {} sessions", indices.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reset_a_peer_that_lost_its_state_answers_reset_and_the_sender_handshakes_again() {
    let net = Net::start(&[], fast()).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    worker.send(surface.id(), &b"one"[..]).await.unwrap();
    recv_within(&surface, SECS(5)).await;
    let before = worker.session_info(surface.id())[0].local_index;
    // The surface restarts: same identity and roster, no sessions.
    let (identity, roster) = (surface.identity(), surface.roster());
    surface.close();
    sleep_ms(100).await;
    let mut opts = MemberOptions::new(identity, roster);
    opts.timing = fast();
    let fresh = Member::connect(opts).await.unwrap();
    // The worker still holds its session; its frame names an index the fresh copy does not.
    worker.send(fresh.id(), &b"lost"[..]).await.unwrap();
    until(|| worker.session_info(fresh.id()).is_empty(), "the worker to drop the session on reset").await;
    worker.send(fresh.id(), &b"two"[..]).await.unwrap();
    assert_eq!(&recv_within(&fresh, SECS(5)).await.bytes[..], b"two");
    assert_ne!(worker.session_info(fresh.id())[0].local_index, before);
    assert!(fresh.try_recv().is_none(), "the message in the reset frame is lost");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_responder_expires_a_session_past_the_rekey_interval_plus_grace_and_answers_reset() {
    let net = Net::start(&[], fast()).await;
    let worker = net.add_with(MemberKind::Worker, &[], |o| o.timing.rekey_interval = SECS(3600)).await;
    let surface = net
        .add_with(MemberKind::Surface, &[&worker], |o| {
            o.timing.rekey_interval = Duration::from_millis(150);
            o.timing.retire_grace = Duration::from_millis(100);
        })
        .await;
    worker.send(surface.id(), &b"fresh"[..]).await.unwrap();
    recv_within(&surface, SECS(5)).await;
    let first = worker.session_info(surface.id())[0].local_index;
    sleep_ms(400).await;
    worker.send(surface.id(), &b"expired"[..]).await.unwrap();
    until(|| worker.session_info(surface.id()).is_empty(), "the reset to arrive").await;
    worker.send(surface.id(), &b"renewed"[..]).await.unwrap();
    assert_eq!(&recv_within(&surface, SECS(5)).await.bytes[..], b"renewed");
    assert_ne!(worker.session_info(surface.id())[0].local_index, first);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_a_send_to_a_member_that_is_not_connected_fails_at_once() {
    let net = Net::start(&[], fast()).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let (absent, _) = net.pair_only(MemberKind::Mcp).await;
    until(|| worker.roster().member(absent.id()).is_some(), "the worker to learn of the mcp").await;
    let started = std::time::Instant::now();
    assert_eq!(worker.send(absent.id(), &b"x"[..]).await.unwrap_err().code(), ErrorCode::Unreachable);
    assert!(started.elapsed() < SECS(1), "at once");
    assert_eq!(worker.send(Identity::generate().id(), &b"x"[..]).await.unwrap_err().code(), ErrorCode::Invalid);
    assert_eq!(worker.send(worker.id(), &b"x"[..]).await.unwrap_err().code(), ErrorCode::Invalid);

    // A peer that leaves mid-session: the next send learns it from the relay.
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    worker.send(surface.id(), &b"1"[..]).await.unwrap();
    recv_within(&surface, SECS(5)).await;
    surface.close();
    sleep_ms(100).await;
    let _ = worker.send(surface.id(), &b"handed to the relay"[..]).await;
    until(|| worker.session_info(surface.id()).is_empty(), "the session to end on unreachable").await;
    assert_eq!(worker.send(surface.id(), &b"x"[..]).await.unwrap_err().code(), ErrorCode::Unreachable);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_copy_of_an_identity_replaces_the_first_which_stops_for_good() {
    let net = Net::start(&[], fast()).await;
    let (wid, wroster) = net.pair_only(MemberKind::Worker).await;
    let mut opts = MemberOptions::new(wid.clone(), wroster);
    opts.timing = fast();
    let worker = Member::connect(opts).await.unwrap();
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    let mut events = events_from_now(&worker);
    let mut copy_opts = MemberOptions::new(wid, worker.roster());
    copy_opts.timing = fast();
    let copy = Member::connect(copy_opts).await.unwrap();
    until(|| worker.state() == MemberState::Replaced, "the first copy to be replaced").await;
    assert_eq!(worker.send(surface.id(), &b"x"[..]).await.unwrap_err().code(), ErrorCode::Replaced);
    assert_eq!(worker.wait_connected(None).await.unwrap_err().code(), ErrorCode::Replaced);
    sleep_ms(400).await;
    let mut seen = Vec::new();
    while let Ok(e) = events.try_recv() {
        match e {
            Event::Disconnect { code, .. } => seen.push(format!("disconnect {code}")),
            Event::State(s) => seen.push(format!("state {s}")),
            _ => {}
        }
    }
    assert_eq!(seen, ["disconnect 4005", "state replaced"], "no reconnect after 4005");
    assert_eq!(copy.state(), MemberState::Connected, "the copy keeps its connection");
    copy.send(surface.id(), &b"from the copy"[..]).await.unwrap();
    let m = recv_within(&surface, SECS(5)).await;
    assert_eq!(m.from, copy.id());
    assert_eq!(&m.bytes[..], b"from the copy");
}
