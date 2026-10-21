//! Membership through the real relay: revocation, resignation, refusal by a member whose
//! roster does not list the sender, the relay forgetting an idle network, rosters spreading
//! member to member, and usage.

mod support;

use std::time::Duration;

use link_client::*;
use support::*;

const SECS: fn(u64) -> Duration = Duration::from_secs;

fn opts(identity: Identity, roster: Roster) -> MemberOptions {
    let mut o = MemberOptions::new(identity, roster);
    o.timing = fast();
    o
}

fn disconnect_codes(events: &mut tokio::sync::broadcast::Receiver<Event>) -> (Vec<u16>, Vec<MemberState>) {
    let (mut codes, mut states) = (Vec::new(), Vec::new());
    while let Ok(e) = events.try_recv() {
        match e {
            Event::Disconnect { code, .. } => codes.push(code),
            Event::State(s) => states.push(s),
            _ => {}
        }
    }
    (codes, states)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_closes_the_member_4008_for_good_and_the_others_drop_it() {
    let net = Net::start(&[], fast()).await;
    let alice = net.add(&[]).await;
    let bob = net.add(&[&alice]).await;
    bob.send(alice.id(), &b"before"[..]).await.unwrap();
    recv_within(&alice, SECS(5)).await;
    alice.send(bob.id(), &b"a session both ways"[..]).await.unwrap();
    let mut events = events_from_now(&bob);

    let r = net.primary.revoke(bob.id()).unwrap();
    assert_eq!(r.version(), 4);
    until(|| bob.state() == MemberState::Revoked, "bob to be revoked").await;
    until(|| alice.roster().version() == 4, "alice to receive v4").await;
    assert!(alice.session_info(bob.id()).is_empty(), "alice dropped its sessions");
    assert_eq!(alice.send(bob.id(), &b"to the revoked"[..]).await.unwrap_err().code(), ErrorCode::Invalid);
    assert_eq!(bob.send(alice.id(), &b"from the revoked"[..]).await.unwrap_err().code(), ErrorCode::Revoked);
    assert_eq!(bob.wait_connected(None).await.unwrap_err().code(), ErrorCode::Revoked);
    sleep_ms(400).await;
    let (codes, states) = disconnect_codes(&mut events);
    assert_eq!(codes, [4008], "no reconnect after 4008");
    assert_eq!(states, [MemberState::Revoked]);
    assert_eq!(net.primary.revoke(bob.id()).unwrap_err().code(), ErrorCode::Invalid);
    assert_eq!(net.primary.revoke(net.primary.id()).unwrap_err().code(), ErrorCode::Invalid);

    // A new copy of the revoked identity, with its old roster, is turned away at registration.
    let again = Member::new(opts(bob.identity(), bob.roster())).unwrap();
    assert_eq!(again.wait_connected(Some(SECS(10))).await.unwrap_err().code(), ErrorCode::Revoked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resign_the_primary_publishes_a_roster_without_the_member_which_the_relay_then_closes() {
    let net = Net::start(&[], fast()).await;
    let alice = net.add(&[]).await;
    let bob = net.add(&[&alice]).await;
    let mut events = events_from_now(&bob);
    bob.resign().await.unwrap();
    assert_eq!(bob.state(), MemberState::Revoked);
    assert_eq!(disconnect_codes(&mut events).0, [4008]);
    assert_eq!(net.primary.roster().version(), 4);
    assert!(net.primary.roster().member(bob.id()).is_none());
    until(|| alice.roster().version() == 4, "alice to receive v4").await;
    assert_eq!(alice.send(bob.id(), &b"x"[..]).await.unwrap_err().code(), ErrorCode::Invalid);
    assert_eq!(net.primary.resign().await.unwrap_err().code(), ErrorCode::Invalid, "the primary cannot resign");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_a_member_whose_roster_lacks_the_sender_refuses_it_then_catches_up_from_the_primary() {
    // The relay forgets an idle network; the first member back presents an old roster and the
    // relay knows no better. Only the member itself can catch up.
    let net = Net::start(&[("LINK_NETWORK_TTL", "500ms")], fast()).await;
    let (wid, wroster) = net.pair_only().await; // v2
    let (sid, sroster) = net.pair_only().await; // v3, which alice never sees
    let (pid, proster) = (net.primary.identity(), net.primary.roster());
    net.primary.close();
    sleep_ms(1500).await;

    let w = Member::connect(opts(wid, wroster)).await.unwrap();
    assert_eq!(w.roster().version(), 2, "the relay had nothing newer");
    let s = Member::connect(opts(sid, sroster)).await.unwrap();
    assert_eq!(w.state(), MemberState::Connected, "v3 still lists alice");

    let err = s.send(w.id(), &b"do you know me?"[..]).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Refused);
    assert_eq!(err.reason(), Some(1));
    assert_eq!(w.roster().version(), 2, "the primary is away, so alice cannot catch up yet");

    let mut po = opts(pid, proster);
    po.timing = fast();
    po.network_seed = Some(*net.network_key.seed());
    let _p = Primary::connect(po).await.unwrap();
    assert!(w.sync_roster().await.unwrap());
    assert_eq!(w.roster().version(), 3);
    s.send(w.id(), &b"now you do"[..]).await.unwrap();
    assert_eq!(&recv_within(&w, SECS(5)).await.bytes[..], b"now you do");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_member_reaching_a_forgetful_relay_is_closed_4008_once_an_up_to_date_member_registers() {
    let net = Net::start(&[("LINK_NETWORK_TTL", "500ms")], fast()).await;
    let alice = net.add(&[]).await;
    let bob = net.add(&[&alice]).await;
    let stale = bob.roster(); // v3
    let sid = bob.identity();
    bob.close();
    sleep_ms(100).await;
    net.primary.revoke(sid.id()).unwrap(); // v4, while bob is away
    let (pid, proster) = (net.primary.identity(), net.primary.roster());
    alice.close();
    net.primary.close();
    sleep_ms(1500).await;

    let back = Member::connect(opts(sid, stale)).await.unwrap();
    let mut events = events_from_now(&back);
    // The primary presents v4, which replaces the relay's v3 and evicts bob.
    let mut po = opts(pid, proster);
    po.network_seed = Some(*net.network_key.seed());
    let _p = Primary::connect(po).await.unwrap();
    until(|| back.state() == MemberState::Revoked, "bob to be closed").await;
    assert_eq!(disconnect_codes(&mut events).0, [4008]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_spreads_member_to_member_with_the_primary_offline_and_the_relay_forgetful() {
    let net = Net::start(&[("LINK_NETWORK_TTL", "300ms")], fast()).await;
    let (wid, _) = net.pair_only().await;
    let (tid, _) = net.pair_only().await;
    let (xid, before) = net.pair_only().await;
    // The tablet stays offline while the primary revokes the phone (x).
    let w = Member::connect(opts(wid.clone(), net.primary.roster())).await.unwrap();
    let t_roster = net.primary.roster();
    net.primary.revoke(xid.id()).unwrap();
    let after = net.primary.roster().version();
    until(|| w.roster().version() == after, "alice to learn the revocation").await;
    // Everyone goes; the relay forgets the network.
    let w_roster = w.roster();
    w.close();
    net.primary.close();
    sleep_ms(800).await;
    // The tablet and the revoked phone come back first, both on the roster from before: a relay
    // that knows nothing newer lets them in, and they would talk.
    let t = Member::connect(opts(tid, t_roster)).await.unwrap();
    let x = Member::connect(opts(xid, before)).await.unwrap();
    t.send(x.id(), &b"before"[..]).await.unwrap();
    recv_within(&x, SECS(5)).await;
    // Alice comes back with the revocation. The primary is still offline: the tablet
    // learns it from alice alone, then refuses the phone by itself.
    let w2 = Member::connect(opts(wid, w_roster)).await.unwrap();
    t.send(w2.id(), &b"hello"[..]).await.unwrap();
    recv_within(&w2, SECS(5)).await;
    until(|| t.roster().version() == after, "the tablet to learn the revocation from its peer").await;
    assert_eq!(t.send(x.id(), &b"after"[..]).await.unwrap_err().code(), ErrorCode::Invalid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_the_primary_reads_the_network_totals_and_each_member_counts_its_own_traffic() {
    let net = Net::start(&[], fast()).await;
    let alice = net.add(&[]).await;
    let bob = net.add(&[&alice]).await;
    net.pair_only().await; // on the roster, never connected
    let before = net.primary.usage().await.unwrap();
    assert_eq!(before.connections, 3.0);
    assert_eq!(before.limits, UsageLimits::default());
    assert_eq!(before.quota_used, 0.0);
    assert!(!before.slowed);

    alice.reset_traffic();
    bob.reset_traffic();
    let payload = vec![7u8; 300_000];
    alice.send(bob.id(), payload.clone()).await.unwrap();
    recv_within(&bob, SECS(10)).await;
    let after = net.primary.usage().await.unwrap();
    assert!(after.bytes_hour - before.bytes_hour >= payload.len() as f64);
    let sent = alice.traffic().peers[bob.id()].sent;
    let got = bob.traffic().peers[alice.id()].received;
    assert_eq!((sent.messages, sent.bytes), (1, payload.len() as u64));
    assert_eq!((got.messages, got.bytes), (1, payload.len() as u64));
    assert_eq!((got.frames, got.frame_bytes), (sent.frames, sent.frame_bytes));
    assert!(sent.frame_bytes > payload.len() as u64 && (sent.frame_bytes as f64) < payload.len() as f64 * 1.01);
    let t = alice.traffic();
    assert_eq!(t.total.sent.bytes, payload.len() as u64);
    assert!(t.relay.sent == 0 && t.relay.received == 0, "no control messages since the reset");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_asks_three_at_once_then_rate_limited_until_the_budget_refills() {
    let net = Net::start(&[], fast()).await;
    let results = futures_util::future::join_all((0..4).map(|_| net.primary.usage())).await;
    let ok = results.iter().filter(|r| r.is_ok()).count();
    let limited: Vec<_> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    assert_eq!(ok, 3, "{results:?}");
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].code(), ErrorCode::RateLimited);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quota_the_primary_learns_the_network_is_slowed_and_the_trickle_slows_traffic() {
    let (quota, trickle) = (1_000_000u64, 200_000u64);
    let env = [("LINK_QUOTA_BYTES_HOUR", "1000000"), ("LINK_TRICKLE_BPS", "200000")];
    let net = Net::start(&env, fast()).await;
    let alice = net.add(&[]).await;
    let bob = net.add(&[&alice]).await;
    alice.send(bob.id(), vec![0u8; 1_100_000]).await.unwrap();
    recv_within(&bob, SECS(20)).await;
    let u = net.primary.usage().await.unwrap();
    assert!(u.slowed);
    assert!(u.quota_used >= 1.0, "quotaUsed {}", u.quota_used);
    assert_eq!(u.limits, UsageLimits { rate_bps: 0.0, quota_bytes_hour: quota as f64, trickle_bps: trickle as f64 });
    // At the trickle rate (its bucket starts with one second of tokens), 600 kB take over 1.5 s.
    let started = std::time::Instant::now();
    alice.send(bob.id(), vec![0u8; 600_000]).await.unwrap();
    recv_within(&bob, SECS(20)).await;
    assert!(started.elapsed() >= Duration::from_millis(1500), "600 kB arrived in {:?}", started.elapsed());
}
