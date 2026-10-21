//! Security review findings reproduced against the real relay.
//!
//! H1: a co-member floods the victim with roster-requests, then with frames naming bad indices,
//! and never reads its own socket, so the relay stops reading the victim. Before the fix the victim
//! queued an answer per request without bound (431 MiB queued, +450 MiB resident, for 11 MiB of
//! requests). Now it answers at a bounded rate and holds a bounded queue.

mod support;

use std::time::{Duration, Instant};

use link_client::wire::*;
use link_client::*;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_flooding_requests_and_not_reading_cannot_grow_the_victim() {
    let net = Net::start(&[], fast()).await;
    let victim = &net.primary;
    // A realistic roster (each member some 170 bytes).
    for _ in 0..8 {
        net.pair_only().await;
    }
    let (aid, aroster) = net.pair_only().await;
    let honest = net.add(&[]).await;
    let roster_bytes = victim.roster().size() as u64;
    let mut attacker = RawMember::connect(net.relay.port, aid.clone(), aroster).await;
    let (mut send, remote) = attacker.handshake(victim.id(), victim.roster().version()).await;
    sleep_ms(300).await;

    // 1. Roster-requests: 100,000 of them, about 4 MiB.
    let rss0 = rss_mib();
    let sent_before = victim.traffic().peers[aid.id()].sent;
    let started = Instant::now();
    for i in 0..100_000u32 {
        let ct = send.encrypt_with_ad(&[], &SessionMessage::RosterRequest.encode()).unwrap();
        attacker.feed(frame_type::CONTROL, victim.id(), &data_body(remote, &ct)).await;
        if i % 1000 == 999 {
            attacker.flush().await;
        }
    }
    attacker.flush().await;
    sleep_ms(3000).await;
    let elapsed = started.elapsed();
    let sent = victim.traffic().peers[aid.id()].sent;
    let answers = sent.frames - sent_before.frames;
    let answer_bytes = sent.frame_bytes - sent_before.frame_bytes;
    // At most one answer per 250 ms (fewer: none is queued while one is unsent).
    let ceiling = 1 + elapsed.as_millis() as u64 / 250;
    println!("roster-requests: {answers} answers ({answer_bytes} bytes) in {elapsed:?}; roster {roster_bytes} bytes");
    assert!(answers <= ceiling, "{answers} answers in {elapsed:?}");
    assert!(answer_bytes <= ceiling * (roster_bytes + 64), "{answer_bytes} bytes of answers");
    let grown = rss_mib().saturating_sub(rss0);
    assert!(grown < 64, "resident memory grew {grown} MiB");

    // 2. Frames naming bad indices (which the relay itself could forge): 100,000 of them.
    let before = victim.traffic().peers[aid.id()].sent.frames;
    let started = Instant::now();
    for i in 0..100_000u32 {
        attacker.feed(frame_type::DATA, victim.id(), &data_body(0x4000_0000 + i, &[0; 17])).await;
        if i % 1000 == 999 {
            attacker.flush().await;
        }
    }
    attacker.flush().await;
    sleep_ms(1000).await;
    let resets = victim.traffic().peers[aid.id()].sent.frames - before;
    let secs = started.elapsed().as_secs() + 1;
    println!(
        "bad indices: {resets} resets in {:?}; resident memory grew {} MiB",
        started.elapsed(),
        rss_mib().saturating_sub(rss0)
    );
    // One peer's reset budget: 64 at once, 32 a second.
    assert!(resets <= 64 + 32 * secs, "{resets} resets in {secs} s");
    let grown = rss_mib().saturating_sub(rss0);
    assert!(grown < 64, "resident memory grew {grown} MiB");

    // The attacker goes; the victim talks with an honest member both ways.
    drop(attacker);
    sleep_ms(500).await;
    victim.wait_connected(Some(Duration::from_secs(10))).await.unwrap();
    honest.send(victim.id(), &b"still here"[..]).await.unwrap();
    assert_eq!(&recv_within(victim, Duration::from_secs(10)).await.bytes[..], b"still here");
    victim.send(honest.id(), &b"and here"[..]).await.unwrap();
    assert_eq!(&recv_within(&honest, Duration::from_secs(10)).await.bytes[..], b"and here");
}

/// Review M1, against the real relay: while one member floods the victim with frames naming
/// unknown indices, an honest peer's frames on a dead session still draw their resets (with a
/// budget shared by all peers it got 2 to 5 of 30).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_members_reset_flood_does_not_starve_an_honest_peers_resets() {
    let net = Net::start(&[], fast()).await;
    let victim = net.primary.id().to_owned();
    let (hid, hroster) = net.pair_only().await;
    let (aid, aroster) = net.pair_only().await;
    sleep_ms(300).await;
    let mut honest = RawMember::connect(net.relay.port, hid, hroster).await;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let attacker = {
        let (port, victim, stop) = (net.relay.port, victim.clone(), stop.clone());
        tokio::spawn(async move {
            let mut a = RawMember::connect(port, aid, aroster).await;
            let mut idx: u32 = 1;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                for _ in 0..300 {
                    idx = idx.wrapping_add(1).max(1);
                    a.feed(frame_type::CONTROL, &victim, &data_body(idx, &[0; 17])).await;
                }
                a.flush().await;
                // Read what comes back, so the relay never holds the victim behind it.
                while a.next_frame_within(Duration::from_millis(1)).await.is_some() {}
                sleep_ms(5).await;
            }
        })
    };
    sleep_ms(300).await;
    // Every reset that comes back, by the index it names. A reset dropped for want of budget is
    // never sent later, so waiting for late ones hides no starvation; it only spares the test a
    // timing assumption about how fast a busy victim answers.
    let mut answered = std::collections::HashSet::new();
    let read = |f: Vec<u8>, answered: &mut std::collections::HashSet<u32>| {
        if let Ok(f) = decode_frame(&f)
            && f.kind == frame_type::RESET
            && let Ok(index) = <[u8; 4]>::try_from(f.body)
        {
            answered.insert(u32::from_be_bytes(index));
        }
    };
    let sent: Vec<u32> = (0..30).map(|i| 0xa000_0000 + i).collect();
    for &index in &sent {
        honest.feed(frame_type::CONTROL, &victim, &data_body(index, &[0; 17])).await;
        honest.flush().await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        while let Some(f) =
            honest.next_frame_within(deadline.saturating_duration_since(tokio::time::Instant::now())).await
        {
            read(f, &mut answered);
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while sent.iter().any(|i| !answered.contains(i)) {
        let Some(f) = honest.next_frame_within(deadline.saturating_duration_since(tokio::time::Instant::now())).await
        else {
            break;
        };
        read(f, &mut answered);
    }
    let resets = sent.iter().filter(|i| answered.contains(i)).count();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = attacker.await;
    println!("honest peer: {resets} resets for 30 frames on dead sessions, under a reset flood");
    assert_eq!(resets, 30);
}

/// Re-review 4, M2 (`member_init_ceiling.rs`), against the real relay: eight members stream
/// handshake-inits in their own names on a bogus static key. With one failure ceiling shared by
/// all members, an honest member's handshakes to the victim were all dropped (0 of 28); with each
/// member's own failure budget, every one paced within its init budget completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_failing_their_own_inits_cannot_block_an_honest_members_handshakes() {
    let net = Net::start(&[], fast()).await;
    let victim = net.primary.id().to_owned();
    let (hid, hroster) = net.pair_only().await;
    let mut attackers = Vec::new();
    for _ in 0..8 {
        attackers.push(net.pair_only().await);
    }
    sleep_ms(300).await;
    let version = net.primary.roster().version();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut tasks = Vec::new();
    for (aid, aroster) in attackers {
        let (port, victim, stop) = (net.relay.port, victim.clone(), stop.clone());
        tasks.push(tokio::spawn(async move {
            let mut a = RawMember::connect(port, aid, aroster).await;
            let theirs = *a.roster.member(&victim).unwrap().x25519();
            let prologue = session_prologue(a.roster.network());
            let mut local: u32 = 1;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                for _ in 0..64 {
                    // A static key that is not this member's: the victim's key check fails.
                    let mut hs = HandshakeState::new(HandshakeOptions {
                        pattern: &IK,
                        initiator: true,
                        prologue: &prologue,
                        s: Some(KeyPair::from_private(&[0x5a; 32])),
                        rs: Some(theirs),
                        fixed_ephemeral: None,
                    })
                    .unwrap();
                    let (m1, _) = hs.write_message(&init_payload(version, stamp())).unwrap();
                    local = local.wrapping_add(1).max(1);
                    a.feed(frame_type::HANDSHAKE_INIT, &victim, &handshake_init_body(local, &m1)).await;
                }
                a.flush().await;
                while a.next_frame_within(Duration::from_millis(1)).await.is_some() {}
                sleep_ms(20).await;
            }
        }));
    }
    // Long enough for the attackers to spend any ceiling they could.
    sleep_ms(400).await;
    let mut honest = RawMember::connect(net.relay.port, hid, hroster).await;
    let theirs = *honest.roster.member(&victim).unwrap().x25519();
    let prologue = session_prologue(honest.roster.network());
    let (mut attempts, mut completed) = (0u32, 0u32);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        attempts += 1;
        let mut hs = HandshakeState::new(HandshakeOptions {
            pattern: &IK,
            initiator: true,
            prologue: &prologue,
            s: Some(KeyPair::from_private(&honest.id.x25519_private())),
            rs: Some(theirs),
            fixed_ephemeral: None,
        })
        .unwrap();
        let (m1, _) = hs.write_message(&init_payload(version, stamp())).unwrap();
        let local = 0x1000_0000 + attempts;
        let tick = tokio::time::Instant::now();
        honest.feed(frame_type::HANDSHAKE_INIT, &victim, &handshake_init_body(local, &m1)).await;
        honest.flush().await;
        // An answer naming this attempt within a second, then the rest of a 100 ms pace (10 a
        // second, within a member's 16).
        let deadline = tick + Duration::from_secs(1);
        while let Some(f) =
            honest.next_frame_within(deadline.saturating_duration_since(tokio::time::Instant::now())).await
        {
            if let Ok(f) = decode_frame(&f)
                && f.kind == frame_type::HANDSHAKE_RESP
                && parse_handshake_resp(f.body).is_some_and(|(_, mine, _)| mine == local)
            {
                completed += 1;
                break;
            }
        }
        tokio::time::sleep_until(tick + Duration::from_millis(100)).await;
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    for t in tasks {
        let _ = t.await;
    }
    println!("honest member: {completed} of {attempts} handshakes completed under 8 members' failing inits");
    assert_eq!(completed, attempts);
}

/// Re-review 4, L4 (`forged_version_push.rs`), against the real relay: a member sends one init in
/// its own name on a bogus static key, claiming roster version 0. The victim had answered the
/// refusal by pushing the member the roster; now the refusal is all that comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_claimed_by_an_init_on_the_wrong_key_pushes_no_roster() {
    let net = Net::start(&[], fast()).await;
    let victim = net.primary.id().to_owned();
    let (aid, aroster) = net.pair_only().await;
    net.pair_only().await;
    // A first comes as a library member, takes the newest roster, and shows the primary it holds
    // it (a handshake carries the version), so no push to it is owed: one owed would rightly be
    // made again, and show up below.
    let mut opts = MemberOptions::new(aid.clone(), aroster);
    opts.timing = fast();
    let member = Member::connect(opts).await.unwrap();
    let version = net.primary.roster().version();
    until(|| member.roster().version() == version, "A to hold the newest roster").await;
    member.send(&victim, &b"here"[..]).await.unwrap();
    assert_eq!(&recv_within(&net.primary, Duration::from_secs(10)).await.bytes[..], b"here");
    let aroster = member.roster();
    member.close();
    sleep_ms(300).await;
    let mut a = RawMember::connect(net.relay.port, aid, aroster).await;
    let theirs = *a.roster.member(&victim).unwrap().x25519();
    let mut hs = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: true,
        prologue: &session_prologue(a.roster.network()),
        s: Some(KeyPair::from_private(&[0x5a; 32])),
        rs: Some(theirs),
        fixed_ephemeral: None,
    })
    .unwrap();
    let (m1, _) = hs.write_message(&init_payload(0, stamp())).unwrap();
    a.feed(frame_type::HANDSHAKE_INIT, &victim, &handshake_init_body(7, &m1)).await;
    a.flush().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut kinds = Vec::new();
    while let Some(f) = a.next_frame_within(deadline.saturating_duration_since(tokio::time::Instant::now())).await {
        kinds.push(decode_frame(&f).unwrap().kind);
    }
    println!("frames to the member after a wrong-key init claiming version 0: {kinds:?}");
    assert_eq!(kinds, [frame_type::REFUSED]);
}
