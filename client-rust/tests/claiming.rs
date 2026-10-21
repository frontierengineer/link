//! Becoming the primary through the real relay (spec section 3.1): the network's own seed names
//! it and signs its roster whoever is primary; a node started with that seed under a roster
//! naming another member primary claims the network once registered; the relay demotes the
//! former primary's connection in place, and nobody is disconnected.

mod support;

use std::time::Duration;

use link_client::*;
use support::*;

const SECS: fn(u64) -> Duration = Duration::from_secs;

fn closes(events: &mut tokio::sync::broadcast::Receiver<Event>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(e) = events.try_recv() {
        match e {
            Event::Disconnect { code, .. } => out.push(format!("disconnect {code}")),
            Event::State(s) => out.push(format!("state {s:?}")),
            _ => {}
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_network_id_comes_from_the_network_seed_and_its_key_signs_the_roster() {
    let net = Net::start(&[], fast()).await;
    let r = net.primary.roster();
    assert_eq!(r.network(), net.network_key.id());
    assert_ne!(r.network(), net.primary.id(), "not the primary's node id");
    assert_eq!(r.network_key(), &net.network_key.ed25519_public());
    let signed = roster_signing_bytes(r.json()).unwrap();
    let sig: [u8; 64] =
        wire::from_b64u(r.json().get("signature").and_then(Json::as_str).unwrap()).unwrap().try_into().unwrap();
    assert!(wire::ed25519_verify(&net.network_key.ed25519_public(), &signed, &sig));
    assert!(!wire::ed25519_verify(&net.primary.identity().ed25519_public(), &signed, &sig));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_started_with_the_seed_claims_and_the_former_primary_is_demoted_in_place() {
    let net = Net::start(&[], fast()).await;
    let bob = net.add(&[]).await;
    let (wid, wroster) = net.pair_only().await;
    assert_eq!(wroster.primary_id(), net.primary.id());
    let former: &Member = &net.primary;
    until(|| former.roster().version() == wroster.version(), "the primary to hold alice's roster").await;
    let mut before = events_from_now(former);

    // The caller starts alice with the network seed, under a roster naming another primary.
    let mut o = MemberOptions::new(wid, wroster.clone());
    o.timing = fast();
    o.network_seed = Some(*net.network_key.seed());
    let alice = Primary::connect(o).await.unwrap();
    until(|| alice.is_primary(), "alice to claim the network").await;
    let claimed = alice.roster();
    assert_eq!(claimed.version(), wroster.version() + 1);
    assert_eq!(claimed.primary_id(), alice.id());
    assert_eq!(claimed.members(), wroster.members(), "the members unchanged: only `primary` moved");
    assert_eq!(claimed.network(), wroster.network());
    until(|| former.roster().version() == claimed.version(), "the former primary to take the claim").await;
    until(|| bob.roster().version() == claimed.version(), "bob to take the claim").await;

    // The former primary: no longer the primary, still connected, nothing closed.
    assert!(!former.is_primary());
    assert!(former.holds_network_seed(), "its caller's seed is untouched");
    sleep_ms(300).await;
    assert_eq!(closes(&mut before), Vec::<String>::new());
    assert_eq!(former.state(), MemberState::Connected);

    // It goes on as a member, both ways, over the same connection.
    former.send(bob.id(), &b"from the former primary"[..]).await.unwrap();
    assert_eq!(&recv_within(&bob, SECS(5)).await.bytes[..], b"from the former primary");
    bob.send(former.id(), &b"to the former primary"[..]).await.unwrap();
    assert_eq!(&recv_within(former, SECS(5)).await.bytes[..], b"to the former primary");
    alice.send(former.id(), &b"from the new primary"[..]).await.unwrap();
    assert_eq!(&recv_within(former, SECS(5)).await.bytes[..], b"from the new primary");

    // It can do nothing a primary does.
    let code = former.open_pairing_code(CodeOptions::default());
    assert_eq!(code.unwrap_err().code(), ErrorCode::Invalid);
    assert_eq!(former.revoke(bob.id()).unwrap_err().code(), ErrorCode::Invalid);
    assert_eq!(former.usage().await.unwrap_err().code(), ErrorCode::Invalid);

    // The new primary does: the relay answers its usage, sends pairing to it, and it revokes.
    assert!(alice.usage().await.unwrap().connections >= 3.0);
    let code = alice.open_pairing_code(CodeOptions::default()).unwrap();
    let paired =
        pair(PairOptions { target: PairTarget::Link(code.link), identity: Identity::generate(), timeout: None })
            .await
            .unwrap();
    assert_eq!(paired.roster.primary_id(), alice.id());
    assert_eq!(paired.pinned_network_key, wire::b64u(&net.network_key.ed25519_public()));
    let v = alice.revoke(bob.id()).unwrap().version();
    until(|| bob.state() == MemberState::Revoked, "bob to be revoked by the new primary").await;
    until(|| former.roster().version() == v, "the former primary to take the new primary's roster").await;
    assert_eq!(former.state(), MemberState::Connected);
    assert!(!former.is_primary(), "a later roster never makes it claim again");
}
