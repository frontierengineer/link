//! A network made with no relay, and placed later (section 3.2): create_network_with_options,
//! is_placed, place_network, a member of an unplaced network refused locally, and an unplaced
//! network placed, registered and paired through the real relay.

mod support;

use std::time::Duration;

use link_client::*;
use support::*;

fn invalid<T: std::fmt::Debug>(r: Result<T, LinkError>, what: &str) -> LinkError {
    let e = r.expect_err(what);
    assert_eq!(e.code(), ErrorCode::Invalid, "{what}: {e}");
    e
}

#[test]
fn create_network_with_options_lists_members_and_defaults_to_no_relay() {
    let p = Identity::from_seed(&[1; 32]);
    let w = Identity::from_seed(&[2; 32]);
    let opts = NetworkOptions {
        members: vec![RosterMember::from_identity(&w)],
        network_seed: Some([0x80; 32]),
        ..Default::default()
    };
    let (r, key) = create_network_with_options(&p, opts).unwrap();
    assert_eq!(key.seed(), &[0x80; 32]);
    assert_eq!(r.relay(), "");
    assert!(!r.is_placed());
    assert_eq!(r.version(), 1);
    assert_eq!(r.members().len(), 2);
    assert_eq!(r.primary_id(), p.id());
    assert!(unix_ms() - r.issued_at() < 60_000, "now_ms None is the current time");
    // The existing create_network is unchanged.
    let (old, _) = create_network(&p, "wss://r/v1", 5).unwrap();
    assert!(old.is_placed());

    let twice = NetworkOptions { members: vec![RosterMember::from_identity(&p)], ..Default::default() };
    invalid(create_network_with_options(&p, twice), "the primary listed");
    let twice = NetworkOptions {
        members: vec![RosterMember::from_identity(&w), RosterMember::from_identity(&w)],
        ..Default::default()
    };
    invalid(create_network_with_options(&p, twice), "a member twice");
    invalid(create_network_with_options(&p, NetworkOptions { now_ms: Some(1 << 53), ..Default::default() }), "now");
    let many = NetworkOptions {
        members: (0..500).map(|_| RosterMember::from_identity(&Identity::generate())).collect(),
        ..Default::default()
    };
    assert_eq!(create_network_with_options(&p, many).unwrap_err().code(), ErrorCode::RosterFull);
}

#[test]
fn place_network_sets_the_relay_and_nothing_else() {
    let p = Identity::from_seed(&[1; 32]);
    let seed = [0x80; 32];
    let (r, _) =
        create_network_with_options(&p, NetworkOptions { network_seed: Some(seed), ..Default::default() }).unwrap();
    let placed = place_network(&r, &seed, "wss://relay.example/v1", None).unwrap();
    assert!(placed.is_placed());
    assert_eq!(placed.version(), 2);
    assert_eq!(placed.relay(), "wss://relay.example/v1");
    assert!(placed.issued_at() >= r.issued_at());
    assert_eq!(placed.members(), r.members());
    assert_eq!(acceptance_problem(placed.json(), &r.network_key_b64u(), 1), None);
    // issuedAt never goes back.
    assert_eq!(place_network(&r, &seed, "wss://relay.example/v1", Some(1)).unwrap().issued_at(), r.issued_at());

    invalid(place_network(&placed, &seed, "wss://elsewhere/v1", None), "placed twice");
    invalid(place_network(&r, &[0x81; 32], "wss://relay.example/v1", None), "another seed");
    for bad in [
        "",
        "https://relay.example/v1",
        "relay.example/v1",
        "wss://",
        "wss:///v1",
        "ws:/x",
        "WSS://relay.example/v1",
        "wss://a b/v1",
    ] {
        invalid(place_network(&r, &seed, bad, None), bad);
    }
    assert!(is_relay_url("ws://127.0.0.1:8080/v1"));
    assert!(is_relay_url("wss://relé.example:8443/v1?q=ü"));

    // A field the protocol does not define is kept, as signed.
    let key = NetworkKey::from_seed(&seed);
    let Json::Object(mut m) = r.json().clone() else { panic!() };
    m.retain(|(k, _)| k != "signature");
    m.push(("future".into(), Json::Array(vec![Json::int(1), Json::str("x")])));
    let sig = key.sign(&roster_signing_bytes(&Json::Object(m.clone())).unwrap());
    m.push(("signature".into(), Json::str(wire::b64u(&sig))));
    let extended = Roster::from_json(Json::Object(m)).unwrap();
    let placed = place_network(&extended, &seed, "wss://relay.example/v1", None).unwrap();
    assert!(placed.to_jcs().contains("\"future\":[1,\"x\"]"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_of_an_unplaced_network_without_a_relay_url_is_refused_at_once() {
    let p = Identity::from_seed(&[1; 32]);
    let w = Identity::from_seed(&[2; 32]);
    let opts = NetworkOptions { members: vec![RosterMember::from_identity(&w)], ..Default::default() };
    let (r, key) = create_network_with_options(&p, opts).unwrap();
    let e = invalid(Member::new(MemberOptions::new(w.clone(), r.clone())), "member");
    assert!(e.message().contains("no relay yet"), "{e}");
    let mut po = MemberOptions::new(p.clone(), r.clone());
    po.network_seed = Some(*key.seed());
    invalid(Primary::new(po.clone()), "primary");
    invalid(Primary::connect(po.clone()).await, "primary connect");
    po.relay_url = Some(String::new());
    invalid(Primary::new(po), "an empty relay_url");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unplaced_network_placed_registers_and_pairs() {
    let relay = Relay::start(&[]);
    let p = Identity::generate();
    let listed = Identity::generate();
    let opts = NetworkOptions { members: vec![RosterMember::from_identity(&listed)], ..Default::default() };
    let (r, key) = create_network_with_options(&p, opts).unwrap();
    let seed = *key.seed();

    // Given a relay URL of its own, a primary of the unplaced network dials it, and its links
    // name it.
    let mut eo = MemberOptions::new(p.clone(), r.clone());
    eo.network_seed = Some(seed);
    eo.relay_url = Some(relay.url.clone());
    eo.timing = fast();
    let early = Primary::connect(eo).await.unwrap();
    let code = early.open_pairing_code(CodeOptions::default()).unwrap();
    assert_eq!(parse_pairing_link(&code.link).unwrap().relay, relay.url);
    early.close();
    drop(early);

    let placed = place_network(&r, &seed, &relay.url, None).unwrap();
    let mut po = MemberOptions::new(p.clone(), placed.clone());
    po.network_seed = Some(seed);
    po.timing = fast();
    let prim = Primary::connect(po).await.unwrap();
    let mut mo = MemberOptions::new(listed.clone(), placed.clone());
    mo.timing = fast();
    let m = Member::connect(mo).await.unwrap();
    let code = prim.open_pairing_code(CodeOptions::default()).unwrap();
    let newcomer = Identity::generate();
    let res = pair(PairOptions { target: PairTarget::Link(code.link), identity: newcomer.clone(), timeout: None })
        .await
        .unwrap();
    assert_eq!(res.roster.version(), 3);
    assert_eq!(res.roster.relay(), relay.url);
    let mut no = MemberOptions::new(newcomer.clone(), res.roster);
    no.timing = fast();
    let n = Member::connect(no).await.unwrap();
    until(|| m.roster().version() >= 3, "the listed member to learn version 3").await;
    m.send(newcomer.id(), &b"placed"[..]).await.unwrap();
    let got = recv_within(&n, Duration::from_secs(10)).await;
    assert_eq!(got.from, listed.id());
    assert_eq!(&got.bytes[..], b"placed");
}
