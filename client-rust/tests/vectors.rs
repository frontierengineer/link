//! Every vector that applies to a client, read from the files the other implementations check:
//! `spec/vectors/client.json` (the TypeScript client's), `spec/vectors/relay.json` (the Go
//! relay's), and the published RFC 9382 and cacophony vectors in `client-typescript/test/vectors/`.

use std::path::PathBuf;

use link_client::wire::*;
use link_client::*;

fn load(rel: &str) -> Json {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Json::parse(&text).unwrap()
}

fn s<'a>(v: &'a Json, k: &str) -> &'a str {
    v.get(k).and_then(Json::as_str).unwrap_or_else(|| panic!("missing string {k}"))
}

fn hex(v: &Json, k: &str) -> Vec<u8> {
    from_hex(s(v, k)).unwrap_or_else(|| panic!("{k} is not hex"))
}

fn arr<'a>(v: &'a Json, k: &str) -> &'a [Json] {
    v.get(k).and_then(Json::as_array).unwrap_or_else(|| panic!("missing array {k}"))
}

fn uint(v: &Json, k: &str) -> u64 {
    v.get(k).and_then(Json::as_safe_uint).unwrap_or_else(|| panic!("missing integer {k}"))
}

fn h32(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap()
}

fn without_signature(r: &Json) -> Json {
    Json::Object(r.as_object().unwrap().iter().filter(|(k, _)| k != "signature").cloned().collect())
}

// ── client.json ──

#[test]
fn client_keys_and_ids() {
    let v = load("spec/vectors/client.json");
    let keys = arr(&v, "keys");
    assert!(keys.len() >= 4);
    for k in keys {
        let id = Identity::from_seed(&h32(&hex(k, "seed")));
        assert_eq!(id.ed25519_seed().to_vec(), hex(k, "ed25519Seed"));
        assert_eq!(id.ed25519_public().to_vec(), hex(k, "ed25519Public"));
        assert_eq!(b64u(&id.ed25519_public()), s(k, "ed25519PublicB64u"));
        assert_eq!(id.x25519_private().to_vec(), hex(k, "x25519Private"));
        assert_eq!(id.x25519_public().to_vec(), hex(k, "x25519Public"));
        assert_eq!(b64u(&id.x25519_public()), s(k, "x25519PublicB64u"));
        assert_eq!(node_id_bytes(&id.ed25519_public()).to_vec(), hex(k, "nodeIdBytes"));
        assert_eq!(id.id(), s(k, "nodeId"));
        assert_eq!(node_id_from_bytes(&node_id_to_bytes(id.id()).unwrap()), id.id());
    }
}

#[test]
fn client_roster_signing_and_unicode() {
    let v = load("spec/vectors/client.json");
    let keys = arr(&v, "keys");
    let primary = Identity::from_seed(&h32(&hex(&keys[0], "seed")));
    let signing = v.get("roster").and_then(|r| r.get("signing")).unwrap();
    let roster = signing.get("roster").unwrap();
    assert_eq!(roster_problem(roster), None);
    let jcs = without_signature(roster).canonicalize().unwrap();
    assert_eq!(jcs, s(signing, "jcs"));
    let signed = roster_signing_bytes(roster).unwrap();
    assert_eq!(signed, hex(signing, "signedBytes"));
    assert_eq!(b64u(&primary.sign(&signed)), s(signing, "signature"));
    assert_eq!(s(roster, "signature"), s(signing, "signature"));
    // Signing the same content from typed parts gives the same roster, byte for byte.
    let r = Roster::from_json(roster.clone()).unwrap();
    let again = sign_roster(
        &UnsignedRoster {
            network: r.network().into(),
            version: r.version(),
            issued_at: r.issued_at(),
            relay: r.relay().into(),
            primary: *r.primary_key(),
            members: r.members().iter().rev().cloned().collect(),
        },
        &primary,
    )
    .unwrap();
    assert_eq!(again.to_jcs(), r.to_jcs());

    let unicode = v.get("roster").and_then(|r| r.get("unicode")).unwrap();
    let roster = unicode.get("roster").unwrap();
    assert_eq!(roster_problem(roster), None);
    assert_eq!(without_signature(roster).canonicalize().unwrap(), s(unicode, "jcs"));
}

#[test]
fn client_roster_validity_and_acceptance() {
    let v = load("spec/vectors/client.json");
    let rosters = v.get("roster").unwrap();
    for c in arr(rosters, "valid") {
        assert_eq!(roster_problem(c.get("roster").unwrap()), None, "{}", s(c, "name"));
    }
    let invalid = arr(rosters, "invalid");
    assert!(invalid.len() >= 10);
    for c in invalid {
        assert!(roster_problem(c.get("roster").unwrap()).is_some(), "{}", s(c, "name"));
    }
    let acceptance = arr(rosters, "acceptance");
    let expected: Vec<bool> = acceptance.iter().map(|c| c.get("accept").and_then(Json::as_bool).unwrap()).collect();
    assert_eq!(expected, [true, false, false, false]);
    for c in acceptance {
        let got = acceptance_problem(c.get("roster").unwrap(), s(c, "pinnedPrimary"), uint(c, "heldVersion")).is_none();
        assert_eq!(got, c.get("accept").and_then(Json::as_bool).unwrap(), "{}", s(c, "name"));
    }
}

#[test]
fn client_register_and_resign_signatures() {
    let v = load("spec/vectors/client.json");
    for r in arr(&v, "register") {
        let id = Identity::from_seed(&h32(&hex(r, "seed")));
        assert_eq!(id.id(), s(r, "node"));
        assert_eq!(origin_of(s(r, "url")).unwrap(), s(r, "origin"));
        let challenge: [u8; 32] = from_b64u(s(r, "challenge")).unwrap().try_into().unwrap();
        let msg = register_signing_bytes(s(r, "network"), s(r, "node"), &challenge, uint(r, "ts"), s(r, "origin"));
        assert_eq!(msg, hex(r, "signedBytes"));
        assert_eq!(b64u(&id.sign(&msg)), s(r, "sig"));
    }
    let r = v.get("resign").unwrap();
    let id = Identity::from_seed(&h32(&hex(r, "seed")));
    let msg = resign_signing_bytes(s(r, "network"), s(r, "node"), uint(r, "ts"));
    assert_eq!(msg, hex(r, "signedBytes"));
    let signed = Resignation::sign(&id, s(r, "network"), uint(r, "ts"));
    assert_eq!(signed.sig, s(r, "sig"));
    assert!(signed.verify(s(r, "network"), &id.ed25519_public()));
    assert!(!signed.verify(s(r, "node"), &id.ed25519_public()));
}

#[test]
fn client_pairing_link_and_codes() {
    let v = load("spec/vectors/client.json");
    let p = v.get("pairing").unwrap();
    let l = p.get("link").unwrap();
    let parts = PairingLink {
        network: s(l, "network").into(),
        code: s(l, "code").into(),
        code_id: s(l, "codeIdB64u").into(),
        relay: s(l, "relay").into(),
    };
    assert_eq!(build_pairing_link(&parts).unwrap(), s(l, "link"));
    assert_eq!(parse_pairing_link(s(l, "link")).unwrap(), parts);
    for c in arr(p, "codeNormalisation") {
        assert_eq!(normalize_code(s(c, "input")).unwrap(), s(c, "code"));
    }
}

/// One RFC 9382 vector: both roles, every derived value. `c_a`/`c_b` name the confirmation
/// fields (the two files spell them differently).
fn check_rfc9382(v: &Json, c_a: &str, c_b: &str) {
    let w = p256_scalar(&hex(v, "w"));
    let (id_a, id_b) = (s(v, "A").as_bytes(), s(v, "B").as_bytes());
    let a = Spake2::new(Spake2Role::A, w, id_a, id_b, &[], Some(p256_scalar(&hex(v, "x")))).unwrap();
    let b = Spake2::new(Spake2Role::B, w, id_a, id_b, &[], Some(p256_scalar(&hex(v, "y")))).unwrap();
    assert_eq!(a.share().to_vec(), hex(v, "pA"));
    assert_eq!(b.share().to_vec(), hex(v, "pB"));
    let ka = a.finish(b.share()).unwrap();
    let kb = b.finish(a.share()).unwrap();
    for k in [&ka, &kb] {
        assert_eq!(k.k.to_vec(), hex(v, "K"));
        assert_eq!(k.tt.to_vec(), hex(v, "TT"));
        assert_eq!(k.hash.to_vec(), hex(v, "hashTT"));
        assert_eq!(k.ke.to_vec(), hex(v, "Ke"));
        assert_eq!(k.ka.to_vec(), hex(v, "Ka"));
        assert_eq!(k.kc_a.to_vec(), hex(v, "KcA"));
        assert_eq!(k.kc_b.to_vec(), hex(v, "KcB"));
        assert_eq!(k.c_a.to_vec(), hex(v, c_a));
        assert_eq!(k.c_b.to_vec(), hex(v, c_b));
    }
    assert!(ka.verify_theirs(kb.ours()) && kb.verify_theirs(ka.ours()));
}

#[test]
fn spake2_rfc9382_appendix_b() {
    let rfc = load("client-typescript/test/vectors/rfc9382.json");
    let vectors = arr(&rfc, "vectors");
    assert_eq!(vectors.len(), 4);
    for v in vectors {
        check_rfc9382(v, "Aconf", "Bconf");
    }
    let client = load("spec/vectors/client.json");
    let vectors = arr(client.get("spake2").unwrap(), "rfc9382");
    assert_eq!(vectors.len(), 4);
    for v in vectors {
        check_rfc9382(v, "cA", "cB");
    }
}

#[test]
fn spake2_profile_and_the_sealed_pairing_messages() {
    let client = load("spec/vectors/client.json");
    let p = client.get("spake2").and_then(|s| s.get("profile")).unwrap();
    let code = normalize_code(s(p, "codeInput")).unwrap();
    assert_eq!(code, s(p, "code"));
    assert_eq!(format_code(&code).unwrap(), s(p, "display"));
    let code_id: [u8; 8] = hex(p, "codeId").try_into().unwrap();
    assert_eq!(b64u(&code_id), s(p, "codeIdB64u"));
    assert_eq!(s(p, "idA").as_bytes(), SPAKE2_ID_A);
    assert_eq!(s(p, "idB").as_bytes(), SPAKE2_ID_B);
    let w = derive_w(&code).unwrap();
    assert_eq!(w, p256_scalar(&hex(p, "w")));
    let x_random: [u8; 48] = hex(p, "xRandom").try_into().unwrap();
    let y_random: [u8; 48] = hex(p, "yRandom").try_into().unwrap();
    assert_eq!(scalar_from_random(&x_random), p256_scalar(&hex(p, "x")));
    assert_eq!(scalar_from_random(&y_random), p256_scalar(&hex(p, "y")));

    let newcomer = Identity::from_seed(&h32(&hex(p, "newcomerSeed")));
    let mine = NewcomerKeys { ed25519: newcomer.ed25519_public(), x25519: newcomer.x25519_public() };
    let mut a = NewcomerExchange::new(&code, &code_id, Some(&x_random)).unwrap();
    let mut b = PrimaryExchange::new(&code, &code_id, Some(&y_random)).unwrap();
    let p1 = a.p1();
    assert_eq!(p1, hex(p, "pA"));
    let p2 = b.on_p1(&p1).unwrap();
    assert_eq!(p2, hex(p, "pB"));
    let p3 = a.on_p2(&p2).unwrap();
    assert_eq!(p3, hex(p, "cA"));
    for k in [a.keys().unwrap(), b.keys().unwrap()] {
        assert_eq!(k.k.to_vec(), hex(p, "K"));
        assert_eq!(k.tt.to_vec(), hex(p, "TT"));
        assert_eq!(k.hash.to_vec(), hex(p, "hashTT"));
        assert_eq!(k.ke.to_vec(), hex(p, "Ke"));
        assert_eq!(k.ka.to_vec(), hex(p, "Ka"));
        assert_eq!(k.kc_a.to_vec(), hex(p, "KcA"));
        assert_eq!(k.kc_b.to_vec(), hex(p, "KcB"));
        assert_eq!(k.c_b.to_vec(), hex(p, "cB"));
    }
    assert!(b.on_p3(&p3).unwrap());
    let p4 = b.p4().unwrap();
    assert_eq!(p4, hex(p, "cB"));
    let p5 = a.on_p4(&p4, &mine).unwrap();
    assert_eq!(p5, hex(p, "p5"));
    assert_eq!(b.on_p5(&p5).unwrap(), mine);
    let p6_plaintext = Json::parse(s(p, "p6Plaintext")).unwrap();
    assert_eq!(p6_plaintext.to_json_string().unwrap(), s(p, "p6Plaintext"));
    let roster = p6_plaintext.get("roster").unwrap();
    let p6 = b.p6(roster).unwrap();
    assert_eq!(p6, hex(p, "p6"));
    assert_eq!(&a.on_p6(&p6).unwrap(), roster);
    // okm: newcomer -> primary key, then primary -> newcomer key.
    let okm = hex(p, "okm");
    for k in [a.keys().unwrap(), b.keys().unwrap()] {
        let (to_primary, to_newcomer) = transport_keys(k);
        assert_eq!([&to_primary[..], &to_newcomer[..]].concat(), okm);
    }
    assert_eq!(
        Json::object([("ed25519", Json::str(b64u(&mine.ed25519))), ("x25519", Json::str(b64u(&mine.x25519)))])
            .to_json_string()
            .unwrap(),
        s(p, "p5Plaintext")
    );
}

#[test]
fn spake2_wrong_code_fails_confirmation_and_burns_nothing_silently() {
    let id = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut a = NewcomerExchange::new("7K2M9QXZ", &id, None).unwrap();
    let mut b = PrimaryExchange::new("7K2M9QXY", &id, None).unwrap();
    let p2 = b.on_p1(&a.p1()).unwrap();
    let p3 = a.on_p2(&p2).unwrap();
    assert!(!b.on_p3(&p3).unwrap());
    assert!(b.p4().is_err(), "no P4 before cA verifies");
    assert!(b.on_p5(&[0; 80]).is_err());
}

#[test]
fn noise_session_vector() {
    let v = load("spec/vectors/client.json");
    let n = v.get("noise").unwrap();
    assert_eq!(s(n, "protocol"), "Noise_IK_25519_ChaChaPoly_SHA256");
    let network = s(n, "network");
    assert_eq!(session_prologue(network), hex(n, "prologue"));
    let (iv, rv) = (n.get("initiator").unwrap(), n.get("responder").unwrap());
    let ini = Identity::from_seed(&h32(&hex(iv, "seed")));
    let res = Identity::from_seed(&h32(&hex(rv, "seed")));
    assert_eq!(ini.id(), s(iv, "node"));
    assert_eq!(res.id(), s(rv, "node"));
    assert_eq!(ini.x25519_private().to_vec(), hex(iv, "staticPrivate"));
    assert_eq!(res.x25519_private().to_vec(), hex(rv, "staticPrivate"));
    let (ii, ri) = (uint(iv, "index") as u32, uint(rv, "index") as u32);
    let prologue = session_prologue(network);
    let mut i = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: true,
        prologue: &prologue,
        s: Some(KeyPair::from_private(&ini.x25519_private())),
        rs: Some(res.x25519_public()),
        fixed_ephemeral: Some(h32(&hex(iv, "ephemeralPrivate"))),
    })
    .unwrap();
    let mut r = HandshakeState::new(HandshakeOptions {
        pattern: &IK,
        initiator: false,
        prologue: &prologue,
        s: Some(KeyPair::from_private(&res.x25519_private())),
        rs: None,
        fixed_ephemeral: Some(h32(&hex(rv, "ephemeralPrivate"))),
    })
    .unwrap();
    let ini_raw = node_id_to_bytes(ini.id()).unwrap();
    let res_raw = node_id_to_bytes(res.id()).unwrap();

    let m1v = n.get("message1").unwrap();
    // Message 1 carries the roster version and the initiator's stamp, 16 bytes.
    let p1 = init_payload(uint(m1v, "rosterVersion"), uint(m1v, "stamp"));
    assert_eq!(p1.to_vec(), hex(m1v, "payload"));
    assert_eq!(parse_init_payload(&p1), Some((uint(m1v, "rosterVersion"), uint(m1v, "stamp"))));
    let (m1, _) = i.write_message(&p1).unwrap();
    assert_eq!(m1, hex(m1v, "noise"));
    let body = handshake_init_body(ii, &m1);
    assert_eq!(encode_frame(frame_type::HANDSHAKE_INIT, &res_raw, &body).unwrap(), hex(m1v, "frameSent"));
    assert_eq!(encode_frame(frame_type::HANDSHAKE_INIT, &ini_raw, &body).unwrap(), hex(m1v, "frameDelivered"));
    let (payload, _) = r.read_message(&m1).unwrap();
    assert_eq!(payload, hex(m1v, "payload"));
    assert_eq!(r.remote_static(), Some(&ini.x25519_public()));

    let m2v = n.get("message2").unwrap();
    let (m2, rt) = r.write_message(&hex(m2v, "payload")).unwrap();
    assert_eq!(m2, hex(m2v, "noise"));
    let body = handshake_resp_body(ri, ii, &m2);
    assert_eq!(encode_frame(frame_type::HANDSHAKE_RESP, &ini_raw, &body).unwrap(), hex(m2v, "frameSent"));
    assert_eq!(encode_frame(frame_type::HANDSHAKE_RESP, &res_raw, &body).unwrap(), hex(m2v, "frameDelivered"));
    let (payload, it) = i.read_message(&m2).unwrap();
    assert_eq!(payload, hex(m2v, "payload"));
    let (mut it, mut rt) = (it.unwrap(), rt.unwrap());
    assert_eq!(it.handshake_hash.to_vec(), hex(n, "handshakeHash"));
    assert_eq!(rt.handshake_hash.to_vec(), hex(n, "handshakeHash"));

    for t in arr(n, "transport") {
        let initiator_sends = s(t, "direction") == "initiator->responder";
        let (send, recv, to, receiver_index) =
            if initiator_sends { (&mut it, &mut rt, &res_raw, ri) } else { (&mut rt, &mut it, &ini_raw, ii) };
        assert_eq!(send.send.nonce(), uint(t, "nonce"));
        let ct = send.send.encrypt_with_ad(&[], &hex(t, "plaintext")).unwrap();
        assert_eq!(ct, hex(t, "ciphertext"));
        assert_eq!(encode_frame(frame_type::DATA, to, &data_body(receiver_index, &ct)).unwrap(), hex(t, "frameSent"));
        assert_eq!(recv.recv.decrypt_with_ad(&[], &ct).unwrap(), hex(t, "plaintext"));
        // The plaintext is a session message.
        assert!(SessionMessage::decode(&hex(t, "plaintext")).is_ok());
    }
}

#[test]
fn client_frames_and_session_messages() {
    let v = load("spec/vectors/client.json");
    let frames = arr(&v, "frames");
    assert_eq!(frames.len(), 8);
    for f in frames {
        let bytes = hex(f, "frame");
        let d = decode_frame(&bytes).unwrap();
        assert_eq!(u64::from(d.kind), uint(f, "type"), "{}", s(f, "name"));
        assert_eq!(d.peer.to_vec(), hex(f, "peer"));
        assert_eq!(d.body.to_vec(), hex(f, "body"));
        assert_eq!(encode_frame(d.kind, &d.peer, d.body).unwrap(), bytes);
    }
    for m in arr(&v, "sessionMessages") {
        let bytes = hex(m, "encoding");
        let d = SessionMessage::decode(&bytes).unwrap_or_else(|e| panic!("{}: {e}", s(m, "name")));
        assert_eq!(d.encode(), bytes, "{}", s(m, "name"));
    }
}

// ── relay.json ──

#[test]
fn relay_keys_and_ids() {
    let v = load("spec/vectors/relay.json");
    let keys = arr(&v, "keys");
    assert!(keys.len() >= 3);
    for k in keys {
        let seed: [u8; 32] = from_b64u(s(k, "seed")).unwrap().try_into().unwrap();
        let id = Identity::from_seed(&seed);
        assert_eq!(b64u(&id.ed25519_seed()), s(k, "ed25519Seed"));
        assert_eq!(b64u(&id.ed25519_public()), s(k, "ed25519"));
        assert_eq!(b64u(&id.x25519_private()), s(k, "x25519Private"));
        assert_eq!(b64u(&id.x25519_public()), s(k, "x25519"));
        assert_eq!(id.id(), s(k, "nodeId"));
        let raw: [u8; 16] = hex(k, "nodeIdRaw").try_into().unwrap();
        assert_eq!(node_id_from_bytes(&raw), s(k, "nodeId"));
    }
}

#[test]
fn relay_rosters() {
    let v = load("spec/vectors/relay.json");
    let mut valid = 0;
    let rosters = arr(&v, "rosters");
    for c in rosters {
        let desc = s(c, "description");
        let roster = c.get("roster").unwrap();
        let ok = c.get("valid").and_then(Json::as_bool).unwrap();
        assert_eq!(roster_problem(roster).is_none(), ok, "{desc}: {:?}", roster_problem(roster));
        let Some(jcs) = c.get("jcs").and_then(Json::as_str) else {
            continue;
        };
        assert_eq!(b64u(without_signature(roster).canonicalize().unwrap().as_bytes()), jcs, "{desc}: JCS");
        if !ok {
            continue;
        }
        valid += 1;
        let input = roster_signing_bytes(roster).unwrap();
        assert_eq!(b64u(&input), s(c, "signingInput"), "{desc}: signing input");
        assert_eq!(s(roster, "signature"), s(c, "signature"));
        let r = Roster::from_json(roster.clone()).unwrap();
        assert_eq!(r.to_jcs(), roster.canonicalize().unwrap());
    }
    assert!(valid > 0 && valid < rosters.len(), "both valid and invalid cases");
}

#[test]
fn relay_registrations() {
    let v = load("spec/vectors/relay.json");
    let keys = arr(&v, "keys");
    let regs = arr(&v, "registrations");
    assert!(!regs.is_empty());
    for r in regs {
        let desc = s(r, "description");
        let challenge: [u8; 32] = from_b64u(s(r, "challenge")).unwrap().try_into().unwrap();
        let msg = register_signing_bytes(s(r, "network"), s(r, "node"), &challenge, uint(r, "ts"), s(r, "origin"));
        assert_eq!(b64u(&msg), s(r, "message"), "{desc}");
        let key = keys.iter().find(|k| s(k, "nodeId") == s(r, "node")).unwrap();
        assert_eq!(s(key, "ed25519"), s(r, "ed25519"), "{desc}: key");
        let seed: [u8; 32] = from_b64u(s(key, "seed")).unwrap().try_into().unwrap();
        assert_eq!(b64u(&Identity::from_seed(&seed).sign(&msg)), s(r, "sig"), "{desc}: signature");
        // A client dialling this origin signs exactly it.
        let origin = s(r, "origin");
        let scheme = if origin.contains(':') { "ws" } else { "wss" };
        assert_eq!(origin_of(&format!("{scheme}://{origin}/v1")).unwrap(), origin, "{desc}: origin");
    }
}

#[test]
fn relay_frames() {
    let v = load("spec/vectors/relay.json");
    let keys = arr(&v, "keys");
    let raw = |i: usize| hex(&keys[i], "nodeIdRaw");
    let frames = arr(&v, "frames");
    // data from seed 1 to seed 0: the relay rewrites the peer to the sender and changes nothing else.
    let (sent, got) = (hex(&frames[0], "sent"), hex(&frames[0], "delivered"));
    let (sent, got) = (decode_frame(&sent).unwrap(), decode_frame(&got).unwrap());
    assert_eq!((sent.kind, got.kind), (frame_type::DATA, frame_type::DATA));
    assert_eq!(sent.peer.to_vec(), raw(0));
    assert_eq!(got.peer.to_vec(), raw(1));
    assert_eq!(got.body, sent.body);
    assert_eq!(parse_data(got.body).unwrap().0, 7);
    // a frame for seed 2, which is not connected: unreachable names seed 2 and has no body.
    let (out, back) = (hex(&frames[1], "sent"), hex(&frames[1], "delivered"));
    let (out, back) = (decode_frame(&out).unwrap(), decode_frame(&back).unwrap());
    assert_eq!(out.peer.to_vec(), raw(2));
    assert_eq!(back.kind, frame_type::UNREACHABLE);
    assert_eq!(back.peer.to_vec(), raw(2));
    assert!(back.body.is_empty());
    // control (type 8) from seed 1 to seed 0, delivered as data (type 3), same body.
    let (c_sent, c_got) = (hex(&frames[2], "sent"), hex(&frames[2], "delivered"));
    let (c_sent, c_got) = (decode_frame(&c_sent).unwrap(), decode_frame(&c_got).unwrap());
    assert_eq!((c_sent.kind, c_got.kind), (frame_type::CONTROL, frame_type::DATA));
    assert_eq!(c_sent.peer.to_vec(), raw(0));
    assert_eq!(c_got.peer.to_vec(), raw(1));
    assert_eq!(c_got.body, c_sent.body);
}

// ── cacophony ──

#[test]
fn noise_cacophony_ik_kk_xx_nn() {
    let v = load("client-typescript/test/vectors/noise-cacophony.json");
    let vectors = arr(&v, "vectors");
    let mut names: Vec<&str> = vectors.iter().map(|x| s(x, "protocol_name")).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "Noise_IK_25519_ChaChaPoly_SHA256",
            "Noise_KK_25519_ChaChaPoly_SHA256",
            "Noise_NN_25519_ChaChaPoly_SHA256",
            "Noise_XX_25519_ChaChaPoly_SHA256",
        ]
    );
    for x in vectors {
        let name = s(x, "protocol_name");
        let pattern: &'static Pattern = match name.split('_').nth(1) {
            Some("IK") => &IK,
            Some("KK") => &KK,
            Some("XX") => &XX,
            Some("NN") => &NN,
            other => panic!("unexpected pattern {other:?}"),
        };
        let opt = |k: &str| x.get(k).and_then(Json::as_str).map(|h| h32(&from_hex(h).unwrap()));
        let mk = |initiator: bool| {
            let (pro, st, eph, rs) = if initiator {
                ("init_prologue", "init_static", "init_ephemeral", "init_remote_static")
            } else {
                ("resp_prologue", "resp_static", "resp_ephemeral", "resp_remote_static")
            };
            let prologue = hex(x, pro);
            HandshakeState::new(HandshakeOptions {
                pattern,
                initiator,
                prologue: &prologue,
                s: opt(st).map(|k| KeyPair::from_private(&k)),
                rs: opt(rs),
                fixed_ephemeral: opt(eph),
            })
            .unwrap()
        };
        let (mut init, mut resp) = (mk(true), mk(false));
        let mut transports: Option<(Transport, Transport)> = None;
        let hs_count = pattern.messages.len();
        for (i, m) in arr(x, "messages").iter().enumerate() {
            let payload = hex(m, "payload");
            // cacophony alternates senders across the whole run, starting with the initiator.
            let initiator_sends = i % 2 == 0;
            if i < hs_count {
                let (w, r) = if initiator_sends { (&mut init, &mut resp) } else { (&mut resp, &mut init) };
                let (out, wt) = w.write_message(&payload).unwrap();
                assert_eq!(out, hex(m, "ciphertext"), "{name} message {i}");
                let (got, rt) = r.read_message(&out).unwrap();
                assert_eq!(got, payload);
                if let (Some(wt), Some(rt)) = (wt, rt) {
                    assert_eq!(wt.handshake_hash.to_vec(), hex(x, "handshake_hash"), "{name} handshake hash");
                    transports = Some(if initiator_sends { (wt, rt) } else { (rt, wt) });
                }
            } else {
                let (ti, tr) = transports.as_mut().unwrap();
                let (snd, rcv) = if initiator_sends { (ti, tr) } else { (tr, ti) };
                let ct = snd.send.encrypt_with_ad(&[], &payload).unwrap();
                assert_eq!(ct, hex(m, "ciphertext"), "{name} transport message {i}");
                assert_eq!(rcv.recv.decrypt_with_ad(&[], &ct).unwrap(), payload);
            }
        }
        assert!(transports.is_some(), "{name}: the handshake completed");
    }
}

#[test]
fn relay_roster_texts() {
    // Rosters as text, whose validity turns on the bytes: repeated names, `12.0`, `1.2e1`,
    // `1.79e12`, escaped lone surrogates (spec section 1).
    let v = load("spec/vectors/relay.json");
    let cases = arr(&v, "rosterTexts");
    assert!(cases.len() >= 11);
    let (mut valid, mut invalid) = (0, 0);
    for c in cases {
        let desc = s(c, "description");
        let want = c.get("valid").and_then(Json::as_bool).unwrap();
        let got = Roster::parse(s(c, "text"));
        assert_eq!(got.is_ok(), want, "{desc}: {:?}", got.err());
        if want { valid += 1 } else { invalid += 1 }
    }
    assert!(valid > 0 && invalid > 0);
}

// ── relay.json: Ed25519 ──

/// Section 1's strict verification, every case: canonical `A` and `R`, neither small-order,
/// `S < L`, the cofactorless equation.
#[test]
fn relay_ed25519_strict_verification() {
    let v = load("spec/vectors/relay.json");
    let cases = arr(&v, "ed25519");
    assert_eq!(cases.len(), 24);
    let b64 = |c: &Json, k: &str| from_b64u(s(c, k)).unwrap_or_else(|| panic!("{k} is not b64u"));
    let mut failed = Vec::new();
    for c in cases {
        let public: [u8; 32] = b64(c, "pub").try_into().unwrap();
        let sig: [u8; 64] = b64(c, "sig").try_into().unwrap();
        let valid = c.get("valid") == Some(&Json::Bool(true));
        if ed25519_verify(&public, &b64(c, "msg"), &sig) != valid {
            failed.push(format!("{} (expected {valid})", s(c, "description")));
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
}
