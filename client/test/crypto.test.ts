// Primitives proven against published vectors: RFC 9382 (SPAKE2, P-256) and
// the cacophony Noise vectors (IK, KK, XX, NN over 25519_ChaChaPoly_SHA256).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fromHex, toHex, utf8 } from '../src/bytes.js';
import { HandshakeState, PATTERNS, type Transport } from '../src/noise.js';
import { bytesToBigint, deriveW, Spake2, verifyConfirmation } from '../src/spake2.js';
import { x25519Public } from '../src/crypto.js';

const json = (name: string) => JSON.parse(readFileSync(new URL(`./vectors/${name}`, import.meta.url), 'utf8'));

interface RfcVector {
  A: string;
  B: string;
  w: string;
  x: string;
  y: string;
  pA: string;
  pB: string;
  K: string;
  TT: string;
  hashTT: string;
  Ke: string;
  Ka: string;
  KcA: string;
  KcB: string;
  Aconf: string;
  Bconf: string;
}

const rfc = json('rfc9382.json').vectors as RfcVector[];

test('SPAKE2 reproduces every RFC 9382 Appendix B vector, both roles', () => {
  assert.equal(rfc.length, 4);
  for (const v of rfc) {
    const w = bytesToBigint(fromHex(v.w));
    const ids = { idA: utf8(v.A), idB: utf8(v.B) };
    const a = new Spake2({ role: 'A', w, ...ids, scalar: bytesToBigint(fromHex(v.x)) });
    const b = new Spake2({ role: 'B', w, ...ids, scalar: bytesToBigint(fromHex(v.y)) });
    assert.equal(toHex(a.share), v.pA);
    assert.equal(toHex(b.share), v.pB);
    const ka = a.finish(b.share);
    const kb = b.finish(a.share);
    for (const k of [ka, kb]) {
      assert.equal(toHex(k.tt), v.TT);
      assert.equal(toHex(k.hash), v.hashTT);
      assert.equal(toHex(k.ke), v.Ke);
      assert.equal(toHex(k.ka), v.Ka);
      assert.equal(toHex(k.kcA), v.KcA);
      assert.equal(toHex(k.kcB), v.KcB);
      assert.equal(toHex(k.cA), v.Aconf);
      assert.equal(toHex(k.cB), v.Bconf);
    }
    assert.ok(verifyConfirmation(ka, kb.ours));
    assert.ok(verifyConfirmation(kb, ka.ours));
  }
});

test('SPAKE2 with different codes fails confirmation', () => {
  const a = new Spake2({ role: 'A', w: deriveW('ABCD1234') });
  const b = new Spake2({ role: 'B', w: deriveW('ABCD1235') });
  const ka = a.finish(b.share);
  const kb = b.finish(a.share);
  assert.ok(!verifyConfirmation(kb, ka.ours));
  assert.ok(!verifyConfirmation(ka, kb.ours));
});

test('SPAKE2 refuses invalid peer shares', () => {
  const a = new Spake2({ role: 'A', w: deriveW('ABCD1234') });
  assert.throws(() => a.finish(new Uint8Array(65)));
  const bad = a.share.slice();
  bad[64]! ^= 1;
  assert.throws(() => a.finish(bad));
  assert.throws(() => a.finish(a.share.subarray(0, 33)));
});

interface NoiseVector {
  protocol_name: string;
  init_prologue: string;
  init_static?: string;
  init_ephemeral: string;
  init_remote_static?: string;
  resp_prologue: string;
  resp_static?: string;
  resp_ephemeral: string;
  resp_remote_static?: string;
  handshake_hash: string;
  messages: { payload: string; ciphertext: string }[];
}

const noise = json('noise-cacophony.json').vectors as NoiseVector[];

test('Noise engine reproduces the cacophony vectors for IK, KK, XX and NN', () => {
  const names = noise.map((v) => v.protocol_name).sort();
  assert.deepEqual(names, [
    'Noise_IK_25519_ChaChaPoly_SHA256',
    'Noise_KK_25519_ChaChaPoly_SHA256',
    'Noise_NN_25519_ChaChaPoly_SHA256',
    'Noise_XX_25519_ChaChaPoly_SHA256',
  ]);
  for (const v of noise) {
    const name = v.protocol_name.split('_')[1] as keyof typeof PATTERNS;
    const pattern = PATTERNS[name];
    const kp = (hex?: string) => (hex ? { priv: fromHex(hex), pub: x25519Public(fromHex(hex)) } : undefined);
    const mk = (initiator: boolean) => {
      const s = kp(initiator ? v.init_static : v.resp_static);
      const rs = initiator ? v.init_remote_static : v.resp_remote_static;
      return new HandshakeState({
        pattern,
        initiator,
        prologue: fromHex(initiator ? v.init_prologue : v.resp_prologue),
        ...(s ? { s } : {}),
        ...(rs ? { rs: fromHex(rs) } : {}),
        fixedEphemeral: fromHex(initiator ? v.init_ephemeral : v.resp_ephemeral),
      });
    };
    const init = mk(true);
    const resp = mk(false);
    let ti: Transport | undefined;
    let tr: Transport | undefined;
    const hsCount = pattern.messages.length;
    v.messages.forEach((m, i) => {
      const payload = fromHex(m.payload);
      // cacophony alternates senders across the whole run, starting with the initiator.
      const initiatorSends = i % 2 === 0;
      if (i < hsCount) {
        const [w, r] = initiatorSends ? [init, resp] : [resp, init];
        const out = w.writeMessage(payload);
        assert.equal(toHex(out.message), m.ciphertext, `${v.protocol_name} message ${i}`);
        const got = r.readMessage(out.message);
        assert.equal(toHex(got.payload), m.payload);
        if (out.transport) {
          [ti, tr] = initiatorSends ? [out.transport, got.transport] : [got.transport, out.transport];
        }
      } else {
        const [s, r] = initiatorSends ? [ti!, tr!] : [tr!, ti!];
        const ct = s.send.encryptWithAd(new Uint8Array(0), payload);
        assert.equal(toHex(ct), m.ciphertext, `${v.protocol_name} transport ${i}`);
        assert.equal(toHex(r.recv.decryptWithAd(new Uint8Array(0), ct)), m.payload);
      }
    });
    assert.equal(toHex(ti!.handshakeHash), v.handshake_hash);
    assert.equal(toHex(tr!.handshakeHash), v.handshake_hash);
  }
});

test('Noise IK responder rejects a message meant for another static key', () => {
  const a = { priv: fromHex('11'.repeat(32)), pub: x25519Public(fromHex('11'.repeat(32))) };
  const b = { priv: fromHex('22'.repeat(32)), pub: x25519Public(fromHex('22'.repeat(32))) };
  const c = { priv: fromHex('33'.repeat(32)), pub: x25519Public(fromHex('33'.repeat(32))) };
  const init = new HandshakeState({ pattern: PATTERNS.IK, initiator: true, s: a, rs: b.pub });
  const wrong = new HandshakeState({ pattern: PATTERNS.IK, initiator: false, s: c });
  const { message } = init.writeMessage();
  assert.throws(() => wrong.readMessage(message));
});
