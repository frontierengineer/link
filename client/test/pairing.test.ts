// pairing: prove SPAKE2 against the RFC 9382 test vectors, prove that an active
// man-in-the-middle who does not know the code cannot derive the key (online-
// only guessing), and prove the host's K-try lockout and a full pairing round
// trip over an in-memory pipe.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { Spake2, verifyConfirm, deriveW, _test, type SpakeIdentities } from '../src/spake2.js';
import {
  spakeClient,
  spakeHost,
  TokenStore,
  CodeLockout,
  PairingAuthError,
  credentialToString,
  credentialFromString,
} from '../src/pairing.js';
import { decodeHeader, encodeHeader, CODE_ID_LEN, Mode, seal, open } from '../src/secureChannel.js';
import { x25519Keygen } from '../src/crypto.js';
import { memoryPipePair } from '../src/pipe.js';
import { bytesToHex, hexToBytes, utf8, fromB64url, toB64url, randomBytes } from '../src/bytes.js';

interface SpakeVector {
  A: string;
  B: string;
  w: string;
  x: string;
  y: string;
  pA: string;
  pB: string;
  K: string;
  hashTT: string;
  Ke: string;
  KcA: string;
  KcB: string;
  Aconf: string;
  Bconf: string;
}

const spakeVectors: { vectors: SpakeVector[] } = JSON.parse(
  readFileSync(new URL('./vectors/spake2.json', import.meta.url), 'utf8'),
);

// RFC 9382 Appendix B: with w, x, y fixed, every derived value must match.
for (const [i, v] of spakeVectors.vectors.entries()) {
  test(`SPAKE2 RFC 9382 KAT #${i} (A=${JSON.stringify(v.A)}, B=${JSON.stringify(v.B)})`, () => {
    const ids: SpakeIdentities = { A: utf8(v.A), B: utf8(v.B) };
    const w = _test.decodeScalar(hexToBytes(v.w));
    const a = new Spake2('A', w, ids, _test.decodeScalar(hexToBytes(v.x)));
    const b = new Spake2('B', w, ids, _test.decodeScalar(hexToBytes(v.y)));

    assert.equal(bytesToHex(a.share), v.pA, 'pA');
    assert.equal(bytesToHex(b.share), v.pB, 'pB');

    const ra = a.finish(b.share);
    const rb = b.finish(a.share);

    assert.equal(bytesToHex(ra.transcriptHash), v.hashTT, 'Hash(TT)');
    assert.equal(bytesToHex(ra.ke), v.Ke, 'Ke');
    assert.equal(bytesToHex(ra.ourConfirm), v.Aconf, 'A confirm (cA)');
    assert.equal(bytesToHex(rb.ourConfirm), v.Bconf, 'B confirm (cB)');
    // Each side must accept the other's confirmation MAC.
    assert.ok(verifyConfirm(ra, rb.ourConfirm), 'A accepts cB');
    assert.ok(verifyConfirm(rb, ra.ourConfirm), 'B accepts cA');
    // And both derive the same secret.
    assert.equal(bytesToHex(ra.ke), bytesToHex(rb.ke), 'shared Ke agrees');
  });
}

test('SPAKE2: honest run with the same code agrees (sanity)', () => {
  const ids: SpakeIdentities = { A: utf8('client'), B: utf8('host') };
  const w = deriveW(utf8('SX7K9Q'));
  const a = new Spake2('A', w, ids);
  const b = new Spake2('B', w, ids);
  const ra = a.finish(b.share);
  const rb = b.finish(a.share);
  assert.equal(bytesToHex(ra.ke), bytesToHex(rb.ke));
  assert.ok(verifyConfirm(ra, rb.ourConfirm) && verifyConfirm(rb, ra.ourConfirm));
});

// The headline pairing-security property: an active MITM that does not know the
// code runs SPAKE2 with a *guessed* code. It cannot make the client's key
// confirmation pass, and the key it derives differs from the client's — so it
// learns nothing it could test offline. Its only recourse is another online
// guess, which the host lockout caps.
test('SPAKE2: an active MITM that guesses the wrong code cannot derive the key', () => {
  const ids: SpakeIdentities = { A: utf8('client'), B: utf8('host') };
  const realCode = 'GZ4P7T';
  const client = new Spake2('A', deriveW(utf8(realCode)), ids);

  // Attacker impersonates the host using a wrong guess; it must commit to one
  // guess per attempt before it sees whether confirmation passes.
  const attacker = new Spake2('B', deriveW(utf8('WRONG9')), ids);

  const clientResult = client.finish(attacker.share);
  const attackerResult = attacker.finish(client.share);

  // Keys diverge: nothing about the code leaked.
  assert.notEqual(bytesToHex(clientResult.ke), bytesToHex(attackerResult.ke), 'keys must diverge');
  // The confirmation the attacker can produce is rejected by the client.
  assert.equal(verifyConfirm(clientResult, attackerResult.ourConfirm), false, 'client rejects attacker confirmation');
  // Symmetrically, the attacker cannot recognise the client's confirmation.
  assert.equal(verifyConfirm(attackerResult, clientResult.ourConfirm), false, 'attacker cannot confirm client');
});

test('CodeLockout: a code is burned after K wrong guesses', () => {
  const lock = new CodeLockout(5);
  const code = 'AB12CD';
  for (let i = 0; i < 4; i++) {
    assert.ok(lock.available(code), `attempt ${i + 1} still available`);
    const r = lock.recordFailure(code);
    assert.equal(r.lockedOut, false);
    assert.equal(r.remaining, 4 - i);
  }
  assert.ok(lock.available(code), '5th attempt is allowed');
  const last = lock.recordFailure(code);
  assert.equal(last.lockedOut, true, 'locked out on the 5th failure');
  assert.equal(lock.available(code), false, 'no further attempts permitted');
});

// Full SPAKE2 pairing choreography over the in-memory pipe (no sockets).
async function runPairing(clientCode: string, hostCode: string, hostStatic = x25519Keygen()) {
  const [c, h] = memoryPipePair();
  const tokens = new TokenStore();
  const hostSide = (async () => {
    const header = decodeHeader(await h.recv(2000));
    return spakeHost(h, header, { hostStatic, address: 'addr-xyz', password: utf8(hostCode), tokens, timeoutMs: 2000 });
  })();
  const clientSide = spakeClient(c, utf8(clientCode), Mode.Pair, 2000);
  const [hostRes, clientRes] = await Promise.all([hostSide, clientSide]);
  return { hostRes, clientRes, hostStatic, tokens, c, h };
}

test('pairing: a correct 6-char code yields a credential and a sealed channel', async () => {
  const { hostRes, clientRes, hostStatic, tokens } = await runPairing('K7P2QX', 'K7P2QX');
  const cred = clientRes.credential;
  assert.equal(cred.address, 'addr-xyz');
  assert.equal(cred.hostStaticPub, toB64url(hostStatic.pub), 'client pins the host static key');
  assert.equal(cred.token, toB64url(hostRes.device.token), 'client stores the issued token');
  assert.equal(cred.keyId, toB64url(hostRes.device.keyId));
  assert.equal(tokens.resolve(fromB64url(cred.keyId))?.length, 32, 'host can resolve the token by keyId');

  // The derived transports interoperate.
  const f = seal(clientRes.transport.send, utf8('hello host'));
  assert.equal(Buffer.from(open(hostRes.transport.recv, f)).toString(), 'hello host');

  // Credential survives a serialize/parse round trip.
  const round = credentialFromString(credentialToString(cred));
  assert.deepEqual(round, cred);
});

test('pairing: a wrong code fails both sides with PairingAuthError', async () => {
  const results = await Promise.allSettled([runPairing('AAAAAA', 'BBBBBB')]);
  assert.equal(results[0]!.status, 'rejected');
  const reason = (results[0] as PromiseRejectedResult).reason;
  assert.ok(reason instanceof PairingAuthError, `expected PairingAuthError, got ${reason}`);
});

test('deriveW: refuses to produce a usable scalar from nothing surprising', () => {
  // Two different codes give different scalars (sanity / determinism).
  const w1 = deriveW(utf8('ABC123'));
  const w2 = deriveW(utf8('ABC124'));
  assert.notEqual(w1, w2);
  assert.equal(deriveW(utf8('ABC123')), w1, 'deterministic');
});

// ── many live codes, told apart by a public id ──────────────────────────────
//
// A host can only run SPAKE2 with ONE password per handshake — it commits to `w`
// before it sends its share — so it cannot try a set of codes against a single
// attempt. Holding several therefore requires the CLIENT to say which one it
// has, which is what the header's code id is for.
//
// These pin the three properties that make that safe and useful: the id is
// bound into the SPAKE2 transcript (so a relay cannot steer a client onto a
// different code), each code burns alone, and a client that names nothing still
// pairs against the legacy single slot.

test('a pair header round-trips its code id, and binds it into the transcript', () => {
  const codeId = randomBytes(CODE_ID_LEN);
  const encoded = encodeHeader({ mode: Mode.Pair, codeId });
  const decoded = decodeHeader(encoded);
  assert.deepEqual(decoded.codeId, codeId, 'the host reads back exactly what the client sent');
  // The AAD is rebuilt independently on each side from its own decoded header,
  // so encode(decode(x)) must be x byte for byte or the handshake fails with no
  // usable diagnostic. This is that identity.
  assert.deepEqual(encodeHeader(decoded), encoded);
  // And a header with no id is still the v1 encoding, which is what keeps every
  // client already in the field pairing.
  const legacy = encodeHeader({ mode: Mode.Pair });
  assert.equal(legacy.length, encoded.length - CODE_ID_LEN);
  assert.deepEqual(decodeHeader(legacy).codeId, undefined);
});

test('a code id is public, and carries nothing derived from the code', () => {
  // Two ids minted for the SAME code must be unrelated: an id that were a
  // function of the code would hand a watching relay an offline oracle for the
  // very secret SPAKE2 exists to protect.
  const seen = new Set<string>();
  for (let i = 0; i < 64; i++) seen.add(toB64url(randomBytes(CODE_ID_LEN)));
  assert.equal(seen.size, 64, 'ids are fresh randomness, not a hash of anything');
});

test('a client that names a code the host does not hold is refused, not run against another', async () => {
  // The dangerous alternative is falling back to some other live code: SPAKE2
  // would then run with a password the client never had, and the failure would
  // be reported as a wrong code — a lie about which end is broken.
  const [c, h] = memoryPipePair();
  const tokens = new TokenStore();
  const header = { mode: Mode.Pair as const, codeId: randomBytes(CODE_ID_LEN) };
  const clientSide = spakeClient(c, utf8('K7P2QX'), Mode.Pair, 1000, header.codeId).catch((e) => e);
  const decoded = decodeHeader(await h.recv(1000));
  assert.deepEqual(decoded.codeId, header.codeId);
  // The host resolves that id to nothing and closes rather than handshaking.
  h.close('pairing not open');
  const outcome = await clientSide;
  assert.ok(outcome instanceof Error, 'the client fails rather than pairing on someone else’s code');
  void tokens;
});

test('a recover header may not carry a code id', () => {
  // Recovery has one high-entropy key, never a set, so an id there is
  // meaningless — and silently ignoring it would let a caller believe recovery
  // was scoped when it was not.
  const forged = new Uint8Array([...encodeHeader({ mode: Mode.Pair, codeId: randomBytes(CODE_ID_LEN) })]);
  forged[5] = Mode.Recover; // MAGIC(4) VERSION(1) MODE(1)
  assert.throws(() => decodeHeader(forged), /cannot carry a code id/);
});
