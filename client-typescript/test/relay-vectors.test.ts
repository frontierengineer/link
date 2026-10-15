// spec/vectors/relay.json is written by the Go relay. The client checks every item in it
// that the client itself understands: keys and ids, roster JCS bytes, signatures and
// validity, rosters given as text, registration signatures and origins, and routed frames.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { b64u, fromB64u, toHex } from '../src/bytes.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed25519Verify } from '../src/crypto.js';
import { decodeFrame, FrameType } from '../src/frames.js';
import { identityFromSeed, nodeIdFromBytes } from '../src/identity.js';
import { canonicalize } from '../src/jcs.js';
import { parseJson } from '../src/json.js';
import { rosterProblem, rosterSigningBytes } from '../src/roster.js';
import { originOf, registerSigningBytes } from '../src/signed.js';

const v = JSON.parse(readFileSync(new URL('../../spec/vectors/relay.json', import.meta.url), 'utf8'));

test('relay vectors: keys and ids derive as the relay derives them', () => {
  assert.ok(v.keys.length >= 3);
  for (const k of v.keys) {
    const id = identityFromSeed(fromB64u(k.seed));
    assert.equal(b64u(id.ed25519.seed), k.ed25519Seed, k.seed);
    assert.equal(b64u(id.ed25519.pub), k.ed25519, k.seed);
    assert.equal(b64u(id.x25519.priv), k.x25519Private, k.seed);
    assert.equal(b64u(id.x25519.pub), k.x25519, k.seed);
    assert.equal(id.id, k.nodeId, k.seed);
    assert.equal(nodeIdFromBytes(Uint8Array.from(Buffer.from(k.nodeIdRaw, 'hex'))), k.nodeId);
  }
});

test('relay vectors: rosters canonicalise, sign and validate as the relay says', () => {
  let valid = 0;
  for (const c of v.rosters) {
    const problem = rosterProblem(c.roster);
    assert.equal(problem === null, c.valid, `${c.description}: client says ${problem ?? 'valid'}`);
    if (!c.jcs) continue;
    const { signature, ...unsigned } = c.roster;
    const jcs = new TextEncoder().encode(canonicalize(unsigned));
    assert.equal(b64u(jcs), c.jcs, `${c.description}: JCS`);
    if (!c.valid) continue;
    valid++;
    const input = rosterSigningBytes(unsigned);
    assert.equal(b64u(input), c.signingInput, `${c.description}: signing input`);
    assert.equal(signature, c.signature);
    assert.ok(ed25519Verify(fromB64u(c.signature), input, fromB64u(c.roster.primary.ed25519)), `${c.description}: signature`);
  }
  assert.ok(valid > 0 && valid < v.rosters.length, 'both valid and invalid cases');
});

test('relay vectors: rosters given as text are valid exactly as the relay says', () => {
  assert.ok(v.rosterTexts.length > 0);
  for (const c of v.rosterTexts as { description: string; text: string; valid: boolean }[]) {
    let problem: string | null;
    try {
      problem = rosterProblem(parseJson(c.text));
    } catch (e) {
      problem = (e as Error).message;
    }
    assert.equal(problem === null, c.valid, `${c.description}: client says ${problem ?? 'valid'}`);
    // A number out of range is invalid to any parser that keeps finite numbers only; the rest
    // are traps for a lenient one.
    if (c.valid || /1e309/.test(c.text)) continue;
    // Each invalid text is a trap: a lenient parser (last name wins, 12.0 is 12, -0 is 0, a
    // lone surrogate becomes U+FFFD as Go's encoding/json makes it, any nesting) reads a valid
    // roster from it.
    const lenient = JSON.parse(c.text.replace(/\\u[dD][89a-fA-F][0-9a-fA-F]{2}/g, '\\ufffd').replace(/:-0([,}])/g, ':0$1'));
    assert.equal(rosterProblem(lenient), null, `${c.description}: a lenient parser finds it valid`);
  }
});

test("relay vectors: Ed25519 verification accepts exactly what section 1's rule does", () => {
  assert.ok(v.ed25519.length > 0);
  let differs = 0;
  for (const c of v.ed25519 as { description: string; pub: string; msg: string; sig: string; valid: boolean }[]) {
    const [sig, msg, pub] = [fromB64u(c.sig), fromB64u(c.msg), fromB64u(c.pub)];
    assert.equal(ed25519Verify(sig, msg, pub), c.valid, c.description);
    // noble's own verify (cofactored, ZIP 215 off) answers some otherwise: the rule is ours.
    let lax: boolean;
    try {
      lax = ed25519.verify(sig, msg, pub, { zip215: false });
    } catch {
      lax = false;
    }
    if (lax !== c.valid) differs++;
  }
  assert.ok(differs > 0, 'the vectors test more than a stock verifier');
});

test('relay vectors: registration signatures and origins', () => {
  const keyOf = new Map<string, string>(v.keys.map((k: { nodeId: string; ed25519: string }) => [k.nodeId, k.ed25519]));
  assert.ok(v.registrations.length > 0);
  for (const r of v.registrations) {
    const msg = registerSigningBytes({ network: r.network, node: r.node, challenge: fromB64u(r.challenge), ts: r.ts, origin: r.origin });
    assert.equal(b64u(msg), r.message, r.description);
    assert.equal(keyOf.get(r.node), r.ed25519, `${r.description}: key`);
    assert.ok(ed25519Verify(fromB64u(r.sig), msg, fromB64u(r.ed25519)), `${r.description}: signature`);
    // A client dialling this origin signs exactly it.
    const scheme = /:\d+$/.test(r.origin) ? 'ws' : 'wss';
    assert.equal(originOf(`${scheme}://${r.origin}/v1`), r.origin, `${r.description}: origin`);
  }
});

test('relay vectors: routed frames, as sent and as delivered', () => {
  const raw = (k: { nodeIdRaw: string }) => k.nodeIdRaw;
  const [k0, k1, k2] = v.keys;
  const [data, unreachable] = v.frames;
  // data from seed 1 to seed 0: the relay rewrites the peer to the sender and changes nothing else.
  const sent = decodeFrame(Uint8Array.from(Buffer.from(data.sent, 'hex')));
  const got = decodeFrame(Uint8Array.from(Buffer.from(data.delivered, 'hex')));
  assert.equal(sent.type, FrameType.Data);
  assert.equal(got.type, FrameType.Data);
  assert.equal(toHex(sent.peer), raw(k0));
  assert.equal(toHex(got.peer), raw(k1));
  assert.equal(toHex(got.body), toHex(sent.body));
  // a frame for seed 2, which is not connected: unreachable names seed 2 and has no body.
  const out = decodeFrame(Uint8Array.from(Buffer.from(unreachable.sent, 'hex')));
  const back = decodeFrame(Uint8Array.from(Buffer.from(unreachable.delivered, 'hex')));
  assert.equal(toHex(out.peer), raw(k2));
  assert.equal(back.type, FrameType.Unreachable);
  assert.equal(toHex(back.peer), raw(k2));
  assert.equal(back.body.length, 0);
});
