// spec/vectors/client.json is what scripts/vectors.ts generates, and the
// client passes every case in it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { b64u, fromHex, toHex } from '../src/bytes.js';
import { decodeFrame, decodeSessionMessage, encodeSessionMessage } from '../src/frames.js';
import { acceptanceProblem, createNetwork, isPlaced, placeNetwork, rosterProblem, type RosterMember } from '../src/roster.js';
import { buildPairingLink, buildPairingParams, parsePairingLink, parsePairingParams } from '../src/code.js';
import { canonicalize } from '../src/jcs.js';
import { InvalidError } from '../src/errors.js';
import { renderVectors, VECTORS_PATH } from '../scripts/vectors.js';
import { FrameType, handshakeInitBody } from '../src/frames.js';
import { identityFromSeed, networkKeyFromSeed } from '../src/identity.js';
import { DEFAULT_SESSION_TIMING, INITIAL_CREDIT, nextStamp, SessionManager, STAMP_WINDOW_MS } from '../src/sessions.js';

const committed = readFileSync(VECTORS_PATH, 'utf8');
const v = JSON.parse(committed);

test('the committed vectors match the generator (run `npm run vectors` after a deliberate change)', () => {
  assert.equal(committed, renderVectors());
});

test('roster cases: valid ones validate, invalid ones do not, acceptance as recorded', () => {
  for (const c of v.roster.valid) assert.equal(rosterProblem(c.roster), null, c.name);
  for (const c of v.roster.invalid) assert.notEqual(rosterProblem(c.roster), null, c.name);
  assert.ok(v.roster.invalid.length >= 10);
  const accepts = v.roster.acceptance.map((c: { accept: boolean }) => c.accept);
  assert.deepEqual(accepts, [true, false, false, true, false, true]);
  for (const c of v.roster.acceptance) {
    assert.equal(acceptanceProblem(c.roster, c.pinnedNetworkKey, c.heldVersion) === null, c.accept, c.name);
  }
});

test('network keys: the network id and key derive from the network seed, and sign the roster', () => {
  for (const n of v.networkKeys) {
    const key = networkKeyFromSeed(fromHex(n.networkSeed));
    assert.equal(toHex(key.ed25519.seed), n.ed25519Seed);
    assert.equal(toHex(key.ed25519.pub), n.ed25519Public);
    assert.equal(b64u(key.ed25519.pub), n.ed25519PublicB64u);
    assert.equal(key.id, n.networkId);
  }
  const s = v.roster.signing;
  const key = networkKeyFromSeed(fromHex(s.networkSeed));
  assert.equal(s.roster.network, key.id);
  assert.equal(s.roster.networkKey, b64u(key.ed25519.pub));
  assert.equal(b64u(key.sign(fromHex(s.signedBytes))), s.signature);
});


test('frames and session messages decode to their recorded parts', () => {
  for (const f of v.frames) {
    const d = decodeFrame(fromHex(f.frame));
    assert.equal(d.type, f.type);
    assert.equal(toHex(d.peer), f.peer);
    assert.equal(toHex(d.body), f.body);
  }
  for (const m of v.sessionMessages) {
    assert.equal(toHex(encodeSessionMessage(decodeSessionMessage(fromHex(m.encoding)))), m.encoding, m.name);
  }
});

test('placing: version 1 with no relay, from createNetwork; version 2 from placeNetwork; the refusals', () => {
  const p = v.roster.placing;
  const created = createNetwork({
    identity: identityFromSeed(fromHex(p.primarySeed)),
    networkSeed: fromHex(p.networkSeed),
    now: p.createdAt,
    members: p.members as RosterMember[],
  }).roster;
  assert.equal(canonicalize(created), canonicalize(p.unplaced));
  assert.equal(isPlaced(p.unplaced), false);
  const placed = placeNetwork({ roster: p.unplaced, networkSeed: fromHex(p.networkSeed), relay: p.relay, now: p.placedAt });
  assert.equal(canonicalize(placed), canonicalize(p.placed));
  assert.equal(isPlaced(p.placed), true);
  for (const c of p.placedAccepted) {
    assert.equal(canonicalize(placeNetwork({ roster: p.unplaced, networkSeed: fromHex(p.networkSeed), relay: c.relay, now: p.placedAt })), canonicalize(c.roster), c.name);
  }
  for (const c of p.refused) {
    assert.throws(() => placeNetwork({ roster: c.roster, networkSeed: fromHex(c.networkSeed), relay: c.relay, now: p.placedAt }), InvalidError, c.name);
  }
});

test('pairing parameters: built, wrapped, and every parse case as recorded', () => {
  const q = v.pairing.params;
  const parts = { network: q.network, code: q.code, codeId: q.codeIdB64u, relay: q.relay };
  assert.equal(buildPairingParams(parts), q.params);
  assert.equal(buildPairingLink(parts), q.link);
  assert.deepEqual(parsePairingLink(q.link), parts);
  assert.deepEqual(parsePairingParams(new URL(q.fragment).hash.slice(1)), parts);
  const { params: unicodeParams, ...unicodeParts } = q.unicode;
  assert.equal(buildPairingParams(unicodeParts), unicodeParams);
  for (const c of q.parse) {
    if (c.valid) assert.deepEqual(parsePairingParams(c.params), c.parsed, c.name);
    else assert.throws(() => parsePairingParams(c.params), InvalidError, c.name);
  }
});

test('the pairing link parses back to its parts', () => {
  const l = v.pairing.link;
  assert.deepEqual(parsePairingLink(l.link), { network: l.network, code: l.code, codeId: l.codeIdB64u, relay: l.relay });
});

test('handshake stamps: encoded as recorded, and a responder accepts and refuses each init as recorded', () => {
  for (const e of v.handshakeStamps.encoding) {
    assert.equal(nextStamp(e.wallNowMs, BigInt(e.lastStamp)), BigInt(e.stamp));
  }
  // Bob of the vectors' roster, as responder; alice's inits arrive in order.
  const full = v.roster.signing.roster;
  let roster = full;
  const bob = identityFromSeed(fromHex(v.noise.responder.seed));
  assert.equal(bob.id, v.handshakeStamps.responder);
  const sent: number[] = [];
  let mono = 0;
  let wall = v.handshakeStamps.responderStartedMs;
  const mgr = new SessionManager({
    identity: bob,
    roster: () => roster,
    now: () => mono,
    wallNow: () => wall,
    creditWindow: INITIAL_CREDIT,
    timing: DEFAULT_SESSION_TIMING,
    sendFrame: (type) => {
      sent.push(type);
      return true;
    },
    writable: () => true,
    whenWritable: (f) => f(),
    bufferedAmount: () => 0,
    wirePosition: () => ({ conn: 1, queued: 0, written: 0 }),
    note: () => undefined,
    deliver: () => undefined,
    control: () => undefined,
    peerVersion: () => undefined,
    rosterHint: () => undefined,
  });
  try {
    assert.equal(STAMP_WINDOW_MS, v.handshakeStamps.windowMs);
    for (const [i, step] of v.handshakeStamps.steps.entries()) {
      // Both clocks advance together to the step's time.
      mono += step.responderWallNowMs - wall;
      wall = step.responderWallNowMs;
      const ps = () => (mgr as unknown as { peers: Map<string, { stamp: bigint }> }).peers.get(v.handshakeStamps.initiator)!;
      if (step.event) {
        roster = step.event === 'removed' ? { ...full, members: full.members.filter((x: { id: string }) => x.id !== v.handshakeStamps.initiator) } : full;
        mgr.rosterChanged();
        if (step.stored !== undefined) assert.equal(ps().stamp, BigInt(step.stored), `${step.description}: stored`);
        continue;
      }
      const before = sent.filter((t) => t === FrameType.HandshakeResp).length;
      mgr.handleFrame({ type: FrameType.HandshakeInit, peer: new Uint8Array(16), body: handshakeInitBody(i + 1, fromHex(step.noise)) }, v.handshakeStamps.initiator);
      const answered = sent.filter((t) => t === FrameType.HandshakeResp).length > before;
      assert.equal(answered, step.accepted, step.description);
      if (step.stored !== undefined) assert.equal(ps().stamp, BigInt(step.stored), `${step.description}: stored`);
    }
  } finally {
    mgr.close();
  }
});

