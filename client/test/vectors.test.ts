// spec/vectors/client.json is what scripts/vectors.ts generates, and the
// client passes every case in it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fromHex, toHex } from '../src/bytes.js';
import { decodeFrame, decodeSessionMessage, encodeSessionMessage } from '../src/frames.js';
import { acceptanceProblem, rosterProblem } from '../src/roster.js';
import { parsePairingLink } from '../src/code.js';
import { renderVectors, VECTORS_PATH } from '../scripts/vectors.js';
import { FrameType, handshakeInitBody } from '../src/frames.js';
import { identityFromSeed } from '../src/identity.js';
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
  assert.deepEqual(accepts, [true, false, false, false]);
  for (const c of v.roster.acceptance) {
    assert.equal(acceptanceProblem(c.roster, c.pinnedPrimary, c.heldVersion) === null, c.accept, c.name);
  }
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

test('the pairing link parses back to its parts', () => {
  const l = v.pairing.link;
  assert.deepEqual(parsePairingLink(l.link), { network: l.network, code: l.code, codeId: l.codeIdB64u, relay: l.relay });
});

test('handshake stamps: encoded as recorded, and a responder accepts and refuses each init as recorded', () => {
  for (const e of v.handshakeStamps.encoding) {
    assert.equal(nextStamp(e.wallNowMs, BigInt(e.lastStamp)), BigInt(e.stamp));
  }
  // The surface of the vectors' roster, as responder; the worker's inits arrive in order.
  const full = v.roster.signing.roster;
  let roster = full;
  const surface = identityFromSeed(fromHex(v.noise.responder.seed));
  assert.equal(surface.id, v.handshakeStamps.responder);
  const sent: number[] = [];
  let mono = 0;
  let wall = v.handshakeStamps.responderStartedMs;
  const mgr = new SessionManager({
    identity: surface,
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

