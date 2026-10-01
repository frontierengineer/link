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
