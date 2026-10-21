// Attacks on a member by a peer or by its relay, each reproduced and shown to fail: receive-side
// flow control and the per-peer bounds (section 7.3), the Noise size bound on receive (7.2),
// the terminal state after a revoking roster in `registered` (4.1, 8), strict JSON (1), integer
// literals (3), and the rates a peer cannot push a member past (7.4, 9).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64u, randomBytes, u64be, utf8 } from '../src/bytes.js';
import { seal } from '../src/crypto.js';
import { dataBody, encodeFrame, FrameType, handshakeInitBody } from '../src/frames.js';
import { nodeIdFromBytes, nodeIdToBytes } from '../src/identity.js';
import { canonicalize } from '../src/jcs.js';
import { parseJson } from '../src/json.js';
import { HandshakeState, PATTERNS } from '../src/noise.js';
import { NewcomerExchange, pairTransportKeys, PrimaryExchange } from '../src/pairing.js';
import { generateCodeId } from '../src/code.js';
import { createIdentity, Member, Primary, RevokedError, rosterProblem, signRoster, type MemberOptions, type Roster } from '../src/index.js';
import { monotonic, RELAY_ERROR_BURST, RELAY_ERROR_RATE, ROSTER_ANSWER_INTERVAL_MS } from '../src/member.js';
import { CHANNEL_SETUP_BURST, CODE_REPLY_MS, PUSH_RETRY_INITIAL_MS, PUSH_RETRY_MAX_MS, REFUSAL_EVENT_MS, REFUSAL_REPLY_BURST } from '../src/primary.js';
import {
  INIT_BURST,
  INIT_RATE,
  INITIAL_CREDIT,
  MAX_FRAGMENT,
  MAX_NOISE_MESSAGE,
  MAX_SESSIONS_PER_PEER,
  PEER_HELD_MESSAGES,
  RESET_BURST,
  RESET_RATE,
  sessionPrologue,
  FAILED_INIT_BURST,
  FAILED_INIT_RATE,
  ROSTER_HINT_MAX_MS,
  ROSTER_HINT_INTERVAL_MS,
  STRANGER_INIT_BURST,
  STRANGER_INIT_RATE,
  STRANGERS,
  STRANGERS_INIT_BURST,
  STRANGERS_INIT_RATE,
  STRANGERS_RESET_BURST,
  STRANGERS_RESET_RATE,
  Bucket,
  initPayload,
  STAMP_WINDOW_MS,
} from '../src/sessions.js';
import { MAX_SOCKET_BYTES } from '../src/socket.js';
import { cast, MiB, pairOfManagers, priv, ScriptedRelay, tick, type Cast, type Pair } from './support/hostile.js';
import type { Identity } from '../src/identity.js';
import { until } from './support/network.js';

const FAST = { backoffInitialMs: 20, backoffMaxMs: 100, requestTimeoutMs: 2000 };

// ── Flow control and per-peer bounds (finding 1) ──

test('a peer that sends message bytes beyond the credit granted has its session ended', async () => {
  const p = pairOfManagers();
  try {
    await p.open();
    // The attack: whole messages, one after another, ignoring the 1 MiB the victim granted.
    const frag = new Uint8Array(MAX_FRAGMENT).fill(0x41);
    const count = Math.ceil((8 * MiB) / frag.length);
    for (let i = 0; i < count; i++) p.transmit({ type: 'message', more: false, bytes: frag });
    await tick(20);
    const held = p.victimInbox.reduce((n, m) => n + m.bytes.length, 0);
    assert.ok(held <= INITIAL_CREDIT, `the victim holds ${held} bytes, more than the ${INITIAL_CREDIT} it granted`);
    assert.equal(p.victimSessions().length, 0, 'the session that overran its credit is ended');
    // Every frame after the violation names a session the victim no longer holds: it is reset.
    assert.ok(p.victimSent.includes(FrameType.Reset));
  } finally {
    p.close();
  }
});

test('an empty fragment that says more follow ends the session, and adds nothing to reassembly', async () => {
  const p = pairOfManagers();
  try {
    await p.open();
    const before = p.victimSessions()[0];
    assert.ok(before);
    // The review's variant: 200000 empty "more" fragments grew a list without bound.
    for (let i = 0; i < 200_000; i++) p.transmit({ type: 'message', more: true, bytes: new Uint8Array(0) });
    await tick(20);
    assert.ok(before.ended, 'the session ended at the first empty "more" fragment');
    assert.equal(before.partialLen, 0);
    assert.equal(before.partial.length, 0);
  } finally {
    p.close();
  }
});

test('a message in reassembly is one buffer, however small its fragments', async () => {
  const p = pairOfManagers();
  try {
    await p.open();
    const n = 20_000;
    for (let i = 0; i < n; i++) p.transmit({ type: 'message', more: true, bytes: Uint8Array.of(i & 0xff) });
    await tick(20);
    const s = p.victimSessions()[0];
    assert.ok(s && !s.ended);
    assert.equal(s.partialLen, n);
    assert.ok(s.partial instanceof Uint8Array, 'no list of fragments');
    assert.ok(s.partial.length <= 2 * n, `buffer of ${s.partial.length} bytes for ${n}`);
    p.transmit({ type: 'message', more: false, bytes: Uint8Array.of(0xee) });
    await tick(5);
    const m = p.victimInbox[0]!.bytes;
    assert.equal(m.length, n + 1);
    assert.equal(m[300], 300 & 0xff);
    assert.equal(m[n], 0xee);
  } finally {
    p.close();
  }
});

test(`at most ${PEER_HELD_MESSAGES} whole messages from one peer wait for the application`, async () => {
  const p = pairOfManagers();
  try {
    await p.open();
    // Empty messages need no credit, so only the count bounds them.
    const empty = new Uint8Array(0);
    for (let i = 0; i < PEER_HELD_MESSAGES + 10; i++) p.transmit({ type: 'message', more: false, bytes: empty });
    await until(() => p.victimSessions().length === 0, 'the session to end', 20_000);
    assert.equal(p.victimInbox.length, PEER_HELD_MESSAGES);
  } finally {
    p.close();
  }
});

test('bytes one peer leaves buffered are bounded across its sessions', async () => {
  const cap = 1.5 * MiB;
  const p = pairOfManagers({ limits: { peerBufferedBytes: cap } });
  try {
    await p.open();
    // An honest sender: 900 KiB, held on the first session (the application takes nothing)...
    await p.attackerMgr.send(p.victim.id, new Uint8Array(900 * 1024));
    await until(() => p.victimInbox.length === 1, 'the first message');
    const first = p.victimSessions()[0];
    // ...then a new session, whose own credit would let 900 KiB more through.
    await priv(p.attackerMgr).initiate(p.victim.id);
    await tick(5);
    const sent = p.attackerMgr.send(p.victim.id, new Uint8Array(900 * 1024)).catch((e: unknown) => e);
    await until(() => p.victimSessions().length < 2, 'the second session to end');
    assert.equal(p.victimInbox.length, 1, 'the second message is lost, not buffered');
    assert.ok(!first.ended, 'the session holding the first message is untouched');
    const held = priv(p.victimMgr).peers.get(p.attacker.id).buffered;
    assert.ok(held <= cap, `${held} bytes buffered over a cap of ${cap}`);
    await sent;
  } finally {
    p.close();
  }
});

test(`at most ${MAX_SESSIONS_PER_PEER} sessions with one peer live at once`, async () => {
  const p = pairOfManagers();
  try {
    await p.open();
    for (let i = 0; i < MAX_SESSIONS_PER_PEER + 4; i++) {
      await priv(p.attackerMgr).initiate(p.victim.id);
      await tick(1);
    }
    const live = p.victimSessions();
    assert.equal(live.length, MAX_SESSIONS_PER_PEER);
    const current = priv(p.victimMgr).peers.get(p.attacker.id).current;
    assert.equal(current.remoteIndex, p.attackerSession().localIndex, 'the newest is current');
  } finally {
    p.close();
  }
});

// ── The Noise size bound on receive (finding 5) ──

test(`a received Noise message over ${MAX_NOISE_MESSAGE} bytes ends the session before it is decrypted`, async () => {
  const p = pairOfManagers();
  try {
    await p.open();
    const s = p.victimSessions()[0];
    let decrypted = 0;
    const real = s.recv.decryptWithAd.bind(s.recv);
    s.recv.decryptWithAd = (ad: Uint8Array, ct: Uint8Array) => {
      decrypted++;
      return real(ad, ct);
    };
    // The attacker encrypts a 900 KiB plaintext on its session and hands over the frame itself.
    const big = new Uint8Array(2 + 900 * 1024).fill(0x42);
    big[0] = 0x01;
    big[1] = 0x00;
    const a = p.attackerSession();
    const ct = a.send.encryptWithAd(new Uint8Array(0), big);
    assert.ok(ct.length > MAX_NOISE_MESSAGE);
    p.victimMgr.handleFrame({ type: FrameType.Data, peer: new Uint8Array(16), body: dataBody(a.remoteIndex, ct) }, p.attacker.id);
    await tick(5);
    assert.equal(decrypted, 0);
    assert.ok(s.ended);
    assert.equal(p.victimInbox.length, 0);
  } finally {
    p.close();
  }
});

// ── A revoking roster in `registered` (finding 2) ──

test('a roster in `registered` that drops this node leaves it revoked, never connected', async () => {
  const c = cast();
  const v3 = signRoster({ ...c.roster, version: 3, members: c.roster.members.filter((m) => m.id !== c.victim.id) }, c.net);
  const relay = new ScriptedRelay();
  relay.registered = (msg) => JSON.stringify({ type: 'registered', node: msg.node, rosterVersion: 3, roster: v3 });
  const m = new Member({ identity: c.victim, roster: c.roster, WebSocket: relay.WebSocket, timing: FAST });
  const states: string[] = [];
  m.on('state', (s) => states.push(s));
  try {
    await assert.rejects(m.waitConnected(2000), RevokedError);
    await tick(300);
    assert.equal(m.state, 'revoked');
    assert.ok(!states.includes('connected'), `states: ${states.join(' -> ')}`);
    assert.equal(m.roster.version, 3);
    assert.equal(relay.sockets.length, 1, 'a revoked node does not reconnect');
    await assert.rejects(m.send(c.attacker.id, utf8('hi')), RevokedError);
  } finally {
    m.close();
  }
});

// ── Strict JSON (finding 3) and integer literals (finding 4) ──

/** A member holding `c.roster`, registered on a scripted relay, with the attacker attached. */
async function memberUnderAttack(
  c: Cast = cast(),
  more: Partial<MemberOptions> = {},
): Promise<{ c: Cast; relay: ScriptedRelay; m: Member; attacker: ReturnType<ScriptedRelay['attach']> }> {
  const relay = new ScriptedRelay();
  const m = new Member({ identity: c.victim, roster: c.roster, WebSocket: relay.WebSocket, timing: FAST, ...more });
  await m.waitConnected(2000);
  const attacker = relay.attach(c.attacker, () => c.roster);
  return { c, relay, m, attacker };
}

/** A roster's JCS text with `edit` applied to it. */
const textOf = (r: Roster, edit: (t: string) => string) => edit(canonicalize(r));

test('a roster with a repeated member name is refused, though JSON.parse would take it', async () => {
  const { c, m, attacker } = await memberUnderAttack();
  try {
    const v3 = signRoster({ ...c.roster, version: 3 }, c.net);
    // The review's document: a genuine signed roster behind a prefix that repeats its names.
    const dup = textOf(v3, (t) => `{"version":999,"members":[],${t.slice(1)}`);
    assert.equal(rosterProblem(JSON.parse(dup)), null, 'last-wins parsing finds it valid');
    assert.throws(() => parseJson(dup), /duplicate member name/);
    await attacker.sendControl(c.victim.id, { type: 'roster', json: dup });
    await tick(20);
    assert.equal(m.roster.version, 2, 'not adopted');
    // The same roster without the prefix is taken.
    await attacker.sendControl(c.victim.id, { type: 'roster', json: canonicalize(v3) });
    await until(() => m.roster.version === 3, 'the clean roster');
  } finally {
    m.close();
  }
});

test('version and issuedAt must be integer literals: 12.0 and 1.2e1 are refused', async () => {
  const { c, m, attacker } = await memberUnderAttack();
  try {
    const v3 = signRoster({ ...c.roster, version: 3 }, c.net);
    const cases = [
      textOf(v3, (t) => t.replace('"version":3', '"version":3.0')),
      textOf(v3, (t) => t.replace('"version":3', '"version":0.3e1')),
      textOf(v3, (t) => t.replace(`"issuedAt":${v3.issuedAt}`, `"issuedAt":${v3.issuedAt}.0`)),
      textOf(v3, (t) => t.replace(`"issuedAt":${v3.issuedAt}`, `"issuedAt":${(v3.issuedAt / 1000).toString()}e3`)),
    ];
    for (const text of cases) {
      assert.equal(rosterProblem(JSON.parse(text)), null, `JSON.parse makes a valid roster of ${text.slice(0, 60)}`);
      assert.notEqual(rosterProblem(parseJson(text)), null, `refused: ${text.slice(0, 60)}`);
      await attacker.sendControl(c.victim.id, { type: 'roster', json: text });
    }
    await tick(20);
    assert.equal(m.roster.version, 2, 'none adopted');
    assert.equal(rosterProblem(parseJson(canonicalize(v3))), null);
  } finally {
    m.close();
  }
});

test('control messages from the relay with a repeated name, a lone surrogate or a number out of range are ignored', async () => {
  const c = cast();
  const relay = new ScriptedRelay();
  let bad = true;
  relay.registered = (msg) =>
    bad
      ? `{"type":"registered","node":"${String(msg.node)}","rosterVersion":2,"rosterVersion":2}`
      : JSON.stringify({ type: 'registered', node: msg.node, rosterVersion: 2 });
  const m = new Member({ identity: c.victim, roster: c.roster, WebSocket: relay.WebSocket, timing: FAST });
  const errors: string[] = [];
  m.on('relayError', (e) => errors.push(e.message ?? ''));
  try {
    await tick(50);
    assert.equal(m.state, 'connecting', 'a `registered` with a repeated name does not register');
    bad = false;
    relay.socket.close(1006);
    await m.waitConnected(2000);
    relay.socket.text('{"type":"error","code":"bad_request","message":"\\ud800"}');
    relay.socket.text('{"type":"error","code":"bad_request","message":"x","message":"y"}');
    relay.socket.text('{"type":"error","code":"bad_request","message":"z","n":1e309}');
    relay.socket.text('{"type":"error","code":"bad_request","message":"ok \\ud83d\\ude00"}');
    await tick(5);
    assert.deepEqual(errors, ['ok \u{1F600}']);
  } finally {
    m.close();
  }
});

test('a sealed pairing message with a repeated name does not open', () => {
  const codeId = generateCodeId();
  const a = new NewcomerExchange('7K2M9QXZ', codeId);
  const b = new PrimaryExchange('7K2M9QXZ', codeId);
  const cA = a.onP2(b.onP1(a.p1()));
  assert.ok(b.onP3(cA));
  const id = createIdentity();
  b.onP5(a.onP4(b.p4(), { ed25519: id.ed25519.pub, x25519: id.x25519.pub }));
  // P6 sealed by hand, as a hostile primary would: two `roster` members.
  const keys = pairTransportKeys(b.spakeKeys!);
  const c = cast();
  const text = `{"roster":{},"roster":${canonicalize(c.roster)}}`;
  assert.throws(() => a.onP6(seal(keys.toNewcomer, 0n, new Uint8Array(0), utf8(text))), /duplicate member name/);
});

// ── Rates and the socket bound (item 6) ──

test('roster-requests are answered at most once per interval, and never twice while one is unsent', async () => {
  const { c, relay, m, attacker } = await memberUnderAttack();
  try {
    await attacker.sendControl(c.victim.id, { type: 'roster-request' });
    await until(() => relay.attackerControl.length === 1, 'the first answer');
    const rosters = () => relay.attackerControl.filter((x) => x.type === 'roster').length;
    // A burst within the interval: one more answer at its end, whatever the count.
    for (let i = 0; i < 1000; i++) await attacker.sendControl(c.victim.id, { type: 'roster-request' });
    await tick(ROSTER_ANSWER_INTERVAL_MS * 2 + 50);
    assert.equal(rosters(), 2);
    // A relay that reads nothing: the answer waiting in the socket is not queued again.
    relay.hold = true;
    for (let round = 0; round < 4; round++) {
      for (let i = 0; i < 100; i++) await attacker.sendControl(c.victim.id, { type: 'roster-request' });
      await tick(ROSTER_ANSWER_INTERVAL_MS + 20);
    }
    const queued = relay.socket.frames.filter((f) => f.type === FrameType.Control).length;
    assert.equal(rosters(), 3, 'one more answer, then none while it is unsent');
    assert.ok(queued <= 3, `${queued} control frames queued`);
  } finally {
    m.close();
  }
});

test("the review's amplification: 3000 roster-requests against a full roster draw one roster while the socket holds it", async () => {
  const { c, relay, m, attacker } = await memberUnderAttack(cast(true));
  try {
    const jcs = canonicalize(c.roster).length;
    assert.ok(jcs > 60_000, `a ${jcs}-byte roster`);
    await attacker.sendControl(c.victim.id, { type: 'roster-request' });
    await until(() => relay.attackerControl.length === 1, 'the session');
    // The relay stops reading the member; the attacker streams requests.
    relay.hold = true;
    const sock = relay.socket;
    const before = sock.bufferedAmount;
    const s = priv(attacker).peers.get(c.victim.id).current;
    // Over several answer intervals, so coalescing alone would answer each of them.
    for (let round = 0; round < 4; round++) {
      for (let i = 0; i < 750; i++) priv(attacker).transmit(s, { type: 'roster-request' });
      await tick(ROSTER_ANSWER_INTERVAL_MS + 20);
    }
    await tick(ROSTER_ANSWER_INTERVAL_MS);
    const out = sock.bufferedAmount - before;
    const asked = 3000 * (18 + 4 + 1 + 16);
    assert.ok(out < 2 * jcs, `${out} bytes queued for ${asked} bytes of requests: about one roster, not 3000`);
    assert.equal(m.state, 'connected');
  } finally {
    m.close();
  }
});

/** Stamps for the inits built here: each later than the last. */
let stamps = 0;

/** A genuine handshake-init from `from` to the victim, saying it holds roster `version`. */
function initFrom(c: Cast, from: { x25519: Cast['attacker']['x25519'] }, version = 2): Uint8Array {
  const victimX = c.roster.members.find((x) => x.id === c.victim.id)!.x25519;
  const hs = new HandshakeState({
    pattern: PATTERNS.IK,
    initiator: true,
    prologue: sessionPrologue(c.roster.network),
    s: from.x25519,
    rs: Buffer.from(victimX, 'base64url'),
  });
  return handshakeInitBody(1 + Math.floor(Math.random() * 1e9), hs.writeMessage(initPayload(version, BigInt(Date.now()) + BigInt(++stamps))).message);
}

/** What the member sent `to`, by frame type, since `from` frames into the socket's log. */
const sentTo = (relay: ScriptedRelay, to: string, type: number, from = 0) =>
  relay.socket.frames.slice(from).filter((f) => f.type === type && nodeIdFromBytes(f.peer) === to).length;

/** At most a budget's burst plus what its rate refilled since `began`. */
const budget = (burst: number, rate: number, began: number) => burst + Math.ceil((rate * (Date.now() - began)) / 1000);

test("resets go once per index, within each peer's own budget: a flooding peer cannot spend another's", async () => {
  const { c, relay, m } = await memberUnderAttack();
  try {
    for (let i = 0; i < 100; i++) relay.fromAttacker(FrameType.Data, dataBody(0x01020304, new Uint8Array(32)));
    await tick(5);
    assert.equal(sentTo(relay, c.attacker.id, FrameType.Reset), 1, 'one reset for one index');
    const began = Date.now();
    for (let i = 0; i < 5000; i++) relay.fromAttacker(FrameType.Data, dataBody(i + 10, new Uint8Array(32)));
    await tick(5);
    const resets = sentTo(relay, c.attacker.id, FrameType.Reset);
    const allowed = 1 + budget(RESET_BURST, RESET_RATE, began);
    assert.ok(resets >= RESET_BURST && resets <= allowed, `${resets} resets for 5000 frames, at most ${allowed} allowed`);
    // Another member, an honest one, is still owed and sent its reset.
    relay.socket.binary(encodeFrame(FrameType.Data, nodeIdToBytes(c.primary.id), dataBody(77, new Uint8Array(32))));
    await tick(5);
    assert.equal(sentTo(relay, c.primary.id, FrameType.Reset), 1);
  } finally {
    m.close();
  }
});

test('handshake-inits are processed within each id\'s own budget, before any Diffie-Hellman work', async () => {
  const { c, relay, m } = await memberUnderAttack();
  try {
    // Made first, so the flood arrives at once.
    const inits = Array.from({ length: 200 }, () => initFrom(c, c.attacker));
    let began = Date.now();
    for (const body of inits) relay.fromAttacker(FrameType.HandshakeInit, body);
    await tick(20);
    const resps = sentTo(relay, c.attacker.id, FrameType.HandshakeResp);
    let allowed = budget(INIT_BURST, INIT_RATE, began);
    assert.ok(resps >= INIT_BURST && resps <= allowed, `${resps} answered of 200, at most ${allowed} allowed`);
    // An id off the roster: answered `refused`, within its own budget...
    const stranger = createIdentity();
    const strangerInits = Array.from({ length: 100 }, () => encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(stranger.id), initFrom(c, stranger)));
    began = Date.now();
    for (const f of strangerInits) relay.socket.binary(f);
    await tick(20);
    const refused = sentTo(relay, stranger.id, FrameType.Refused);
    allowed = budget(STRANGER_INIT_BURST, STRANGER_INIT_RATE, began);
    assert.ok(refused >= STRANGER_INIT_BURST && refused <= allowed, `${refused} refused of 100, at most ${allowed} allowed`);
    // ...which leaves another stranger's, and every member's, untouched.
    const other = createIdentity();
    relay.socket.binary(encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(other.id), initFrom(c, other)));
    relay.socket.binary(encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(c.primary.id), initFrom(c, c.primary)));
    await tick(20);
    assert.equal(sentTo(relay, other.id, FrameType.Refused), 1);
    assert.equal(sentTo(relay, c.primary.id, FrameType.HandshakeResp), 1);
  } finally {
    m.close();
  }
});

test(`inits from ids off the roster: ${STRANGERS} budgets kept, under a ceiling only forged ids reach`, async () => {
  const { c, relay, m } = await memberUnderAttack();
  try {
    // A relay forging 400 ids, one init each: short ones, so the flood is not slowed by this
    // member's own Diffie-Hellman work and outruns the ceiling's refill.
    const frames = Array.from({ length: 400 }, (_, i) =>
      encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(createIdentity().id), handshakeInitBody(i + 1, new Uint8Array(8))),
    );
    const late = createIdentity();
    const lateInit = encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(late.id), initFrom(c, late));
    const memberInit = encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(c.primary.id), initFrom(c, c.primary));
    for (const f of frames) relay.socket.binary(f);
    assert.ok(priv(m).sessions.strangers.size <= STRANGERS, 'the table of strangers is bounded');
    // The ceiling is spent: a genuine init from yet another id off the roster is dropped...
    relay.socket.binary(lateInit);
    // ...while a member's comes out of its own budget, untouched.
    relay.socket.binary(memberInit);
    await tick(20);
    assert.equal(sentTo(relay, late.id, FrameType.Refused), 0);
    assert.equal(sentTo(relay, c.primary.id, FrameType.HandshakeResp), 1);
    assert.ok(STRANGERS_INIT_BURST < frames.length && STRANGERS_INIT_RATE < frames.length);
  } finally {
    m.close();
  }
});

test('a dropped init from an id off the roster asks the primary for its roster, at most once a second', async () => {
  const { c, relay, m } = await memberUnderAttack();
  try {
    let asked = 0;
    priv(m).askPrimary = () => asked++;
    const stranger = createIdentity();
    const frames = Array.from({ length: 60 }, () => encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(stranger.id), initFrom(c, stranger)));
    for (const f of frames) relay.socket.binary(f);
    await tick(20);
    assert.equal(asked, 1);
    await tick(ROSTER_HINT_INTERVAL_MS + 50);
    for (const f of frames.slice(0, 20)) relay.socket.binary(f);
    await tick(20);
    assert.equal(asked, 2);
  } finally {
    m.close();
  }
});

test('budgets carry across a reconnect: a relay that forces one gains nothing', async () => {
  const { c, relay, m } = await memberUnderAttack();
  try {
    const inits = Array.from({ length: 2 * (INIT_BURST + 10) }, () => initFrom(c, c.attacker));
    const flood = (bodies: Uint8Array[]) => {
      for (const body of bodies) relay.fromAttacker(FrameType.HandshakeInit, body);
    };
    // Each init costs this member real Diffie-Hellman work, so the rate refills during a flood.
    const began = Date.now();
    flood(inits.slice(0, INIT_BURST + 10));
    await tick(20);
    relay.socket.close(1006);
    await until(() => relay.sockets.length === 2 && m.state === 'connected', 'the member to reconnect');
    flood(inits.slice(INIT_BURST + 10));
    await tick(20);
    // Over both connections together: one burst and what time refilled, not two bursts.
    const answered = relay.sockets.reduce((n, sock) => n + sock.frames.filter((f) => f.type === FrameType.HandshakeResp).length, 0);
    const allowed = budget(INIT_BURST, INIT_RATE, began);
    assert.ok(answered <= allowed, `${answered} answered over two connections, at most ${allowed}`);
  } finally {
    m.close();
  }
});

test("inits labelled with a member's id that fail spend that id's own budget: it alone is silenced", async () => {
  const { c, relay, m } = await memberUnderAttack(cast(true));
  try {
    const relayKey = createIdentity();
    // Inits under the attacker's id but on another key: forged by a relay, or sent by the
    // attacker itself with a bogus static key. Both fail the key check.
    const bad = Array.from({ length: 40 }, () => initFrom(c, relayKey));
    const honest = initFrom(c, c.attacker);
    const later = initFrom(c, c.attacker);
    const others = Array.from({ length: 8 }, (_, i) => c.roster.members.filter((x) => x.id !== c.victim.id && x.id !== c.attacker.id && x.id !== c.primary.id)[i]!.id);
    const otherInit = initFrom(c, c.primary);
    for (const body of bad) relay.fromAttacker(FrameType.HandshakeInit, body);
    await tick(20);
    // Only the failure burst was read; the rest were dropped before any Diffie-Hellman work.
    const refused = sentTo(relay, c.attacker.id, FrameType.Refused);
    assert.ok(refused >= FAILED_INIT_BURST && refused <= FAILED_INIT_BURST + 1, `${refused} refused of 40`);
    // The id is silenced, even for a genuine init under it...
    const from = relay.socket.frames.length;
    relay.fromAttacker(FrameType.HandshakeInit, honest);
    // ...but no other member is: bad inits under eight other ids leave the primary's untouched.
    for (const id of others) for (let k = 0; k < 10; k++) relay.socket.binary(encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(id), handshakeInitBody(k + 1, new Uint8Array(8))));
    relay.socket.binary(encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(c.primary.id), otherInit));
    await tick(20);
    assert.equal(sentTo(relay, c.attacker.id, FrameType.HandshakeResp, from), 0);
    assert.equal(sentTo(relay, c.primary.id, FrameType.HandshakeResp, from), 1);
    // Once the failures stop, the budget refills with time and the id's inits are read again.
    await tick(1000 / FAILED_INIT_RATE + 50);
    relay.fromAttacker(FrameType.HandshakeInit, later);
    await tick(20);
    assert.equal(sentTo(relay, c.attacker.id, FrameType.HandshakeResp, from), 1);
  } finally {
    m.close();
  }
});

test('members sending bad-key inits as themselves starve only themselves: an honest member still opens a session', async () => {
  const { c, relay, m, attacker } = await memberUnderAttack(cast(true));
  try {
    // Eight members, each sending inits under its own id but on a bogus static key, 40 apiece:
    // a shared budget for failures would be drained by them (the Rust re-review's case).
    const bad = c.roster.members.filter((x) => x.id !== c.victim.id && x.id !== c.attacker.id).slice(0, 8);
    const frames: Uint8Array[] = [];
    for (const x of bad) {
      for (let k = 0; k < 40; k++) frames.push(encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(x.id), initFrom(c, createIdentity(), 1)));
    }
    let pushed = 0;
    const real = priv(m).offerRosterTo.bind(m);
    priv(m).offerRosterTo = (peer: string) => {
      pushed++;
      real(peer);
    };
    for (const f of frames) relay.socket.binary(f);
    await tick(20);
    for (const x of bad) {
      const refused = sentTo(relay, x.id, FrameType.Refused);
      assert.ok(refused <= FAILED_INIT_BURST + 1, `${refused} of ${x.id}'s 40 bad inits read`);
    }
    // Their claimed version 1 (older than the member's 2) steered no roster at them.
    assert.equal(pushed, 0);
    // The honest member, a real SessionManager, opens a session and is answered.
    await attacker.sendControl(c.victim.id, { type: 'roster-request' });
    await until(() => relay.attackerControl.some((x) => x.type === 'roster'), 'the honest member to be answered');
  } finally {
    m.close();
  }
});

test('a member-labelled init on another key is refused and spends that id\'s failure budget, but pushes no roster', async () => {
  const { c, relay, m } = await memberUnderAttack();
  try {
    const relayKey = createIdentity();
    let pushed = 0;
    const real = priv(m).offerRosterTo.bind(m);
    priv(m).offerRosterTo = (peer: string) => {
      pushed++;
      real(peer);
    };
    const before = priv(m).sessions.peers.get(c.attacker.id)?.failedInits.tokens ?? FAILED_INIT_BURST;
    // Version 1: if believed, the member would push its roster to the attacker.
    relay.fromAttacker(FrameType.HandshakeInit, initFrom(c, relayKey, 1));
    await tick(20);
    assert.equal(sentTo(relay, c.attacker.id, FrameType.Refused), 1);
    assert.ok(priv(m).sessions.peers.get(c.attacker.id).failedInits.tokens <= before - 1 + 0.5);
    assert.equal(pushed, 0);
  } finally {
    m.close();
  }
});

test('resets to ids off the roster have a shared ceiling as well as their own budgets', async () => {
  const { relay, m } = await memberUnderAttack();
  try {
    // 400 forged ids, each with a few unknown indices.
    const frames: Uint8Array[] = [];
    for (let i = 0; i < 400; i++) {
      const id = createIdentity().id;
      for (let k = 0; k < 2; k++) frames.push(encodeFrame(FrameType.Data, nodeIdToBytes(id), dataBody(k + 1, new Uint8Array(32))));
    }
    const before = relay.socket.frames.length;
    const began = Date.now();
    for (const f of frames) relay.socket.binary(f);
    await tick(5);
    const resets = relay.socket.frames.slice(before).filter((f) => f.type === FrameType.Reset).length;
    const allowed = budget(STRANGERS_RESET_BURST, STRANGERS_RESET_RATE, began);
    assert.ok(resets >= STRANGERS_RESET_BURST && resets <= allowed, `${resets} resets for 800 frames, at most ${allowed}`);
  } finally {
    m.close();
  }
});

test('a replayed handshake-init showing an old roster draws one roster per interval, not one per replay', async () => {
  const { c, relay, m } = await memberUnderAttack(cast(true));
  try {
    // One genuine init from the attacker, holding version 1; the relay replays it.
    const recorded = initFrom(c, c.attacker, 1);
    const began = Date.now();
    for (let round = 0; round < 4; round++) {
      for (let i = 0; i < 30; i++) relay.fromAttacker(FrameType.HandshakeInit, recorded);
      await tick(ROSTER_ANSWER_INTERVAL_MS + 20);
    }
    await tick(ROSTER_ANSWER_INTERVAL_MS);
    const pushed = sentTo(relay, c.attacker.id, FrameType.Control);
    const intervals = Math.ceil((Date.now() - began) / ROSTER_ANSWER_INTERVAL_MS) + 1;
    assert.ok(pushed >= 1 && pushed <= intervals, `${pushed} rosters pushed for 120 replays over ${intervals} intervals`);
    // With the relay reading nothing, none beyond the one still unsent.
    relay.hold = true;
    const held = relay.socket.frames.length;
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 30; i++) relay.fromAttacker(FrameType.HandshakeInit, recorded);
      await tick(ROSTER_ANSWER_INTERVAL_MS + 20);
    }
    assert.ok(sentTo(relay, c.attacker.id, FrameType.Control, held) <= 1);
  } finally {
    m.close();
  }
});

test('relay `error` messages raise `relayError` events within a budget', async () => {
  const { relay, m } = await memberUnderAttack();
  try {
    let events = 0;
    m.on('relayError', () => events++);
    const began = Date.now();
    for (let i = 0; i < 1000; i++) relay.socket.text('{"type":"error","code":"bad_request","message":"x"}');
    await tick(5);
    const allowed = budget(RELAY_ERROR_BURST, RELAY_ERROR_RATE, began);
    assert.ok(events >= RELAY_ERROR_BURST && events <= allowed, `${events} events for 1000 errors, at most ${allowed}`);
  } finally {
    m.close();
  }
});

test('a primary refuses `pairing`s for code ids it never opened without an event, and within a rate', async () => {
  const c = cast();
  const relay = new ScriptedRelay();
  // A clock the test moves, so no budget refills while the flood is read.
  let clock = 0;
  const p = new Primary({ identity: c.primary, roster: c.roster, networkSeed: c.networkSeed, WebSocket: relay.WebSocket, timing: FAST, monotonicNow: () => clock });
  const events: { codeId: string; reason: string }[] = [];
  p.on('pairingFailed', (e) => events.push(e));
  try {
    await p.waitConnected(2000);
    const pairing = (code: string, channel = b64u(randomBytes(16))) =>
      relay.socket.text(JSON.stringify({ type: 'pairing', channel, code }));
    const pairEnds = () => relay.socket.texts.filter((t) => t.type === 'pairEnd').length;
    // The Go primary's finding: made-up code ids, streamed.
    for (let i = 0; i < 2000; i++) pairing(b64u(randomBytes(8)));
    await tick(5);
    assert.equal(events.length, 0, 'no event for an id never opened');
    assert.equal(pairEnds(), REFUSAL_REPLY_BURST, `${pairEnds()} pairEnd answers`);
    // A code it opened and cancelled, with the shared budget spent by the made-up ids: the first
    // refusal on every channel is still answered (so neither those ids nor anyone else holding
    // the code id can use up an honest newcomer's answer), repeats on one channel once a second,
    // and the event once a second per code and reason.
    const code = p.openPairingCode();
    p.cancelPairingCode(code.codeId);
    for (let i = 0; i < 2000; i++) pairing(b64u(randomBytes(8)));
    let before = pairEnds();
    for (let i = 0; i < 50; i++) pairing(code.codeId);
    await tick(5);
    assert.equal(pairEnds() - before, 50, 'the first refusal on each channel is answered');
    assert.deepEqual(events, [{ codeId: code.codeId, reason: 'unknown or expired code' }]);
    const channel = b64u(randomBytes(16));
    before = pairEnds();
    for (let i = 0; i < 200; i++) pairing(code.codeId, channel);
    await tick(5);
    assert.equal(pairEnds() - before, 1, 'repeats on one channel: once a second');
    clock += Math.max(REFUSAL_EVENT_MS, CODE_REPLY_MS);
    pairing(code.codeId, channel);
    await tick(5);
    assert.equal(events.length, 2);
    assert.equal(pairEnds() - before, 2);
  } finally {
    p.close();
  }
});

test(`a socket holding ${MAX_SOCKET_BYTES} bytes unsent is dropped and redialled, never grown`, async () => {
  const { relay, m } = await memberUnderAttack();
  try {
    relay.hold = true;
    const first = relay.socket;
    first.bufferedAmount = MAX_SOCKET_BYTES - 10;
    // Anything that makes the member send: here a reset for an index it does not hold.
    relay.fromAttacker(FrameType.Data, dataBody(0x0badf00d, new Uint8Array(32)));
    await tick(5);
    assert.ok(first.bufferedAmount <= MAX_SOCKET_BYTES, 'nothing was added past the bound');
    assert.equal(first.readyState, 3, 'the connection was dropped');
    relay.hold = false;
    await until(() => relay.sockets.length === 2 && m.state === 'connected', 'the member to reconnect');
  } finally {
    m.close();
  }
});

// ── Clocks (re-review 2, R2-1) ──

test('a wall clock stepping back an hour strands no budget and holds back no roster offer', async () => {
  let wall = Date.now();
  const { c, relay, m, attacker } = await memberUnderAttack(cast(), { now: () => wall });
  try {
    const relayKey = createIdentity();
    const bad = Array.from({ length: FAILED_INIT_BURST + 2 }, () => initFrom(c, relayKey));
    await attacker.sendControl(c.victim.id, { type: 'roster-request' });
    await until(() => relay.attackerControl.filter((x) => x.type === 'roster').length === 1, 'the first answer');
    // The wall clock steps back an hour (an NTP step, a restored VM).
    wall -= 3_600_000;
    // The next roster offer goes within the interval, not an hour later...
    await tick(ROSTER_ANSWER_INTERVAL_MS + 20);
    await attacker.sendControl(c.victim.id, { type: 'roster-request' });
    await until(() => relay.attackerControl.filter((x) => x.type === 'roster').length === 2, 'the second answer', 2000);
    // ...and a budget drained across a step refills on schedule: bad inits under the attacker's
    // id empty its failure budget, the clock steps back again, and half a second on (the clock
    // set right again, since a responder whose clock is behind refuses stamps from correct
    // clocks as too far ahead, section 7.1) a genuine init is read.
    for (const body of bad) relay.fromAttacker(FrameType.HandshakeInit, body);
    await tick(20);
    wall -= 3_600_000;
    await tick(1000 / FAILED_INIT_RATE + 50);
    wall = Date.now();
    // Stamped now: later than the attacker's own handshakes above.
    const good = initFrom(c, c.attacker);
    const from = relay.socket.frames.length;
    relay.fromAttacker(FrameType.HandshakeInit, good);
    await tick(20);
    assert.equal(sentTo(relay, c.attacker.id, FrameType.HandshakeResp, from), 1);
  } finally {
    m.close();
  }
});

test('the monotonic clock holds a step back at its last reading, and a bucket refills from there', () => {
  let t = 1000;
  const clock = monotonic(() => t);
  assert.equal(clock(), 1000);
  t = 500;
  assert.equal(clock(), 1000, 'never earlier than the last reading');
  t = 1500;
  assert.equal(clock(), 1500);
  // A bucket given a time that steps back (it should never be) refills from there, not later.
  const b = new Bucket(2, 1);
  assert.ok(b.take(10_000));
  assert.ok(!b.take(10_000));
  assert.ok(!b.take(5_000));
  assert.ok(b.take(5_600), 'half a second after the step, not 4.5 s');
});

// ── Pairing channel setups (re-review 2, R2-2) ──

test('a relay cycling pairing and pairEnd on an open code sets up channels within its budget, and raises few events', async () => {
  const c = cast();
  const relay = new ScriptedRelay();
  let clock = 0;
  const p = new Primary({ identity: c.primary, roster: c.roster, networkSeed: c.networkSeed, WebSocket: relay.WebSocket, timing: FAST, monotonicNow: () => clock });
  const events: { codeId: string; reason: string }[] = [];
  p.on('pairingFailed', (e) => events.push(e));
  try {
    await p.waitConnected(2000);
    const code = p.openPairingCode();
    const pairEnds = () => relay.socket.texts.filter((t) => t.type === 'pairEnd').length;
    // 100 cycles: a channel set up on the open code, then ended by the relay (refunding the slot).
    for (let i = 0; i < 100; i++) {
      const channel = b64u(randomBytes(16));
      relay.socket.text(JSON.stringify({ type: 'pairing', channel, code: code.codeId }));
      relay.socket.text(JSON.stringify({ type: 'pairEnd', channel }));
    }
    await tick(5);
    // Every setup beyond the budget was refused at once (answered pairEnd), with no SPAKE2 work.
    assert.equal(pairEnds(), 100 - CHANNEL_SETUP_BURST, `${pairEnds()} refused`);
    const byReason = (r: string) => events.filter((e) => e.reason === r).length;
    assert.equal(byReason('the newcomer left'), 1, 'one event for the channels the relay ended');
    assert.equal(byReason('too many attempts at once; try again'), 1, 'one event for the setups refused');
    // The code is still usable once the budget refills: an honest newcomer is not locked out.
    clock += 1000;
    const before = pairEnds();
    relay.socket.text(JSON.stringify({ type: 'pairing', channel: b64u(randomBytes(16)), code: code.codeId }));
    await tick(5);
    assert.equal(pairEnds(), before, 'set up, not refused');
  } finally {
    p.close();
  }
});

test("a member's own init with a malformed payload counts as a failed init", async () => {
  const { c, relay, m } = await memberUnderAttack();
  try {
    const victimX = c.roster.members.find((x) => x.id === c.victim.id)!.x25519;
    // On the attacker's own key, but carrying 4 bytes where the roster version's 8 belong.
    const malformed = Array.from({ length: FAILED_INIT_BURST }, () => {
      const hs = new HandshakeState({
        pattern: PATTERNS.IK,
        initiator: true,
        prologue: sessionPrologue(c.roster.network),
        s: c.attacker.x25519,
        rs: Buffer.from(victimX, 'base64url'),
      });
      return handshakeInitBody(1 + Math.floor(Math.random() * 1e9), hs.writeMessage(new Uint8Array(4)).message);
    });
    const good = initFrom(c, c.attacker);
    for (const body of malformed) relay.fromAttacker(FrameType.HandshakeInit, body);
    await tick(20);
    const from = relay.socket.frames.length;
    relay.fromAttacker(FrameType.HandshakeInit, good);
    await tick(20);
    assert.equal(sentTo(relay, c.attacker.id, FrameType.HandshakeResp, from), 0, 'the failure budget is spent');
    assert.equal(sentTo(relay, c.attacker.id, FrameType.HandshakeResp), 0, 'no session for a malformed payload');
  } finally {
    m.close();
  }
});

test('roster hints back off: doubling from 1 s to 5 min while they bring nothing, reset by a newer roster', async () => {
  let clock = 0;
  const { c, relay, m, attacker } = await memberUnderAttack(cast(), { monotonicNow: () => clock });
  try {
    let asked = 0;
    priv(m).askPrimary = () => asked++;
    // A stranger whose own budget is spent at once (the clock stands still), so every init of
    // its after that is dropped, and each drop is a hint.
    const stranger = createIdentity();
    const junk = (i: number) => encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(stranger.id), handshakeInitBody(i + 1, new Uint8Array(8)));
    let n = 0;
    const provoke = () => {
      for (let i = 0; i < STRANGER_INIT_BURST + 2; i++) relay.socket.binary(junk(n++));
    };
    provoke();
    assert.equal(asked, 1);
    // Waits of 1, 2, 4, 8 s: a hint goes only once each has passed.
    for (const wait of [1000, 2000, 4000, 8000]) {
      clock += wait - 1;
      provoke();
      assert.equal(asked, 1 + [1000, 2000, 4000, 8000].indexOf(wait), `not before ${wait} ms`);
      clock += 1;
      provoke();
      assert.equal(asked, 2 + [1000, 2000, 4000, 8000].indexOf(wait), `at ${wait} ms`);
    }
    // It stops doubling at five minutes.
    for (let k = 0; k < 10; k++) {
      clock += ROSTER_HINT_MAX_MS;
      provoke();
    }
    const capped = asked;
    clock += ROSTER_HINT_MAX_MS - 1;
    provoke();
    assert.equal(asked, capped, 'the wait is at its five-minute cap');
    // A newer roster resets it: the next hint may go one second after the last.
    clock += 1;
    provoke();
    const at = asked;
    const v3 = signRoster({ ...c.roster, version: 3 }, c.net);
    await attacker.sendControl(c.victim.id, { type: 'roster', json: canonicalize(v3) });
    await until(() => m.roster.version === 3, 'the newer roster');
    clock += 1000;
    provoke();
    assert.equal(asked, at + 1);
  } finally {
    m.close();
  }
});

test('a failed init labelled with a member id never hints', async () => {
  const { c, relay, m } = await memberUnderAttack();
  try {
    let asked = 0;
    priv(m).askPrimary = () => asked++;
    const relayKey = createIdentity();
    // On another key, unreadable, and on the member's own key with a malformed payload; some
    // claiming a newer version, and enough to spend the id's failure budget and be dropped.
    for (let i = 0; i < 10; i++) relay.fromAttacker(FrameType.HandshakeInit, initFrom(c, relayKey, 99));
    for (let i = 0; i < 10; i++) relay.fromAttacker(FrameType.HandshakeInit, handshakeInitBody(i + 1, new Uint8Array(8)));
    await tick(20);
    assert.equal(asked, 0);
  } finally {
    m.close();
  }
});

test('a roster hint within the wait is deferred to its end, not dropped: one ask however many came', async () => {
  let clock = 0;
  const { relay, m } = await memberUnderAttack(cast(), { monotonicNow: () => clock });
  try {
    let asked = 0;
    priv(m).askPrimary = () => asked++;
    const stranger = createIdentity();
    let n = 0;
    const provoke = () => {
      for (let i = 0; i < STRANGER_INIT_BURST + 2; i++) {
        relay.socket.binary(encodeFrame(FrameType.HandshakeInit, nodeIdToBytes(stranger.id), handshakeInitBody(++n, new Uint8Array(8))));
      }
    };
    provoke();
    assert.equal(asked, 1);
    // 100 ms on: within the 1 s wait, so not asked now...
    clock += 100;
    for (let k = 0; k < 20; k++) provoke();
    assert.equal(asked, 1);
    // ...but once, when the wait ends (900 ms on).
    await tick(700);
    assert.equal(asked, 1);
    await tick(400);
    assert.equal(asked, 2, 'the deferred hint asked once');
    await tick(300);
    assert.equal(asked, 2);
  } finally {
    m.close();
  }
});

// ── Replay protection for message 1 (section 7.1) ──

test('a replayed handshake-init is dropped unanswered and evicts nothing', async () => {
  const { c, relay, m, attacker } = await memberUnderAttack();
  try {
    // A genuine handshake, recorded by the relay.
    await attacker.sendControl(c.victim.id, { type: 'roster-request' });
    await until(() => relay.attackerControl.length === 1, 'the session');
    const recorded = relay.fromAttackerLog.find((f) => f.type === FrameType.HandshakeInit)!;
    const session = () => priv(m).sessions.peers.get(c.attacker.id).current;
    const before = session();
    assert.ok(before);
    const from = relay.socket.frames.length;
    // Replayed, again and again.
    for (let i = 0; i < 10; i++) relay.fromAttacker(FrameType.HandshakeInit, recorded.body);
    await tick(20);
    assert.equal(sentTo(relay, c.attacker.id, FrameType.HandshakeResp, from), 0, 'no answer');
    assert.equal(sentTo(relay, c.attacker.id, FrameType.Refused, from), 0, 'not even refused');
    assert.equal(session(), before, 'the live session is still current');
    assert.equal(priv(m).sessions.peers.get(c.attacker.id).sessions.size, 1, 'no session was made');
    // And it still carries messages both ways.
    const got = new Promise<Uint8Array>((resolve) => m.onMessage((x) => resolve(x.bytes)));
    await attacker.send(c.victim.id, utf8('still here'));
    assert.equal(new TextDecoder().decode(await got), 'still here');
  } finally {
    m.close();
  }
});

test('inits sent in the same millisecond get increasing stamps, and every one is accepted', async () => {
  // The initiator's wall clock stands still: stamps still rise, by one.
  const p = pairOfManagers({ wallNow: () => 1_790_000_000_000 }, { wallNow: () => 1_790_000_000_000 });
  try {
    await p.open();
    for (let i = 0; i < 5; i++) await priv(p.attackerMgr).initiate(p.victim.id);
    await tick(5);
    assert.equal(p.victimSent.filter((t) => t === FrameType.HandshakeResp).length, 6, 'six inits, six answers');
    assert.equal(priv(p.attackerMgr).lastStamp, 1_790_000_000_005n);
    assert.equal(priv(p.victimMgr).peers.get(p.attacker.id).stamp, 1_790_000_000_005n);
  } finally {
    p.close();
  }
});

test('the stamp table outlives the sessions: after a peer goes idle, a replay of its old init is still refused', async () => {
  const { c, relay, m, attacker } = await memberUnderAttack(cast(), { timing: { ...FAST, idleMs: 200 } });
  try {
    await attacker.sendControl(c.victim.id, { type: 'roster-request' });
    await until(() => relay.attackerControl.length === 1, 'the session');
    const recorded = relay.fromAttackerLog.find((f) => f.type === FrameType.HandshakeInit)!;
    // Idle: every session with the attacker is forgotten.
    await until(() => (priv(m).sessions.peers.get(c.attacker.id)?.sessions.size ?? 0) === 0, 'the session to go idle', 3000);
    const from = relay.socket.frames.length;
    relay.fromAttacker(FrameType.HandshakeInit, recorded.body);
    await tick(20);
    assert.equal(sentTo(relay, c.attacker.id, FrameType.HandshakeResp, from), 0, 'the replay is refused');
    assert.equal(priv(m).sessions.peers.get(c.attacker.id).sessions.size, 0, 'and makes no session');
    // A fresh init, stamped later, is accepted as ever.
    relay.fromAttacker(FrameType.HandshakeInit, initFrom(c, c.attacker));
    await tick(20);
    assert.equal(sentTo(relay, c.attacker.id, FrameType.HandshakeResp, from), 1);
  } finally {
    m.close();
  }
});

/** An init from `from` to the victim of `c`, with the given stamp. */
function initStamped(c: Cast, from: Identity, stamp: bigint): Uint8Array {
  return initFromPayload(c, from, initPayload(2, stamp));
}

function initFromPayload(c: Cast, from: Identity, payload: Uint8Array): Uint8Array {
  const victimX = c.roster.members.find((x) => x.id === c.victim.id)!.x25519;
  const hs = new HandshakeState({
    pattern: PATTERNS.IK,
    initiator: true,
    prologue: sessionPrologue(c.roster.network),
    s: from.x25519,
    rs: Buffer.from(victimX, 'base64url'),
  });
  return handshakeInitBody(1 + Math.floor(Math.random() * 1e9), hs.writeMessage(payload).message);
}

/** Hands the victim an init from the attacker; true when it was answered. */
async function offer(p: Pair, body: Uint8Array): Promise<boolean> {
  const before = p.victimSent.filter((t) => t === FrameType.HandshakeResp).length;
  p.victimMgr.handleFrame({ type: FrameType.HandshakeInit, peer: new Uint8Array(16), body }, p.attacker.id);
  await tick(5);
  return p.victimSent.filter((t) => t === FrameType.HandshakeResp).length > before;
}

/** A victim whose wall clock and monotonic clock the test moves; both advance together unless
 * the test steps the wall clock alone. */
function clockedPair(startWall: number) {
  const clock = { wall: startWall, mono: 0 };
  const p = pairOfManagers({ wallNow: () => clock.wall, now: () => clock.mono });
  const pass = (ms: number) => {
    clock.wall += ms;
    clock.mono += ms;
  };
  return { p, clock, pass };
}

test('a stamp more than W ahead is refused and stores nothing; once the clock is fixed the member is accepted at once', async () => {
  const T = 1_790_000_000_000;
  const { p, clock, pass } = clockedPair(T);
  try {
    // Its clock a year ahead: refused, visibly, while it is wrong, and nothing stored.
    assert.ok(!(await offer(p, initStamped(p, p.attacker, BigInt(clock.wall) + 365n * 86_400_000n))));
    assert.equal(priv(p.victimMgr).peers.get(p.attacker.id).stamp, 0n);
    // W ahead is still honest (two members each 5 minutes off the relay): accepted, stored as is.
    pass(10_000);
    const edge = BigInt(clock.wall) + BigInt(STAMP_WINDOW_MS);
    assert.ok(await offer(p, initStamped(p, p.attacker, edge)));
    assert.equal(priv(p.victimMgr).peers.get(p.attacker.id).stamp, edge);
    pass(10_000);
    assert.ok(!(await offer(p, initStamped(p, p.attacker, BigInt(clock.wall) + BigInt(STAMP_WINDOW_MS) + 1n))), 'W + 1 ahead');
  } finally {
    p.close();
  }
});

test('after a restart, only inits stamped within W before it are accepted: older recordings stay refused', async () => {
  const T = 1_790_000_000_000;
  const { p, pass } = clockedPair(T);
  try {
    const step = async (stamp: number) => {
      pass(10_000);
      return offer(p, initStamped(p, p.attacker, BigInt(stamp)));
    };
    // A relay replaying recordings in ascending order, oldest first.
    assert.ok(!(await step(T - 3_600_000)));
    assert.ok(!(await step(T - STAMP_WINDOW_MS)));
    assert.ok(await step(T - STAMP_WINDOW_MS + 1));
  } finally {
    p.close();
  }
});

test('the floor is kept on the monotonic clock: a wall-clock correction after start does not freeze it', async () => {
  const T = 1_790_000_000_000;
  const { p, clock } = clockedPair(T);
  try {
    // A second after starting, the responder's wall clock is corrected back an hour.
    clock.mono += 1000;
    clock.wall = T - 3_600_000 + 1000;
    // An honest member, its clock 9 minutes behind the corrected one: accepted. (A floor kept in
    // wall time, T - W, would refuse it for an hour.)
    clock.mono += 10_000;
    clock.wall += 10_000;
    assert.ok(await offer(p, initStamped(p, p.attacker, BigInt(clock.wall - 9 * 60_000))));
  } finally {
    p.close();
  }
});

test('a member removed and admitted again within two minutes still refuses its inits from before: its stamp is retained', async () => {
  const T = 1_790_000_000_000;
  const { p, pass } = clockedPair(T);
  let current: Roster | undefined;
  // The victim's roster, as the test changes it.
  priv(p.victimMgr).h.roster = () => current ?? p.roster;
  try {
    pass(10_000);
    const recorded = initStamped(p, p.attacker, BigInt(T + 5_000));
    assert.ok(await offer(p, recorded));
    // Revoked a minute later, and admitted again a minute after that.
    pass(60_000);
    current = signRoster({ ...p.roster, version: 3, members: p.roster.members.filter((x) => x.id !== p.attacker.id) }, p.net);
    p.victimMgr.rosterChanged();
    assert.equal(priv(p.victimMgr).peers.get(p.attacker.id).stamp, 0n);
    pass(60_000);
    current = signRoster({ ...p.roster, version: 4 }, p.net);
    p.victimMgr.rosterChanged();
    assert.equal(priv(p.victimMgr).peers.get(p.attacker.id).stamp, BigInt(T + 5_000), 'restored');
    // The init from before the revocation, replayed: refused (a floor of re-admission - W would
    // have let it through).
    pass(10_000);
    assert.ok(!(await offer(p, recorded)));
    // A fresh one, stamped later: accepted.
    pass(10_000);
    assert.ok(await offer(p, initStamped(p, p.attacker, BigInt(T + 6_000))));
  } finally {
    p.close();
  }
});

test('a member 9 minutes slow is accepted right after the responder restarts', async () => {
  const T = 1_790_000_000_000;
  const { p, pass } = clockedPair(T);
  try {
    pass(1_000);
    assert.ok(await offer(p, initStamped(p, p.attacker, BigInt(T + 1_000 - 9 * 60_000))));
  } finally {
    p.close();
  }
});

// ── Roster pushes are retried (section 8) ──

test('a roster push that fails is tried again until it goes: an idle member learns of a revocation', async () => {
  const c = cast();
  const relay = new ScriptedRelay();
  const p = new Primary({ identity: c.primary, roster: c.roster, networkSeed: c.networkSeed, WebSocket: relay.WebSocket, timing: FAST });
  try {
    await p.waitConnected(2000);
    // The attacker, here an honest member that sends nothing at all, is offline for the push.
    relay.attach(c.attacker, () => c.roster);
    relay.unreachableNext = 1;
    const rosters = () => relay.attackerControl.filter((x) => x.type === 'roster') as { type: 'roster'; json: string }[];
    p.revoke(c.victim.id);
    await tick(PUSH_RETRY_INITIAL_MS / 2);
    assert.equal(rosters().length, 0, 'the first push went nowhere');
    // Tried again a second later: delivered, with the revocation.
    await until(() => rosters().length >= 1, 'the push to be tried again', PUSH_RETRY_INITIAL_MS * 3);
    const got = JSON.parse(rosters()[0]!.json) as Roster;
    assert.equal(got.version, 3);
    assert.ok(!got.members.some((x) => x.id === c.victim.id));
    assert.equal(priv(priv(p).prim).pushRetries.size, 0);
  } finally {
    p.close();
  }
});

test('push retries back off, and stop once the member leaves the roster', async () => {
  const c = cast();
  const relay = new ScriptedRelay();
  const p = new Primary({ identity: c.primary, roster: c.roster, networkSeed: c.networkSeed, WebSocket: relay.WebSocket, timing: FAST });
  try {
    await p.waitConnected(2000);
    relay.attach(c.attacker, () => c.roster);
    relay.unreachableNext = 1000;
    const inits = () => relay.socket.frames.filter((f) => f.type === FrameType.HandshakeInit && nodeIdFromBytes(f.peer) === c.attacker.id).length;
    p.revoke(c.victim.id);
    // 1 s doubling, to at most 10 minutes (section 8).
    assert.equal(PUSH_RETRY_INITIAL_MS, 1000);
    assert.equal(PUSH_RETRY_MAX_MS, 600_000);
    // Tries at 0, 1 and 3 seconds (1 s, doubling): three in 3.5 s, not one a second's worth more.
    await tick(3_500);
    assert.equal(inits(), 3);
    assert.equal(priv(priv(p).prim).pushRetries.size, 1);
    // The member leaves the roster: nothing more is tried for it.
    p.revoke(c.attacker.id);
    assert.equal(priv(priv(p).prim).pushRetries.size, 0);
    await tick(4_500);
    assert.equal(inits(), 3);
  } finally {
    p.close();
  }
});

test('an init recorded but never delivered before a removal is refused once the re-admission is more than W after it', async () => {
  const T = 1_790_000_000_000;
  const { p, clock, pass } = clockedPair(T);
  let current: Roster | undefined;
  priv(p.victimMgr).h.roster = () => current ?? p.roster;
  try {
    pass(10_000);
    assert.ok(await offer(p, initStamped(p, p.attacker, BigInt(clock.wall))));
    // A later init, recorded by the relay and held back, never delivered.
    pass(10_000);
    const held = initStamped(p, p.attacker, BigInt(clock.wall));
    // Removed, and admitted again eleven minutes after that init was made.
    current = signRoster({ ...p.roster, version: 3, members: p.roster.members.filter((x) => x.id !== p.attacker.id) }, p.net);
    p.victimMgr.rosterChanged();
    pass(11 * 60_000);
    current = signRoster({ ...p.roster, version: 4 }, p.net);
    p.victimMgr.rosterChanged();
    // Its stamp is above the retained one, but not after re-admission - W: refused.
    pass(1_000);
    assert.ok(!(await offer(p, held)));
    assert.ok(await offer(p, initStamped(p, p.attacker, BigInt(clock.wall))));
  } finally {
    p.close();
  }
});

