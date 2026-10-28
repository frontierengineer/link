// Generates spec/vectors/client.json from fixed inputs with this client's
// implementation. Every value is deterministic: fixed seeds, fixed
// randomness, fixed clocks. Run `npm run vectors` to rewrite the file; the
// test suite fails when the committed file differs from what this produces.

import { writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { b64u, concat, EMPTY, fromHex, toHex, u32be, u64be, utf8 } from '../src/bytes.js';
import { buildPairingLink, buildPairingParams, DEFAULT_CODE_ID, formatCode, normalizeCode, parsePairingParams } from '../src/code.js';
import { open } from '../src/crypto.js';
import {
  dataBody,
  encodeFrame,
  encodeSessionMessage,
  FrameType,
  handshakeInitBody,
  handshakeRespBody,
  type SessionMessage,
} from '../src/frames.js';
import { identityFromSeed, networkKeyFromSeed, nodeIdToBytes, type NetworkKey } from '../src/identity.js';
import { canonicalize } from '../src/jcs.js';
import { HandshakeState, PATTERNS } from '../src/noise.js';
import { NewcomerExchange, pairTransportKeys, PrimaryExchange } from '../src/pairing.js';
import {
  acceptanceProblem,
  createNetwork,
  isPlaced,
  memberFromIdentity,
  placeNetwork,
  rosterProblem,
  rosterSigningBytes,
  signRoster,
  type Roster,
} from '../src/roster.js';
import { originOf, registerSigningBytes, resignSigningBytes } from '../src/signed.js';
import { initPayload, nextStamp, sessionPrologue } from '../src/sessions.js';
import { bytesToBigint, deriveW, scalarFromRandom, scalarTo32, Spake2 } from '../src/spake2.js';
import rfc9382 from '../test/vectors/rfc9382.json' with { type: 'json' };

export const VECTORS_PATH = fileURLToPath(new URL('../../spec/vectors/client.json', import.meta.url));

const seedHex = (n: number) => toHex(Uint8Array.from({ length: 32 }, (_, i) => (n * 16 + i) & 0xff));

function keyVector(seed: string) {
  const id = identityFromSeed(fromHex(seed));
  return {
    seed,
    ed25519Seed: toHex(id.ed25519.seed),
    ed25519Public: toHex(id.ed25519.pub),
    ed25519PublicB64u: b64u(id.ed25519.pub),
    x25519Private: toHex(id.x25519.priv),
    x25519Public: toHex(id.x25519.pub),
    x25519PublicB64u: b64u(id.x25519.pub),
    nodeIdBytes: toHex(nodeIdToBytes(id.id)),
    nodeId: id.id,
  };
}

function networkKeyVector(networkSeed: string) {
  const k = networkKeyFromSeed(fromHex(networkSeed));
  return {
    networkSeed,
    ed25519Seed: toHex(k.ed25519.seed),
    ed25519Public: toHex(k.ed25519.pub),
    ed25519PublicB64u: b64u(k.ed25519.pub),
    networkIdBytes: toHex(nodeIdToBytes(k.id)),
    networkId: k.id,
  };
}

function resign(r: Roster, key: NetworkKey): Roster {
  const { signature: _s, ...rest } = r;
  return { ...rest, signature: b64u(key.sign(rosterSigningBytes(rest as Roster))) };
}

export function buildVectors(): unknown {
  const seeds = { primary: seedHex(1), second: seedHex(2), third: seedHex(3) };
  const primary = identityFromSeed(fromHex(seeds.primary));
  const second = identityFromSeed(fromHex(seeds.second));
  const third = identityFromSeed(fromHex(seeds.third));
  // Network seeds, apart from every node's (section 2).
  const networkSeeds = { network: seedHex(8), other: '77'.repeat(32) };
  const net = networkKeyFromSeed(fromHex(networkSeeds.network));
  const otherNet = networkKeyFromSeed(fromHex(networkSeeds.other));
  const relay = 'wss://eu.frontierengineer.link/v1';

  // ── Rosters ──
  const roster = signRoster(
    {
      network: net.id,
      version: 12,
      issuedAt: 1790000000000,
      relay,
      networkKey: b64u(net.ed25519.pub),
      primary: primary.id,
      members: [memberFromIdentity(primary), memberFromIdentity(second), memberFromIdentity(third)],
    },
    net,
  );
  const { signature: _sig, ...unsigned } = roster;
  const clone = () => JSON.parse(JSON.stringify(roster)) as Roster;
  const invalid: { name: string; roster: unknown }[] = [];
  const bad = (name: string, f: (r: Roster) => void, reSign = true) => {
    const r = clone();
    f(r);
    invalid.push({ name, roster: reSign ? resign(r, net) : r });
  };
  bad('body changed after signing', (r) => (r.version = 13), false);
  bad('signature by another key', (r) => (r.signature = b64u(second.sign(rosterSigningBytes(r)))), false);
  bad("signature by the primary's own node key, not the network key", (r) => (r.signature = b64u(primary.sign(rosterSigningBytes(r)))), false);
  bad('network not derived from networkKey', (r) => (r.network = otherNet.id));
  bad("network is the primary's node id (the old rule)", (r) => (r.network = primary.id));
  bad('networkKey missing', (r) => delete (r as Partial<Roster>).networkKey);
  bad('members not sorted by id', (r) => r.members.reverse());
  bad('member id not derived from its ed25519', (r) => (r.members.find((m) => m.id === second.id)!.id = third.id));
  bad('primary missing', (r) => delete (r as Partial<Roster>).primary);
  bad('primary is not a node id', (r) => (r.primary = 'PRIMARY'));
  bad('primary is not a member (the network id)', (r) => (r.primary = r.network));
  bad('primary is not a member (a member removed)', (r) => (r.members = r.members.filter((m) => m.id !== r.primary)));
  bad('version zero', (r) => (r.version = 0));
  for (const v of invalid) {
    if (rosterProblem(v.roster) === null) throw new Error(`invalid roster case passes: ${v.name}`);
  }
  const unicodeRoster = signRoster({ ...unsigned, relay: 'wss://relé.example/v1?q=ü€😀' }, net);
  // The same network once the second member claimed the primary (section 3.1): the node that
  // created the network is an ordinary member; the network key signs it as before.
  const claimed = signRoster({ ...unsigned, version: 13, primary: second.id }, net);
  // A field the protocol does not define, on a member: signed like the rest, otherwise ignored.
  const withLabel = signRoster({ ...unsigned, members: roster.members.map((m) => (m.id === third.id ? { ...m, kind: 'label' } : m)) }, net);
  const otherNetwork = signRoster(
    {
      network: otherNet.id,
      version: 20,
      issuedAt: 1790000000000,
      relay,
      networkKey: b64u(otherNet.ed25519.pub),
      primary: second.id,
      members: [memberFromIdentity(second)],
    },
    otherNet,
  );
  // A network made with no relay, and placed later (section 3.2): version 1 lists the primary
  // and the second member and names no relay; version 2 sets it, nothing else changed.
  const createdAt = 1790000000000;
  const placedAt = 1790000060000;
  const unplaced = createNetwork({ identity: primary, networkSeed: net.seed, now: createdAt, members: [memberFromIdentity(second)] }).roster;
  const placed = placeNetwork({ roster: unplaced, networkSeed: net.seed, relay, now: placedAt });
  if (isPlaced(unplaced) || !isPlaced(placed)) throw new Error('placing vector: isPlaced');
  const refusedPlacing = [
    { name: 'already placed', roster: placed, networkSeed: networkSeeds.network, relay: 'wss://elsewhere.example/v1' },
    { name: 'the seed of another network', roster: unplaced, networkSeed: networkSeeds.other, relay },
    ...[
      ['no relay', ''],
      ['an https URL', 'https://eu.frontierengineer.link/v1'],
      ['no scheme', 'eu.frontierengineer.link/v1'],
      ['no host', 'wss:///v1'],
      ['one slash', 'ws:/eu.frontierengineer.link/v1'],
      ['an upper-case scheme', 'WSS://eu.frontierengineer.link/v1'],
      ['a host that is not one', 'wss://eu frontierengineer.link/v1'],
    ].map(([name, r]) => ({ name: `relay: ${name!}`, roster: unplaced, networkSeed: networkSeeds.network, relay: r! })),
  ];
  for (const c of refusedPlacing) {
    let refused = false;
    try {
      placeNetwork({ roster: c.roster, networkSeed: fromHex(c.networkSeed), relay: c.relay, now: placedAt });
    } catch {
      refused = true;
    }
    if (!refused) throw new Error(`placing vector: ${c.name} is placed`);
  }
  const placing = {
    primarySeed: seeds.primary,
    networkSeed: networkSeeds.network,
    members: [memberFromIdentity(second)],
    createdAt,
    unplaced,
    relay,
    placedAt,
    placed,
    placedAccepted: [
      { name: 'any relay URL of the rule', relay: 'ws://127.0.0.1:8080/v1', roster: placeNetwork({ roster: unplaced, networkSeed: net.seed, relay: 'ws://127.0.0.1:8080/v1', now: placedAt }) },
      { name: 'a non-ASCII host, a port and a query', relay: 'wss://relé.example:8443/v1?q=ü', roster: placeNetwork({ roster: unplaced, networkSeed: net.seed, relay: 'wss://relé.example:8443/v1?q=ü', now: placedAt }) },
    ],
    refused: refusedPlacing,
  };

  const acceptance = [
    { name: 'newer, pinned network key', roster, pinnedNetworkKey: roster.networkKey, heldVersion: 11 },
    { name: 'same version', roster, pinnedNetworkKey: roster.networkKey, heldVersion: 12 },
    { name: 'older version', roster, pinnedNetworkKey: roster.networkKey, heldVersion: 13 },
    { name: 'another primary, the same network key', roster: claimed, pinnedNetworkKey: roster.networkKey, heldVersion: 12 },
    { name: 'valid but signed by another network key', roster: otherNetwork, pinnedNetworkKey: roster.networkKey, heldVersion: 1 },
    { name: 'placed, over the unplaced version 1', roster: placed, pinnedNetworkKey: placed.networkKey, heldVersion: 1 },
  ].map((c) => ({ ...c, accept: acceptanceProblem(c.roster, c.pinnedNetworkKey, c.heldVersion) === null }));

  // ── Registration and resignation ──
  const challenge = fromHex('9f'.repeat(16) + '01'.repeat(16));
  const register = ['wss://EU.FrontierEngineer.link/v1', 'wss://eu.frontierengineer.link:443/v1', 'ws://127.0.0.1:8080/v1'].map(
    (url) => {
      const origin = originOf(url);
      const ts = 1790000000123;
      const bytes = registerSigningBytes({ network: net.id, node: second.id, challenge, ts, origin });
      return {
        seed: seeds.second,
        url,
        origin,
        network: net.id,
        node: second.id,
        challenge: b64u(challenge),
        ts,
        signedBytes: toHex(bytes),
        sig: b64u(second.sign(bytes)),
      };
    },
  );
  const resignTs = 1790000000456;
  const resignBytes = resignSigningBytes({ network: net.id, node: second.id, ts: resignTs });
  const resignation = {
    seed: seeds.second,
    network: net.id,
    node: second.id,
    ts: resignTs,
    signedBytes: toHex(resignBytes),
    sig: b64u(second.sign(resignBytes)),
  };

  // ── SPAKE2 ──
  const rfc = rfc9382.vectors.map((v) => {
    const w = bytesToBigint(fromHex(v.w));
    const ids = { idA: utf8(v.A), idB: utf8(v.B) };
    const a = new Spake2({ role: 'A', w, ...ids, scalar: bytesToBigint(fromHex(v.x)) });
    const b = new Spake2({ role: 'B', w, ...ids, scalar: bytesToBigint(fromHex(v.y)) });
    const k = a.finish(b.share);
    return {
      A: v.A, B: v.B, w: v.w, x: v.x, y: v.y,
      pA: toHex(a.share), pB: toHex(b.share), K: toHex(k.K), TT: toHex(k.tt), hashTT: toHex(k.hash),
      Ke: toHex(k.ke), Ka: toHex(k.ka), KcA: toHex(k.kcA), KcB: toHex(k.kcB), cA: toHex(k.cA), cB: toHex(k.cB),
    };
  });
  const newcomer = identityFromSeed(fromHex(seedHex(4)));
  const codeInput = '7k2m-9qxz';
  const code = normalizeCode(codeInput);
  const codeId = fromHex('0102030405060708');
  const xRandom = fromHex('a5'.repeat(24) + '3c'.repeat(24));
  const yRandom = fromHex('5a'.repeat(24) + 'c3'.repeat(24));
  const na = new NewcomerExchange(code, codeId, xRandom);
  const pb = new PrimaryExchange(code, codeId, yRandom);
  const p1 = na.p1();
  const p2 = pb.onP1(p1);
  const p3 = na.onP2(p2);
  if (!pb.onP3(p3)) throw new Error('profile vector: cA does not verify');
  const p4 = pb.p4();
  const p5 = na.onP4(p4, { ed25519: newcomer.ed25519.pub, x25519: newcomer.x25519.pub });
  const paired = signRoster(
    {
      ...unsigned,
      version: 13,
      members: [...roster.members, memberFromIdentity(newcomer)],
    },
    net,
  );
  const p6 = pb.p6(paired);
  const keys = na.spakeKeys!;
  const transport = pairTransportKeys(keys);
  const profile = {
    codeInput,
    code,
    display: formatCode(code),
    codeId: toHex(codeId),
    codeIdB64u: b64u(codeId),
    idA: 'frontier-link/1/newcomer',
    idB: 'frontier-link/1/primary',
    w: toHex(scalarTo32(deriveW(code))),
    xRandom: toHex(xRandom),
    yRandom: toHex(yRandom),
    x: toHex(scalarTo32(scalarFromRandom(xRandom))),
    y: toHex(scalarTo32(scalarFromRandom(yRandom))),
    pA: toHex(p1),
    pB: toHex(p2),
    K: toHex(keys.K),
    TT: toHex(keys.tt),
    hashTT: toHex(keys.hash),
    Ke: toHex(keys.ke),
    Ka: toHex(keys.ka),
    KcA: toHex(keys.kcA),
    KcB: toHex(keys.kcB),
    cA: toHex(p3),
    cB: toHex(p4),
    okm: toHex(concat(transport.toPrimary, transport.toNewcomer)),
    p5Plaintext: new TextDecoder().decode(open(transport.toPrimary, 0n, EMPTY, p5)),
    p5: toHex(p5),
    p6Plaintext: new TextDecoder().decode(open(transport.toNewcomer, 0n, EMPTY, p6)),
    p6: toHex(p6),
    newcomerSeed: seedHex(4),
  };

  // ── Noise IK ──
  const iEph = fromHex(seedHex(5));
  const rEph = fromHex(seedHex(6));
  const prologue = sessionPrologue(net.id);
  const init = new HandshakeState({ pattern: PATTERNS.IK, initiator: true, prologue, s: second.x25519, rs: third.x25519.pub, fixedEphemeral: iEph });
  const resp = new HandshakeState({ pattern: PATTERNS.IK, initiator: false, prologue, s: third.x25519, fixedEphemeral: rEph });
  const initIndex = 0x0badcafe;
  const respIndex = 0x00c0ffee;
  const stamp1 = 1790000000000n;
  const m1 = init.writeMessage(initPayload(12, stamp1));
  const r1 = resp.readMessage(m1.message);
  const m2 = resp.writeMessage(u64be(13));
  const r2 = init.readMessage(m2.message);
  const ti = r2.transport!;
  const tr = m2.transport!;
  const t1: SessionMessage = { type: 'message', more: false, bytes: utf8('hello') };
  const t2: SessionMessage = { type: 'credit', bytes: 13 };
  const ct1 = ti.send.encryptWithAd(EMPTY, encodeSessionMessage(t1));
  const ct2 = tr.send.encryptWithAd(EMPTY, encodeSessionMessage(t2));
  const secondPeer = nodeIdToBytes(second.id);
  const thirdPeer = nodeIdToBytes(third.id);
  const noise = {
    protocol: 'Noise_IK_25519_ChaChaPoly_SHA256',
    network: net.id,
    prologue: toHex(prologue),
    initiator: { node: second.id, seed: seeds.second, staticPrivate: toHex(second.x25519.priv), ephemeralPrivate: toHex(iEph), index: initIndex },
    responder: { node: third.id, seed: seeds.third, staticPrivate: toHex(third.x25519.priv), ephemeralPrivate: toHex(rEph), index: respIndex },
    message1: {
      payload: toHex(initPayload(12, stamp1)),
      rosterVersion: 12,
      stamp: Number(stamp1),
      noise: toHex(m1.message),
      frameSent: toHex(encodeFrame(FrameType.HandshakeInit, thirdPeer, handshakeInitBody(initIndex, m1.message))),
      frameDelivered: toHex(encodeFrame(FrameType.HandshakeInit, secondPeer, handshakeInitBody(initIndex, m1.message))),
    },
    message2: {
      payload: toHex(u64be(13)),
      noise: toHex(m2.message),
      frameSent: toHex(encodeFrame(FrameType.HandshakeResp, secondPeer, handshakeRespBody(respIndex, initIndex, m2.message))),
      frameDelivered: toHex(encodeFrame(FrameType.HandshakeResp, thirdPeer, handshakeRespBody(respIndex, initIndex, m2.message))),
    },
    handshakeHash: toHex(ti.handshakeHash),
    transport: [
      {
        direction: 'initiator->responder',
        nonce: 0,
        plaintext: toHex(encodeSessionMessage(t1)),
        ciphertext: toHex(ct1),
        frameSent: toHex(encodeFrame(FrameType.Data, thirdPeer, dataBody(respIndex, ct1))),
      },
      {
        direction: 'responder->initiator',
        nonce: 0,
        plaintext: toHex(encodeSessionMessage(t2)),
        ciphertext: toHex(ct2),
        frameSent: toHex(encodeFrame(FrameType.Data, secondPeer, dataBody(initIndex, ct2))),
      },
    ],
  };
  if (toHex(r1.payload) !== toHex(initPayload(12, stamp1)) || toHex(tr.handshakeHash) !== toHex(ti.handshakeHash)) {
    throw new Error('noise vector does not round-trip');
  }

  // ── Handshake stamps (section 7.1) ──
  // The second member's inits to the third, in order, each with its own ephemeral; the third,
  // starting with no stamp for the second, accepts or refuses each as recorded.
  const stampInit = (stamp: bigint, eph: number, payload = initPayload(12, stamp)) => {
    const hs = new HandshakeState({ pattern: PATTERNS.IK, initiator: true, prologue, s: second.x25519, rs: third.x25519.pub, fixedEphemeral: fromHex(seedHex(eph)) });
    return { ephemeralPrivate: seedHex(eph), payload: toHex(payload), noise: toHex(hs.writeMessage(payload).message) };
  };
  const T = 1790000000000n;
  const W = 600000n;
  const first = stampInit(T, 7);
  const far = T + 10n * 365n * 86_400_000n;
  // Step k (from 1) comes 10 s after the last, on both of the responder's clocks.
  const at = (k: number) => Number(T) + 10_000 * k;
  type Step =
    | { description: string; stamp: number | null; ephemeralPrivate: string; payload: string; noise: string; accepted: boolean; stored?: number }
    | { description: string; event: 'removed' | 'readmitted'; stored?: number };
  const tenAhead = stampInit(BigInt(at(10)) + W, 15);
  const steps: Step[] = [
    { description: 'stamp T - W, recorded W before the responder started: refused', stamp: Number(T - W), ...stampInit(T - W, 12), accepted: false },
    { description: 'a member 9 minutes slow, right after the restart: accepted', stamp: Number(T - 540000n), ...stampInit(T - 540000n, 13), accepted: true, stored: Number(T - 540000n) },
    { description: 'stamp T: accepted', stamp: Number(T), ...first, accepted: true, stored: Number(T) },
    { description: 'the same bytes again, a replay: refused', stamp: Number(T), ...first, accepted: false, stored: Number(T) },
    { description: 'an older stamp, T - 1: refused', stamp: Number(T - 1n), ...stampInit(T - 1n, 8), accepted: false },
    { description: 'stamp T again from a new ephemeral: refused', stamp: Number(T), ...stampInit(T, 9), accepted: false },
    { description: 'a newer stamp, T + 1: accepted', stamp: Number(T + 1n), ...stampInit(T + 1n, 10), accepted: true, stored: Number(T + 1n) },
    { description: 'an 8-byte payload, the roster version alone: refused as malformed', stamp: null, ...stampInit(0n, 11, u64be(12)), accepted: false },
    { description: 'a stamp ten years ahead: refused, and nothing stored', stamp: Number(far), ...stampInit(far, 14), accepted: false, stored: Number(T + 1n) },
    { description: 'a stamp exactly W ahead of the responder: accepted, and stored as it is', stamp: at(10) + Number(W), ...tenAhead, accepted: true, stored: at(10) + Number(W) },
    { description: 'a stamp W + 1 ahead of the responder: refused', stamp: at(11) + Number(W) + 1, ...stampInit(BigInt(at(11)) + W + 1n, 16), accepted: false, stored: at(10) + Number(W) },
    { description: 'the initiator leaves the roster: its stamp is retained', event: 'removed' },
    { description: 'and is admitted again: its stamp is restored', event: 'readmitted', stored: at(10) + Number(W) },
    { description: 'a replay of an init from before its removal: refused', stamp: at(10) + Number(W), ...tenAhead, accepted: false },
    { description: 'a fresh init after its return, stamped after the restored stamp: accepted', stamp: at(10) + Number(W) + 1, ...stampInit(BigInt(at(10)) + W + 1n, 17), accepted: true, stored: at(10) + Number(W) + 1 },
  ];
  const handshakeStamps = {
    encoding: [
      { wallNowMs: 1790000000000, lastStamp: 0, stamp: Number(nextStamp(1790000000000, 0n)) },
      { wallNowMs: 1790000000000, lastStamp: 1790000000000, stamp: Number(nextStamp(1790000000000, 1790000000000n)) },
      { wallNowMs: 1789999999000, lastStamp: 1790000000005, stamp: Number(nextStamp(1789999999000, 1790000000005n)) },
      { wallNowMs: 1790000001000, lastStamp: 1790000000005, stamp: Number(nextStamp(1790000001000, 1790000000005n)) },
    ],
    initiator: second.id,
    responder: third.id,
    windowMs: Number(W),
    // The responder started at wall time T with the second on its roster; step k comes 10 s
    // after the one before (both its clocks advance together), at responderWallNowMs, so no
    // budget is in play. stored is the responder's stamp for the second after the step.
    responderStartedMs: Number(T),
    steps: steps.map((st, k) => ({ ...st, responderWallNowMs: at(k + 1) })),
  };

  // ── Frames and session messages ──
  const peer = nodeIdToBytes(second.id);
  const frame = (name: string, type: number, body: Uint8Array) => ({
    name,
    type,
    peer: toHex(peer),
    body: toHex(body),
    frame: toHex(encodeFrame(type, peer, body)),
  });
  const frames = [
    frame('handshake-init', FrameType.HandshakeInit, handshakeInitBody(1, fromHex('aa'.repeat(8)))),
    frame('handshake-resp', FrameType.HandshakeResp, handshakeRespBody(2, 1, fromHex('bb'.repeat(8)))),
    frame('data', FrameType.Data, dataBody(0xfffffffe, fromHex('cc'.repeat(17)))),
    frame('unreachable', FrameType.Unreachable, EMPTY),
    frame('refused', FrameType.Refused, Uint8Array.of(1)),
    frame('pair', FrameType.Pair, p1),
    frame('reset', FrameType.Reset, u32be(0x0badcafe)),
    // A credit message as control: the body is exactly a data body (section 6).
    frame('control', FrameType.Control, dataBody(0xfffffffe, fromHex('dd'.repeat(21)))),
  ];
  const resignJson = JSON.stringify({ node: resignation.node, ts: resignation.ts, sig: resignation.sig });
  const sm = (name: string, m: SessionMessage) => ({ name, encoding: toHex(encodeSessionMessage(m)) });
  const sessionMessages = [
    sm('message, last fragment', { type: 'message', more: false, bytes: utf8('hi') }),
    sm('message, more fragments follow', { type: 'message', more: true, bytes: fromHex('00ff') }),
    sm('message, empty', { type: 'message', more: false, bytes: EMPTY }),
    sm('credit 1 MiB', { type: 'credit', bytes: 1048576 }),
    sm('roster-request', { type: 'roster-request' }),
    sm('roster', { type: 'roster', json: canonicalize(roster) }),
    sm('resign', { type: 'resign', json: resignJson }),
  ];

  // ── Pairing parameters (section 5.1): Link's, without a scheme ──
  const paramParts = { network: net.id, code, codeId: b64u(codeId), relay };
  const params = buildPairingParams(paramParts);
  const defaultParts = { ...paramParts, codeId: DEFAULT_CODE_ID };
  const defaultParams = buildPairingParams(defaultParts);
  const unicodeParts = { ...paramParts, relay: 'wss://relé.example:8443/v1?q=ü&x=1' };
  const unicodeParams = buildPairingParams(unicodeParts);
  const drop = (k: string) => params.split('&').filter((p) => !p.startsWith(`${k}=`)).join('&');
  const cases: { name: string; params: string; valid: boolean }[] = [
    { name: 'as built', params, valid: true },
    { name: 'a non-ASCII relay with a port and a query, percent-encoded as UTF-8', params: unicodeParams, valid: true },
    { name: 'any order, a displayed lower-case code, a parameter it does not know, an empty part', params: `r=${encodeURIComponent(relay)}&&x=9&i=${b64u(codeId)}&c=7k2m-9qxz&n=${net.id}&v=1`, valid: true },
    { name: 'v missing', params: drop('v'), valid: false },
    { name: 'an unknown version', params: params.replace('v=1', 'v=2'), valid: false },
    { name: 'n missing', params: drop('n'), valid: false },
    { name: 'c missing', params: drop('c'), valid: false },
    { name: "i missing: the network's default code", params: drop('i'), valid: true },
    { name: "i given as the default code's id, which a writer leaves out", params: params.replace(`i=${b64u(codeId)}`, `i=${DEFAULT_CODE_ID}`), valid: true },
    { name: 'i empty', params: params.replace(`i=${b64u(codeId)}`, 'i='), valid: false },
    { name: 'r missing', params: drop('r'), valid: false },
    { name: 'r empty', params: params.replace(/r=[^&]*/, 'r='), valid: false },
    { name: 'n repeated', params: `${params}&n=${net.id}`, valid: false },
    { name: 'a part without =', params: `${params}&x`, valid: false },
    { name: 'n not a node id', params: params.replace(`n=${net.id}`, 'n=nope'), valid: false },
    { name: 'c not a code', params: params.replace(`c=${code}`, 'c=7K2M9QXU'), valid: false },
    { name: 'i not 8 bytes', params: params.replace(`i=${b64u(codeId)}`, 'i=AQID'), valid: false },
    { name: 'r an https URL', params: params.replace('r=wss', 'r=https'), valid: false },
    { name: 'r malformed percent-encoding', params: params.replace(/r=[^&]*/, 'r=wss%3A%2F%2Fa%2'), valid: false },
    { name: 'r percent-encoding that is not UTF-8', params: params.replace(/r=[^&]*/, 'r=wss%3A%2F%2Frel%FF.example%2Fv1'), valid: false },
  ];
  const parseCases: { name: string; params: string; valid: boolean; parsed?: unknown }[] = cases.map((c) => {
    try {
      return { ...c, valid: true, parsed: parsePairingParams(c.params) };
    } catch {
      return { ...c, valid: false };
    }
  });
  const otherwise = parseCases.find((c, i) => c.valid !== cases[i]!.valid);
  if (otherwise) throw new Error(`pairing params vector: ${otherwise.name} parses otherwise`);
  const pairingParams = {
    network: net.id,
    code,
    codeIdB64u: b64u(codeId),
    relay,
    params,
    link: `frontier://pair?${params}`,
    fragment: `https://frontier.link/#${params}`,
    default: { network: net.id, code, codeIdB64u: DEFAULT_CODE_ID, relay, params: defaultParams, link: `frontier://pair?${defaultParams}` },
    unicode: { ...unicodeParts, params: unicodeParams },
    parse: parseCases,
  };

  return {
    description:
      'Link protocol v1 vectors produced by the TypeScript client (client-typescript/scripts/vectors.ts). Byte strings are lowercase hex unless the field name ends in B64u or the spec puts them in JSON as b64u.',
    keys: [keyVector(seeds.primary), keyVector(seeds.second), keyVector(seeds.third), keyVector(seedHex(4))],
    networkKeys: [networkKeyVector(networkSeeds.network), networkKeyVector(networkSeeds.other)],
    roster: {
      signing: {
        networkSeed: networkSeeds.network,
        roster,
        jcs: canonicalize(unsigned),
        signedBytes: toHex(rosterSigningBytes(roster)),
        signature: roster.signature,
      },
      unicode: { roster: unicodeRoster, jcs: canonicalize((({ signature: _s, ...r }) => r)(unicodeRoster)) },
      valid: [
        { name: 'three members', roster },
        { name: 'non-ASCII relay URL', roster: unicodeRoster },
        { name: 'the second member claimed the primary', roster: claimed },
        { name: 'a member carrying a field the protocol does not define (kind): signed, and otherwise ignored', roster: withLabel },
        { name: 'another network', roster: otherNetwork },
        { name: 'unplaced: version 1 with no relay yet', roster: unplaced },
        { name: 'placed: version 2 with the relay set', roster: placed },
      ],
      invalid,
      acceptance,
      placing,
    },
    register,
    resign: resignation,
    pairing: {
      link: {
        network: net.id,
        code,
        codeIdB64u: b64u(codeId),
        relay,
        link: buildPairingLink({ network: net.id, code, codeId: b64u(codeId), relay }),
      },
      params: pairingParams,
      codeNormalisation: ['7k2m-9qxz', '7K2M9QXZ', ' 7k2m 9qxz ', 'o1l1-i0OK'].map((input) => ({ input, code: normalizeCode(input) })),
    },
    spake2: { rfc9382: rfc, profile },
    noise,
    handshakeStamps,
    frames,
    sessionMessages,
  };
}

export function renderVectors(): string {
  return JSON.stringify(buildVectors(), null, 2) + '\n';
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  writeFileSync(VECTORS_PATH, renderVectors());
  console.log(`wrote ${VECTORS_PATH}`);
}
