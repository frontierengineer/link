// Generates spec/vectors/client.json from fixed inputs with this client's
// implementation. Every value is deterministic: fixed seeds, fixed
// randomness, fixed clocks. Run `npm run vectors` to rewrite the file; the
// test suite fails when the committed file differs from what this produces.

import { writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { b64u, concat, EMPTY, fromHex, toHex, u32be, u64be, utf8 } from '../src/bytes.js';
import { buildPairingLink, formatCode, normalizeCode } from '../src/code.js';
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
import { identityFromSeed, nodeIdToBytes, type Identity } from '../src/identity.js';
import { canonicalize } from '../src/jcs.js';
import { HandshakeState, PATTERNS } from '../src/noise.js';
import { NewcomerExchange, pairTransportKeys, PrimaryExchange } from '../src/pairing.js';
import {
  acceptanceProblem,
  memberFromIdentity,
  rosterProblem,
  rosterSigningBytes,
  signRoster,
  type Roster,
} from '../src/roster.js';
import { originOf, registerSigningBytes, resignSigningBytes } from '../src/signed.js';
import { sessionPrologue } from '../src/sessions.js';
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

function resign(r: Roster, primary: Identity): Roster {
  const { signature: _s, ...rest } = r;
  return { ...rest, signature: b64u(primary.sign(rosterSigningBytes(rest as Roster))) };
}

export function buildVectors(): unknown {
  const seeds = { primary: seedHex(1), worker: seedHex(2), surface: seedHex(3) };
  const primary = identityFromSeed(fromHex(seeds.primary));
  const worker = identityFromSeed(fromHex(seeds.worker));
  const surface = identityFromSeed(fromHex(seeds.surface));
  const relay = 'wss://eu.frontierengineer.link/v1';

  // ── Rosters ──
  const roster = signRoster(
    {
      network: primary.id,
      version: 12,
      issuedAt: 1790000000000,
      relay,
      primary: { ed25519: b64u(primary.ed25519.pub) },
      members: [
        memberFromIdentity(primary, 'primary'),
        memberFromIdentity(worker, 'worker'),
        memberFromIdentity(surface, 'surface'),
      ],
    },
    primary,
  );
  const { signature: _sig, ...unsigned } = roster;
  const clone = () => JSON.parse(JSON.stringify(roster)) as Roster;
  const invalid: { name: string; roster: unknown }[] = [];
  const bad = (name: string, f: (r: Roster) => void, reSign = true) => {
    const r = clone();
    f(r);
    invalid.push({ name, roster: reSign ? resign(r, primary) : r });
  };
  bad('body changed after signing', (r) => (r.version = 13), false);
  bad('signature by another key', (r) => (r.signature = b64u(worker.sign(rosterSigningBytes(r)))), false);
  bad('network not derived from primary.ed25519', (r) => (r.network = worker.id));
  bad('members not sorted by id', (r) => r.members.reverse());
  bad('member id not derived from its ed25519', (r) => (r.members.find((m) => m.kind === 'worker')!.id = surface.id));
  bad('two primary members', (r) => (r.members.find((m) => m.kind === 'worker')!.kind = 'primary'));
  bad('no primary member', (r) => (r.members = r.members.filter((m) => m.kind !== 'primary')));
  bad('primary member key differs from primary.ed25519', (r) => {
    const p = r.members.find((m) => m.kind === 'primary')!;
    p.kind = 'worker';
    r.members.find((m) => m.id === worker.id)!.kind = 'primary';
  });
  bad('unknown kind', (r) => ((r.members.find((m) => m.kind === 'surface') as { kind: string }).kind = 'admin'));
  bad('version zero', (r) => (r.version = 0));
  for (const v of invalid) {
    if (rosterProblem(v.roster) === null) throw new Error(`invalid roster case passes: ${v.name}`);
  }
  const unicodeRoster = signRoster({ ...unsigned, relay: 'wss://relé.example/v1?q=ü€😀' }, primary);
  const otherNetwork = signRoster(
    {
      network: worker.id,
      version: 20,
      issuedAt: 1790000000000,
      relay,
      primary: { ed25519: b64u(worker.ed25519.pub) },
      members: [memberFromIdentity(worker, 'primary')],
    },
    worker,
  );
  const acceptance = [
    { name: 'newer, pinned primary', roster, pinnedPrimary: roster.primary.ed25519, heldVersion: 11 },
    { name: 'same version', roster, pinnedPrimary: roster.primary.ed25519, heldVersion: 12 },
    { name: 'older version', roster, pinnedPrimary: roster.primary.ed25519, heldVersion: 13 },
    { name: 'valid but signed by another primary', roster: otherNetwork, pinnedPrimary: roster.primary.ed25519, heldVersion: 1 },
  ].map((c) => ({ ...c, accept: acceptanceProblem(c.roster, c.pinnedPrimary, c.heldVersion) === null }));

  // ── Registration and resignation ──
  const challenge = fromHex('9f'.repeat(16) + '01'.repeat(16));
  const register = ['wss://EU.FrontierEngineer.link/v1', 'wss://eu.frontierengineer.link:443/v1', 'ws://127.0.0.1:8080/v1'].map(
    (url) => {
      const origin = originOf(url);
      const ts = 1790000000123;
      const bytes = registerSigningBytes({ network: primary.id, node: worker.id, challenge, ts, origin });
      return {
        seed: seeds.worker,
        url,
        origin,
        network: primary.id,
        node: worker.id,
        challenge: b64u(challenge),
        ts,
        signedBytes: toHex(bytes),
        sig: b64u(worker.sign(bytes)),
      };
    },
  );
  const resignTs = 1790000000456;
  const resignBytes = resignSigningBytes({ network: primary.id, node: worker.id, ts: resignTs });
  const resignation = {
    seed: seeds.worker,
    network: primary.id,
    node: worker.id,
    ts: resignTs,
    signedBytes: toHex(resignBytes),
    sig: b64u(worker.sign(resignBytes)),
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
      members: [...roster.members, memberFromIdentity(newcomer, 'mcp')],
    },
    primary,
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
  const prologue = sessionPrologue(primary.id);
  const init = new HandshakeState({ pattern: PATTERNS.IK, initiator: true, prologue, s: worker.x25519, rs: surface.x25519.pub, fixedEphemeral: iEph });
  const resp = new HandshakeState({ pattern: PATTERNS.IK, initiator: false, prologue, s: surface.x25519, fixedEphemeral: rEph });
  const initIndex = 0x0badcafe;
  const respIndex = 0x00c0ffee;
  const m1 = init.writeMessage(u64be(12));
  const r1 = resp.readMessage(m1.message);
  const m2 = resp.writeMessage(u64be(13));
  const r2 = init.readMessage(m2.message);
  const ti = r2.transport!;
  const tr = m2.transport!;
  const t1: SessionMessage = { type: 'message', more: false, bytes: utf8('hello surface') };
  const t2: SessionMessage = { type: 'credit', bytes: 13 };
  const ct1 = ti.send.encryptWithAd(EMPTY, encodeSessionMessage(t1));
  const ct2 = tr.send.encryptWithAd(EMPTY, encodeSessionMessage(t2));
  const workerPeer = nodeIdToBytes(worker.id);
  const surfacePeer = nodeIdToBytes(surface.id);
  const noise = {
    protocol: 'Noise_IK_25519_ChaChaPoly_SHA256',
    network: primary.id,
    prologue: toHex(prologue),
    initiator: { node: worker.id, seed: seeds.worker, staticPrivate: toHex(worker.x25519.priv), ephemeralPrivate: toHex(iEph), index: initIndex },
    responder: { node: surface.id, seed: seeds.surface, staticPrivate: toHex(surface.x25519.priv), ephemeralPrivate: toHex(rEph), index: respIndex },
    message1: {
      payload: toHex(u64be(12)),
      noise: toHex(m1.message),
      frameSent: toHex(encodeFrame(FrameType.HandshakeInit, surfacePeer, handshakeInitBody(initIndex, m1.message))),
      frameDelivered: toHex(encodeFrame(FrameType.HandshakeInit, workerPeer, handshakeInitBody(initIndex, m1.message))),
    },
    message2: {
      payload: toHex(u64be(13)),
      noise: toHex(m2.message),
      frameSent: toHex(encodeFrame(FrameType.HandshakeResp, workerPeer, handshakeRespBody(respIndex, initIndex, m2.message))),
      frameDelivered: toHex(encodeFrame(FrameType.HandshakeResp, surfacePeer, handshakeRespBody(respIndex, initIndex, m2.message))),
    },
    handshakeHash: toHex(ti.handshakeHash),
    transport: [
      {
        direction: 'initiator->responder',
        nonce: 0,
        plaintext: toHex(encodeSessionMessage(t1)),
        ciphertext: toHex(ct1),
        frameSent: toHex(encodeFrame(FrameType.Data, surfacePeer, dataBody(respIndex, ct1))),
      },
      {
        direction: 'responder->initiator',
        nonce: 0,
        plaintext: toHex(encodeSessionMessage(t2)),
        ciphertext: toHex(ct2),
        frameSent: toHex(encodeFrame(FrameType.Data, workerPeer, dataBody(initIndex, ct2))),
      },
    ],
  };
  if (toHex(r1.payload) !== toHex(u64be(12)) || toHex(tr.handshakeHash) !== toHex(ti.handshakeHash)) {
    throw new Error('noise vector does not round-trip');
  }

  // ── Frames and session messages ──
  const peer = nodeIdToBytes(worker.id);
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

  return {
    description:
      'Link protocol v1 vectors produced by the TypeScript client (client/scripts/vectors.ts). Byte strings are lowercase hex unless the field name ends in B64u or the spec puts them in JSON as b64u.',
    keys: [keyVector(seeds.primary), keyVector(seeds.worker), keyVector(seeds.surface), keyVector(seedHex(4))],
    roster: {
      signing: {
        roster,
        jcs: canonicalize(unsigned),
        signedBytes: toHex(rosterSigningBytes(roster)),
        signature: roster.signature,
      },
      unicode: { roster: unicodeRoster, jcs: canonicalize((({ signature: _s, ...r }) => r)(unicodeRoster)) },
      valid: [
        { name: 'three members', roster },
        { name: 'non-ASCII relay URL', roster: unicodeRoster },
        { name: 'another network', roster: otherNetwork },
      ],
      invalid,
      acceptance,
    },
    register,
    resign: resignation,
    pairing: {
      link: {
        network: primary.id,
        code,
        codeIdB64u: b64u(codeId),
        relay,
        link: buildPairingLink({ network: primary.id, code, codeId: b64u(codeId), relay }),
      },
      codeNormalisation: ['7k2m-9qxz', '7K2M9QXZ', ' 7k2m 9qxz ', 'o1l1-i0OK'].map((input) => ({ input, code: normalizeCode(input) })),
    },
    spake2: { rfc9382: rfc, profile },
    noise,
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
