// gen-native-kat.ts — emit the shared Known-Answer-Test vectors (`kat.json`) that
// any independent implementation of this protocol (in any language) can check
// itself against.
//
// THE LIBRARY IS THE ORACLE. Every byte in the output is produced by these very
// functions, so a green KAT proves that an independent port is byte-identical to
// this reference implementation.
//
// Determinism: all inputs are FIXED constants (no Math.random / Date). Where the
// runtime API would draw randomness (SPAKE2 x/y scalars, the host static key,
// token/keyId/reachId), we feed fixed bytes through the library's test-only
// fixed-scalar / explicit-key paths and record the inputs, so the file is exactly
// reproducible.
//
// Usage:
//   npx tsx scripts/gen-native-kat.ts            # → JSON to stdout, report to stderr
//   npx tsx scripts/gen-native-kat.ts --validate <kat.json>   # re-derive & check a file

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

import { HandshakeState, PATTERNS, type Transport } from '../src/noise.js';
import { Spake2, deriveW, verifyConfirm, _test } from '../src/spake2.js';
import {
  Mode,
  encodeHeader,
  transportFromSecret,
  seal,
  open,
  KEY_ID_LEN,
  TOKEN_LEN,
  STATIC_PUB_LEN,
  type Header,
} from '../src/secureChannel.js';
import { x25519PublicKey, hkdfSha256, aeadEncrypt } from '../src/crypto.js';
import { Writer, Reader, bytesToHex, hexToBytes, utf8, toB64url, fromB64url } from '../src/bytes.js';

// ── paths ──
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_ROOT = path.resolve(HERE, '..');
const NOISE_SRC = path.join(CLIENT_ROOT, 'test/vectors/noise.json');
const SPAKE_SRC = path.join(CLIENT_ROOT, 'test/vectors/spake2.json');

// ── library constants reproduced verbatim (module-private in the library) ──
// Pairing identities — src/pairing.ts:34-35 (ID_CLIENT / ID_HOST).
const ID_CLIENT = utf8('FrontierLink/v1/client');
const ID_HOST = utf8('FrontierLink/v1/host');
// Transport HKDF info — src/secureChannel.ts:106.
const TRANSPORT_INFO = 'FrontierLink/transport/v1';
const EMPTY = new Uint8Array(0);

// encodeWelcome / decodeWelcome are module-private in src/pairing.ts:88-99. These
// reconstruct their EXACT bodies from the same exported Writer/Reader primitives
// (lenStr = u32-BE length prefix + utf8; see src/bytes.ts:58-73). The byte layout
// is asserted equal to a decode round-trip during validation.
function encodeWelcome(reachId: string, hostStaticPub: Uint8Array, token: Uint8Array, keyId: Uint8Array): Uint8Array {
  return new Writer().lenStr(reachId).bytes(hostStaticPub).bytes(token).bytes(keyId).finish();
}
function decodeWelcome(buf: Uint8Array): { reachId: string; hostStaticPub: Uint8Array; token: Uint8Array; keyId: Uint8Array } {
  const r = new Reader(buf);
  const reachId = r.lenStr(256);
  const hostStaticPub = r.bytes(STATIC_PUB_LEN).slice();
  const token = r.bytes(TOKEN_LEN).slice();
  const keyId = r.bytes(KEY_ID_LEN).slice();
  return { reachId, hostStaticPub, token, keyId };
}

// ── FIXED inputs (the seed of the whole file) ──
const FIX = {
  // SPAKE2 short pairing code (alphabet 23456789ABCDEFGHJKMNPQRSTUVWXYZ, 6 chars).
  code: 'A7K2MN',
  // Fixed SPAKE2 secret scalars x (client) and y (host), big-endian, both < n.
  xHex: '2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe',
  yHex: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
  // Welcome / credential payload (the four persisted credential fields).
  reachId: 'a1b2c3d4e5f6a7b8c9d0e1f203142536', // host device reachId (16 bytes hex)
  hostStaticPrivHex: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
  tokenHex: '00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100', // Noise psk0 (32B)
  keyIdHex: '0f1e2d3c4b5a69788796a5b4c3d2e1f0', // keyId / device id (16B)
  // deriveW probe passwords (first MUST equal `code` so wHex cross-checks).
  deriveWPasswords: ['A7K2MN', 'SX7K9Q', 'river-otter-galaxy-7'],
};

// Sealed-transport plaintexts: the transport KAT only needs deterministic byte
// strings. These are neutral, content-free `{t:"evt",data:…}` frames — any fixed
// bytes would do. Counters are per-direction (c2h: 0,1 ; h2c: 0,1).
const FRAME_PLAINTEXTS = {
  c2h: [
    utf8(JSON.stringify({ t: 'evt', data: { cmd: 'ping', n: 1 } })),
    utf8(JSON.stringify({ t: 'evt', data: { cmd: 'ping', n: 2 } })),
  ],
  h2c: [
    utf8(JSON.stringify({ t: 'evt', data: { ok: true, n: 1 } })),
    utf8(JSON.stringify({ t: 'evt', data: { ok: true, n: 2 } })),
  ],
};

// ── builders ──

interface FrontierRow {
  code: string;
  wHex: string;
  header_mode: string;
  headerHex: string;
  xHex: string;
  yHex: string;
  pA: string;
  pB: string;
  transcriptHash: string;
  ke: string;
  cA: string;
  cB: string;
}

function buildFrontier(): { row: FrontierRow; ke: Uint8Array; transcriptHash: Uint8Array } {
  const w = deriveW(utf8(FIX.code));
  const header: Header = { mode: Mode.Pair };
  const headerBytes = encodeHeader(header); // also the SPAKE2 aad
  const x = _test.decodeScalar(hexToBytes(FIX.xHex));
  const y = _test.decodeScalar(hexToBytes(FIX.yHex));
  const ids = { A: ID_CLIENT, B: ID_HOST, aad: headerBytes };

  const a = new Spake2('A', w, ids, x);
  const b = new Spake2('B', w, ids, y);
  const ra = a.finish(b.share);
  const rb = b.finish(a.share);

  // Self-consistency: both sides must agree before we record the row.
  assert.equal(bytesToHex(ra.transcriptHash), bytesToHex(rb.transcriptHash), 'frontier transcriptHash agrees');
  assert.equal(bytesToHex(ra.ke), bytesToHex(rb.ke), 'frontier ke agrees');
  assert.ok(verifyConfirm(ra, rb.ourConfirm) && verifyConfirm(rb, ra.ourConfirm), 'frontier confirmations verify');

  const row: FrontierRow = {
    code: FIX.code,
    wHex: bytesToHex(_test.wToBytes(w)),
    header_mode: 'pair',
    headerHex: bytesToHex(headerBytes),
    xHex: FIX.xHex,
    yHex: FIX.yHex,
    pA: bytesToHex(a.share),
    pB: bytesToHex(b.share),
    transcriptHash: bytesToHex(ra.transcriptHash),
    ke: bytesToHex(ra.ke),
    cA: bytesToHex(ra.ourConfirm),
    cB: bytesToHex(rb.ourConfirm),
  };
  return { row, ke: ra.ke, transcriptHash: ra.transcriptHash };
}

interface TransportFrame {
  dir: 'c2h' | 'h2c';
  counter: number;
  plaintextHex: string;
  frameHex: string;
}

function buildTransport(secret: Uint8Array, salt: Uint8Array): {
  secretHex: string;
  saltHex: string;
  info: string;
  kClientToHostHex: string;
  kHostToClientHex: string;
  frames: TransportFrame[];
} {
  // Mirror transportFromSecret's internal okm split to RECORD the raw direction
  // keys (CipherState.k is private), then use the library to SEAL the frames.
  const okm = hkdfSha256(secret, salt, utf8(TRANSPORT_INFO), 64);
  const kC2H = okm.slice(0, 32);
  const kH2C = okm.slice(32, 64);

  const client = transportFromSecret(secret, true, salt); // send = c2h, recv = h2c
  const host = transportFromSecret(secret, false, salt); // send = h2c, recv = c2h

  const frames: TransportFrame[] = [];
  FRAME_PLAINTEXTS.c2h.forEach((pt, counter) => {
    frames.push({ dir: 'c2h', counter, plaintextHex: bytesToHex(pt), frameHex: bytesToHex(seal(client.send, pt)) });
  });
  FRAME_PLAINTEXTS.h2c.forEach((pt, counter) => {
    frames.push({ dir: 'h2c', counter, plaintextHex: bytesToHex(pt), frameHex: bytesToHex(seal(host.send, pt)) });
  });

  return {
    secretHex: bytesToHex(secret),
    saltHex: bytesToHex(salt),
    info: TRANSPORT_INFO,
    kClientToHostHex: bytesToHex(kC2H),
    kHostToClientHex: bytesToHex(kH2C),
    frames,
  };
}

function buildWelcome(ke: Uint8Array, transcriptHash: Uint8Array) {
  const hostStaticPub = x25519PublicKey(hexToBytes(FIX.hostStaticPrivHex));
  const token = hexToBytes(FIX.tokenHex);
  const keyId = hexToBytes(FIX.keyIdHex);
  const plaintext = encodeWelcome(FIX.reachId, hostStaticPub, token, keyId);
  // Sealed by the SPAKE2-derived host→client CipherState at counter 0 (F5).
  const host = transportFromSecret(ke, false, transcriptHash); // send = host→client
  const sealed = seal(host.send, plaintext);
  return {
    reachId: FIX.reachId,
    hostStaticPubB64url: toB64url(hostStaticPub),
    tokenB64url: toB64url(token),
    keyIdB64url: toB64url(keyId),
    plaintextHex: bytesToHex(plaintext),
    sealedHex: bytesToHex(sealed),
  };
}

function buildHeaders() {
  const keyId = hexToBytes(FIX.keyIdHex);
  return [
    { mode: 'reconnect', keyIdHex: FIX.keyIdHex, hex: bytesToHex(encodeHeader({ mode: Mode.Reconnect, keyId })) },
    { mode: 'pair', hex: bytesToHex(encodeHeader({ mode: Mode.Pair })) },
  ];
}

function buildDeriveW() {
  return FIX.deriveWPasswords.map((p) => ({ passwordUtf8: p, wHex: bytesToHex(_test.wToBytes(deriveW(utf8(p)))) }));
}

function build(): Record<string, unknown> {
  const srcNoise = JSON.parse(readFileSync(NOISE_SRC, 'utf8')) as { vectors: unknown[] };
  const srcSpake = JSON.parse(readFileSync(SPAKE_SRC, 'utf8')) as { vectors: unknown[] };

  const frontier = buildFrontier();
  const transport = buildTransport(frontier.ke, frontier.transcriptHash);
  const welcome = buildWelcome(frontier.ke, frontier.transcriptHash);

  return {
    schema: 'frontier-link-v1/kat',
    version: 1,
    // Copied verbatim from test/vectors/noise.json (MUST include NKpsk0).
    noise: { patterns: srcNoise.vectors },
    // Copied verbatim from test/vectors/spake2.json (RFC 9382 App. B, no aad).
    spake2_rfc: srcSpake.vectors,
    // Frontier SPAKE2: deriveW + aad=header, fixed x/y.
    spake2_frontier: [frontier.row],
    // Transport keys + sealed frames from transportFromSecret + seal.
    transport,
    // Sealed SPAKE2 welcome (host→client @ counter 0).
    welcome,
    // Byte-exact encoding helpers.
    headers: buildHeaders(),
    deriveW: buildDeriveW(),
  };
}

// ── validation: re-derive everything from the library and compare to the file ──

type Check = { name: string; ok: boolean; detail?: string };

function validate(kat: any): { checks: Check[]; ok: boolean } {
  const checks: Check[] = [];
  const chk = (name: string, ok: boolean, detail?: string) => checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
  const tryChk = (name: string, fn: () => boolean | void) => {
    try {
      const r = fn();
      chk(name, r === undefined ? true : r);
    } catch (e) {
      chk(name, false, e instanceof Error ? e.message : String(e));
    }
  };

  // 1. schema + every §7.1 section present & non-empty.
  chk('schema/version', kat.schema === 'frontier-link-v1/kat' && kat.version === 1);
  chk('noise.patterns non-empty', Array.isArray(kat.noise?.patterns) && kat.noise.patterns.length > 0);
  chk(
    'noise includes Noise_NKpsk0_25519_ChaChaPoly_SHA256',
    Array.isArray(kat.noise?.patterns) && kat.noise.patterns.some((p: any) => p.protocol_name === 'Noise_NKpsk0_25519_ChaChaPoly_SHA256'),
  );
  chk('spake2_rfc non-empty', Array.isArray(kat.spake2_rfc) && kat.spake2_rfc.length > 0);
  chk('spake2_frontier non-empty', Array.isArray(kat.spake2_frontier) && kat.spake2_frontier.length > 0);
  chk('transport.frames non-empty', Array.isArray(kat.transport?.frames) && kat.transport.frames.length > 0);
  chk('welcome present', typeof kat.welcome?.sealedHex === 'string' && kat.welcome.sealedHex.length > 0);
  chk('headers >= 2', Array.isArray(kat.headers) && kat.headers.length >= 2);
  chk('deriveW non-empty', Array.isArray(kat.deriveW) && kat.deriveW.length > 0);

  // 2. noise.patterns / spake2_rfc byte-identical (verbatim) to the source files.
  const srcNoise = JSON.parse(readFileSync(NOISE_SRC, 'utf8'));
  const srcSpake = JSON.parse(readFileSync(SPAKE_SRC, 'utf8'));
  chk('noise.patterns == source vectors (verbatim)', JSON.stringify(kat.noise.patterns) === JSON.stringify(srcNoise.vectors));
  chk('spake2_rfc == source vectors (verbatim)', JSON.stringify(kat.spake2_rfc) === JSON.stringify(srcSpake.vectors));

  // 3. Noise engine round-trip: re-run NKpsk0 through the engine.
  tryChk('noise NKpsk0 engine reproduces every message + handshake_hash', () => {
    const v = kat.noise.patterns.find((p: any) => p.protocol_name === 'Noise_NKpsk0_25519_ChaChaPoly_SHA256');
    const hx = (s?: string) => (s === undefined ? undefined : hexToBytes(s));
    const kp = (priv?: string) => (priv === undefined ? undefined : { priv: hexToBytes(priv), pub: x25519PublicKey(hexToBytes(priv)) });
    const mk = (initiator: boolean): HandshakeState => {
      const o: any = { pattern: PATTERNS.NKpsk0, initiator };
      const pro = hx(initiator ? v.init_prologue : v.resp_prologue);
      if (pro) o.prologue = pro;
      const s = kp(initiator ? v.init_static : v.resp_static);
      if (s) o.s = s;
      const rs = hx(initiator ? v.init_remote_static : v.resp_remote_static);
      if (rs) o.rs = rs;
      const psk = hx(initiator ? v.init_psks?.[0] : v.resp_psks?.[0]);
      if (psk) o.psk = psk;
      const fe = hx(initiator ? v.init_ephemeral : v.resp_ephemeral);
      if (fe) o.fixedEphemeral = fe;
      return new HandshakeState(o);
    };
    const ini = mk(true);
    const res = mk(false);
    let iniT: Transport | undefined;
    let resT: Transport | undefined;
    for (let i = 0; i < v.messages.length; i++) {
      const m = v.messages[i];
      const payload = hexToBytes(m.payload);
      const senderIsInit = i % 2 === 0;
      let ct: Uint8Array;
      if (!iniT || !resT) {
        const w = senderIsInit ? ini.writeMessage(payload) : res.writeMessage(payload);
        ct = w.message;
        const r = senderIsInit ? res.readMessage(ct) : ini.readMessage(ct);
        if (bytesToHex(r.payload) !== m.payload) throw new Error(`msg ${i} payload mismatch`);
        if (w.transport) senderIsInit ? (iniT = w.transport) : (resT = w.transport);
        if (r.transport) senderIsInit ? (resT = r.transport) : (iniT = r.transport);
      } else {
        const sender = senderIsInit ? iniT : resT;
        const receiver = senderIsInit ? resT : iniT;
        ct = sender.send.encryptWithAd(EMPTY, payload);
        const pt = receiver.recv.decryptWithAd(EMPTY, ct);
        if (bytesToHex(pt) !== m.payload) throw new Error(`transport ${i} payload mismatch`);
      }
      if (bytesToHex(ct) !== m.ciphertext) throw new Error(`msg ${i} ciphertext mismatch`);
    }
    if (!iniT) throw new Error('handshake did not complete');
    if (bytesToHex(iniT.handshakeHash) !== v.handshake_hash) throw new Error('handshake_hash mismatch');
    return true;
  });

  // 4. SPAKE2 frontier row re-derivation.
  tryChk('spake2_frontier row[0] re-derives (pA/pB/transcriptHash/ke/cA/cB)', () => {
    const row = kat.spake2_frontier[0];
    const w = deriveW(utf8(row.code));
    if (bytesToHex(_test.wToBytes(w)) !== row.wHex) throw new Error('wHex mismatch');
    const mode = row.header_mode === 'pair' ? Mode.Pair : row.header_mode === 'recover' ? Mode.Recover : Mode.Reconnect;
    const headerBytes = encodeHeader({ mode });
    if (bytesToHex(headerBytes) !== row.headerHex) throw new Error('headerHex mismatch');
    const ids = { A: ID_CLIENT, B: ID_HOST, aad: headerBytes };
    const a = new Spake2('A', w, ids, _test.decodeScalar(hexToBytes(row.xHex)));
    const b = new Spake2('B', w, ids, _test.decodeScalar(hexToBytes(row.yHex)));
    if (bytesToHex(a.share) !== row.pA) throw new Error('pA mismatch');
    if (bytesToHex(b.share) !== row.pB) throw new Error('pB mismatch');
    const ra = a.finish(b.share);
    const rb = b.finish(a.share);
    if (bytesToHex(ra.transcriptHash) !== row.transcriptHash) throw new Error('transcriptHash mismatch');
    if (bytesToHex(ra.ke) !== row.ke) throw new Error('ke mismatch');
    if (bytesToHex(ra.ourConfirm) !== row.cA) throw new Error('cA mismatch');
    if (bytesToHex(rb.ourConfirm) !== row.cB) throw new Error('cB mismatch');
    return true;
  });

  // 5. Transport: keys, re-seal, open-inverts, tamper rejected.
  const t = kat.transport;
  const secret = hexToBytes(t.secretHex);
  const salt = hexToBytes(t.saltHex);
  tryChk('transport direction keys == HKDF(secret,salt,info)[0:32]/[32:64]', () => {
    const okm = hkdfSha256(secret, salt, utf8(t.info), 64);
    if (bytesToHex(okm.slice(0, 32)) !== t.kClientToHostHex) throw new Error('kClientToHost mismatch');
    if (bytesToHex(okm.slice(32, 64)) !== t.kHostToClientHex) throw new Error('kHostToClient mismatch');
    return true;
  });
  const c2hFrames = t.frames.filter((f: any) => f.dir === 'c2h').sort((a: any, b: any) => a.counter - b.counter);
  const h2cFrames = t.frames.filter((f: any) => f.dir === 'h2c').sort((a: any, b: any) => a.counter - b.counter);
  tryChk('transport frames re-seal to recorded frameHex', () => {
    const cSend = transportFromSecret(secret, true, salt); // send = c2h
    for (const f of c2hFrames) if (bytesToHex(seal(cSend.send, hexToBytes(f.plaintextHex))) !== f.frameHex) throw new Error(`c2h@${f.counter} reseal mismatch`);
    const hSend = transportFromSecret(secret, false, salt); // send = h2c
    for (const f of h2cFrames) if (bytesToHex(seal(hSend.send, hexToBytes(f.plaintextHex))) !== f.frameHex) throw new Error(`h2c@${f.counter} reseal mismatch`);
    return true;
  });
  tryChk('transport frames open back to plaintext', () => {
    const hRecv = transportFromSecret(secret, false, salt); // recv = c2h
    for (const f of c2hFrames) if (bytesToHex(open(hRecv.recv, hexToBytes(f.frameHex))) !== f.plaintextHex) throw new Error(`c2h@${f.counter} open mismatch`);
    const cRecv = transportFromSecret(secret, true, salt); // recv = h2c
    for (const f of h2cFrames) if (bytesToHex(open(cRecv.recv, hexToBytes(f.frameHex))) !== f.plaintextHex) throw new Error(`h2c@${f.counter} open mismatch`);
    return true;
  });
  tryChk('transport kClientToHost independently seals c2h@0 (aeadEncrypt)', () => {
    const f0 = c2hFrames[0];
    return bytesToHex(aeadEncrypt(hexToBytes(t.kClientToHostHex), 0n, EMPTY, hexToBytes(f0.plaintextHex))) === f0.frameHex;
  });
  tryChk('transport tampered frame is rejected', () => {
    const fr = hexToBytes(c2hFrames[0].frameHex);
    const last = fr.length - 1;
    fr[last] = (fr[last]! ^ 0x01) & 0xff;
    const hRecv = transportFromSecret(secret, false, salt);
    let threw = false;
    try {
      open(hRecv.recv, fr);
    } catch {
      threw = true;
    }
    return threw;
  });

  // 6. Welcome: re-seal, open, decode round-trip.
  tryChk('welcome re-seals to sealedHex (host→client @ 0) and opens + decodes', () => {
    const wc = kat.welcome;
    const reEnc = encodeWelcome(wc.reachId, fromB64url(wc.hostStaticPubB64url), fromB64url(wc.tokenB64url), fromB64url(wc.keyIdB64url));
    if (bytesToHex(reEnc) !== wc.plaintextHex) throw new Error('plaintextHex != encodeWelcome(fields)');
    const hSend = transportFromSecret(secret, false, salt); // send = host→client @ 0
    if (bytesToHex(seal(hSend.send, reEnc)) !== wc.sealedHex) throw new Error('sealedHex mismatch');
    const cRecv = transportFromSecret(secret, true, salt); // recv = host→client @ 0
    const opened = open(cRecv.recv, hexToBytes(wc.sealedHex));
    if (bytesToHex(opened) !== wc.plaintextHex) throw new Error('open(welcome) != plaintext');
    const dec = decodeWelcome(opened);
    if (dec.reachId !== wc.reachId) throw new Error('reachId mismatch');
    if (toB64url(dec.hostStaticPub) !== wc.hostStaticPubB64url) throw new Error('hostStaticPub mismatch');
    if (toB64url(dec.token) !== wc.tokenB64url) throw new Error('token mismatch');
    if (toB64url(dec.keyId) !== wc.keyIdB64url) throw new Error('keyId mismatch');
    return true;
  });

  // 7. Encoding helpers.
  tryChk('headers re-encode (encodeHeader)', () => {
    for (const h of kat.headers) {
      if (h.mode === 'reconnect') {
        if (bytesToHex(encodeHeader({ mode: Mode.Reconnect, keyId: hexToBytes(h.keyIdHex) })) !== h.hex) throw new Error('reconnect header mismatch');
      } else if (h.mode === 'pair') {
        if (bytesToHex(encodeHeader({ mode: Mode.Pair })) !== h.hex) throw new Error('pair header mismatch');
      } else {
        throw new Error(`unknown header mode ${h.mode}`);
      }
    }
    return true;
  });
  tryChk('deriveW re-derives', () => {
    for (const d of kat.deriveW) if (bytesToHex(_test.wToBytes(deriveW(utf8(d.passwordUtf8)))) !== d.wHex) throw new Error(`deriveW(${d.passwordUtf8}) mismatch`);
    return true;
  });
  // 8. Cross-links (the file is internally consistent).
  chk('transport.secretHex == spake2_frontier[0].ke', kat.transport.secretHex === kat.spake2_frontier[0].ke);
  chk('transport.saltHex == spake2_frontier[0].transcriptHash', kat.transport.saltHex === kat.spake2_frontier[0].transcriptHash);
  chk('headers[pair].hex == spake2_frontier[0].headerHex', kat.headers.find((h: any) => h.mode === 'pair')?.hex === kat.spake2_frontier[0].headerHex);
  chk('deriveW[0].wHex == spake2_frontier[0].wHex', kat.deriveW[0]?.wHex === kat.spake2_frontier[0].wHex);

  return { checks, ok: checks.every((c) => c.ok) };
}

function report(checks: Check[]): void {
  for (const c of checks) process.stderr.write(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? `  — ${c.detail}` : ''}\n`);
}

// ── main ──
function main(): void {
  const argv = process.argv.slice(2);
  if (argv[0] === '--validate') {
    const file = argv[1];
    if (!file) throw new Error('--validate needs a file path');
    const kat = JSON.parse(readFileSync(file, 'utf8'));
    process.stderr.write(`Validating ${file}\n`);
    const { checks, ok } = validate(kat);
    report(checks);
    process.stderr.write(`${ok ? 'ALL CHECKS PASSED' : 'SOME CHECKS FAILED'} (${checks.filter((c) => c.ok).length}/${checks.length})\n`);
    process.exit(ok ? 0 : 1);
  }

  const kat = build();
  const { checks, ok } = validate(kat);
  process.stderr.write('Self-validation (in-memory, against the library):\n');
  report(checks);
  process.stderr.write(`${ok ? 'ALL CHECKS PASSED' : 'SOME CHECKS FAILED'} (${checks.filter((c) => c.ok).length}/${checks.length})\n`);
  // Pure JSON on stdout so `> kat.json` yields a clean file.
  process.stdout.write(JSON.stringify(kat, null, 2) + '\n');
  if (!ok) process.exit(1);
}

main();
