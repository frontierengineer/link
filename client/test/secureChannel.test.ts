// secureChannel: prove the Noise engine byte-for-byte against the published
// cacophony vectors, then exercise the live reconnect handshake (NKpsk0) and
// the sealed transport's rejection of tamper / replay / reorder.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { HandshakeState, PATTERNS, type Transport } from '../src/noise.js';
import { x25519PublicKey, x25519Keygen, type KeyPair } from '../src/crypto.js';
import {
  reconnectInitiator,
  reconnectResponder,
  decodeHeader,
  transportFromSecret,
  seal,
  open,
  SealedError,
  Mode,
} from '../src/secureChannel.js';
import { memoryPipePair, type Pipe } from '../src/pipe.js';
import { bytesToHex, hexToBytes, randomBytes, utf8 } from '../src/bytes.js';

interface NoiseVector {
  protocol_name: string;
  init_prologue?: string;
  resp_prologue?: string;
  init_psks?: string[];
  resp_psks?: string[];
  init_static?: string;
  resp_static?: string;
  init_ephemeral?: string;
  resp_ephemeral?: string;
  init_remote_static?: string;
  resp_remote_static?: string;
  handshake_hash: string;
  messages: { payload: string; ciphertext: string }[];
}

const vectors: { vectors: NoiseVector[] } = JSON.parse(
  readFileSync(new URL('./vectors/noise.json', import.meta.url), 'utf8'),
);

const hx = (s?: string): Uint8Array | undefined => (s === undefined ? undefined : hexToBytes(s));
const keypairOf = (priv?: string): KeyPair | undefined =>
  priv === undefined ? undefined : { priv: hexToBytes(priv), pub: x25519PublicKey(hexToBytes(priv)) };

// One KAT per pattern: replay every message (handshake + transport), asserting
// byte-equality of each ciphertext and the final handshake hash. This is what
// makes "we built Noise correctly" checkable rather than asserted.
for (const v of vectors.vectors) {
  test(`Noise KAT: ${v.protocol_name}`, () => {
    const patternName = v.protocol_name.split('_')[1]!;
    const pattern = PATTERNS[patternName];
    assert.ok(pattern, `pattern ${patternName} known to the engine`);

    const mk = (initiator: boolean): HandshakeState => {
      const opts: ConstructorParameters<typeof HandshakeState>[0] = {
        pattern,
        initiator,
      };
      const prologue = hx(initiator ? v.init_prologue : v.resp_prologue);
      if (prologue) opts.prologue = prologue;
      const s = keypairOf(initiator ? v.init_static : v.resp_static);
      if (s) opts.s = s;
      const rs = hx(initiator ? v.init_remote_static : v.resp_remote_static);
      if (rs) opts.rs = rs;
      const psk = hx(initiator ? v.init_psks?.[0] : v.resp_psks?.[0]);
      if (psk) opts.psk = psk;
      const fixed = hx(initiator ? v.init_ephemeral : v.resp_ephemeral);
      if (fixed) opts.fixedEphemeral = fixed;
      return new HandshakeState(opts);
    };

    const ini = mk(true);
    const res = mk(false);
    let iniT: Transport | undefined;
    let resT: Transport | undefined;

    for (let i = 0; i < v.messages.length; i++) {
      const m = v.messages[i]!;
      const payload = hexToBytes(m.payload);
      const senderIsInitiator = i % 2 === 0;
      let ciphertext: Uint8Array;
      if (!iniT || !resT) {
        const w = senderIsInitiator ? ini.writeMessage(payload) : res.writeMessage(payload);
        ciphertext = w.message;
        const r = senderIsInitiator ? res.readMessage(ciphertext) : ini.readMessage(ciphertext);
        assert.equal(bytesToHex(r.payload), m.payload, `msg ${i} payload decrypts`);
        if (w.transport) senderIsInitiator ? (iniT = w.transport) : (resT = w.transport);
        if (r.transport) senderIsInitiator ? (resT = r.transport) : (iniT = r.transport);
      } else {
        const sender = senderIsInitiator ? iniT : resT;
        const receiver = senderIsInitiator ? resT : iniT;
        ciphertext = sender.send.encryptWithAd(new Uint8Array(0), payload);
        const pt = receiver.recv.decryptWithAd(new Uint8Array(0), ciphertext);
        assert.equal(bytesToHex(pt), m.payload, `transport ${i} decrypts`);
      }
      assert.equal(bytesToHex(ciphertext), m.ciphertext, `msg ${i} ciphertext matches vector`);
    }
    assert.ok(iniT, 'handshake completed');
    assert.equal(bytesToHex(iniT.handshakeHash), v.handshake_hash, 'handshake hash matches vector');
  });
}

// Drive both ends of the NKpsk0 reconnect over an in-memory pipe pair. The host
// reads the header frame first (as serveHost does) then runs the responder.
async function runReconnect(
  client: Pipe,
  host: Pipe,
  clientOpts: { hostStaticPub: Uint8Array; token: Uint8Array; keyId: Uint8Array },
  hostStatic: KeyPair,
  resolveToken: (keyId: Uint8Array) => Uint8Array | undefined,
): Promise<[Transport, Transport]> {
  const hostSide = (async (): Promise<Transport> => {
    const header = decodeHeader(await host.recv(2000));
    const { transport } = await reconnectResponder(host, header, { hostStatic, resolveToken, handshakeTimeoutMs: 2000 });
    return transport;
  })();
  const clientSide = reconnectInitiator(client, { ...clientOpts, handshakeTimeoutMs: 2000 });
  return Promise.all([clientSide, hostSide]);
}

test('reconnect (NKpsk0): round-trips and seals the transport', async () => {
  const [c, h] = memoryPipePair();
  const hostStatic = x25519Keygen();
  const token = randomBytes(32);
  const keyId = randomBytes(16);
  const [clientT, hostT] = await runReconnect(
    c,
    h,
    { hostStaticPub: hostStatic.pub, token, keyId },
    hostStatic,
    () => token,
  );
  // sealed both ways
  const a = seal(clientT.send, utf8('ping'));
  assert.equal(Buffer.from(open(hostT.recv, a)).toString(), 'ping');
  const b = seal(hostT.send, utf8('pong'));
  assert.equal(Buffer.from(open(clientT.recv, b)).toString(), 'pong');
});

test('reconnect: a substituted host static key fails the handshake', async () => {
  const [c, h] = memoryPipePair();
  const hostStatic = x25519Keygen();
  const attackerKey = x25519Keygen(); // client pins the WRONG key
  const token = randomBytes(32);
  const keyId = randomBytes(16);
  await assert.rejects(
    runReconnect(c, h, { hostStaticPub: attackerKey.pub, token, keyId }, hostStatic, () => token),
    'handshake must reject when the pinned key is not the host key',
  );
});

test('reconnect: a wrong device token fails the handshake', async () => {
  const [c, h] = memoryPipePair();
  const hostStatic = x25519Keygen();
  const keyId = randomBytes(16);
  const clientToken = randomBytes(32);
  const hostToken = randomBytes(32); // different secret
  await assert.rejects(
    runReconnect(c, h, { hostStaticPub: hostStatic.pub, token: clientToken, keyId }, hostStatic, () => hostToken),
    'handshake must reject when the token (PSK) is wrong',
  );
});

test('reconnect: an unknown/revoked keyId is refused immediately', async () => {
  const [c, h] = memoryPipePair();
  const hostStatic = x25519Keygen();
  await assert.rejects(
    runReconnect(c, h, { hostStaticPub: hostStatic.pub, token: randomBytes(32), keyId: randomBytes(16) }, hostStatic, () => undefined),
    /unknown or revoked/,
  );
});

// The sealed-transport guarantees, tested directly on a matched key pair.
function matchedTransports(): [Transport, Transport] {
  const secret = randomBytes(32);
  const salt = randomBytes(32);
  return [transportFromSecret(secret, true, salt), transportFromSecret(secret, false, salt)];
}

test('sealed transport: tampered ciphertext is rejected', () => {
  const [client, host] = matchedTransports();
  const frame = seal(client.send, utf8('secret payload'));
  const last = frame.length - 1;
  frame[last] = ((frame[last] ?? 0) ^ 0x01) & 0xff; // flip a tag bit
  assert.throws(() => open(host.recv, frame), SealedError);
});

test('sealed transport: a replayed frame is rejected', () => {
  const [client, host] = matchedTransports();
  const f0 = seal(client.send, utf8('frame-0'));
  const f0copy = f0.slice();
  assert.equal(Buffer.from(open(host.recv, f0)).toString(), 'frame-0');
  // Replaying f0 now fails: the receiver's counter has advanced past nonce 0.
  assert.throws(() => open(host.recv, f0copy), SealedError);
});

test('sealed transport: a reordered frame is rejected', () => {
  const [client, host] = matchedTransports();
  const f0 = seal(client.send, utf8('frame-0'));
  const f1 = seal(client.send, utf8('frame-1'));
  void f0;
  // Delivering frame 1 before frame 0 fails: it was sealed under nonce 1 but the
  // receiver expects nonce 0.
  assert.throws(() => open(host.recv, f1), SealedError);
});

test('sealed transport: no-plaintext — every frame is authenticated ciphertext', () => {
  const [client] = matchedTransports();
  const plaintext = utf8('the quick brown fox');
  const frame = seal(client.send, plaintext);
  assert.notEqual(bytesToHex(frame), bytesToHex(plaintext), 'frame is not the plaintext');
  assert.equal(frame.length, plaintext.length + 16, 'frame carries a 16-byte AEAD tag');
});
