// The binary envelope: JSON meta + a raw-bytes payload in the sealed plaintext.
//
// Three things are worth holding still here, and only one of them is the happy
// path.
//
//   1. THE WIRE, byte for byte. The native iOS/Android shells hand-port this
//      framing, so the test asserts the actual bytes — version, big-endian meta
//      length, meta, payload — rather than only that a roundtrip survives. A
//      roundtrip passes just as happily against a wire nobody else can read.
//
//   2. NEGOTIATION IS ONE-DIRECTIONAL. Reading both forms is unconditional;
//      SENDING the framed form is allowed only after the peer announced it can
//      read it. Get that backwards and a peer that predates the envelope takes
//      an unparseable plaintext, which is fatal to its session — so the test
//      that a legacy peer is never sent a framed frame matters more than the
//      test that two new peers negotiate.
//
//   3. THE PAYLOAD IS BYTES, unchanged. Any value: a zero byte, a 0xFF, a
//      sequence that is not valid UTF-8 at all. That is the whole point — if
//      the payload had to survive a UTF-8 round trip it would be base64 again.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  ENVELOPE_VERSION,
  frameSealedPlaintext,
  parseSealedPlaintext,
  SealedError,
  SecureSession,
  open,
  seal,
  transportFromSecret,
} from '../src/secureChannel.js';
import { memoryPipePair } from '../src/pipe.js';
import { randomBytes, utf8 } from '../src/bytes.js';

// ── 1. The wire ──────────────────────────────────────────────────────────────

test('the framed plaintext is version, BE meta length, meta, then payload', () => {
  const meta = '{"t":"evt"}';
  const payload = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
  const framed = frameSealedPlaintext(meta, payload);

  assert.equal(framed[0], ENVELOPE_VERSION, 'first byte is the version');
  assert.equal(framed[0], 0x01, 'and that version is 0x01 — pinned, the shells port it');
  // Big-endian, four bytes. meta is 11 ASCII bytes.
  assert.deepEqual([...framed.slice(1, 5)], [0, 0, 0, 11], 'meta length is big-endian u32');
  assert.equal(Buffer.from(framed.slice(5, 16)).toString('utf8'), meta);
  assert.deepEqual([...framed.slice(16)], [0xde, 0xad, 0xbe, 0xef], 'payload follows, raw');
  assert.equal(framed.length, 5 + 11 + 4, 'and nothing else is on the wire');
});

test('a framed plaintext is distinguishable from a legacy one by its first byte', () => {
  const framed = frameSealedPlaintext('{"t":"evt"}', new Uint8Array(0));
  const legacy = utf8('{"t":"evt"}');
  assert.equal(framed[0], 0x01);
  assert.equal(legacy[0], 0x7b, "legacy plaintext starts with '{'");
  assert.notEqual(framed[0], legacy[0], 'so one comparison tells them apart, with no state');
  assert.equal(parseSealedPlaintext(legacy), null, 'and the parser reports legacy rather than guessing');
});

test('the payload length is implicit, so an empty payload is the ordinary case', () => {
  const framed = frameSealedPlaintext('{"t":"evt"}', new Uint8Array(0));
  const parsed = parseSealedPlaintext(framed);
  assert.ok(parsed);
  assert.equal(parsed.meta, '{"t":"evt"}');
  assert.equal(parsed.payload.length, 0, 'no payload, and no second length that could disagree');
});

test('a payload is arbitrary bytes, including ones no UTF-8 round trip survives', () => {
  // 0xC3 0x28 is invalid UTF-8; a lone 0xFF is not a valid code unit either.
  const payload = Uint8Array.of(0x00, 0xff, 0xc3, 0x28, 0x80, 0x7f);
  const parsed = parseSealedPlaintext(frameSealedPlaintext('{"t":"evt"}', payload));
  assert.ok(parsed);
  assert.deepEqual([...parsed.payload], [...payload]);
});

/** A big, non-repeating buffer. Not randomBytes: that is capped at 64 KiB, and a
 *  deterministic fill makes a byte-identity failure reproducible. */
function bulk(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + (i >> 8)) & 0xff;
  return b;
}

test('a large payload survives intact (the case the envelope exists for)', () => {
  const payload = bulk(256 * 1024);
  const parsed = parseSealedPlaintext(frameSealedPlaintext('{"t":"evt","seq":0}', payload));
  assert.ok(parsed);
  assert.equal(parsed.payload.length, payload.length);
  assert.ok(Buffer.from(parsed.payload).equals(Buffer.from(payload)), 'byte-identical');
});

test('a meta length that runs past the plaintext is refused, not read short', () => {
  const framed = frameSealedPlaintext('{"t":"evt"}', new Uint8Array(0));
  // Claim a meta far longer than the frame. The AEAD already proved these bytes
  // are authentic, so this can only be a peer that built a bad frame.
  framed[1] = 0xff;
  assert.throws(() => parseSealedPlaintext(framed), SealedError);
});

test('a framed plaintext too short for its own header is refused', () => {
  assert.throws(() => parseSealedPlaintext(Uint8Array.of(ENVELOPE_VERSION, 0, 0)), SealedError);
});

// ── 2 + 3. Negotiation and delivery, over two live sessions ─────────────────

function sessionPair(): { a: SecureSession; b: SecureSession } {
  const secret = randomBytes(32);
  const salt = randomBytes(32);
  const [pa, pb] = memoryPipePair();
  return {
    a: new SecureSession(pa, transportFromSecret(secret, true, salt)),
    b: new SecureSession(pb, transportFromSecret(secret, false, salt)),
  };
}

/** Give the sessions a turn of the event loop to exchange their capability hellos. */
const settle = () => new Promise((r) => setTimeout(r, 20));

test('two current peers negotiate, then bulk rides as raw bytes', async () => {
  const { a, b } = sessionPair();
  try {
    assert.equal(a.supportsPayload, false, 'nothing is assumed before the peer speaks');
    await settle();
    assert.equal(a.supportsPayload, true, 'the hello is the first thing a session sends');
    assert.equal(b.supportsPayload, true);

    const audio = bulk(64 * 1024);
    const got = new Promise<{ data: unknown; payload: Uint8Array | undefined }>((resolve) => {
      b.onMessage((data, payload) => resolve({ data, payload }));
    });
    a.sendWithPayload({ type: 'stream_chunk', seq: 0 }, audio);

    const received = await got;
    assert.deepEqual(received.data, { type: 'stream_chunk', seq: 0 });
    assert.ok(received.payload, 'the payload arrived beside the meta');
    assert.ok(Buffer.from(received.payload).equals(Buffer.from(audio)), 'byte-identical, never base64');
  } finally {
    a.close();
    b.close();
  }
});

test('an ordinary send carries no payload, so existing listeners see exactly what they did', async () => {
  const { a, b } = sessionPair();
  try {
    await settle();
    const got = new Promise<{ data: unknown; payload: Uint8Array | undefined }>((resolve) => {
      b.onMessage((data, payload) => resolve({ data, payload }));
    });
    a.send({ hello: 'world' });
    const received = await got;
    assert.deepEqual(received.data, { hello: 'world' });
    assert.equal(received.payload, undefined, 'undefined, not an empty array');
  } finally {
    a.close();
    b.close();
  }
});

test('a payload send to a peer that never announced support throws rather than base64-ing', async () => {
  const { a, b } = sessionPair();
  try {
    // Do NOT settle: `a` has not yet seen b's hello, which is exactly the state
    // a legacy peer leaves it in permanently.
    assert.equal(a.supportsPayload, false);
    assert.throws(() => a.sendWithPayload({ t: 'x' }, Uint8Array.of(1, 2, 3)), SealedError);
  } finally {
    a.close();
    b.close();
  }
});

test('a request/response still round-trips once framing is on', async () => {
  const secret = randomBytes(32);
  const salt = randomBytes(32);
  const [pa, pb] = memoryPipePair();
  const a = new SecureSession(pa, transportFromSecret(secret, true, salt));
  const b = new SecureSession(pb, transportFromSecret(secret, false, salt), {
    onRequest: (cmd) => ({ echoed: cmd }),
  });
  try {
    await settle();
    assert.equal(a.supportsPayload, true, 'framing is on for this exchange');
    assert.deepEqual(await a.request({ ping: 1 }), { echoed: { ping: 1 } });
  } finally {
    a.close();
    b.close();
  }
});

test('the capability hello is never delivered to the application', async () => {
  const { a, b } = sessionPair();
  const seen: unknown[] = [];
  try {
    b.onMessage((data) => seen.push(data));
    await settle();
    a.send({ real: 'event' });
    await settle();
    assert.deepEqual(seen, [{ real: 'event' }], 'the hello is the session\'s business, not the app\'s');
  } finally {
    a.close();
    b.close();
  }
});

// ── The compatibility direction, which is the one that can break a live peer ──
//
// A peer built before the envelope has no capability hello and one parser:
// JSON.parse over the whole plaintext. It is simulated here rather than
// described, because "we never send it something it cannot read" is the claim
// that matters and it is only worth as much as its test.

test('a legacy peer is never sent a framed frame, and is understood in both directions', async () => {
  const secret = randomBytes(32);
  const salt = randomBytes(32);
  const [pNew, pLegacy] = memoryPipePair();
  // The real session is the INITIATOR side of the transport pair.
  const session = new SecureSession(pNew, transportFromSecret(secret, true, salt));
  const legacy = transportFromSecret(secret, false, salt);

  const seenByLegacy: unknown[] = [];
  const seenBySession: unknown[] = [];
  session.onMessage((data) => seenBySession.push(data));

  // The legacy peer's whole read path: open, then JSON.parse. No version byte,
  // no framing, no idea any of it exists.
  const readLegacy = (async () => {
    for (;;) {
      let frame: Uint8Array;
      try { frame = await pLegacy.recv(); } catch { return; }
      const plain = open(legacy.recv, frame);
      // If we ever sent this peer a framed plaintext, THIS is where it dies —
      // 0x01 is not JSON, and an unparseable plaintext is fatal to a session.
      seenByLegacy.push(JSON.parse(Buffer.from(plain).toString('utf8')));
    }
  })();

  try {
    // Everything the session sends, across the kinds of frame it can send.
    session.send({ first: true });
    await settle();
    session.send({ second: true });
    await settle();

    assert.equal(session.supportsPayload, false, 'a peer that never announced stays un-upgraded, forever');
    assert.throws(
      () => session.sendWithPayload({ t: 'x' }, Uint8Array.of(1)),
      SealedError,
      'and a payload send refuses rather than sending bytes it cannot read',
    );

    // The legacy peer parsed every frame, including the capability hello it does
    // not understand (an unknown envelope type has always been ignored).
    assert.ok(seenByLegacy.length >= 3, `legacy peer read every frame (${seenByLegacy.length})`);
    assert.deepEqual(seenByLegacy[0], { t: 'cap', env: [ENVELOPE_VERSION] }, 'the hello is legacy JSON, by construction');
    assert.deepEqual(seenByLegacy[1], { t: 'evt', data: { first: true } });
    assert.deepEqual(seenByLegacy[2], { t: 'evt', data: { second: true } });

    // And the other direction: the legacy peer's plain JSON is still understood.
    pLegacy.send(seal(legacy.send, utf8(JSON.stringify({ t: 'evt', data: { fromLegacy: true } }))));
    await settle();
    assert.deepEqual(seenBySession, [{ fromLegacy: true }]);
  } finally {
    session.close();
    pLegacy.close('done');
    await readLegacy;
  }
});
