// Encodings: b64u, b32, JCS (RFC 8785), frames and session messages.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b32, b64u, fromB32, fromB64u, fromHex, lenStr, toHex, u64be } from '../src/bytes.js';
import { canonicalize } from '../src/jcs.js';
import {
  dataBody,
  decodeFrame,
  decodeSessionMessage,
  encodeFrame,
  encodeSessionMessage,
  FrameType,
  handshakeInitBody,
  handshakeRespBody,
  MAX_FRAME,
  parseData,
  parseHandshakeInit,
  parseHandshakeResp,
} from '../src/frames.js';

test('b64u is RFC 4648 base64url without padding, strict on decode', () => {
  const cases: [string, string][] = [
    ['', ''],
    ['66', 'Zg'],
    ['666f', 'Zm8'],
    ['666f6f', 'Zm9v'],
    ['fbff', '-_8'],
  ];
  for (const [hex, enc] of cases) {
    assert.equal(b64u(fromHex(hex)), enc);
    assert.equal(toHex(fromB64u(enc)), hex);
  }
  assert.throws(() => fromB64u('Zg=='));
  assert.throws(() => fromB64u('Zh')); // non-zero trailing bits
  assert.throws(() => fromB64u('Z'));
  assert.throws(() => fromB64u('Zm9+'));
});

test('b32 is RFC 4648 base32, lowercase, without padding', () => {
  // RFC 4648 section 10 vectors, lowercased and unpadded.
  const cases: [string, string][] = [
    ['', ''],
    ['f', 'my'],
    ['fo', 'mzxq'],
    ['foo', 'mzxw6'],
    ['foob', 'mzxw6yq'],
    ['fooba', 'mzxw6ytb'],
    ['foobar', 'mzxw6ytboi'],
  ];
  for (const [plain, enc] of cases) {
    const bytes = new TextEncoder().encode(plain);
    assert.equal(b32(bytes), enc);
    assert.deepEqual(fromB32(enc), bytes);
  }
  assert.equal(b32(new Uint8Array(16)).length, 26);
  assert.throws(() => fromB32('MY'));
  assert.throws(() => fromB32('mz')); // non-zero trailing bits
});

test('lenStr and u64be', () => {
  assert.equal(toHex(lenStr('ab')), '000000026162');
  assert.equal(toHex(lenStr('é')), '00000002c3a9');
  assert.equal(toHex(u64be(1790000000000)), '000001a0c4506c00');
});

test('JCS: RFC 8785 section 3.2.2 example', () => {
  const input = JSON.parse(
    '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],' +
      '"string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",' +
      '"literals": [null, true, false]}',
  );
  assert.equal(
    canonicalize(input),
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
  );
});

test('JCS: RFC 8785 section 3.2.3 sorting by UTF-16 code units', () => {
  const input = JSON.parse(
    '{"\\u20ac": "Euro Sign", "\\r": "Carriage Return", "\\ufb33": "Hebrew Letter Dalet With Dagesh",' +
      '"1": "One", "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control",' +
      '"\\u00f6": "Latin Small Letter O With Diaeresis"}',
  );
  // Object.keys would move "1" first; read the member order from the text.
  const keys = [...canonicalize(input).matchAll(/"([^"]*)":"/g)].map((m) => JSON.parse(`"${m[1]}"`) as string);
  assert.deepEqual(keys, ['\r', '1', '\u0080', 'ö', '€', '😀', 'דּ']);
});

test('JCS: numbers follow ECMAScript Number::toString (RFC 8785 Appendix B samples)', () => {
  const samples: [number, string][] = [
    [0, '0'],
    [-0, '0'],
    [5e-324, '5e-324'],
    [-5e-324, '-5e-324'],
    [1.7976931348623157e308, '1.7976931348623157e+308'],
    [9007199254740992, '9007199254740992'],
    [-9007199254740992, '-9007199254740992'],
    [295147905179352830000, '295147905179352830000'],
    [1e21, '1e+21'],
    [1e-7, '1e-7'],
    [0.000001, '0.000001'],
    [1790000000000, '1790000000000'],
  ];
  for (const [n, s] of samples) assert.equal(canonicalize(n), s);
  assert.throws(() => canonicalize(NaN));
  assert.throws(() => canonicalize(Infinity));
});

test('JCS: nesting, empty containers and refusals', () => {
  assert.equal(canonicalize({ b: [], a: {}, c: [{ z: 1, y: 'x' }] }), '{"a":{},"b":[],"c":[{"y":"x","z":1}]}');
  assert.throws(() => canonicalize({ a: undefined }));
  assert.throws(() => canonicalize('\ud800'));
  assert.throws(() => canonicalize({ '\udc00': 1 }));
  assert.throws(() => canonicalize(new Date(0)));
  assert.throws(() => canonicalize(1n as unknown));
});

test('frames: layout, limits and every type', () => {
  const peer = fromHex('00112233445566778899aabbccddeeff');
  const f = encodeFrame(FrameType.Data, peer, dataBody(7, fromHex('cafe')));
  assert.equal(toHex(f), '0103' + '00112233445566778899aabbccddeeff' + '00000007' + 'cafe');
  const d = decodeFrame(f);
  assert.equal(d.type, FrameType.Data);
  assert.deepEqual(d.peer, peer);
  assert.deepEqual(parseData(d.body), { receiverIndex: 7, ciphertext: fromHex('cafe') });

  const init = parseHandshakeInit(handshakeInitBody(0xdeadbeef, fromHex('01')));
  assert.equal(init.senderIndex, 0xdeadbeef);
  const resp = parseHandshakeResp(handshakeRespBody(1, 2, fromHex('02')));
  assert.equal(resp.senderIndex, 1);
  assert.equal(resp.receiverIndex, 2);
  assert.deepEqual(resp.noise, fromHex('02'));

  assert.equal(encodeFrame(FrameType.Unreachable, peer, new Uint8Array(0)).length, 18);
  assert.equal(toHex(encodeFrame(FrameType.Refused, peer, Uint8Array.of(1))).slice(0, 4), '0105');
  assert.equal(encodeFrame(FrameType.Pair, peer, new Uint8Array(MAX_FRAME - 18)).length, MAX_FRAME);
  assert.equal(toHex(encodeFrame(FrameType.Reset, peer, fromHex('0badcafe'))), '0107' + toHex(peer) + '0badcafe');
  assert.throws(() => encodeFrame(FrameType.Pair, peer, new Uint8Array(MAX_FRAME - 17)));
  assert.throws(() => decodeFrame(new Uint8Array(17)));
  assert.throws(() => decodeFrame(Uint8Array.of(2, 3, ...peer)));
  assert.throws(() => encodeFrame(FrameType.Data, peer.subarray(1), new Uint8Array(0)));
});

test('session messages: every type round-trips and malformed ones are refused', () => {
  const cases = [
    { type: 'message', more: true, bytes: fromHex('0102') },
    { type: 'message', more: false, bytes: new Uint8Array(0) },
    { type: 'credit', bytes: 1048576 },
    { type: 'roster-request' },
    { type: 'roster', json: '{"a":1}' },
    { type: 'resign', json: '{"node":"x"}' },
  ] as const;
  const hex = ['01010102', '0100', '0200100000', '03', '047b2261223a317d', '057b226e6f6465223a2278227d'];
  cases.forEach((c, i) => {
    const enc = encodeSessionMessage(c);
    assert.equal(toHex(enc), hex[i]);
    assert.deepEqual(decodeSessionMessage(enc), c);
  });
  assert.throws(() => decodeSessionMessage(new Uint8Array(0)));
  assert.throws(() => decodeSessionMessage(Uint8Array.of(1)));
  assert.throws(() => decodeSessionMessage(Uint8Array.of(2, 0, 0)));
  assert.throws(() => decodeSessionMessage(Uint8Array.of(3, 0)));
  assert.throws(() => decodeSessionMessage(Uint8Array.of(9)));
  assert.throws(() => encodeSessionMessage({ type: 'credit', bytes: 2 ** 32 }));
});
