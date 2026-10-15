// Pairing codes and links (section 5.1) and the exchange (section 5.3),
// run end to end in memory without a relay.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64u, EMPTY, fromHex, toHex, utf8 } from '../src/bytes.js';
import { hkdf, open } from '../src/crypto.js';
import {
  buildPairingLink,
  CROCKFORD,
  formatCode,
  generateCode,
  generateCodeId,
  normalizeCode,
  parsePairingLink,
} from '../src/code.js';
import { identityFromSeed } from '../src/identity.js';
import { NewcomerExchange, pairTransportKeys, PrimaryExchange } from '../src/pairing.js';
import { createNetwork } from '../src/roster.js';
import { deriveW } from '../src/spake2.js';
import { P256_ORDER } from '../src/crypto.js';

test('codes are 8 Crockford characters and normalise as section 5.1 says', () => {
  for (let i = 0; i < 50; i++) {
    const c = generateCode();
    assert.equal(c.length, 8);
    for (const ch of c) assert.ok(CROCKFORD.includes(ch));
  }
  assert.equal(normalizeCode('abcd-efgh'), 'ABCDEFGH');
  assert.equal(normalizeCode('o1l1-i0OK'), '0111100K');
  assert.equal(normalizeCode(' 7K2M - 9QXZ '), '7K2M9QXZ');
  assert.equal(formatCode('7k2m9qxz'), '7K2M-9QXZ');
  assert.throws(() => normalizeCode('ABCD-EFGU'));
  assert.throws(() => normalizeCode('ABCD-EFG'));
  assert.throws(() => normalizeCode('ABCD-EFGHJ'));
  assert.equal(generateCodeId().length, 8);
});

test('w derives from the canonical code; display and input spellings agree', () => {
  const expected =
    BigInt('0x' + toHex(hkdf(utf8('7K2M9QXZ'), EMPTY, utf8('frontier-link/1/spake2/w'), 40))) % P256_ORDER;
  assert.equal(deriveW(normalizeCode('7k2m-9qxz')), expected);
});

test('pairing links build and parse', () => {
  const network = identityFromSeed(new Uint8Array(32).fill(1)).id;
  const codeId = b64u(fromHex('0102030405060708'));
  const relay = 'wss://eu.frontierengineer.link:8443/v1?x=1&y=2';
  const link = buildPairingLink({ network, code: '7k2m-9qxz', codeId, relay });
  assert.equal(
    link,
    `frontier://pair?v=1&n=${network}&c=7K2M9QXZ&i=AQIDBAUGBwg&r=wss%3A%2F%2Feu.frontierengineer.link%3A8443%2Fv1%3Fx%3D1%26y%3D2`,
  );
  assert.deepEqual(parsePairingLink(link), { network, code: '7K2M9QXZ', codeId, relay });
  // A hyphenated, lower-case code in a hand-written link still parses.
  assert.equal(parsePairingLink(link.replace('7K2M9QXZ', '7k2m-9qxz')).code, '7K2M9QXZ');
  assert.throws(() => parsePairingLink(link.replace('v=1', 'v=2')));
  assert.throws(() => parsePairingLink(link.replace(`n=${network}`, 'n=nope')));
  assert.throws(() => parsePairingLink(link.replace('i=AQIDBAUGBwg', 'i=AQID')));
  assert.throws(() => parsePairingLink(link.replace('r=wss', 'r=https')));
  assert.throws(() => parsePairingLink('https://pair?v=1'));
});

test('the exchange: P1..P6 between newcomer and primary', () => {
  const primary = identityFromSeed(new Uint8Array(32).fill(1));
  const me = identityFromSeed(new Uint8Array(32).fill(9));
  const codeId = generateCodeId();
  const a = new NewcomerExchange('7K2M9QXZ', codeId);
  const b = new PrimaryExchange('7K2M9QXZ', codeId);
  const p2 = b.onP1(a.p1());
  assert.equal(p2.length, 65);
  const p3 = a.onP2(p2);
  assert.equal(p3.length, 32);
  assert.ok(b.onP3(p3));
  const p4 = b.p4();
  const p5 = a.onP4(p4, { ed25519: me.ed25519.pub, x25519: me.x25519.pub });
  const keys = b.onP5(p5);
  assert.deepEqual(keys.ed25519, me.ed25519.pub);
  assert.deepEqual(keys.x25519, me.x25519.pub);
  const roster = createNetwork({ identity: primary, relay: 'wss://r/v1', now: 1 });
  assert.deepEqual(a.onP6(b.p6(roster)), roster);

  // P5 is sealed with okm[0..32], counter 0.
  const t = pairTransportKeys(a.spakeKeys!);
  const plain = open(t.toPrimary, 0n, EMPTY, p5);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(plain)), { ed25519: b64u(me.ed25519.pub), x25519: b64u(me.x25519.pub) });
});

test('the exchange fails on a wrong code, a different code id, or a forged cB', () => {
  const codeId = generateCodeId();
  const wrong = () => {
    const a = new NewcomerExchange('7K2M9QXZ', codeId);
    const b = new PrimaryExchange('7K2M9QXY', codeId);
    return b.onP3(a.onP2(b.onP1(a.p1())));
  };
  assert.equal(wrong(), false);
  const otherId = () => {
    const a = new NewcomerExchange('7K2M9QXZ', codeId);
    const b = new PrimaryExchange('7K2M9QXZ', generateCodeId());
    return b.onP3(a.onP2(b.onP1(a.p1())));
  };
  assert.equal(otherId(), false);
  const a = new NewcomerExchange('7K2M9QXZ', codeId);
  const b = new PrimaryExchange('7K2M9QXZ', codeId);
  a.onP2(b.onP1(a.p1()));
  const me = identityFromSeed(new Uint8Array(32).fill(9));
  assert.throws(() => a.onP4(new Uint8Array(32), { ed25519: me.ed25519.pub, x25519: me.x25519.pub }), /did not prove/);
});
