// Pairing codes and links (section 5.1) and the exchange (section 5.3),
// run end to end in memory without a relay.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64u, EMPTY, fromHex, toHex, utf8 } from '../src/bytes.js';
import { hkdf, open } from '../src/crypto.js';
import {
  buildPairingLink,
  buildPairingParams,
  CROCKFORD,
  DEFAULT_CODE_ID,
  formatCode,
  generateCode,
  generateCodeId,
  normalizeCode,
  parsePairingLink,
  parsePairingParams,
} from '../src/code.js';
import { InvalidError } from '../src/errors.js';
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

test('pairing parameters: Link defines the parameters, and a link is one wrapping of them', () => {
  const network = identityFromSeed(new Uint8Array(32).fill(1)).id;
  const codeId = b64u(fromHex('0102030405060708'));
  const relay = 'wss://eu.frontierengineer.link:8443/v1?x=1&y=2';
  const parts = { network, code: '7k2m-9qxz', codeId, relay };
  const params = buildPairingParams(parts);
  assert.equal(params, `v=1&n=${network}&c=7K2M9QXZ&i=AQIDBAUGBwg&r=wss%3A%2F%2Feu.frontierengineer.link%3A8443%2Fv1%3Fx%3D1%26y%3D2`);
  assert.equal(buildPairingLink(parts), `frontier://pair?${params}`);
  const want = { network, code: '7K2M9QXZ', codeId, relay };
  assert.deepEqual(parsePairingParams(params), want);
  // As an https URL's fragment carries it, taken out again.
  assert.deepEqual(parsePairingParams(new URL(`https://frontier.link/#${params}`).hash.slice(1)), want);
  // Any order, a displayed code, parameters it does not know.
  assert.deepEqual(parsePairingParams(`r=${encodeURIComponent(relay)}&x=9&i=${codeId}&c=7k2m-9qxz&n=${network}&v=1`), want);
  const invalid = (s: string, what: RegExp) =>
    assert.throws(() => parsePairingParams(s), (e: unknown) => e instanceof InvalidError && e.code === 'invalid' && what.test(e.message), s);
  invalid(params.replace('v=1&', ''), /missing v/);
  invalid(params.replace('v=1', 'v=2'), /unknown version 2/);
  for (const [k, name] of [['n', 'network id'], ['c', 'code'], ['r', 'relay']] as const) {
    const without = params.split('&').filter((p) => !p.startsWith(`${k}=`)).join('&');
    invalid(without, new RegExp(`missing ${k} \\(the ${name}\\)`));
    invalid(params.replace(new RegExp(`${k}=[^&]*`), `${k}=`), new RegExp(`missing ${k} `));
  }
  // No `i` is the default code; an empty one is refused.
  assert.deepEqual(parsePairingParams(params.replace('&i=AQIDBAUGBwg', '')), { ...want, codeId: DEFAULT_CODE_ID });
  invalid(params.replace('i=AQIDBAUGBwg', 'i='), /empty i \(the code id\)/);
  invalid(`${params}&n=${network}`, /repeats n/);
  invalid(params.replace(`n=${network}`, 'n=nope'), /network id/);
  invalid(params.replace('i=AQIDBAUGBwg', 'i=AQID'), /code id/);
  invalid(params.replace('r=wss', 'r=https'), /ws:\/\/ or wss:\/\//);
  invalid(params.replace('c=7K2M9QXZ', 'c=7K2M9QXU'), /pairing code/);
  invalid(`${params}&bare`, /without a value/);
  invalid(params.replace('r=wss', 'r=%E0%A4%A'), /percent-encoding/);
  assert.throws(() => buildPairingParams({ ...parts, relay: '' }), InvalidError);
  assert.throws(() => buildPairingParams({ ...parts, network: 'nope' }), InvalidError);
  assert.throws(() => buildPairingParams({ ...parts, codeId: 'AQID' }), InvalidError);
  assert.throws(() => buildPairingParams({ ...parts, code: 'U' }), InvalidError);
  // The default code's parameters leave its id out, whether it is given or not.
  const defaultParams = `v=1&n=${network}&c=7K2M9QXZ&r=wss%3A%2F%2Feu.frontierengineer.link%3A8443%2Fv1%3Fx%3D1%26y%3D2`;
  assert.equal(buildPairingParams({ network, code: '7K2M9QXZ', relay }), defaultParams);
  assert.equal(buildPairingParams({ ...parts, codeId: DEFAULT_CODE_ID }), defaultParams);
  assert.equal(buildPairingLink({ network, code: '7K2M9QXZ', relay }), `frontier://pair?${defaultParams}`);
  assert.deepEqual(parsePairingLink(`frontier://pair?${defaultParams}`), { ...want, codeId: DEFAULT_CODE_ID });
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
  const { roster } = createNetwork({ identity: primary, relay: 'wss://r/v1', now: 1 });
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
