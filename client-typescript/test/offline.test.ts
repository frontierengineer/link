// A member must never crash for want of a network: with its relay unreachable (connection
// refused, a name that does not resolve, an address with no route), with its relay going away
// mid-session, and on a roster with no relay yet, it keeps running and says so through its
// states, events and the errors of the calls made on it, retrying where it retries.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import {
  createIdentity,
  createNetwork,
  LinkError,
  Member,
  memberFromIdentity,
  pair,
  Primary,
  type MemberState,
  type Roster,
  type WebSocketConstructor,
} from '../src/index.js';
import { FAST as FAST_RECONNECT, bytesOf, inbox, textOf, until } from './support/network.js';

/** Fast reconnects, and a send to a peer it cannot reach given up in a second, not ten. */
const FAST = { ...FAST_RECONNECT, handshakeTimeoutMs: 1000 };
import { TestRelay } from './support/relay.js';

/** Fails the test on any uncaught exception or unhandled rejection while `body` runs. */
async function noCrash(body: () => Promise<void>): Promise<void> {
  const crashes: unknown[] = [];
  const onCrash = (e: unknown) => crashes.push(e);
  process.on('uncaughtException', onCrash);
  process.on('unhandledRejection', onCrash);
  try {
    await body();
    // Whatever a socket or a timer would throw comes a moment later.
    await new Promise((r) => setTimeout(r, 200));
  } finally {
    process.off('uncaughtException', onCrash);
    process.off('unhandledRejection', onCrash);
  }
  assert.deepEqual(crashes, [], 'nothing thrown out of a callback, no rejection left unhandled');
}

/** A loopback port nothing listens on: connections to it are refused. */
async function refusedPort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const port = (s.address() as { port: number }).port;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

function network(relay: string): { primary: ReturnType<typeof createIdentity>; member: ReturnType<typeof createIdentity>; roster: Roster; networkSeed: Uint8Array } {
  const primary = createIdentity();
  const member = createIdentity();
  const { roster, networkSeed } = createNetwork({ identity: primary, relay, members: [memberFromIdentity(member)] });
  return { primary, member, roster, networkSeed };
}

function watch(m: Member): MemberState[] {
  const states: MemberState[] = [];
  m.on('state', (s) => states.push(s));
  return states;
}

const unreachable: [string, () => Promise<string>][] = [
  ['connection refused', async () => `ws://127.0.0.1:${await refusedPort()}/v1`],
  ['a name that does not resolve', async () => 'ws://link-relay.invalid/v1'],
  ['an address with no route', async () => 'ws://192.0.2.1:9/v1'],
];

for (const [what, url] of unreachable) {
  test(`the relay unreachable (${what}): a primary and a member keep running, retry, and fail calls with their errors`, () =>
    noCrash(async () => {
      const n = network(await url());
      const primary = new Primary({ identity: n.primary, roster: n.roster, networkSeed: n.networkSeed, timing: FAST });
      const member = new Member({ identity: n.member, roster: n.roster, timing: FAST });
      const states = watch(member);
      try {
        await assert.rejects(member.waitConnected(1500), (e: unknown) => e instanceof LinkError && e.code === 'timeout');
        await assert.rejects(primary.waitConnected(100), (e: unknown) => e instanceof LinkError && e.code === 'timeout');
        if (what !== 'an address with no route') {
          // It retries: dials again after each failure (an address with no route may hang in one dial).
          await until(() => states.filter((s) => s === 'connecting').length >= 2, 'a second dial');
        }
        assert.ok(['connecting', 'disconnected'].includes(member.state), member.state);
        await assert.rejects(member.send(n.primary.id, bytesOf('x')), LinkError);
        await assert.rejects(primary.usage(), LinkError);
        // What needs no relay still works.
        assert.match(primary.openPairingCode().code, /^[0-9A-Z]{4}-[0-9A-Z]{4}$/);
      } finally {
        member.close();
        primary.close();
      }
      assert.equal(member.state, 'closed');
    }));
}

test('the relay going away mid-session: members say disconnected, calls fail with their errors, and they reconnect when it is back', () =>
  noCrash(async () => {
    let relay = await TestRelay.start();
    const port = Number(new URL(relay.url).port);
    const n = network(relay.url);
    const primary = await Primary.connect({ identity: n.primary, roster: n.roster, networkSeed: n.networkSeed, timing: FAST });
    const member = await Member.connect({ identity: n.member, roster: n.roster, timing: FAST });
    const got = inbox(member);
    try {
      await primary.send(n.member.id, bytesOf('before'));
      assert.equal(textOf((await got.next())[0]!.bytes), 'before');
      const states = watch(member);
      await relay.stop();
      await until(() => member.state !== 'connected' && primary.state !== 'connected', 'both to see the relay gone');
      assert.ok(states.includes('disconnected'));
      await assert.rejects(primary.send(n.member.id, bytesOf('lost')), LinkError);
      await until(() => states.filter((s) => s === 'connecting').length >= 2, 'the member to dial again');
      relay = await TestRelay.start({ port });
      await member.waitConnected(5000);
      await primary.waitConnected(5000);
      await primary.send(n.member.id, bytesOf('after'));
      assert.equal(textOf((await got.next())[0]!.bytes), 'after');
    } finally {
      member.close();
      primary.close();
      await relay.stop();
    }
  }));

test('a roster with no relay yet, or a relay URL that is not one: refused at once with InvalidError, never thrown later', () =>
  noCrash(async () => {
    const n = network('');
    assert.throws(() => new Primary({ identity: n.primary, roster: n.roster, networkSeed: n.networkSeed }), { code: 'invalid' });
    assert.throws(() => new Member({ identity: n.member, roster: n.roster }), { code: 'invalid' });
    await assert.rejects(Member.connect({ identity: n.member, roster: n.roster }), { code: 'invalid' });
    assert.throws(() => new Member({ identity: n.member, roster: n.roster, relayUrl: 'not a url' }), { code: 'invalid' });
  }));

test('a lookup after 4009 that answers something not a URL, or throws: the member keeps its relay and reconnects, nothing thrown', () =>
  noCrash(async () => {
    const relay = await TestRelay.start();
    const n = network(relay.url);
    const primary = await Primary.connect({ identity: n.primary, roster: n.roster, networkSeed: n.networkSeed, timing: FAST });
    let calls = 0;
    const member = await Member.connect({
      identity: n.member,
      roster: n.roster,
      timing: FAST,
      resolveRelay: (() => {
        calls++;
        if (calls === 1) return Promise.resolve('not a url');
        throw new Error('the directory is unreachable');
      }) as unknown as (network: string) => Promise<string | undefined>,
    });
    const moved: string[] = [];
    member.on('moved', (m) => moved.push(m.network));
    try {
      for (const round of [1, 2]) {
        relay.closeNode(n.roster.network, n.member.id, 4009);
        await until(() => moved.length === round && calls === round && member.state === 'connected', `reconnected after 4009 #${round}`);
      }
      assert.equal(member.relayUrl, relay.url);
    } finally {
      member.close();
      primary.close();
      await relay.stop();
    }
  }));

test('a WebSocket constructor that throws is a failed connection, retried, never an uncaught exception', () =>
  noCrash(async () => {
    const n = network('wss://relay.example/v1');
    let dials = 0;
    const Throwing = class {
      constructor() {
        dials++;
        throw new SyntaxError('refused by the constructor');
      }
    } as unknown as WebSocketConstructor;
    const member = new Member({ identity: n.member, roster: n.roster, timing: FAST, WebSocket: Throwing });
    try {
      await until(() => dials >= 3, 'three dials');
      assert.notEqual(member.state, 'connected');
    } finally {
      member.close();
    }
  }));

test('pairing with the relay unreachable, or at a relay that is not a URL: pair rejects with its error, nothing thrown', () =>
  noCrash(async () => {
    const n = network('wss://relay.example/v1');
    const code = { network: n.roster.network, code: '7K2M9QXZ', codeId: 'AQIDBAUGBwg' };
    for (const relay of [`ws://127.0.0.1:${await refusedPort()}/v1`, 'ws://link-relay.invalid/v1']) {
      await assert.rejects(pair({ link: { ...code, relay }, identity: createIdentity(), timeoutMs: 3000 }), LinkError, relay);
    }
    await assert.rejects(pair({ link: { ...code, relay: 'not a url' }, identity: createIdentity(), timeoutMs: 3000 }), LinkError);
  }));
