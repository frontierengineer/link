// Section 4.1 (spec 71b8288): the origin a member signs omits the port when it is 80 or 443,
// whatever the scheme, as the relay compares it. A member dialling ws://127.0.0.1:443 sends
// Host 127.0.0.1:443 and signs 127.0.0.1; before, it signed 127.0.0.1:443 and was closed 4007.
//
// The relay must listen on port 443, which needs root or a lowered
// net.ipv4.ip_unprivileged_port_start. Without that the test is skipped and says so; CI
// lowers it and sets LINK_REQUIRE_PORT_443=1 so that there the test cannot be skipped.

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { relayBinary } from './support/relay.js';
import { bytesOf, inbox, startNet, type Net } from './support/net.js';

before(() => {
  relayBinary();
});

test('members dialling ws://127.0.0.1:443 register with the origin 127.0.0.1', async (t) => {
  let net: Net;
  try {
    net = await startNet({ env: { LINK_ADDR: '127.0.0.1:443' } });
  } catch (e) {
    // Only a relay that could not listen is skipped; a registration that fails is a failure.
    const message = (e as Error).message;
    if (process.env.LINK_REQUIRE_PORT_443 || !/before listening/.test(message)) throw e;
    t.skip(`cannot listen on 127.0.0.1:443 here (${message.split('\n').slice(1).join(' ').trim()}); see the comment at the top`);
    return;
  }
  try {
    assert.equal(net.relay.url, 'ws://127.0.0.1:443/v1');
    assert.equal(net.primary.state, 'connected');
    const worker = await net.add('worker');
    const pIn = inbox(net.primary);
    await worker.send(net.primary.id, bytesOf('signed without :443'));
    assert.equal(new TextDecoder().decode((await pIn.next())[0]!.bytes), 'signed without :443');
  } finally {
    await net.close();
  }
});
