// The newcomer's side of pairing (sections 5.2 and 5.3): find the primary
// through the relay, prove the code with SPAKE2, hand over the node's keys and
// receive the roster that includes it.

import { b64u, fromB64uLen } from './bytes.js';
import { normalizeCode, parsePairingLink } from './code.js';
import { PairingError, TimeoutError, UnreachableError, type LinkError } from './errors.js';
import { decodeFrame, encodeFrame, FrameType } from './frames.js';
import type { Identity } from './identity.js';
import { NewcomerExchange } from './pairing.js';
import { findMember, rosterProblem, type Roster } from './roster.js';
import { Channel, defaultWebSocket, type WebSocketConstructor } from './socket.js';

export interface PairTarget {
  network: string;
  /** As typed: `XXXX-XXXX` or any spelling `normalizeCode` accepts. */
  code: string;
  /** b64u of the 8-byte code id. */
  codeId: string;
  /** The relay URL, e.g. `wss://eu.frontierengineer.link/v1`. */
  relay: string;
}

export interface PairOptions {
  /** A `frontier://pair?...` link, or its parts. */
  link: string | PairTarget;
  identity: Identity;
  WebSocket?: WebSocketConstructor;
  /** Whole-exchange timeout (60 s, the relay's channel lifetime). */
  timeoutMs?: number;
}

export interface PairResult {
  /** The roster that includes this node. Persist it with the identity. */
  roster: Roster;
  /** The primary's Ed25519 key, pinned from the roster: `roster.primary.ed25519`. */
  pinnedPrimary: string;
}

/** Pairs `identity` into the network the link names. */
export function pair(opts: PairOptions): Promise<PairResult> {
  let target: PairTarget;
  try {
    target = typeof opts.link === 'string' ? parsePairingLink(opts.link) : { ...opts.link, code: normalizeCode(opts.link.code) };
  } catch (e) {
    return Promise.reject(new PairingError((e as Error).message));
  }
  const WS = opts.WebSocket ?? defaultWebSocket();
  const id = opts.identity;
  const codeId = fromB64uLen(target.codeId, 8, 'code id');
  const exchange = new NewcomerExchange(target.code, codeId);

  return new Promise<PairResult>((resolve, reject) => {
    let stage: 'hello' | 'pairing' | 'p2' | 'p4' | 'p6' | 'done' = 'hello';
    let channelId: Uint8Array | undefined;
    let settled = false;
    const timer = setTimeout(() => fail(new TimeoutError('pairing')), opts.timeoutMs ?? 60_000);

    const fail = (e: LinkError) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ch.close(1000);
      reject(e);
    };
    const succeed = (r: PairResult) => {
      settled = true;
      clearTimeout(timer);
      stage = 'done';
      ch.close(1000);
      resolve(r);
    };
    const sendPair = (body: Uint8Array) => ch.sendBinary(encodeFrame(FrameType.Pair, channelId!, body));

    const ch: Channel = new Channel(target.relay, WS, {
      onControl: (msg) => {
        if (msg.type === 'hello' && stage === 'hello') {
          if (msg.version !== 1) return fail(new PairingError(`relay speaks version ${String(msg.version)}`));
          stage = 'pairing';
          ch.sendControl({ type: 'pair', network: target.network, code: target.codeId });
        } else if (msg.type === 'pairing' && stage === 'pairing') {
          try {
            channelId = fromB64uLen(msg.channel, 16, 'channel');
          } catch (e) {
            return fail(new PairingError((e as Error).message));
          }
          stage = 'p2';
          sendPair(exchange.p1());
        } else if (msg.type === 'pairEnd' && stage !== 'hello') {
          fail(new PairingError(stage === 'p4' ? 'the primary rejected the code' : 'the primary ended pairing before it finished'));
        } else if (msg.type === 'error') {
          if (msg.code === 'unreachable') fail(new UnreachableError(target.network));
          else fail(new PairingError(`relay answered ${String(msg.code)}`));
        }
      },
      onBinary: (bytes) => {
        let f;
        try {
          f = decodeFrame(bytes);
        } catch {
          return;
        }
        if (f.type !== FrameType.Pair || !channelId || b64u(f.peer) !== b64u(channelId)) return;
        try {
          if (stage === 'p2') {
            stage = 'p4';
            sendPair(exchange.onP2(f.body));
          } else if (stage === 'p4') {
            stage = 'p6';
            sendPair(exchange.onP4(f.body, { ed25519: id.ed25519.pub, x25519: id.x25519.pub }));
          } else if (stage === 'p6') {
            succeed(checkRoster(exchange.onP6(f.body), target.network, id));
          }
        } catch (e) {
          fail(e instanceof PairingError ? e : new PairingError((e as Error).message));
        }
      },
      onClose: (code) => {
        if (settled) return;
        fail(
          new PairingError(
            stage === 'p4'
              ? 'the primary rejected the code'
              : `the relay ended pairing (close ${code}) before it finished`,
          ),
        );
      },
    });
  });
}

function checkRoster(value: unknown, network: string, id: Identity): PairResult {
  const problem = rosterProblem(value);
  if (problem) throw new PairingError(`the primary sent an invalid roster: ${problem}`);
  const roster = value as Roster;
  if (roster.network !== network) throw new PairingError('the roster is for a different network');
  const me = findMember(roster, id.id);
  if (!me || me.ed25519 !== b64u(id.ed25519.pub) || me.x25519 !== b64u(id.x25519.pub)) {
    throw new PairingError('the roster does not list this node with its keys');
  }
  return { roster, pinnedPrimary: roster.primary.ed25519 };
}
