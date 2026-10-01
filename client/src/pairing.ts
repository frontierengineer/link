// The pairing exchange of section 5.3 as two transport-agnostic state machines.
// The relay plumbing around them lives in newcomer.ts and primary.ts.

import { b64u, fromB64uLen, fromUtf8, utf8 } from './bytes.js';
import { hkdf, open, seal } from './crypto.js';
import { deriveW, scalarFromRandom, Spake2, verifyConfirmation, type Spake2Keys } from './spake2.js';

export interface PairTransportKeys {
  /** newcomer -> primary */
  toPrimary: Uint8Array;
  /** primary -> newcomer */
  toNewcomer: Uint8Array;
}

export function pairTransportKeys(keys: Spake2Keys): PairTransportKeys {
  const okm = hkdf(keys.ke, keys.hash, utf8('frontier-link/1/pair-transport'), 64);
  return { toPrimary: okm.slice(0, 32), toNewcomer: okm.slice(32, 64) };
}

class Sealer {
  private sendN = 0n;
  private recvN = 0n;
  constructor(
    private readonly sendKey: Uint8Array,
    private readonly recvKey: Uint8Array,
  ) {}

  seal(value: unknown): Uint8Array {
    return seal(this.sendKey, this.sendN++, new Uint8Array(0), utf8(JSON.stringify(value)));
  }

  open(ciphertext: Uint8Array): unknown {
    const pt = open(this.recvKey, this.recvN, new Uint8Array(0), ciphertext);
    this.recvN++;
    return JSON.parse(fromUtf8(pt)) as unknown;
  }
}

export interface NewcomerKeys {
  ed25519: Uint8Array;
  x25519: Uint8Array;
}

/** A, the newcomer: P1, P3, P5 out; P2, P4, P6 in. */
export class NewcomerExchange {
  private readonly spake: Spake2;
  private keys: Spake2Keys | undefined;
  private sealer: Sealer | undefined;
  private confirmed = false;

  /** `code` is canonical; `random48` fixes x for vectors. */
  constructor(code: string, codeId: Uint8Array, random48?: Uint8Array) {
    this.spake = new Spake2({
      role: 'A',
      w: deriveW(code),
      aad: codeId,
      ...(random48 ? { scalar: scalarFromRandom(random48) } : {}),
    });
  }

  /** P1: pA. */
  p1(): Uint8Array {
    return this.spake.share;
  }

  /** P2 in, P3 (cA) out. */
  onP2(pB: Uint8Array): Uint8Array {
    if (this.keys) throw new Error('pairing: P2 already received');
    this.keys = this.spake.finish(pB);
    return this.keys.ours;
  }

  /** P4 in; returns P5 sealed with our public keys. Throws when cB is wrong. */
  onP4(cB: Uint8Array, mine: NewcomerKeys): Uint8Array {
    if (!this.keys) throw new Error('pairing: P4 before P2');
    if (!verifyConfirmation(this.keys, cB)) throw new Error('pairing: the primary did not prove the code');
    this.confirmed = true;
    const t = pairTransportKeys(this.keys);
    this.sealer = new Sealer(t.toPrimary, t.toNewcomer);
    return this.sealer.seal({ ed25519: b64u(mine.ed25519), x25519: b64u(mine.x25519) });
  }

  /** P6 in: the roster object, not yet validated. */
  onP6(sealed: Uint8Array): unknown {
    if (!this.sealer || !this.confirmed) throw new Error('pairing: P6 before P4');
    const msg = this.sealer.open(sealed);
    if (typeof msg !== 'object' || msg === null || !('roster' in msg)) throw new Error('pairing: P6 carries no roster');
    return (msg as { roster: unknown }).roster;
  }

  get spakeKeys(): Spake2Keys | undefined {
    return this.keys;
  }
}

/** B, the primary: P2, P4, P6 out; P1, P3, P5 in. */
export class PrimaryExchange {
  private readonly spake: Spake2;
  private keys: Spake2Keys | undefined;
  private sealer: Sealer | undefined;

  constructor(code: string, codeId: Uint8Array, random48?: Uint8Array) {
    this.spake = new Spake2({
      role: 'B',
      w: deriveW(code),
      aad: codeId,
      ...(random48 ? { scalar: scalarFromRandom(random48) } : {}),
    });
  }

  /** P1 in, P2 (pB) out. */
  onP1(pA: Uint8Array): Uint8Array {
    if (this.keys) throw new Error('pairing: P1 already received');
    this.keys = this.spake.finish(pA);
    return this.spake.share;
  }

  /** P3 in. True when cA verifies; then `p4()` may be sent. */
  onP3(cA: Uint8Array): boolean {
    if (!this.keys) throw new Error('pairing: P3 before P1');
    if (!verifyConfirmation(this.keys, cA)) return false;
    const t = pairTransportKeys(this.keys);
    this.sealer = new Sealer(t.toNewcomer, t.toPrimary);
    return true;
  }

  p4(): Uint8Array {
    if (!this.keys || !this.sealer) throw new Error('pairing: P4 before cA verified');
    return this.keys.ours;
  }

  /** P5 in: the newcomer's keys. */
  onP5(sealed: Uint8Array): NewcomerKeys {
    if (!this.sealer) throw new Error('pairing: P5 before cA verified');
    const msg = this.sealer.open(sealed) as Record<string, unknown> | null;
    if (typeof msg !== 'object' || msg === null) throw new Error('pairing: P5 is not an object');
    return {
      ed25519: fromB64uLen(msg.ed25519, 32, 'P5 ed25519'),
      x25519: fromB64uLen(msg.x25519, 32, 'P5 x25519'),
    };
  }

  /** P6 out. */
  p6(roster: unknown): Uint8Array {
    if (!this.sealer) throw new Error('pairing: P6 before cA verified');
    return this.sealer.seal({ roster });
  }

  get spakeKeys(): Spake2Keys | undefined {
    return this.keys;
  }
}
