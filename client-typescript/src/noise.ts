// A Noise Protocol engine (revision 34) for the 25519_ChaChaPoly_SHA256 suite.
// Sessions use IK (section 7.1); NN, KK and XX exist so the engine can be
// proven byte for byte against the cacophony vectors on every token branch.
// Structure and names mirror Noise sections 5.1-5.3.

import { concat, EMPTY, utf8 } from './bytes.js';
import { hkdfNoise, open, seal, sha256, x25519Dh, x25519Generate, x25519Public, type KeyPair } from './crypto.js';

export type Token = 'e' | 's' | 'ee' | 'es' | 'se' | 'ss';

export interface MessagePattern {
  readonly dir: '->' | '<-';
  readonly tokens: readonly Token[];
}

export interface HandshakePattern {
  readonly name: string;
  readonly preMessages: readonly MessagePattern[];
  readonly messages: readonly MessagePattern[];
}

export const PATTERNS = {
  IK: {
    name: 'IK',
    preMessages: [{ dir: '<-', tokens: ['s'] }],
    messages: [
      { dir: '->', tokens: ['e', 'es', 's', 'ss'] },
      { dir: '<-', tokens: ['e', 'ee', 'se'] },
    ],
  },
  NN: {
    name: 'NN',
    preMessages: [],
    messages: [
      { dir: '->', tokens: ['e'] },
      { dir: '<-', tokens: ['e', 'ee'] },
    ],
  },
  KK: {
    name: 'KK',
    preMessages: [
      { dir: '->', tokens: ['s'] },
      { dir: '<-', tokens: ['s'] },
    ],
    messages: [
      { dir: '->', tokens: ['e', 'es', 'ss'] },
      { dir: '<-', tokens: ['e', 'ee', 'se'] },
    ],
  },
  XX: {
    name: 'XX',
    preMessages: [],
    messages: [
      { dir: '->', tokens: ['e'] },
      { dir: '<-', tokens: ['e', 'ee', 's', 'es'] },
      { dir: '->', tokens: ['s', 'se'] },
    ],
  },
} as const satisfies Record<string, HandshakePattern>;

const MAX_NONCE = 0xffff_ffff_ffff_ffffn;

/** One direction's key and 64-bit counter nonce (Noise section 5.1). */
export class CipherState {
  private n = 0n;
  constructor(private readonly k?: Uint8Array) {}

  hasKey(): boolean {
    return this.k !== undefined;
  }

  /** Messages processed so far in this direction. */
  get nonce(): bigint {
    return this.n;
  }

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.k) return plaintext;
    if (this.n >= MAX_NONCE) throw new Error('noise: nonce exhausted');
    const ct = seal(this.k, this.n, ad, plaintext);
    this.n++;
    return ct;
  }

  /** Throws on a bad tag; the counter only advances on success. */
  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.k) return ciphertext;
    if (this.n >= MAX_NONCE) throw new Error('noise: nonce exhausted');
    const pt = open(this.k, this.n, ad, ciphertext);
    this.n++;
    return pt;
  }
}

class SymmetricState {
  ck: Uint8Array;
  h: Uint8Array;
  private cs = new CipherState();

  constructor(protocolName: string) {
    const name = utf8(protocolName);
    if (name.length <= 32) {
      this.h = new Uint8Array(32);
      this.h.set(name);
    } else {
      this.h = sha256(name);
    }
    this.ck = this.h.slice();
  }

  hasKey(): boolean {
    return this.cs.hasKey();
  }

  mixKey(ikm: Uint8Array): void {
    const [ck, k] = hkdfNoise(this.ck, ikm, 2);
    this.ck = ck!;
    this.cs = new CipherState(k!);
  }

  mixHash(data: Uint8Array): void {
    this.h = sha256(concat(this.h, data));
  }

  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const ct = this.cs.encryptWithAd(this.h, plaintext);
    this.mixHash(ct);
    return ct;
  }

  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    const pt = this.cs.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return pt;
  }

  split(): [CipherState, CipherState] {
    const [k1, k2] = hkdfNoise(this.ck, EMPTY, 2);
    return [new CipherState(k1!), new CipherState(k2!)];
  }
}

export interface Transport {
  readonly send: CipherState;
  readonly recv: CipherState;
  readonly handshakeHash: Uint8Array;
}

export interface HandshakeOptions {
  pattern: HandshakePattern;
  initiator: boolean;
  prologue?: Uint8Array;
  s?: KeyPair;
  rs?: Uint8Array;
  /** Fixes the ephemeral private key; only for vectors and tests. */
  fixedEphemeral?: Uint8Array;
}

export class HandshakeState {
  private readonly ss: SymmetricState;
  private readonly initiator: boolean;
  private readonly messages: readonly MessagePattern[];
  private readonly fixedEphemeral: Uint8Array | undefined;
  private s: KeyPair | undefined;
  private e: KeyPair | undefined;
  private rs: Uint8Array | undefined;
  private re: Uint8Array | undefined;
  private index = 0;

  constructor(opts: HandshakeOptions) {
    this.initiator = opts.initiator;
    this.messages = opts.pattern.messages;
    this.s = opts.s;
    this.rs = opts.rs;
    this.fixedEphemeral = opts.fixedEphemeral;
    this.ss = new SymmetricState(`Noise_${opts.pattern.name}_25519_ChaChaPoly_SHA256`);
    this.ss.mixHash(opts.prologue ?? EMPTY);
    for (const pm of opts.pattern.preMessages) {
      const mine = (pm.dir === '->') === this.initiator;
      for (const tok of pm.tokens) {
        if (tok === 's') this.ss.mixHash(mine ? need(this.s?.pub, 's') : need(this.rs, 'rs'));
        else if (tok === 'e') this.ss.mixHash(mine ? need(this.e?.pub, 'e') : need(this.re, 're'));
      }
    }
  }

  /** The peer's static key, once known. */
  get remoteStatic(): Uint8Array | undefined {
    return this.rs;
  }

  get ephemeralPublic(): Uint8Array | undefined {
    return this.e?.pub;
  }

  get isComplete(): boolean {
    return this.index >= this.messages.length;
  }

  writeMessage(payload: Uint8Array = EMPTY): { message: Uint8Array; transport?: Transport } {
    const mp = this.messages[this.index];
    if (!mp || (mp.dir === '->') !== this.initiator) throw new Error('noise: not our turn to write');
    this.index++;
    const out: Uint8Array[] = [];
    for (const tok of mp.tokens) {
      if (tok === 'e') {
        this.e = this.fixedEphemeral
          ? { priv: this.fixedEphemeral, pub: x25519Public(this.fixedEphemeral) }
          : x25519Generate();
        out.push(this.e.pub);
        this.ss.mixHash(this.e.pub);
      } else if (tok === 's') {
        out.push(this.ss.encryptAndHash(need(this.s?.pub, 's')));
      } else {
        this.mixDh(tok);
      }
    }
    out.push(this.ss.encryptAndHash(payload));
    const message = concat(...out);
    const transport = this.maybeSplit();
    return transport ? { message, transport } : { message };
  }

  /** Throws on any authentication failure. */
  readMessage(message: Uint8Array): { payload: Uint8Array; transport?: Transport } {
    const mp = this.messages[this.index];
    if (!mp || (mp.dir === '->') === this.initiator) throw new Error('noise: not our turn to read');
    this.index++;
    let off = 0;
    const take = (n: number): Uint8Array => {
      if (off + n > message.length) throw new Error('noise: truncated handshake message');
      const b = message.slice(off, off + n);
      off += n;
      return b;
    };
    for (const tok of mp.tokens) {
      if (tok === 'e') {
        this.re = take(32);
        this.ss.mixHash(this.re);
      } else if (tok === 's') {
        this.rs = this.ss.decryptAndHash(take(this.ss.hasKey() ? 48 : 32));
      } else {
        this.mixDh(tok);
      }
    }
    const payload = this.ss.decryptAndHash(message.subarray(off));
    const transport = this.maybeSplit();
    return transport ? { payload, transport } : { payload };
  }

  private mixDh(tok: Token): void {
    const e = () => need(this.e?.priv, 'e');
    const s = () => need(this.s?.priv, 's');
    const re = () => need(this.re, 're');
    const rs = () => need(this.rs, 'rs');
    switch (tok) {
      case 'ee':
        return this.ss.mixKey(x25519Dh(e(), re()));
      case 'es':
        return this.ss.mixKey(this.initiator ? x25519Dh(e(), rs()) : x25519Dh(s(), re()));
      case 'se':
        return this.ss.mixKey(this.initiator ? x25519Dh(s(), re()) : x25519Dh(e(), rs()));
      case 'ss':
        return this.ss.mixKey(x25519Dh(s(), rs()));
      default:
        throw new Error(`noise: unexpected token ${tok}`);
    }
  }

  private maybeSplit(): Transport | undefined {
    if (this.index < this.messages.length) return undefined;
    const [c1, c2] = this.ss.split();
    const h = this.ss.h.slice();
    return this.initiator ? { send: c1, recv: c2, handshakeHash: h } : { send: c2, recv: c1, handshakeHash: h };
  }
}

function need<T>(v: T | undefined, what: string): T {
  if (v === undefined) throw new Error(`noise: missing ${what}`);
  return v;
}
