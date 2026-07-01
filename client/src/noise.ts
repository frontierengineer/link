// A small, complete Noise Protocol engine (revision 34) over the @noble
// primitives, specialized to the 25519_ChaChaPoly_SHA256 cipher suite.
//
// Why hand-build the engine instead of pulling a Noise library: the engine is
// ~200 lines, the primitives are all audited (@noble), and an in-repo engine is
// auditable end to end and provable byte-for-byte against the published Noise
// test vectors (see test/secureChannel.test.ts, which replays the cacophony
// vectors for NN/NK/NKpsk0/XX/NNpsk0/KK and asserts equality of every message,
// the handshake hash, and the transport stream). The reconnect handshake this
// library actually runs is NKpsk0; the other patterns exist only to exercise —
// and prove correct — every branch of the engine (e/s/ee/es/se/ss/psk).
//
// The engine follows the spec structure exactly: CipherState, SymmetricState,
// HandshakeState. Names mirror §5 so a reviewer can diff against the spec.

import {
  HASH_LEN,
  DH_LEN,
  TAG_LEN,
  type KeyPair,
  sha256d,
  x25519PublicKey,
  x25519Keygen,
  x25519Dh,
  aeadEncrypt,
  aeadDecrypt,
  hkdfNoise,
} from './crypto.js';
import { concatBytes, utf8 } from './bytes.js';

export type Token = 'e' | 's' | 'ee' | 'es' | 'se' | 'ss' | 'psk';

export interface MessagePattern {
  readonly dir: '->' | '<-';
  readonly tokens: readonly Token[];
}

export interface HandshakePattern {
  readonly name: string; // e.g. "NKpsk0"
  readonly preMessages: readonly MessagePattern[];
  readonly messages: readonly MessagePattern[];
}

const EMPTY = new Uint8Array(0);

// ── CipherState (§5.1) ──
// One direction's AEAD with a monotonic 64-bit counter. The counter is never
// transmitted: the receiver authenticates each frame against the nonce it
// expects next, so a replayed, reordered, dropped, or tampered frame fails the
// Poly1305 tag and is rejected. This is exactly the "reject tamper/replay/
// out-of-order" property the transport layer is built on.
export class CipherState {
  private n = 0n;
  constructor(private readonly k?: Uint8Array) {}

  hasKey(): boolean {
    return this.k !== undefined;
  }

  // Current counter, exposed for the transport layer's tests/diagnostics only.
  get nonce(): bigint {
    return this.n;
  }

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.k) return plaintext;
    const ct = aeadEncrypt(this.k, this.n, ad, plaintext);
    this.n++;
    return ct;
  }

  // Throws on authentication failure; on success advances the counter so the
  // same frame can never be accepted twice.
  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.k) return ciphertext;
    const pt = aeadDecrypt(this.k, this.n, ad, ciphertext);
    this.n++;
    return pt;
  }
}

// ── SymmetricState (§5.2) ──
class SymmetricState {
  ck: Uint8Array;
  h: Uint8Array;
  private cs: CipherState;

  constructor(protocolName: string) {
    const name = utf8(protocolName);
    // h = name, zero-padded to HASH_LEN if short, else HASH(name).
    if (name.length <= HASH_LEN) {
      const h = new Uint8Array(HASH_LEN);
      h.set(name);
      this.h = h;
    } else {
      this.h = sha256d(name);
    }
    this.ck = this.h.slice();
    this.cs = new CipherState(); // empty key
  }

  hasKey(): boolean {
    return this.cs.hasKey();
  }

  mixKey(ikm: Uint8Array): void {
    const [ck, tempK] = hkdfNoise(this.ck, ikm, 2);
    this.ck = ck;
    this.cs = new CipherState(tempK);
  }

  mixHash(data: Uint8Array): void {
    this.h = sha256d(concatBytes(this.h, data));
  }

  // §9: a PSK is mixed into both the chaining key and the transcript hash.
  mixKeyAndHash(ikm: Uint8Array): void {
    const [ck, tempH, tempK] = hkdfNoise(this.ck, ikm, 3);
    this.ck = ck;
    this.mixHash(tempH);
    this.cs = new CipherState(tempK);
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
    const [t1, t2] = hkdfNoise(this.ck, EMPTY, 2);
    return [new CipherState(t1), new CipherState(t2)];
  }
}

// The two transport CipherStates after a completed handshake, oriented to this
// party: `send` encrypts what we transmit, `recv` decrypts what we receive.
export interface Transport {
  readonly send: CipherState;
  readonly recv: CipherState;
  readonly handshakeHash: Uint8Array;
}

export interface HandshakeOptions {
  pattern: HandshakePattern;
  initiator: boolean;
  prologue?: Uint8Array;
  s?: KeyPair; // our static
  rs?: Uint8Array; // peer static (pre-known), for pre-messages
  psk?: Uint8Array; // 32-byte pre-shared key for psk patterns
  // Test-only: pin the ephemeral so handshakes are reproducible against the
  // published vectors. Never set in production — ephemerals must be random.
  fixedEphemeral?: Uint8Array;
}

// ── HandshakeState (§5.3) ──
export class HandshakeState {
  private readonly ss: SymmetricState;
  private readonly initiator: boolean;
  private readonly isPSK: boolean;
  private readonly fixedEphemeral?: Uint8Array;
  private readonly messages: readonly MessagePattern[];

  private s?: KeyPair;
  private e?: KeyPair;
  private rs?: Uint8Array;
  private re?: Uint8Array;
  private psk?: Uint8Array;
  private msgIndex = 0;
  private split?: Transport;

  constructor(opts: HandshakeOptions) {
    const { pattern } = opts;
    this.initiator = opts.initiator;
    this.isPSK = pattern.name.includes('psk');
    this.messages = pattern.messages;
    if (opts.s) this.s = opts.s;
    if (opts.rs) this.rs = opts.rs;
    if (opts.psk) this.psk = opts.psk;
    if (opts.fixedEphemeral) this.fixedEphemeral = opts.fixedEphemeral;

    this.ss = new SymmetricState(`Noise_${pattern.name}_25519_ChaChaPoly_SHA256`);
    this.ss.mixHash(opts.prologue ?? EMPTY);

    // Pre-messages: hash in the public keys both sides already know, in order.
    for (const pm of pattern.preMessages) {
      const ownerIsInitiator = pm.dir === '->';
      for (const tok of pm.tokens) {
        const mine = ownerIsInitiator === this.initiator;
        if (tok === 's') this.ss.mixHash(mine ? this.requireStaticPub() : this.require(this.rs, 'rs'));
        else if (tok === 'e') this.ss.mixHash(mine ? this.requireEphemeralPub() : this.require(this.re, 're'));
      }
    }
  }

  get isComplete(): boolean {
    return this.split !== undefined;
  }

  // Whose turn it is to write next (true = this party writes).
  get isMyTurn(): boolean {
    const mp = this.messages[this.msgIndex];
    if (!mp) return false;
    return (mp.dir === '->') === this.initiator;
  }

  // Produce the next handshake message carrying `payload` (default empty). When
  // this is the final message, `transport` is the resulting CipherState pair.
  writeMessage(payload: Uint8Array = EMPTY): { message: Uint8Array; transport?: Transport } {
    const mp = this.messages[this.msgIndex++];
    if (!mp) throw new Error('noise: no message to write');
    if ((mp.dir === '->') !== this.initiator) throw new Error('noise: not our turn to write');
    const out: Uint8Array[] = [];
    for (const tok of mp.tokens) {
      switch (tok) {
        case 'e': {
          this.e = this.makeEphemeral();
          out.push(this.e.pub);
          this.ss.mixHash(this.e.pub);
          if (this.isPSK) this.ss.mixKey(this.e.pub);
          break;
        }
        case 's':
          out.push(this.ss.encryptAndHash(this.requireStaticPub()));
          break;
        default:
          this.mixDh(tok);
      }
    }
    out.push(this.ss.encryptAndHash(payload));
    const message = concatBytes(...out);
    return this.maybeSplit(message);
  }

  // Consume a handshake message, returning its payload (and, on the final
  // message, the transport). Throws on any AEAD failure — i.e. a wrong static
  // key, wrong PSK/token, or tampered bytes abort the handshake here.
  readMessage(message: Uint8Array): { payload: Uint8Array; transport?: Transport } {
    const mp = this.messages[this.msgIndex++];
    if (!mp) throw new Error('noise: no message to read');
    if ((mp.dir === '->') === this.initiator) throw new Error('noise: not our turn to read');
    let off = 0;
    const take = (n: number): Uint8Array => {
      if (off + n > message.length) throw new Error('noise: truncated handshake message');
      const slice = message.subarray(off, off + n);
      off += n;
      return slice;
    };
    for (const tok of mp.tokens) {
      switch (tok) {
        case 'e': {
          this.re = take(DH_LEN).slice();
          this.ss.mixHash(this.re);
          if (this.isPSK) this.ss.mixKey(this.re);
          break;
        }
        case 's': {
          const len = this.ss.hasKey() ? DH_LEN + TAG_LEN : DH_LEN;
          this.rs = this.ss.decryptAndHash(take(len)).slice();
          break;
        }
        default:
          this.mixDh(tok);
      }
    }
    const payload = this.ss.decryptAndHash(message.subarray(off));
    const { transport } = this.maybeSplit(message);
    return transport ? { payload, transport } : { payload };
  }

  // The orientation of `es`/`se` depends on which side we are (§7.1): es always
  // mixes the initiator's ephemeral with the responder's static; se the
  // reverse. `ee`/`ss` are symmetric.
  private mixDh(tok: Token): void {
    switch (tok) {
      case 'ee':
        this.ss.mixKey(x25519Dh(this.require(this.e?.priv, 'e'), this.require(this.re, 're')));
        return;
      case 'es':
        this.ss.mixKey(
          this.initiator
            ? x25519Dh(this.require(this.e?.priv, 'e'), this.require(this.rs, 'rs'))
            : x25519Dh(this.require(this.s?.priv, 's'), this.require(this.re, 're')),
        );
        return;
      case 'se':
        this.ss.mixKey(
          this.initiator
            ? x25519Dh(this.require(this.s?.priv, 's'), this.require(this.re, 're'))
            : x25519Dh(this.require(this.e?.priv, 'e'), this.require(this.rs, 'rs')),
        );
        return;
      case 'ss':
        this.ss.mixKey(x25519Dh(this.require(this.s?.priv, 's'), this.require(this.rs, 'rs')));
        return;
      case 'psk':
        this.ss.mixKeyAndHash(this.require(this.psk, 'psk'));
        return;
      default:
        throw new Error(`noise: unexpected token ${tok}`);
    }
  }

  private maybeSplit(message: Uint8Array): { message: Uint8Array; transport?: Transport } {
    if (this.msgIndex < this.messages.length) return { message };
    const [c1, c2] = this.ss.split();
    // c1 is initiator->responder, c2 is responder->initiator.
    const transport: Transport = this.initiator
      ? { send: c1, recv: c2, handshakeHash: this.ss.h.slice() }
      : { send: c2, recv: c1, handshakeHash: this.ss.h.slice() };
    this.split = transport;
    return { message, transport };
  }

  private makeEphemeral(): KeyPair {
    if (this.fixedEphemeral) return { priv: this.fixedEphemeral, pub: x25519PublicKey(this.fixedEphemeral) };
    return x25519Keygen();
  }

  private requireStaticPub(): Uint8Array {
    return this.require(this.s?.pub, 's');
  }

  private requireEphemeralPub(): Uint8Array {
    return this.require(this.e?.pub, 'e');
  }

  private require<T>(v: T | undefined, what: string): T {
    if (v === undefined) throw new Error(`noise: missing key material '${what}' for this pattern`);
    return v;
  }
}

// ── The patterns the engine knows. ──
// Only NKpsk0 is used at runtime; the rest are here so the KAT can prove the
// engine against the published vectors. Definitions are transcribed verbatim
// from the Noise spec's pattern catalogue.
export const PATTERNS: Record<string, HandshakePattern> = {
  NN: {
    name: 'NN',
    preMessages: [],
    messages: [
      { dir: '->', tokens: ['e'] },
      { dir: '<-', tokens: ['e', 'ee'] },
    ],
  },
  NK: {
    name: 'NK',
    preMessages: [{ dir: '<-', tokens: ['s'] }],
    messages: [
      { dir: '->', tokens: ['e', 'es'] },
      { dir: '<-', tokens: ['e', 'ee'] },
    ],
  },
  NKpsk0: {
    name: 'NKpsk0',
    preMessages: [{ dir: '<-', tokens: ['s'] }],
    messages: [
      { dir: '->', tokens: ['psk', 'e', 'es'] },
      { dir: '<-', tokens: ['e', 'ee'] },
    ],
  },
  NNpsk0: {
    name: 'NNpsk0',
    preMessages: [],
    messages: [
      { dir: '->', tokens: ['psk', 'e'] },
      { dir: '<-', tokens: ['e', 'ee'] },
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
};
