// Byte plumbing shared across the library. Nothing here is security-sensitive
// on its own, but two functions are: `equalCt` (constant-time compare, used
// wherever a comparison decides authentication) and the framing reader/writer
// (so a malicious peer cannot make us read past a buffer). They are kept small
// and dependency-light on purpose — they are part of the audit surface.

import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { randomBytes } from '@noble/hashes/utils.js';

export { bytesToHex, hexToBytes, concatBytes, utf8ToBytes, randomBytes };

export function utf8(s: string): Uint8Array {
  return utf8ToBytes(s);
}

export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(b);
}

// Constant-time equality. Always compares every byte of the longer input so the
// running time leaks neither the contents nor (beyond the public length) where
// a mismatch occurred. Returns false immediately only on a length mismatch,
// which is not secret in our uses (tag/token lengths are fixed and public).
export function equalCt(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// base64url without padding — the wire form for tokens, key ids, and the
// serialized DeviceCredential. URL-safe so a credential can live in a config
// value, env var, or QR payload without escaping.
export function toB64url(b: Uint8Array): string {
  return Buffer.from(b).toString('base64url');
}

export function fromB64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

// A monotonic write buffer for length-prefixed framing. `u32` lengths are
// big-endian and bound the payload, so frames are self-describing and a reader
// never has to trust an out-of-band length.
export class Writer {
  private chunks: Uint8Array[] = [];

  bytes(b: Uint8Array): this {
    this.chunks.push(b);
    return this;
  }

  u8(n: number): this {
    this.chunks.push(Uint8Array.of(n & 0xff));
    return this;
  }

  u32(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) throw new RangeError('u32 out of range');
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, false);
    this.chunks.push(b);
    return this;
  }

  // Length-delimited byte string (u32 length prefix + bytes).
  lenBytes(b: Uint8Array): this {
    return this.u32(b.length).bytes(b);
  }

  // Length-delimited UTF-8 string.
  lenStr(s: string): this {
    return this.lenBytes(utf8(s));
  }

  finish(): Uint8Array {
    return concatBytes(...this.chunks);
  }
}

// The reader's contract: every accessor checks bounds and throws on a short
// read, so decoding attacker-controlled bytes can fail but never over-read.
export class Reader {
  private off = 0;
  constructor(private readonly buf: Uint8Array) {}

  get remaining(): number {
    return this.buf.length - this.off;
  }

  private need(n: number): void {
    if (n < 0 || this.off + n > this.buf.length) throw new RangeError('short read');
  }

  bytes(n: number): Uint8Array {
    this.need(n);
    const out = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return out;
  }

  u8(): number {
    this.need(1);
    return this.buf[this.off++]!;
  }

  u32(): number {
    this.need(4);
    const v = new DataView(this.buf.buffer, this.buf.byteOffset + this.off, 4).getUint32(0, false);
    this.off += 4;
    return v;
  }

  lenBytes(max = 0xffff_ffff): Uint8Array {
    const n = this.u32();
    if (n > max) throw new RangeError('length-prefixed field exceeds max');
    return this.bytes(n).slice(); // copy: detach from the backing buffer
  }

  lenStr(max = 0xffff_ffff): string {
    return fromUtf8(this.lenBytes(max));
  }

  rest(): Uint8Array {
    const out = this.buf.subarray(this.off);
    this.off = this.buf.length;
    return out;
  }
}
