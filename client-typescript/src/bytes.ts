// Byte helpers and the encodings the spec's notation names: lenStr, u32be, u64be,
// b64u (base64url, no padding) and b32 (RFC 4648 base32, lowercase, no padding).
// Decoders are strict: they reject padding, foreign characters and non-canonical
// trailing bits, so one value has exactly one text form.

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const EMPTY = new Uint8Array(0);

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function u32be(x: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, x, false);
  return b;
}

export function u64be(x: number | bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(x), false);
  return b;
}

export function u64le(x: number | bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(x), true);
  return b;
}

export function readU32be(b: Uint8Array, off: number): number {
  if (off + 4 > b.length) throw new RangeError('truncated u32');
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, false);
}

export function readU64be(b: Uint8Array, off: number): bigint {
  if (off + 8 > b.length) throw new RangeError('truncated u64');
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(off, false);
}

/** `u32be(byte length of the UTF-8 encoding) || UTF-8 bytes`. */
export function lenStr(s: string): Uint8Array {
  const b = utf8(s);
  return concat(u32be(b.length), b);
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) throw new Error('invalid hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

// ── base64url, no padding ──

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64U_REV = new Map<string, number>([...B64U].map((c, i) => [c, i]));

export function b64u(b: Uint8Array): string {
  let s = '';
  let i = 0;
  for (; i + 3 <= b.length; i += 3) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    s += B64U[n >> 18]! + B64U[(n >> 12) & 63]! + B64U[(n >> 6) & 63]! + B64U[n & 63]!;
  }
  const rest = b.length - i;
  if (rest === 1) {
    const n = b[i]! << 16;
    s += B64U[n >> 18]! + B64U[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8);
    s += B64U[n >> 18]! + B64U[(n >> 12) & 63]! + B64U[(n >> 6) & 63]!;
  }
  return s;
}

export function fromB64u(s: string): Uint8Array {
  if (s.length % 4 === 1) throw new Error('invalid base64url length');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of s) {
    const v = B64U_REV.get(c);
    if (v === undefined) throw new Error('invalid base64url character');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  if ((acc & ((1 << bits) - 1)) !== 0) throw new Error('non-canonical base64url');
  return out;
}

/** Decodes b64u and requires an exact byte length. */
export function fromB64uLen(s: unknown, len: number, what: string): Uint8Array {
  if (typeof s !== 'string') throw new Error(`${what}: not a string`);
  const b = fromB64u(s);
  if (b.length !== len) throw new Error(`${what}: expected ${len} bytes`);
  return b;
}

// ── base32 (RFC 4648), lowercase, no padding ──

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
const B32_REV = new Map<string, number>([...B32].map((c, i) => [c, i]));

export function b32(b: Uint8Array): string {
  let s = '';
  let acc = 0;
  let bits = 0;
  for (const x of b) {
    acc = ((acc << 8) | x) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      s += B32[(acc >> bits) & 31]!;
    }
  }
  if (bits > 0) s += B32[(acc << (5 - bits)) & 31]!;
  return s;
}

export function fromB32(s: string): Uint8Array {
  const out = new Uint8Array(Math.floor((s.length * 5) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of s) {
    const v = B32_REV.get(c);
    if (v === undefined) throw new Error('invalid base32 character');
    acc = ((acc << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  if (bits >= 5 || (acc & ((1 << bits) - 1)) !== 0) throw new Error('non-canonical base32');
  return out;
}
