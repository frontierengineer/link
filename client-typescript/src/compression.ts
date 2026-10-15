// `@frontierengineer/link-client/compression`: deflate-raw before encrypting, for
// the content that gains from it (section 6 of the client README). Each call is
// its own compression context, so nothing one message holds can shape another's
// size; the relay sees every ciphertext length, and sharing a context across
// messages (or mixing a secret with data a peer controls in one message) would
// let it learn content from sizes (CRIME, BREACH). The helper cannot know what a
// message mixes or whether it is media: that is the caller's rule to keep.

import { compressionListeners } from './diag-hook.js';
import { InvalidError } from './errors.js';
import { MAX_MESSAGE } from './sessions.js';

/** Smaller inputs gain nothing worth the framing and CPU; `deflate` refuses them. */
export const MIN_COMPRESS_BYTES = 1024;

/**
 * Compresses one message with deflate-raw (CompressionStream). For large, text-like content the
 * sender wrote itself: never media, audio or anything already compressed, and never a secret
 * together with data a peer controls. Rejects with InvalidError under MIN_COMPRESS_BYTES.
 */
export async function deflate(bytes: Uint8Array): Promise<Uint8Array> {
  if (!(bytes instanceof Uint8Array)) throw new InvalidError('bytes must be a Uint8Array');
  if (bytes.length < MIN_COMPRESS_BYTES) throw new InvalidError(`deflate is for ${MIN_COMPRESS_BYTES} bytes or more`);
  const out = await run(new CompressionStream('deflate-raw'), bytes, Infinity);
  for (const l of compressionListeners()) {
    try {
      l(bytes.length, out.length);
    } catch {
      // A listener's failure is not the caller's.
    }
  }
  return out;
}

/**
 * Decompresses what `deflate` produced. Stops and rejects with InvalidError once the output
 * passes `maxBytes` (default 64 MiB, the largest message), so a peer cannot make a small
 * message expand without bound.
 */
export async function inflate(bytes: Uint8Array, maxBytes = MAX_MESSAGE): Promise<Uint8Array> {
  if (!(bytes instanceof Uint8Array)) throw new InvalidError('bytes must be a Uint8Array');
  try {
    return await run(new DecompressionStream('deflate-raw'), bytes, maxBytes);
  } catch (e) {
    throw e instanceof InvalidError ? e : new InvalidError(`inflate failed: ${(e as Error).message}`);
  }
}

async function run(t: { writable: WritableStream<BufferSource>; readable: ReadableStream<Uint8Array> }, input: Uint8Array, max: number): Promise<Uint8Array> {
  const writer = t.writable.getWriter();
  writer.write(input as Uint8Array<ArrayBuffer>).catch(() => undefined);
  writer.close().catch(() => undefined);
  const reader = t.readable.getReader();
  const parts: Uint8Array[] = [];
  let len = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    len += value.length;
    if (len > max) {
      reader.cancel().catch(() => undefined);
      throw new InvalidError(`inflated output exceeds ${max} bytes`);
    }
    parts.push(value);
  }
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
