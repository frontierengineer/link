// First-contact and recovery: the SPAKE2 choreography that bootstraps a device
// credential from a short human code (or a high-entropy recovery key), plus the
// host-side token store, lockout, and revocation.
//
// Threat model recap (why this is safe with a 6-char code): SPAKE2 reveals
// nothing about the code to a passive observer, and an *active* MITM who does
// not know the code can only test one guess per live attempt — there is no
// offline dictionary attack on the transcript. The host caps attempts per code
// (default 5) and the code is single-use, so the attacker's success chance is
// at most attempts / charset^len. The pairing test proves both halves: the RFC
// vectors pass, and a simulated active MITM fails to derive the key.

import { Spake2, verifyConfirm, deriveW, type SpakeIdentities } from './spake2.js';
import {
  Mode,
  encodeHeader,
  transportFromSecret,
  seal,
  open,
  type Header,
  KEY_ID_LEN,
  TOKEN_LEN,
  STATIC_PUB_LEN,
} from './secureChannel.js';
import type { Transport } from './noise.js';
import type { KeyPair } from './crypto.js';
import type { Pipe } from './pipe.js';
import { Reader, Writer, utf8, fromUtf8, randomBytes, toB64url, fromB64url } from './bytes.js';

// Fixed, public identity strings hashed into every SPAKE2 transcript. Binding
// the roles prevents unknown-key-share confusion about who paired with whom.
const ID_CLIENT = utf8('FrontierLink/v1/client');
const ID_HOST = utf8('FrontierLink/v1/host');

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 15_000;

// A wrong code/recovery-key (or an active MITM) shows up as a confirmation-MAC
// mismatch. The host treats this — and only this — as a counted attempt.
export class PairingAuthError extends Error {
  constructor(message = 'pairing authentication failed (wrong code or active attacker)') {
    super(message);
    this.name = 'PairingAuthError';
  }
}

// What the client persists after a successful pair/recovery and presents on
// every reconnect. The host static key is *pinned* here: reconnect authenticates
// the host by this exact key, so a substituted key fails.
export interface DeviceCredential {
  address: string;
  hostStaticPub: string; // base64url, 32 bytes
  token: string; // base64url, 32 bytes
  keyId: string; // base64url, 16 bytes
}

export function credentialToString(c: DeviceCredential): string {
  return toB64url(utf8(JSON.stringify(c)));
}

export function credentialFromString(s: string): DeviceCredential {
  const c = JSON.parse(fromUtf8(fromB64url(s))) as DeviceCredential;
  if (!c.address || !c.hostStaticPub || !c.token || !c.keyId) throw new Error('malformed credential');
  return c;
}

// — the welcome message (host -> client, first sealed frame) —
// Carries everything the client needs to build its credential. Sealed by the
// freshly derived SPAKE2 transport, so only a party that knew the code sees it.
function encodeWelcome(address: string, hostStaticPub: Uint8Array, token: Uint8Array, keyId: Uint8Array): Uint8Array {
  return new Writer().lenStr(address).bytes(hostStaticPub).bytes(token).bytes(keyId).finish();
}

function decodeWelcome(buf: Uint8Array): { address: string; hostStaticPub: Uint8Array; token: Uint8Array; keyId: Uint8Array } {
  const r = new Reader(buf);
  const address = r.lenStr(256);
  const hostStaticPub = r.bytes(STATIC_PUB_LEN).slice();
  const token = r.bytes(TOKEN_LEN).slice();
  const keyId = r.bytes(KEY_ID_LEN).slice();
  return { address, hostStaticPub, token, keyId };
}

function identities(header: Header): SpakeIdentities {
  return { A: ID_CLIENT, B: ID_HOST, aad: encodeHeader(header) };
}

// ── client side ──

export interface PairClientResult {
  transport: Transport;
  credential: DeviceCredential;
}

// Run the connecting side of pairing (mode = Pair) or recovery (mode = Recover).
// `password` is the short code or the recovery key, as raw bytes. On success the
// returned transport is live and the credential is ready to persist.
export async function spakeClient(
  pipe: Pipe,
  password: Uint8Array,
  mode: Mode.Pair | Mode.Recover,
  timeoutMs: number = DEFAULT_HANDSHAKE_TIMEOUT_MS,
): Promise<PairClientResult> {
  const header: Header = { mode };
  const headerBytes = encodeHeader(header);
  const spake = new Spake2('A', deriveW(password), identities(header));

  // F0 header, F1 our SPAKE2 share — sent back to back (no extra round trip).
  pipe.send(headerBytes);
  pipe.send(spake.share);

  const peerShare = await pipe.recv(timeoutMs); // F2: pB
  const result = spake.finish(peerShare);
  pipe.send(result.ourConfirm); // F3: cA

  const peerConfirm = await pipe.recv(timeoutMs); // F4: cB
  if (!verifyConfirm(result, peerConfirm)) throw new PairingAuthError();

  const transport = transportFromSecret(result.ke, true, result.transcriptHash);

  const welcomeFrame = await pipe.recv(timeoutMs); // F5: sealed welcome
  const welcome = decodeWelcome(open(transport.recv, welcomeFrame));
  const credential: DeviceCredential = {
    address: welcome.address,
    hostStaticPub: toB64url(welcome.hostStaticPub),
    token: toB64url(welcome.token),
    keyId: toB64url(welcome.keyId),
  };
  return { transport, credential };
}

// ── host side: token store + lockout ──

export interface IssuedDevice {
  keyId: Uint8Array;
  token: Uint8Array;
  createdAt: number;
  label?: string;
}

// A device row in its serialized (base64url) form, for persistence.
export interface SerializedDevice {
  keyId: string;
  token: string;
  createdAt: number;
  label?: string;
}

// In-memory device registry: keyId -> { token, ... }.
//
// SECURITY — these are SECRETS AT REST. A device token *is* the Noise PSK, so it
// cannot be stored hashed: the host needs the raw value to authenticate the
// client on reconnect. Persist this store only through an authenticated-
// encryption layer you control (OS keychain, a KMS/HSM, or an encrypted file) —
// never as plaintext. `export()`/`import()` exist precisely for that seam:
// export -> encrypt -> store, and load -> decrypt -> import. The same applies to
// the client-side DeviceCredential, which also carries the token.
export class TokenStore {
  private readonly byKeyId = new Map<string, IssuedDevice>();

  issue(label?: string): IssuedDevice {
    const keyId = randomBytes(KEY_ID_LEN);
    const token = randomBytes(TOKEN_LEN);
    const dev: IssuedDevice = label !== undefined
      ? { keyId, token, createdAt: Date.now(), label }
      : { keyId, token, createdAt: Date.now() };
    this.byKeyId.set(toB64url(keyId), dev);
    return dev;
  }

  // The reconnect responder's PSK lookup and the single revocation point.
  resolve(keyId: Uint8Array): Uint8Array | undefined {
    return this.byKeyId.get(toB64url(keyId))?.token;
  }

  revoke(keyId: Uint8Array | string): boolean {
    const k = typeof keyId === 'string' ? keyId : toB64url(keyId);
    return this.byKeyId.delete(k);
  }

  list(): IssuedDevice[] {
    return [...this.byKeyId.values()];
  }

  get size(): number {
    return this.byKeyId.size;
  }

  // Serialize for encrypt-at-rest. Encrypt the result before storing it.
  export(): SerializedDevice[] {
    return [...this.byKeyId.values()].map((d) => ({
      keyId: toB64url(d.keyId),
      token: toB64url(d.token),
      createdAt: d.createdAt,
      ...(d.label !== undefined ? { label: d.label } : {}),
    }));
  }

  // Reload a previously exported (and decrypted) set of devices.
  static import(rows: SerializedDevice[]): TokenStore {
    const store = new TokenStore();
    for (const r of rows) {
      const keyId = fromB64url(r.keyId);
      const dev: IssuedDevice = r.label !== undefined
        ? { keyId, token: fromB64url(r.token), createdAt: r.createdAt, label: r.label }
        : { keyId, token: fromB64url(r.token), createdAt: r.createdAt };
      store.byKeyId.set(r.keyId, dev);
    }
    return store;
  }
}

// Bounds guesses against a single-use pairing code to K tries — the mechanism
// that makes online guessing the *only* attack and caps it.
//
// Correctness note (this used to be TOCTOU-bypassable): the host runs a
// multi-round-trip handshake between deciding to attempt and recording the
// outcome, so a plain "check, then later record" let N concurrent attempts all
// pass a stale check. The fix is `reserve()`: a slot is taken ATOMICALLY at
// attempt entry (no `await` between read and write, so indivisible on a
// single-threaded runtime), and an in-flight reservation counts toward K. That
// both closes the race AND bounds concurrent handshakes per code to K, which in
// turn bounds the unauthenticated P-256 work an attacker can pin on the host.
export class CodeLockout {
  private readonly failed = new Map<string, number>();
  private readonly inFlight = new Map<string, number>();
  constructor(private readonly maxAttempts = 5) {}

  // Atomically reserve a guess slot. Returns false once failed + in-flight is at
  // budget; the caller MUST refuse the attempt. Pair with exactly one of
  // recordFailure()/refund()/clear().
  reserve(code: string): boolean {
    const used = (this.failed.get(code) ?? 0) + (this.inFlight.get(code) ?? 0);
    if (used >= this.maxAttempts) return false;
    this.inFlight.set(code, (this.inFlight.get(code) ?? 0) + 1);
    return true;
  }

  // Release a reservation that was NOT a code guess (network error, timeout,
  // peer vanished): frees the slot without counting it against the budget.
  refund(code: string): void {
    const n = this.inFlight.get(code) ?? 0;
    if (n <= 1) this.inFlight.delete(code);
    else this.inFlight.set(code, n - 1);
  }

  // Convert a reservation into a permanent failure: a wrong guess. After K of
  // these the code is locked out.
  recordFailure(code: string): { lockedOut: boolean; remaining: number } {
    this.refund(code);
    const f = (this.failed.get(code) ?? 0) + 1;
    this.failed.set(code, f);
    return { lockedOut: f >= this.maxAttempts, remaining: Math.max(0, this.maxAttempts - f) };
  }

  // Read-only peek; does not reserve a slot.
  available(code: string): boolean {
    return (this.failed.get(code) ?? 0) + (this.inFlight.get(code) ?? 0) < this.maxAttempts;
  }

  clear(code: string): void {
    this.failed.delete(code);
    this.inFlight.delete(code);
  }
}

export interface SpakeHostOptions {
  hostStatic: KeyPair;
  address: string;
  // The shared secret for this mode: the active pairing code (Pair) or the
  // host's recovery key (Recover), as raw bytes.
  password: Uint8Array;
  tokens: TokenStore;
  label?: string;
  timeoutMs?: number;
}

export interface SpakeHostResult {
  transport: Transport;
  device: IssuedDevice;
}

// Run the host side of pairing/recovery after the header frame is read. On a
// confirmation mismatch it throws PairingAuthError (the caller counts it toward
// lockout); on success it issues a token, sends the sealed welcome, and returns
// the live transport plus the newly issued device.
export async function spakeHost(pipe: Pipe, header: Header, opts: SpakeHostOptions): Promise<SpakeHostResult> {
  const timeout = opts.timeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
  const spake = new Spake2('B', deriveW(opts.password), identities(header));

  const peerShare = await pipe.recv(timeout); // F1: pA
  pipe.send(spake.share); // F2: pB
  const result = spake.finish(peerShare);

  const peerConfirm = await pipe.recv(timeout); // F3: cA
  if (!verifyConfirm(result, peerConfirm)) throw new PairingAuthError();
  pipe.send(result.ourConfirm); // F4: cB

  const transport = transportFromSecret(result.ke, false, result.transcriptHash);

  const device = opts.tokens.issue(opts.label);
  const welcome = encodeWelcome(opts.address, opts.hostStatic.pub, device.token, device.keyId);
  pipe.send(seal(transport.send, welcome)); // F5: sealed welcome
  return { transport, device };
}
