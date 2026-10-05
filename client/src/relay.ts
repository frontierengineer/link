// The member's connection to its relay (sections 4.1, 10, 11): hello, a signed
// register, registered; reconnect with backoff forever, except after 4008.

import { b64u, fromB64uLen } from './bytes.js';
import { Emitter } from './events.js';
import type { Identity } from './identity.js';
import type { Roster } from './roster.js';
import { originOf, registerSigningBytes } from './signed.js';
import { Channel, type ControlMessage, type WebSocketConstructor } from './socket.js';

export type RelayState = 'connecting' | 'registered' | 'disconnected' | 'revoked' | 'replaced' | 'closed';

export const CloseCode = {
  Normal: 1000,
  GoingAway: 1001,
  BadRequest: 4000,
  RateLimited: 4002,
  Replaced: 4005,
  SlowPeer: 4006,
  RegistrationFailed: 4007,
  NotMember: 4008,
  Moved: 4009,
} as const;

export interface RelayConnectionOptions {
  url: string;
  identity: Identity;
  /** The newest roster held, read at every registration. */
  roster: () => Roster;
  WebSocket: WebSocketConstructor;
  now: () => number;
  backoffInitialMs: number;
  backoffMaxMs: number;
  /** On 4009: where the network lives now (undefined keeps the current URL). */
  resolveRelay?: ((network: string) => Promise<string | undefined>) | undefined;
}

export type RelayEvents = {
  state: RelayState;
  control: ControlMessage;
  binary: Uint8Array;
  /** The `registered` message, emitted before the state turns `registered`. */
  registered: ControlMessage;
  /** Every close of the underlying connection. */
  disconnect: { code: number; reason: string };
  /** 4009: the network moved; the connection looks it up again and reconnects. */
  moved: { network: string };
};

export class RelayConnection extends Emitter<RelayEvents> {
  private channel: Channel | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private backoff: number;
  private _state: RelayState = 'disconnected';
  private url: string;
  private _features: ReadonlySet<string> = new Set();
  /** UTF-8 bytes of control messages sent and received, over every connection. */
  textSent = 0;
  textReceived = 0;

  constructor(private readonly o: RelayConnectionOptions) {
    super();
    this.url = o.url;
    this.backoff = o.backoffInitialMs;
  }

  get state(): RelayState {
    return this._state;
  }

  get relayUrl(): string {
    return this.url;
  }

  /** The optional behaviours the current relay listed in `hello` (section 4.1); empty before it. */
  get features(): ReadonlySet<string> {
    return this._features;
  }

  /** Data may be handed to the socket now: little is waiting in it, or there is no socket (a send then fails at once). */
  get writable(): boolean {
    return this.channel?.writable ?? true;
  }

  /** Bytes handed to the socket and not yet sent. */
  get bufferedAmount(): number {
    return this.channel?.bufferedAmount ?? 0;
  }

  /** Calls `f` once data may be handed to the socket again. */
  whenWritable(f: () => void): void {
    if (this.channel) this.channel.whenWritable(f);
    else f();
  }

  /** closed, revoked or replaced: no further connection attempts. */
  get terminal(): boolean {
    return this._state === 'closed' || this._state === 'revoked' || this._state === 'replaced';
  }

  start(): void {
    if (this._state === 'disconnected') this.dial();
  }

  /** Binary frames go out only once registered. */
  sendBinary(bytes: Uint8Array): boolean {
    return this._state === 'registered' && !!this.channel?.sendBinary(bytes);
  }

  sendControl(msg: ControlMessage): boolean {
    if (this._state !== 'registered' || !this.channel) return false;
    const n = this.channel.sendControl(msg);
    this.textSent += n;
    return n > 0;
  }

  close(): void {
    if (this._state === 'closed') return;
    clearTimeout(this.timer);
    this.setState('closed');
    this.channel?.close(1000);
    this.channel = undefined;
  }

  /** Enter the terminal revoked state (also used when a roster drops this node). */
  revoke(): void {
    if (this.terminal) return;
    clearTimeout(this.timer);
    this.setState('revoked');
    this.channel?.close(1000);
    this.channel = undefined;
  }

  private setState(s: RelayState): void {
    if (this._state === s) return;
    this._state = s;
    this.emit('state', s);
  }

  private dial(): void {
    this.setState('connecting');
    this._features = new Set();
    let challenge: Uint8Array | undefined;
    const ch: Channel = new Channel(this.url, this.o.WebSocket, {
      onControl: (msg, bytes) => {
        if (this.channel !== ch) return;
        this.textReceived += bytes;
        if (msg.type === 'hello' && challenge === undefined) {
          try {
            if (msg.version !== 1) throw new Error(`relay speaks version ${String(msg.version)}`);
            challenge = fromB64uLen(msg.challenge, 32, 'challenge');
            // Names this client does not know are ignored; a missing list is empty.
            this._features = new Set(Array.isArray(msg.features) ? msg.features.filter((f): f is string => typeof f === 'string') : []);
            this.textSent += ch.sendControl(this.registerMessage(challenge));
          } catch {
            ch.close(CloseCode.BadRequest);
          }
          return;
        }
        if (msg.type === 'registered' && challenge !== undefined && this._state === 'connecting') {
          this.backoff = this.o.backoffInitialMs;
          // A newer roster in `registered` is applied before anything is sent under it.
          this.emit('registered', msg);
          this.setState('registered');
          return;
        }
        if (this._state === 'registered' || msg.type === 'error') this.emit('control', msg);
      },
      onBinary: (bytes) => {
        if (this.channel === ch && this._state === 'registered') this.emit('binary', bytes);
      },
      onClose: (code, reason) => {
        if (this.channel !== ch) return;
        this.channel = undefined;
        this.emit('disconnect', { code, reason });
        this.afterClose(code);
      },
    });
    this.channel = ch;
  }

  private registerMessage(challenge: Uint8Array): ControlMessage {
    const roster = this.o.roster();
    const id = this.o.identity;
    const ts = this.o.now();
    const sig = id.sign(
      registerSigningBytes({ network: roster.network, node: id.id, challenge, ts, origin: originOf(this.url) }),
    );
    return {
      type: 'register',
      network: roster.network,
      node: id.id,
      ed25519: b64u(id.ed25519.pub),
      ts,
      sig: b64u(sig),
      roster,
    };
  }

  private afterClose(code: number): void {
    if (this.terminal) return;
    if (code === CloseCode.NotMember) {
      this.setState('revoked');
      return;
    }
    if (code === CloseCode.Replaced) {
      // Section 11: a newer copy of this identity holds the connection; stop rather than fight it.
      this.setState('replaced');
      return;
    }
    this.setState('disconnected');
    if (code === CloseCode.Moved) {
      const network = this.o.roster().network;
      this.emit('moved', { network });
      if (this.o.resolveRelay) {
        this.o.resolveRelay(network).then(
          (url) => {
            if (url) this.url = url;
            this.schedule();
          },
          () => this.schedule(),
        );
        return;
      }
    }
    this.schedule();
  }

  private schedule(): void {
    if (this._state !== 'disconnected') return;
    const delay = this.backoff;
    this.backoff = Math.min(this.backoff * 2, this.o.backoffMaxMs);
    clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      if (this._state === 'disconnected') this.dial();
    }, delay);
  }
}
