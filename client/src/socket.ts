// The WebSocket seam. The package never imports a WebSocket implementation: a
// constructor is injected, defaulting to globalThis.WebSocket (browsers, and
// Node 22+). This file adapts it to text-JSON and binary callbacks.

/** The subset of the WHATWG WebSocket this package uses. */
export interface WebSocketLike {
  binaryType: string;
  readonly readyState: number;
  readonly bufferedAmount: number;
  send(data: string | Uint8Array | ArrayBuffer): void;
  close(code?: number, reason?: string): void;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code: number; reason: string }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
}

export type WebSocketConstructor = new (url: string) => WebSocketLike;

export const MAX_CONTROL_BYTES = 1048576;

export function defaultWebSocket(): WebSocketConstructor {
  const ws = (globalThis as { WebSocket?: unknown }).WebSocket;
  if (typeof ws !== 'function') {
    throw new Error('no WebSocket implementation: pass one as the WebSocket option');
  }
  return ws as WebSocketConstructor;
}

export type ControlMessage = { type: string } & Record<string, unknown>;

export interface ChannelHandlers {
  onOpen?: () => void;
  onControl: (msg: ControlMessage) => void;
  onBinary: (bytes: Uint8Array) => void;
  /** Called exactly once. A connection that never opened reports 1006. */
  onClose: (code: number, reason: string) => void;
}

const OPEN = 1;

/** One WebSocket connection, framed as the protocol uses it. */
export class Channel {
  private readonly ws: WebSocketLike;
  private closed = false;

  constructor(url: string, WS: WebSocketConstructor, private readonly h: ChannelHandlers) {
    this.ws = new WS(url);
    this.ws.binaryType = 'arraybuffer';
    this.ws.onopen = () => this.h.onOpen?.();
    this.ws.onmessage = (ev) => this.receive(ev.data);
    this.ws.onclose = (ev) => this.finish(ev.code, ev.reason);
    this.ws.onerror = () => {
      // The close event follows with the code; nothing to add here.
    };
  }

  get isOpen(): boolean {
    return !this.closed && this.ws.readyState === OPEN;
  }

  get bufferedAmount(): number {
    return this.ws.bufferedAmount;
  }

  sendControl(msg: ControlMessage): boolean {
    if (!this.isOpen) return false;
    const text = JSON.stringify(msg);
    if (new TextEncoder().encode(text).length > MAX_CONTROL_BYTES) throw new Error('control message exceeds 1 MiB');
    this.ws.send(text);
    return true;
  }

  sendBinary(bytes: Uint8Array): boolean {
    if (!this.isOpen) return false;
    this.ws.send(bytes);
    return true;
  }

  close(code = 1000, reason = ''): void {
    if (this.closed) return;
    try {
      this.ws.close(code, reason);
    } catch {
      this.ws.close();
    }
    // Report the close now; the socket's own close event is ignored afterwards.
    this.finish(code, reason);
  }

  private receive(data: unknown): void {
    if (this.closed) return;
    if (typeof data === 'string') {
      let msg: unknown;
      try {
        msg = JSON.parse(data);
      } catch {
        return;
      }
      if (typeof msg === 'object' && msg !== null && typeof (msg as { type?: unknown }).type === 'string') {
        this.h.onControl(msg as ControlMessage);
      }
    } else if (data instanceof ArrayBuffer) {
      this.h.onBinary(new Uint8Array(data));
    } else if (ArrayBuffer.isView(data)) {
      this.h.onBinary(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
    }
  }

  private finish(code: number, reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.ws.onopen = null;
    this.ws.onmessage = null;
    this.ws.onclose = null;
    this.h.onClose(code, reason);
  }
}
