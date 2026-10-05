// The WebSocket seam. The package never imports a WebSocket implementation: a
// constructor is injected, defaulting to globalThis.WebSocketStream where it
// exists (real back-pressure) and globalThis.WebSocket otherwise (browsers, and
// Node 22+). This file adapts either to text-JSON and binary callbacks, and
// tells the sender how much it has handed the socket that is not yet on the
// network, so data waits in the client's own queue rather than in the socket.

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

/** The subset of the WHATWG WebSocketStream this package uses. */
export interface WebSocketStreamLike {
  readonly opened: Promise<{ readable: ReadableStream<unknown>; writable: WritableStream<unknown> }>;
  readonly closed: Promise<{ closeCode?: number; reason?: string }>;
  close(info?: { closeCode?: number; reason?: string }): void;
}

export type WebSocketStreamConstructor = new (url: string) => WebSocketStreamLike;

/** Control (text) messages are at most 128 KiB (section 4). */
export const MAX_CONTROL_BYTES = 131072;

/** Data is handed to a socket only while at most this much is waiting in it. */
export const SOCKET_LOW_WATER = 65536;

/** How often a classic WebSocket's bufferedAmount is looked at while data waits on it. */
const DRAIN_POLL_MS = 10;

export function defaultWebSocket(): WebSocketConstructor {
  const ws = (globalThis as { WebSocket?: unknown }).WebSocket;
  if (typeof ws !== 'function') {
    throw new Error('no WebSocket implementation: pass one as the WebSocket option');
  }
  return ws as WebSocketConstructor;
}

/** globalThis.WebSocketStream, where the platform has it. */
export function globalWebSocketStream(): WebSocketStreamConstructor | undefined {
  const wss = (globalThis as { WebSocketStream?: unknown }).WebSocketStream;
  return typeof wss === 'function' ? (wss as WebSocketStreamConstructor) : undefined;
}

/** The socket a member dials with: an explicit WebSocket wins, then an explicit or global WebSocketStream. */
export function chooseSocket(opts: { WebSocket?: WebSocketConstructor | undefined; WebSocketStream?: WebSocketStreamConstructor | undefined }): WebSocketConstructor {
  if (opts.WebSocket) return opts.WebSocket;
  const wss = opts.WebSocketStream ?? globalWebSocketStream();
  return wss ? streamSocket(wss) : defaultWebSocket();
}

/** UTF-8 length of a string, without encoding it. */
export function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

/**
 * A WebSocketStream behind the WebSocketLike shape. `bufferedAmount` is the bytes written
 * whose write has not completed (the stream resolves a write once the data is sent), and
 * `ondrain` fires as writes complete, so the channel waits on real back-pressure instead of
 * polling. Close codes, and 1006 for a connection that never opened, match the classic socket.
 */
export function streamSocket(WSS: WebSocketStreamConstructor): WebSocketConstructor {
  return class StreamSocket implements WebSocketLike {
    binaryType = 'arraybuffer';
    readyState = 0;
    bufferedAmount = 0;
    onopen: ((ev: unknown) => void) | null = null;
    onmessage: ((ev: { data: unknown }) => void) | null = null;
    onclose: ((ev: { code: number; reason: string }) => void) | null = null;
    onerror: ((ev: unknown) => void) | null = null;
    /** Called whenever a write completes (bufferedAmount fell). */
    ondrain: (() => void) | null = null;
    private readonly wss: WebSocketStreamLike;
    private writer: WritableStreamDefaultWriter<unknown> | undefined;
    private ended = false;

    constructor(url: string) {
      this.wss = new WSS(url);
      this.wss.opened.then(
        ({ readable, writable }) => {
          if (this.ended || this.readyState !== 0) return;
          this.writer = writable.getWriter();
          this.readyState = 1;
          this.onopen?.({});
          void this.pump(readable.getReader());
        },
        () => undefined, // `closed` rejects too and reports it
      );
      this.wss.closed.then(
        (info) => this.finish(info.closeCode ?? 1005, info.reason ?? ''),
        (e: unknown) => {
          const code = (e as { closeCode?: unknown } | null)?.closeCode;
          this.onerror?.(e);
          this.finish(typeof code === 'number' && code !== 0 ? code : 1006, '');
        },
      );
    }

    send(data: string | Uint8Array | ArrayBuffer): void {
      if (this.readyState !== 1 || !this.writer) throw new Error('WebSocketStream is not open');
      const size = typeof data === 'string' ? utf8Length(data) : data.byteLength;
      this.bufferedAmount += size;
      const done = () => {
        this.bufferedAmount -= size;
        this.ondrain?.();
      };
      this.writer.write(data).then(done, done);
    }

    close(code?: number, reason?: string): void {
      if (this.readyState >= 2) return;
      this.readyState = 2;
      const info: { closeCode?: number; reason?: string } = {};
      if (code !== undefined) info.closeCode = code;
      if (reason !== undefined) info.reason = reason;
      this.wss.close(info);
    }

    private async pump(reader: ReadableStreamDefaultReader<unknown>): Promise<void> {
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done || this.ended) return;
          this.onmessage?.({ data: value });
        }
      } catch {
        // The stream errored; `closed` reports how.
      }
    }

    private finish(code: number, reason: string): void {
      if (this.ended) return;
      this.ended = true;
      this.readyState = 3;
      this.onclose?.({ code, reason });
    }
  };
}

export type ControlMessage = { type: string } & Record<string, unknown>;

export interface ChannelHandlers {
  onOpen?: () => void;
  /** A control message and its size in UTF-8 bytes. */
  onControl: (msg: ControlMessage, bytes: number) => void;
  onBinary: (bytes: Uint8Array) => void;
  /** Called exactly once. A connection that never opened reports 1006. */
  onClose: (code: number, reason: string) => void;
}

const OPEN = 1;

/** One WebSocket connection, framed as the protocol uses it. */
export class Channel {
  private readonly ws: WebSocketLike;
  private closed = false;
  private drainWaiters: (() => void)[] = [];
  private drainTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(url: string, WS: WebSocketConstructor, private readonly h: ChannelHandlers) {
    this.ws = new WS(url);
    this.ws.binaryType = 'arraybuffer';
    this.ws.onopen = () => this.h.onOpen?.();
    this.ws.onmessage = (ev) => this.receive(ev.data);
    this.ws.onclose = (ev) => this.finish(ev.code, ev.reason);
    this.ws.onerror = () => {
      // The close event follows with the code; nothing to add here.
    };
    const streamed = this.ws as { ondrain?: (() => void) | null };
    if ('ondrain' in streamed) streamed.ondrain = () => this.drained();
  }

  get isOpen(): boolean {
    return !this.closed && this.ws.readyState === OPEN;
  }

  /** Bytes handed to the socket and not yet sent. */
  get bufferedAmount(): number {
    return this.ws.bufferedAmount;
  }

  /** Data may be handed over: little enough is waiting in the socket (or it is not open, so a send fails at once). */
  get writable(): boolean {
    return !this.isOpen || this.ws.bufferedAmount <= SOCKET_LOW_WATER;
  }

  /** Calls `f` once the socket is `writable` again (at once if it is). */
  whenWritable(f: () => void): void {
    if (this.writable) {
      f();
      return;
    }
    this.drainWaiters.push(f);
    // A WebSocketStream says when writes complete; a classic socket is looked at until it drains.
    if (!('ondrain' in (this.ws as object)) && this.drainTimer === undefined) this.poll();
  }

  /** Sends a control message; returns its size in UTF-8 bytes, or 0 when not open. */
  sendControl(msg: ControlMessage): number {
    if (!this.isOpen) return 0;
    const text = JSON.stringify(msg);
    const size = utf8Length(text);
    if (size > MAX_CONTROL_BYTES) throw new Error('control message exceeds 128 KiB');
    this.ws.send(text);
    return size;
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

  private poll(): void {
    this.drainTimer = setTimeout(() => {
      this.drainTimer = undefined;
      if (this.writable) this.drained();
      else if (this.drainWaiters.length > 0) this.poll();
    }, DRAIN_POLL_MS);
  }

  private drained(): void {
    if (!this.writable || this.drainWaiters.length === 0) return;
    for (const f of this.drainWaiters.splice(0)) f();
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
        this.h.onControl(msg as ControlMessage, utf8Length(data));
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
    clearTimeout(this.drainTimer);
    this.drainTimer = undefined;
    this.ws.onopen = null;
    this.ws.onmessage = null;
    this.ws.onclose = null;
    // Whoever waits to write learns at once that the socket is gone.
    for (const f of this.drainWaiters.splice(0)) f();
    this.h.onClose(code, reason);
  }
}
