// A Pipe is the one abstraction the secure layer needs from the network: an
// ordered, message-framed, bidirectional byte channel that can close. The Link
// relay preserves WebSocket frame boundaries verbatim, so "one frame in = one
// frame out" holds whether we are spliced through a relay or talking directly.
//
// Everything above this line (Noise, SPAKE2, the app session) is transport-
// agnostic and is unit-tested over the in-memory pipe pair below, with no
// sockets in sight.

export interface CloseInfo {
  code?: number;
  reason?: string;
}

export interface Pipe {
  // Send exactly one frame. Never throws for flow-control reasons; if the pipe
  // is closed the frame is dropped (the handshake/session will fail on recv).
  send(frame: Uint8Array): void;
  // Resolve with the next inbound frame, or reject if the pipe closes or the
  // (optional) timeout elapses first.
  recv(timeoutMs?: number): Promise<Uint8Array>;
  close(reason?: string): void;
  readonly closed: Promise<CloseInfo>;
  readonly isOpen: boolean;
}

export class PipeClosedError extends Error {
  constructor(readonly info: CloseInfo) {
    super(`pipe closed${info.reason ? `: ${info.reason}` : ''}${info.code ? ` (${info.code})` : ''}`);
    this.name = 'PipeClosedError';
  }
}

export class PipeTimeoutError extends Error {
  constructor(ms: number) {
    super(`pipe recv timed out after ${ms}ms`);
    this.name = 'PipeTimeoutError';
  }
}

// In-memory pipe backing both unit tests and any "loopback" wiring. Frames are
// delivered in order; recv() honours an optional timeout and rejects cleanly on
// close so handshake drivers can fail fast.
class MemoryPipe implements Pipe {
  private readonly queue: Uint8Array[] = [];
  private readonly waiters: { resolve: (f: Uint8Array) => void; reject: (e: Error) => void; timer?: NodeJS.Timeout }[] = [];
  private closeInfo: CloseInfo | undefined;
  private resolveClosed!: (info: CloseInfo) => void;
  readonly closed: Promise<CloseInfo> = new Promise((r) => (this.resolveClosed = r));
  peer!: MemoryPipe;

  get isOpen(): boolean {
    return this.closeInfo === undefined;
  }

  // Called by the peer to deliver a frame to us.
  deliver(frame: Uint8Array): void {
    if (this.closeInfo) return;
    const w = this.waiters.shift();
    if (w) {
      if (w.timer) clearTimeout(w.timer);
      w.resolve(frame);
    } else {
      this.queue.push(frame);
    }
  }

  send(frame: Uint8Array): void {
    if (!this.isOpen) return;
    // Copy so a caller reusing its buffer cannot mutate an in-flight frame.
    this.peer.deliver(frame.slice());
  }

  recv(timeoutMs?: number): Promise<Uint8Array> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closeInfo) return Promise.reject(new PipeClosedError(this.closeInfo));
    return new Promise((resolve, reject) => {
      const waiter: { resolve: (f: Uint8Array) => void; reject: (e: Error) => void; timer?: NodeJS.Timeout } = { resolve, reject };
      if (timeoutMs !== undefined) {
        waiter.timer = setTimeout(() => {
          const i = this.waiters.indexOf(waiter);
          if (i >= 0) this.waiters.splice(i, 1);
          reject(new PipeTimeoutError(timeoutMs));
        }, timeoutMs);
      }
      this.waiters.push(waiter);
    });
  }

  close(reason?: string): void {
    this.doClose(reason !== undefined ? { reason } : {});
    this.peer.doClose(reason !== undefined ? { reason } : {});
  }

  doClose(info: CloseInfo): void {
    if (this.closeInfo) return;
    this.closeInfo = info;
    for (const w of this.waiters.splice(0)) {
      if (w.timer) clearTimeout(w.timer);
      w.reject(new PipeClosedError(info));
    }
    this.resolveClosed(info);
  }
}

// A connected pair of in-memory pipes (client end, host end).
export function memoryPipePair(): [Pipe, Pipe] {
  const a = new MemoryPipe();
  const b = new MemoryPipe();
  a.peer = b;
  b.peer = a;
  return [a, b];
}
