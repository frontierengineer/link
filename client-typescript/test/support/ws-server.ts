// A minimal RFC 6455 WebSocket server for the test relay: the upgrade
// handshake, masked client frames, fragmentation, ping/pong and close codes.
// Test support only; the real relay is Go.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Duplex } from 'node:stream';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export interface ServerSocketHandlers {
  onText(text: string): void;
  onBinary(bytes: Uint8Array): void;
  onClose(code: number): void;
}

export class ServerSocket {
  private buf: Buffer = Buffer.alloc(0);
  private fragments: Buffer[] = [];
  private fragOpcode = 0;
  private closed = false;
  handlers: ServerSocketHandlers | undefined;

  constructor(
    private readonly sock: Duplex,
    readonly req: IncomingMessage,
    private readonly maxMessage: number,
  ) {
    sock.on('data', (d: Buffer) => this.onData(d));
    sock.on('close', () => this.finish(1006));
    sock.on('error', () => this.finish(1006));
  }

  get isOpen(): boolean {
    return !this.closed;
  }

  sendText(text: string): void {
    this.write(0x1, Buffer.from(text, 'utf8'));
  }

  sendBinary(bytes: Uint8Array): void {
    this.write(0x2, Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  }

  close(code: number, reason = ''): void {
    if (this.closed) return;
    const r = Buffer.from(reason, 'utf8');
    const payload = Buffer.alloc(2 + r.length);
    payload.writeUInt16BE(code, 0);
    r.copy(payload, 2);
    this.write(0x8, payload);
    this.sock.end();
    this.finish(code);
  }

  /** Drops the TCP connection without a close frame. */
  destroy(): void {
    this.sock.destroy();
    this.finish(1006);
  }

  private finish(code: number): void {
    if (this.closed) return;
    this.closed = true;
    this.handlers?.onClose(code);
  }

  private write(opcode: number, payload: Buffer): void {
    if (this.closed) return;
    let header: Buffer;
    if (payload.length < 126) {
      header = Buffer.from([0x80 | opcode, payload.length]);
    } else if (payload.length < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 126;
      header.writeUInt16BE(payload.length, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(payload.length), 2);
    }
    this.sock.write(Buffer.concat([header, payload]));
  }

  private onData(d: Buffer): void {
    this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
    for (;;) {
      if (this.closed || this.buf.length < 2) return;
      const b0 = this.buf[0]!;
      const b1 = this.buf[1]!;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) {
        if (this.buf.length < 4) return;
        len = this.buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (this.buf.length < 10) return;
        len = Number(this.buf.readBigUInt64BE(2));
        off = 10;
      }
      const masked = (b1 & 0x80) !== 0;
      if (!masked) return this.close(1002);
      if (len > this.maxMessage + 1024) return this.close(1009);
      if (this.buf.length < off + 4 + len) return;
      const mask = this.buf.subarray(off, off + 4);
      const payload = Buffer.from(this.buf.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < payload.length; i++) payload[i]! ^= mask[i & 3]!;
      this.buf = this.buf.subarray(off + 4 + len);
      this.onFrame((b0 & 0x80) !== 0, b0 & 0x0f, payload);
    }
  }

  private onFrame(fin: boolean, opcode: number, payload: Buffer): void {
    if (opcode === 0x8) {
      const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
      this.write(0x8, payload.subarray(0, 2));
      this.sock.end();
      this.finish(code);
      return;
    }
    if (opcode === 0x9) return this.write(0xa, payload);
    if (opcode === 0xa) return;
    if (opcode === 0x1 || opcode === 0x2) {
      this.fragOpcode = opcode;
      this.fragments = [payload];
    } else if (opcode === 0x0) {
      this.fragments.push(payload);
    } else {
      return this.close(1002);
    }
    if (!fin) return;
    const whole = this.fragments.length === 1 ? this.fragments[0]! : Buffer.concat(this.fragments);
    this.fragments = [];
    if (this.fragOpcode === 0x1) this.handlers?.onText(whole.toString('utf8'));
    else this.handlers?.onBinary(new Uint8Array(whole.buffer, whole.byteOffset, whole.byteLength));
  }
}

export interface WsServer {
  url: string;
  server: Server;
  close(): Promise<void>;
}

/** Listens on 127.0.0.1 at a free port and hands each upgraded socket to `onSocket`. */
export async function listen(
  path: string,
  maxMessage: number,
  onSocket: (s: ServerSocket) => void,
): Promise<WsServer> {
  const sockets = new Set<Duplex>();
  const server = createServer((_req, res) => {
    res.writeHead(426).end();
  });
  server.on('upgrade', (req, sock: Duplex) => {
    const key = req.headers['sec-websocket-key'];
    if (req.url?.split('?')[0] !== path || typeof key !== 'string') {
      sock.end('HTTP/1.1 404 Not Found\r\n\r\n');
      return;
    }
    const accept = createHash('sha1').update(key + GUID).digest('base64');
    sock.write(
      'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    sockets.add(sock);
    sock.on('close', () => sockets.delete(sock));
    onSocket(new ServerSocket(sock, req, maxMessage));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `ws://127.0.0.1:${port}${path}`,
    server,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
      }),
  };
}
