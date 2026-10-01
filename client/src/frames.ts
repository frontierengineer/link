// Routed frames (section 6) and session messages (section 7.3): the two binary
// layouts of the protocol, encoded and decoded strictly.

import { concat, fromUtf8, readU32be, u32be, utf8 } from './bytes.js';

export const FRAME_VERSION = 1;
export const FRAME_HEADER = 18;
export const MAX_FRAME = 1048576;

export const FrameType = {
  HandshakeInit: 0x01,
  HandshakeResp: 0x02,
  Data: 0x03,
  Unreachable: 0x04,
  Refused: 0x05,
  Pair: 0x06,
} as const;
export type FrameType = (typeof FrameType)[keyof typeof FrameType];

export const RefusedReason = { NotOnRoster: 1 } as const;

export interface Frame {
  type: number;
  /** 16 bytes: a raw node id, or a pairing channel id for `pair` frames. */
  peer: Uint8Array;
  body: Uint8Array;
}

export function encodeFrame(type: number, peer: Uint8Array, body: Uint8Array): Uint8Array {
  if (peer.length !== 16) throw new Error('frame peer must be 16 bytes');
  const out = new Uint8Array(FRAME_HEADER + body.length);
  if (out.length > MAX_FRAME) throw new Error('frame exceeds 1 MiB');
  out[0] = FRAME_VERSION;
  out[1] = type;
  out.set(peer, 2);
  out.set(body, FRAME_HEADER);
  return out;
}

export function decodeFrame(b: Uint8Array): Frame {
  if (b.length < FRAME_HEADER) throw new Error('frame shorter than its header');
  if (b.length > MAX_FRAME) throw new Error('frame exceeds 1 MiB');
  if (b[0] !== FRAME_VERSION) throw new Error(`unknown frame version ${b[0]}`);
  return { type: b[1]!, peer: b.slice(2, 18), body: b.subarray(FRAME_HEADER) };
}

export function handshakeInitBody(senderIndex: number, noise: Uint8Array): Uint8Array {
  return concat(u32be(senderIndex), noise);
}

export function parseHandshakeInit(body: Uint8Array): { senderIndex: number; noise: Uint8Array } {
  return { senderIndex: readU32be(body, 0), noise: body.subarray(4) };
}

export function handshakeRespBody(senderIndex: number, receiverIndex: number, noise: Uint8Array): Uint8Array {
  return concat(u32be(senderIndex), u32be(receiverIndex), noise);
}

export function parseHandshakeResp(body: Uint8Array): { senderIndex: number; receiverIndex: number; noise: Uint8Array } {
  return { senderIndex: readU32be(body, 0), receiverIndex: readU32be(body, 4), noise: body.subarray(8) };
}

export function dataBody(receiverIndex: number, ciphertext: Uint8Array): Uint8Array {
  return concat(u32be(receiverIndex), ciphertext);
}

export function parseData(body: Uint8Array): { receiverIndex: number; ciphertext: Uint8Array } {
  return { receiverIndex: readU32be(body, 0), ciphertext: body.subarray(4) };
}

// ── Session messages (section 7.3) ──

export const SessionType = {
  Message: 0x01,
  Credit: 0x02,
  RosterRequest: 0x03,
  Roster: 0x04,
  Resign: 0x05,
} as const;

export const FLAG_MORE = 0x01;

export type SessionMessage =
  | { type: 'message'; more: boolean; bytes: Uint8Array }
  | { type: 'credit'; bytes: number }
  | { type: 'roster-request' }
  | { type: 'roster'; json: string }
  | { type: 'resign'; json: string };

export function encodeSessionMessage(m: SessionMessage): Uint8Array {
  switch (m.type) {
    case 'message': {
      const out = new Uint8Array(2 + m.bytes.length);
      out[0] = SessionType.Message;
      out[1] = m.more ? FLAG_MORE : 0;
      out.set(m.bytes, 2);
      return out;
    }
    case 'credit':
      if (!Number.isInteger(m.bytes) || m.bytes < 0 || m.bytes > 0xffffffff) throw new RangeError('credit out of range');
      return concat(Uint8Array.of(SessionType.Credit), u32be(m.bytes));
    case 'roster-request':
      return Uint8Array.of(SessionType.RosterRequest);
    case 'roster':
      return concat(Uint8Array.of(SessionType.Roster), utf8(m.json));
    case 'resign':
      return concat(Uint8Array.of(SessionType.Resign), utf8(m.json));
  }
}

export function decodeSessionMessage(p: Uint8Array): SessionMessage {
  if (p.length < 1) throw new Error('empty session message');
  const rest = p.subarray(1);
  switch (p[0]) {
    case SessionType.Message:
      if (rest.length < 1) throw new Error('message without flags');
      return { type: 'message', more: (rest[0]! & FLAG_MORE) !== 0, bytes: rest.subarray(1) };
    case SessionType.Credit:
      if (rest.length !== 4) throw new Error('credit must carry 4 bytes');
      return { type: 'credit', bytes: readU32be(rest, 0) };
    case SessionType.RosterRequest:
      if (rest.length !== 0) throw new Error('roster-request must be empty');
      return { type: 'roster-request' };
    case SessionType.Roster:
      return { type: 'roster', json: fromUtf8(rest) };
    case SessionType.Resign:
      return { type: 'resign', json: fromUtf8(rest) };
    default:
      throw new Error(`unknown session message type ${p[0]}`);
  }
}
