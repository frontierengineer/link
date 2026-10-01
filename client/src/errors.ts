// Typed errors. Every error this package rejects with is a LinkError with a
// stable `code`, so callers can branch without parsing messages.

export type LinkErrorCode =
  | 'unreachable'
  | 'refused'
  | 'revoked'
  | 'timeout'
  | 'closed'
  | 'pairing'
  | 'invalid';

export class LinkError extends Error {
  readonly code: LinkErrorCode;
  constructor(code: LinkErrorCode, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

/** The relay reports the peer is not connected. Nothing is queued for it. */
export class UnreachableError extends LinkError {
  constructor(readonly peer: string) {
    super('unreachable', `peer ${peer} is not connected`);
  }
}

/** The peer will not talk to this node (reason 1: this node is not on its roster). */
export class RefusedError extends LinkError {
  constructor(
    readonly peer: string,
    readonly reason: number,
  ) {
    super('refused', `peer ${peer} refused the session (reason ${reason})`);
  }
}

/** This node is no longer a member (registration closed 4008). Terminal. */
export class RevokedError extends LinkError {
  constructor() {
    super('revoked', 'this node is not a member of the network');
  }
}

export class TimeoutError extends LinkError {
  constructor(what: string) {
    super('timeout', `${what} timed out`);
  }
}

/** The member was closed, or the session ended before the operation finished. */
export class ClosedError extends LinkError {
  constructor(what = 'the member is closed') {
    super('closed', what);
  }
}

export class PairingError extends LinkError {
  constructor(message: string) {
    super('pairing', message);
  }
}

/** A caller error: bad argument, unknown peer, message too large. */
export class InvalidError extends LinkError {
  constructor(message: string) {
    super('invalid', message);
  }
}
