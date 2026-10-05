// Typed errors. Every error this package rejects with is a LinkError with a
// stable `code`, so callers can branch without parsing messages.

export type LinkErrorCode =
  | 'unreachable'
  | 'refused'
  | 'revoked'
  | 'replaced'
  | 'timeout'
  | 'closed'
  | 'pairing'
  | 'roster-full'
  | 'rate-limited'
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

/** A newer connection for this node took over (close 4005). Terminal: this copy stops. */
export class ReplacedError extends LinkError {
  constructor() {
    super('replaced', 'a newer connection for this node replaced this one');
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

/** Adding a member would take the roster's JCS encoding over 65000 bytes (section 3). */
export class RosterFullError extends LinkError {
  constructor(readonly bytes: number) {
    super('roster-full', `the roster would be ${bytes} bytes, over the 65000-byte limit`);
  }
}

/** The relay refused a request over its budget (section 4.3: usage asks); nothing was queued. Ask again later. */
export class RateLimitedError extends LinkError {
  constructor(what: string) {
    super('rate-limited', `${what} refused: over the relay's budget`);
  }
}

/** A caller error: bad argument, unknown peer, message too large. */
export class InvalidError extends LinkError {
  constructor(message: string) {
    super('invalid', message);
  }
}
