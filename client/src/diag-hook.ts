// The seam between the core and the optional diagnostics entry point
// (`@frontierengineer/link-client/diagnostics`). The core holds at most one hook
// and checks it once per send and per receive; everything that inspects
// messages lives in diagnostics.ts, so a bundle that never imports it carries
// none of that code.

/** The key a member's diagnostics hook is installed under. Global, so separately bundled copies agree. */
export const DIAGNOSTICS: unique symbol = Symbol.for('@frontierengineer/link-client/diagnostics') as never;

/** Things the core tells an installed hook about, besides messages. */
export type DiagnosticsEvent =
  /** This side started a handshake with `peer` (a first session, a rekey or a retry). */
  | { kind: 'handshake'; peer: string }
  /** A send to `peer` failed: it is not connected. */
  | { kind: 'unreachable'; peer: string }
  /** The relay connection is being dialled again after it had been registered. */
  | { kind: 'reconnect' }
  /** A newer copy of this identity replaced this one (close 4005). */
  | { kind: 'replaced' }
  /** The primary asked the relay for usage; `refused` when the relay answered rate_limited. */
  | { kind: 'usageAsk' }
  | { kind: 'usageRefused' }
  /** A usage answer arrived. */
  | { kind: 'usage'; slowed: boolean; trickleBps: number };

/** Counters the core keeps whether or not diagnostics are installed. */
export interface CoreStats {
  /** Credit messages this side sent, and whole messages it received. */
  creditsSent: number;
  messagesReceived: number;
  /** High-water mark of message bytes sent on one session and not yet credited back. */
  inflightMaxBytes: number;
  /** High-water mark of bytes waiting in the socket when a data fragment was handed over. */
  socketBacklogMaxBytes: number;
  /** High-water mark of bytes already waiting in the socket when a control frame was handed over. */
  controlBacklogMaxBytes: number;
}

/** What `enableDiagnostics` installs on a member. Not for applications: use the diagnostics entry point. */
export interface DiagnosticsHook {
  /** Before a message goes anywhere; may throw (`throw` mode), which fails the send. */
  send(peer: string, bytes: Uint8Array): void;
  /** A message was handed to the relay (or failed) `waitedMs` after `send` was called. */
  sent(peer: string, size: number, waitedMs: number, failed: boolean): void;
  received(peer: string, bytes: Uint8Array): void;
  event(e: DiagnosticsEvent): void;
  report(stats: CoreStats): DiagnosticsReport;
  reset(): void;
}

export type FindingKind =
  | 'textEncodedBinary'
  | 'base64InJson'
  | 'hotJsonHeaders'
  | 'tinyBatchable'
  | 'compressibleUncompressed'
  | 'compressedNoGain'
  | 'backlog'
  | 'usageAsks'
  | 'sentWhileSlowed'
  | 'unreachableRetries'
  | 'sessionChurn';

/** `member.diagnostics()`: sizes, counts, verdicts and peer ids; never payload bytes. */
export interface DiagnosticsReport {
  mode: 'count' | 'warn' | 'throw';
  sent: { messages: number; bytes: number };
  received: { messages: number; bytes: number };
  /** Findings per kind: what warns, throws and calls onFinding. All zero is a clean run. */
  counts: Record<FindingKind, number>;
  findings: {
    /** R1: a whole message is base64, base64url or hex text. */
    textEncodedBinary: { count: number; bytes: number; firstAt: number | null };
    /** R1: a JSON message carries a long base64 or hex string. */
    base64InJson: { count: number; bytes: number; firstAt: number | null };
    /** R2: over 10 messages a second to a peer, each more than 25% JSON header. */
    hotJsonHeaders: { count: number; jsonBytes: number };
    /** R3: tiny messages to one peer less than 40 ms apart, sustained. */
    tinyBatchable: { count: number };
    /** R4: large, low-entropy messages sent uncompressed (sampled; confirmed with deflate-raw where available). */
    compressibleUncompressed: { sampled: number; flagged: number; confirmed: number; confirmedSavings: number[]; estSavableBytes: number };
    /** R5: the compression helper saved under 10%. */
    compressedNoGain: { count: number; bytes: number };
    /** R6: high-water marks; `count` is small messages that waited over 2 s to be handed over. */
    backlog: {
      count: number;
      inflightMaxBytes: number;
      socketBacklogMaxBytes: number;
      controlBacklogMaxBytes: number;
      queuedMaxBytes: number;
      waitMaxMs: number;
    };
    /** R7: usage asks, refusals, and asks made with 80% or more of the relay's budget spent. */
    usageAsks: { count: number; refused: number; nearBudget: number };
    /** R8: bytes sent since a usage answer said slowed, and the count of times that beat the trickle rate. */
    sentWhileSlowed: { count: number; bytes: number };
    /** R9: sends that failed unreachable (all of them); the worst peer's count within one minute. */
    unreachableRetries: { count: number; worstPeerPerMin: number };
    /** R10: findings; handshakes this side started, the most with one peer within one rekey interval, reconnects, replacements. */
    sessionChurn: { count: number; handshakes: number; perPeerPerIntervalMax: number; reconnects: number; reconnectsPerMinMax: number; replaced: number };
    /** The library's own check, over the member's whole life (not cleared by a reset): credit messages sent per message received. */
    credits: { sent: number; messagesReceived: number; sentPerMessageReceived: number };
  };
  /** Finding kinds accepted with a stated reason; they are still counted, never warned or thrown. */
  accepted: Partial<Record<FindingKind, string>>;
}

/** Listeners told of every `deflate` from the compression entry point: input and output sizes. */
export type CompressionListener = (inBytes: number, outBytes: number) => void;

/** The process-wide set of compression listeners (global, so separately bundled copies agree). */
export function compressionListeners(): Set<CompressionListener> {
  const key = Symbol.for('@frontierengineer/link-client/compression');
  const g = globalThis as unknown as Record<symbol, Set<CompressionListener> | undefined>;
  return (g[key] ??= new Set());
}
