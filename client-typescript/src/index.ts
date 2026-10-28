// @frontierengineer/link-client: the public surface.

export {
  createIdentity,
  identityFromSeed,
  nodeIdFromEd25519,
  isNodeId,
  networkKeyFromSeed,
  createNetworkSeed,
  type Identity,
  type NetworkKey,
} from './identity.js';
export {
  createNetwork,
  placeNetwork,
  isPlaced,
  isRelayUrl,
  signRoster,
  rosterProblem,
  isValidRoster,
  acceptanceProblem,
  rosterSigningBytes,
  rosterSize,
  MAX_ROSTER_BYTES,
  memberFromIdentity,
  findMember,
  primaryOf,
  type Roster,
  type UnsignedRoster,
  type RosterMember,
} from './roster.js';
export { canonicalize, type JsonValue } from './jcs.js';
export {
  pickRelay,
  shardOf,
  parseDirectory,
  type RelayDirectory,
  type DirectoryRegion,
  type PickRelayOptions,
  type PickedRelay,
} from './directory.js';
export {
  generateCode,
  normalizeCode,
  formatCode,
  buildPairingLink,
  parsePairingLink,
  buildPairingParams,
  parsePairingParams,
  DEFAULT_CODE_ID,
  type PairingLink,
  type PairingParts,
} from './code.js';
export { pair, type PairOptions, type PairTarget, type PairResult } from './newcomer.js';
export {
  Member,
  DEFAULT_TIMING,
  DEMOTED_REASON,
  type MemberOptions,
  type MemberState,
  type MemberEvents,
  type InboundMessage,
  type Timing,
  type Traffic,
  type PeerTraffic,
  type TrafficReport,
  type Shaping,
} from './member.js';
export {
  Primary,
  CODE_LIFETIME_MS,
  CODE_ATTEMPTS,
  USAGE_BURST,
  USAGE_INTERVAL_MS,
  type PairingCode,
  type PrimaryEvents,
  type UsageReport,
} from './primary.js';
export { DEFAULT_CREDIT_WINDOW, INITIAL_CREDIT, MAX_MESSAGE, CREDIT_BATCH_BYTES, CREDIT_DELAY_MS, PACE_FLOOR_BYTES, PACE_SHARE, pacedFragment } from './sessions.js';
export type { DiagnosticsReport, FindingKind, CoreStats } from './diag-hook.js';
export { CloseCode } from './relay.js';
export {
  LinkError,
  UnreachableError,
  RefusedError,
  RevokedError,
  ReplacedError,
  TimeoutError,
  ClosedError,
  PairingError,
  InvalidError,
  RosterFullError,
  RateLimitedError,
  type LinkErrorCode,
} from './errors.js';
export { MAX_CONTROL_BYTES } from './socket.js';
export type { WebSocketLike, WebSocketConstructor, WebSocketStreamLike, WebSocketStreamConstructor } from './socket.js';
