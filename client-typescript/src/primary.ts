// The primary (section 3.1): a member that holds the network seed and that its
// roster names primary. Any member given the seed can be the primary, claiming it
// on the same connection; `Primary` is a member created as the primary, for an
// application that starts one.

import { InvalidError } from './errors.js';
import { Member, type MemberOptions } from './member.js';

export {
  CODE_LIFETIME_MS,
  CODE_ATTEMPTS,
  PAIRING_CHANNEL_MS,
  REFUSAL_EVENT_MS,
  CODE_REPLY_MS,
  REFUSAL_REPLY_RATE,
  REFUSAL_REPLY_BURST,
  CHANNEL_SETUP_RATE,
  CHANNEL_SETUP_BURST,
  USAGE_BURST,
  USAGE_INTERVAL_MS,
  PUSH_RETRY_INITIAL_MS,
  PUSH_RETRY_MAX_MS,
  type PairingCode,
  type PrimaryEvents,
  type UsageReport,
} from './primary-role.js';

export class Primary extends Member {
  /** Creates the primary and starts connecting. `networkSeed` is required; when the roster names
   * another member primary, this node claims the primary once registered (section 3.1). */
  constructor(opts: MemberOptions) {
    // Checked before the member starts connecting.
    if (opts.networkSeed === undefined) throw new InvalidError('the primary needs the network seed');
    super(opts);
  }

  /** Creates the primary and resolves once it is registered with the relay. */
  static override async connect(opts: MemberOptions): Promise<Primary> {
    const p = new Primary(opts);
    await p.waitConnected();
    return p;
  }
}
