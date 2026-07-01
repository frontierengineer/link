// ─────────────────────────────────────────────────────────────────────────
// FUTURE OPTIMIZATION: this server runs via ts-node today (package.json
// "start": "ts-node index.ts"). Precompile to plain JS for production — the
// link relay is on the hot path for every relayed client connection and must
// run blazingly fast; ts-node adds startup latency + per-process overhead.
// ─────────────────────────────────────────────────────────────────────────
import { loadConfig } from './config';
import { createLinkServer } from './server';
import { log } from './log';

function main(): void {
  const config = loadConfig();
  const link = createLinkServer(config);
  link.server.listen(config.port, () => {
    log('info', 'link listening', {
      port: config.port,
      relayMaxBps: config.relayMaxBps,
      relayHourlyBytes: config.relayHourlyBytes,
      relayTrickleBps: config.relayTrickleBps,
      relayIdleSec: config.relayIdleSec,
      // Access control: open (any signed host) vs closed (allowlisted keys only).
      mode: config.allowedRegisterKeys.size > 0 ? 'closed' : 'open',
      allowedRegisterKeys: config.allowedRegisterKeys.size,
      bindAddressToKey: config.bindAddressToKey,
      origin: config.origin || '(from Host header)',
    });
  });

  // Everything is in memory, so shutdown is just: tell clients to go away.
  // Live relays drop and clients re-pair — that is the documented contract.
  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    log('info', 'shutting down', { signal });
    link.stop()
      .then(() => { log('info', 'bye'); process.exit(0); })
      .catch((err: unknown) => {
        log('error', 'shutdown failed', { err: err instanceof Error ? err.message : String(err) });
        process.exit(1);
      });
    setTimeout(() => { log('error', 'shutdown timed out; forcing exit'); process.exit(1); }, 5_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main();
