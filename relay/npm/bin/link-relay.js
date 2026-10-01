#!/usr/bin/env node
// Runs the relay binary built for this platform, passing arguments, environment and
// signals through and exiting as it exits.

import { spawn } from 'node:child_process';
import { accessSync, chmodSync, constants, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const platforms = {
  'linux-x64': 'link-relay',
  'linux-arm64': 'link-relay',
  'darwin-x64': 'link-relay',
  'darwin-arm64': 'link-relay',
  'win32-x64': 'link-relay.exe',
};

const target = `${process.platform}-${process.arch}`;
const file = platforms[target];
if (!file) {
  console.error(`link-relay: no binary for ${target}; built for ${Object.keys(platforms).join(', ')}`);
  process.exit(1);
}
const binary = join(dirname(fileURLToPath(import.meta.url)), '..', 'vendor', target, file);
if (!existsSync(binary)) {
  console.error(`link-relay: ${binary} is missing from this package`);
  process.exit(1);
}
if (process.platform !== 'win32') {
  try {
    accessSync(binary, constants.X_OK);
  } catch {
    chmodSync(binary, 0o755);
  }
}

const child = spawn(binary, process.argv.slice(2), { stdio: 'inherit', env: process.env });

// The relay shuts down cleanly on SIGTERM and SIGINT (code 1001 to every connection).
const forward = ['SIGTERM', 'SIGINT', 'SIGHUP'];
for (const sig of forward) process.on(sig, () => child.kill(sig));

child.on('error', (err) => {
  console.error(`link-relay: ${err.message}`);
  process.exit(1);
});
child.on('exit', (code, signal) => {
  if (signal) {
    // Die of the same signal, so whoever started us sees what happened.
    for (const sig of forward) process.removeAllListeners(sig);
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
