// The real relay: built once per test process from ../relay with `go build`, then started
// as a child process on a random port, configured only through its environment.

import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const relaySource = join(root, 'relay');

let binary: string | undefined;

/**
 * The relay binary: LINK_RELAY_BIN when set (CI may build it once), else a static build
 * into a temporary directory, removed when the process exits.
 */
export function relayBinary(): string {
  if (binary) return binary;
  const given = process.env.LINK_RELAY_BIN;
  if (given) {
    if (!existsSync(given)) throw new Error(`LINK_RELAY_BIN=${given} does not exist`);
    return (binary = given);
  }
  const dir = mkdtempSync(join(tmpdir(), 'link-relay-'));
  process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
  const out = join(dir, process.platform === 'win32' ? 'link-relay.exe' : 'link-relay');
  execFileSync('go', ['build', '-o', out, './cmd/link-relay'], {
    cwd: relaySource,
    env: { ...process.env, CGO_ENABLED: '0' },
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  return (binary = out);
}

export interface RelayProcess {
  /** ws://127.0.0.1:<port>/v1 */
  url: string;
  /** http://127.0.0.1:<port> */
  http: string;
  port: number;
  /** Everything the relay wrote to stderr. */
  log: string[];
  /** SIGTERM, then resolves with the exit code once the process has ended. */
  stop(): Promise<number | null>;
}

/**
 * Starts the relay with `env` (the LINK_* variables) on a random loopback port, and
 * resolves once it is listening.
 */
export async function startRelay(env: Record<string, string> = {}): Promise<RelayProcess> {
  const bin = relayBinary();
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !k.startsWith('LINK_')) clean[k] = v;
  const child: ChildProcess = spawn(bin, [], {
    env: { ...clean, LINK_ADDR: '127.0.0.1:0', ...env },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  const log: string[] = [];
  const exited = new Promise<number | null>((resolve) => child.on('exit', (code) => resolve(code)));
  const port = await new Promise<number>((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error(`relay did not start:\n${log.join('')}`)), 15_000);
    child.stderr!.setEncoding('utf8');
    child.stderr!.on('data', (chunk: string) => {
      log.push(chunk);
      buf += chunk;
      const m = /listening on 127\.0\.0\.1:(\d+)/.exec(buf);
      if (m) {
        clearTimeout(timer);
        resolve(Number(m[1]));
      }
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`relay exited ${code} before listening:\n${log.join('')}`));
    });
  });
  let stopping: Promise<number | null> | undefined;
  return {
    url: `ws://127.0.0.1:${port}/v1`,
    http: `http://127.0.0.1:${port}`,
    port,
    log,
    stop() {
      if (!stopping) {
        child.kill('SIGTERM');
        const kill = setTimeout(() => child.kill('SIGKILL'), 20_000);
        stopping = exited.finally(() => clearTimeout(kill));
      }
      return stopping;
    },
  };
}
