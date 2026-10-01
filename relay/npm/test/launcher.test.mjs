// The package as npm would install it: `npm pack`, install the tarball into an empty
// project, then run `link-relay` from it. Needs `npm run build` first, and runs the binary
// for this machine's platform.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkg = join(dirname(fileURLToPath(import.meta.url)), '..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
let work;
let launcher;
let listing;

before(() => {
  for (const t of ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64', 'win32-x64']) {
    const exe = t.startsWith('win32') ? 'link-relay.exe' : 'link-relay';
    assert.ok(existsSync(join(pkg, 'vendor', t, exe)), `vendor/${t}/${exe} is missing: run npm run build`);
  }
  work = mkdtempSync(join(tmpdir(), 'link-server-pack-'));
  const packed = JSON.parse(execFileSync(npm, ['pack', '--json', '--pack-destination', work], { cwd: pkg, encoding: 'utf8' }));
  // npm 10 and 11 print an array of packages; npm 12 an object keyed by package name.
  listing = Array.isArray(packed) ? packed[0] : Object.values(packed)[0];
  const app = join(work, 'app');
  execFileSync('mkdir', ['-p', app]);
  writeFileSync(join(app, 'package.json'), '{"name":"app","private":true}');
  execFileSync(npm, ['install', '--no-audit', '--no-fund', '--offline', join(work, listing.filename)], { cwd: app, stdio: 'ignore' });
  launcher = join(app, 'node_modules', '.bin', process.platform === 'win32' ? 'link-relay.cmd' : 'link-relay');
});

after(() => {
  if (work) rmSync(work, { recursive: true, force: true });
});

test('the tarball holds the launcher, the README and a binary for every platform', () => {
  const files = listing.files.map((f) => f.path).sort();
  assert.deepEqual(files, [
    'README.md',
    'bin/link-relay.js',
    'package.json',
    'vendor/darwin-arm64/link-relay',
    'vendor/darwin-x64/link-relay',
    'vendor/linux-arm64/link-relay',
    'vendor/linux-x64/link-relay',
    'vendor/win32-x64/link-relay.exe',
  ]);
  assert.equal(listing.name, '@frontierengineer/link-server');
});

test('link-relay from the installed tarball serves /health and stops cleanly on SIGTERM', async () => {
  const child = spawn(launcher, [], { env: { ...process.env, LINK_ADDR: '127.0.0.1:0' }, stdio: ['ignore', 'ignore', 'pipe'] });
  const exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve({ code, signal })));
  let log = '';
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no listening line:\n${log}`)), 15000);
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (d) => {
      log += d;
      const m = /listening on 127\.0\.0\.1:(\d+)/.exec(log);
      if (m) {
        clearTimeout(timer);
        resolve(Number(m[1]));
      }
    });
  });
  const res = await fetch(`http://127.0.0.1:${port}/health`);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'ok');
  child.kill('SIGTERM');
  assert.deepEqual(await exited, { code: 0, signal: null });
  assert.match(log, /shutting down/);
});

test('arguments, environment and the exit code pass through the launcher', () => {
  // The relay takes no arguments: it prints its usage and exits 2.
  let status;
  let stderr = '';
  try {
    execFileSync(launcher, ['--help'], { encoding: 'utf8', stdio: ['ignore', 'ignore', 'pipe'] });
  } catch (e) {
    status = e.status;
    stderr = e.stderr;
  }
  assert.equal(status, 2);
  assert.match(stderr, /usage: link-relay/);
  // A bad setting in the environment reaches the relay, which refuses to start.
  try {
    execFileSync(launcher, [], { env: { ...process.env, LINK_RATE_BPS: 'fast' }, encoding: 'utf8', stdio: ['ignore', 'ignore', 'pipe'] });
    assert.fail('the relay started with a bad setting');
  } catch (e) {
    assert.equal(e.status, 1);
    assert.match(e.stderr, /LINK_RATE_BPS/);
  }
});
