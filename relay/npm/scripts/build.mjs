// Cross-compiles the relay into vendor/<platform>-<arch>/ for every platform the
// launcher knows: static binaries (CGO_ENABLED=0), stripped, with reproducible paths.
// Run from relay/npm: `npm run build`.

import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = join(here, '..');
const relay = join(pkg, '..');

const targets = [
  ['linux', 'x64', 'linux', 'amd64'],
  ['linux', 'arm64', 'linux', 'arm64'],
  ['darwin', 'x64', 'darwin', 'amd64'],
  ['darwin', 'arm64', 'darwin', 'arm64'],
  ['win32', 'x64', 'windows', 'amd64'],
];

rmSync(join(pkg, 'vendor'), { recursive: true, force: true });
for (const [platform, arch, goos, goarch] of targets) {
  const dir = join(pkg, 'vendor', `${platform}-${arch}`);
  mkdirSync(dir, { recursive: true });
  const out = join(dir, platform === 'win32' ? 'link-relay.exe' : 'link-relay');
  execFileSync('go', ['build', '-trimpath', '-ldflags=-s -w', '-o', out, './cmd/link-relay'], {
    cwd: relay,
    env: { ...process.env, CGO_ENABLED: '0', GOOS: goos, GOARCH: goarch },
    stdio: 'inherit',
  });
  console.log(`${platform}-${arch}: ${(statSync(out).size / 1048576).toFixed(1)} MiB`);
}
