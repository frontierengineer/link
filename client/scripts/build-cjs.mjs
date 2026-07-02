// Build the CJS half of the dual package: dist/index.cjs.
//
// The library is ESM and depends on @noble/* which is ESM-ONLY. A CJS consumer
// (e.g. an esbuild-bundled CJS backend) that `require()`s an ESM package throws
// ERR_REQUIRE_ESM. So we ship a self-contained CJS bundle with @noble INLINED and
// only `ws` kept external (it's a peerDependency — the consumer's single shared ws
// instance). The ESM build (tsc -> dist/index.js) is the `import` half; this is the
// `require` half. Consumers pick automatically via package.json "exports".
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const entry = path.join(root, 'dist', 'index.js'); // the tsc ESM output
if (!fs.existsSync(entry)) {
  console.error(`[build-cjs] ${entry} missing — run \`npm run build\` (tsc) first`);
  process.exit(1);
}

const result = await build({
  entryPoints: [entry],
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'cjs',
  outfile: path.join(root, 'dist', 'index.cjs'),
  external: ['ws'], // the ONLY external — the consumer's shared ws (peerDependency)
  legalComments: 'none',
  banner: {
    js: '// @frontierengineer/link-client — CJS bundle (@noble inlined, ws external). Generated from src/; do not edit.',
  },
});
if (result.errors.length) {
  console.error('[build-cjs] esbuild errors:', result.errors);
  process.exit(1);
}
const kib = (fs.statSync(path.join(root, 'dist', 'index.cjs')).size / 1024).toFixed(0);
console.log(`[build-cjs] wrote dist/index.cjs (${kib} KiB)`);
