// Public API of @frontierengineer/link-server — the embeddable, content-blind Link
// relay. Embed it in-process (createLinkServer(config).server is a Node http.Server
// you listen() yourself) or run it standalone (see index.ts). Its ONLY runtime
// dependency is `ws` (a peerDependency — the consumer's single shared instance).
export { createLinkServer } from './server';
export type { LinkServer } from './server';
export { loadConfig } from './config';
export type { Config } from './config';
