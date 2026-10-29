import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from './app.js';

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

const server = await createServer({
  // Point DATA_DIR at a mounted persistent volume in production when one is configured.
  dataDir: resolve(process.env.DATA_DIR || join(projectRoot, 'data')),
  distDir: join(projectRoot, 'dist'),
});
const port = Number(process.env.PORT || 3000);
await server.listen(port, '0.0.0.0');
console.log(`QuantumSafe Chat API + WebSocket relay listening on port ${port}`);
console.log('Research prototype: not independently audited. See SECURITY.md before handling real data.');
