import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vite';

// LAN mode must use HTTPS because the app uses browser Web Crypto APIs.
// Create these files with mkcert; do not commit or share the private key.
const lanHttps = process.env.LAN_HTTPS === '1';
const https = lanHttps
  ? {
      key: readFileSync(resolve(process.env.LAN_TLS_KEY || 'certs/lan-key.pem')),
      cert: readFileSync(resolve(process.env.LAN_TLS_CERT || 'certs/lan-cert.pem')),
    }
  : undefined;

export default defineConfig({
  server: {
    host: '0.0.0.0',
    https,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:3000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://127.0.0.1:3000',
        ws: true,
      },
    },
  },
});
