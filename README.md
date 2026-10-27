# QuantumSafe Chat — Simple Phase 1 build

A minimal one-to-one messaging prototype with a warm Ember & Brass interface. The UI focuses on chat only; the separate Crypto Activity, Benchmarks, and Attack Lab screens are removed from this variant.

## What it does

- Username/password registration and login.
- ML-KEM-768 key generation in the browser.
- Client-side per-message key establishment using ML-KEM encapsulation, HKDF-SHA-256 key derivation, and AES-256-GCM message encryption.
- WebSocket relay of encrypted message envelopes.
- Salted scrypt password hashes on the backend.
- HttpOnly, SameSite session cookies, marked Secure in production.
- Basic in-memory login throttling: after 8 failed attempts from an IP within the current window, further attempts are blocked for 15 minutes.
- Render-compatible binding on `0.0.0.0` and `process.env.PORT`.

## Run locally

Requires Node.js 20+.

```bash
npm install
npm run dev
```

Open the local URL printed by Vite. The development frontend and backend run as separate processes. For the production-shaped local test:

```bash
npm run build
npm start
```

Then open `http://127.0.0.1:3000`.

## Render settings

- Build command: `npm install --include=dev && npm run build`
- Start command: `npm start`
- `NODE_ENV=production`
- `ALLOWED_ORIGINS=https://YOUR-SERVICE.onrender.com` (replace with the exact Render origin; no trailing slash)

The server reads Render's `PORT` environment variable and listens on `0.0.0.0`.

## Important security limitations

This is an educational proof of concept, not a production-secure messenger. The browser stores the ML-KEM private key unencrypted in `localStorage`. Public keys are not authenticated, so the system does not protect against malicious public-key substitution. The implementation detects duplicate copies of the same recipient envelope among retained messages, but this is not complete protocol-level replay protection. It does not provide a reviewed Double Ratchet or forward secrecy. Login throttling is process-local and resets on restart; it is not a substitute for a distributed rate limiter. Accounts and message envelopes are stored in `data/store.json`, which can be lost on ephemeral hosting filesystems unless persistent storage or a database is configured. Sessions are in memory and reset on server restart.

Use only test accounts and non-sensitive messages. Do not claim that the whole application is production-secure or fully quantum-safe.


### Message composer shortcuts

- Press **Enter** to send a message.
- Press **Shift+Enter** to insert a newline.
