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
- ML-KEM private keys are encrypted with AES-256-GCM using a password-derived PBKDF2-HMAC-SHA-256 key (600,000 iterations). The encrypted key bundle is stored on the server and locally, allowing the same account to unlock the same key on another browser after a successful login.
- One-time migration for accounts created before encrypted server-side key bundles existed: users must log in on the original browser once so the existing key can be wrapped and uploaded.
- The server never receives the unwrapped private key. The bundle itself is encrypted client-side before transmission, but account/password compromise or malicious JavaScript remains in scope as a risk.
- Security response headers, a Content Security Policy, and `Cache-Control: no-store` on API responses.
- Duplicate recipient-envelope detection plus client message IDs that make reconnect retries idempotent, preventing the same acknowledged send from being stored twice. This is still not full protocol-level replay protection.
- Live contact/presence updates, per-conversation message caching, race-safe history loading, reconnect backoff, and pending-send retry.
- Drafts are preserved when switching conversations and cleared only after the server confirms a message was saved.
- Optional `DATA_DIR` environment variable so the JSON store can live on a mounted persistent volume; startup attempts a one-time copy from the old local `data/store.json` if the file is still available.
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
- Optional `DATA_DIR=/var/data` if you configure a persistent disk mounted at `/var/data` on your Render service. Use the exact mount path you configure.

The server reads Render's `PORT` environment variable and listens on `0.0.0.0`. A persistent disk/managed database is needed if accounts, messages, and encrypted key bundles must survive ephemeral filesystem resets. If you add a disk to an existing deployment, configure `DATA_DIR` and redeploy; the app attempts a best-effort copy from the old `data/store.json` only if that file is still present during startup. Back up data before changing storage paths where possible.

## Security improvements and remaining limitations

This is an educational proof of concept, not a production-secure messenger. The ML-KEM private key is now encrypted before it is stored in browser `localStorage`: the user's password is processed with PBKDF2-HMAC-SHA-256 (600,000 iterations) to derive an AES-256-GCM wrapping key, and the private-key ciphertext uses a fresh random salt and nonce. A legacy plaintext key record is migrated after a successful login. This reduces risk from someone who can read the localStorage file without also knowing the user's password; it does not protect against malicious JavaScript running on the site, malware in an unlocked browser, weak passwords, or key theft while the key is in use. Users must re-enter their password after reloading the app to unlock the key. Older plaintext local key records are migrated the next time the user successfully logs in. If the user loses the password or local key data, key recovery is not implemented.

The server also sends a Content Security Policy and other security response headers and marks API responses `no-store`. It validates encrypted-envelope lengths, throttles repeated login failures, and rejects duplicate recipient-envelope copies still present in retained message history. That duplicate check is only basic replay mitigation, not complete protocol-level replay protection. Public keys are not cryptographically authenticated, so a malicious server could substitute a contact key. A reviewed Double Ratchet or other forward-secrecy protocol is not implemented. Login throttling and sessions are process-local and reset on restart; throttling is not distributed across multiple instances. The JSON store contains password hashes/salts, public keys, message ciphertext and readable metadata; the entire file is not encrypted by the application. Use `DATA_DIR` to place it on a configured persistent mounted volume if available. Without persistent storage or a database, data can be lost on ephemeral hosting filesystems.

Use only test accounts and non-sensitive messages. Do not claim that the whole application is production-secure or fully quantum-safe.


### Message composer shortcuts

- Press **Enter** to send a message.
- Press **Shift+Enter** to insert a newline.
- The message composer keeps keyboard focus after re-renders.
- Contacts and online/offline presence update live through WebSocket events.
- Conversation history is cached per chat, incoming background messages are decrypted/cached, and stale history responses are ignored.
- The WebSocket reconnects with exponential backoff and resends unacknowledged packets using the same message ID.
- A draft is cleared only after the server acknowledges the message was persisted.
- Existing account key migration: sign in on the original browser once; the encrypted key bundle is then available on other browsers for the same account.
