# Upgrade to QuantumSafe Chat Reliability Update (v0.4.0)

This is an incremental update: it keeps the existing warm UI, login flow, and ML-KEM/HKDF/AES-GCM message-encryption design while fixing contact refresh, message loading, composer focus, reconnect handling, and cross-browser key access.

## Before replacing a deployed version

1. **Back up account data if possible.** The JSON store may contain account password verifiers, public keys, password-encrypted private-key bundles, ciphertext, and metadata.
2. Configure persistent storage for Render if you need accounts and messages to survive deployments. Mount a persistent disk (if your service plan supports it) at `/var/data` and set `DATA_DIR=/var/data`. On startup, this version makes a best-effort copy from the old `data/store.json` path if that file still exists; it cannot recover data already lost from an ephemeral filesystem.
3. Keep the existing GitHub repository history. Do not run `git init` in a fresh extracted folder and force-push over the deployed repository. Copy the updated project files into a clone of the existing repository, test, commit, and push normally.
4. Keep `ALLOWED_ORIGINS` set to the exact deployed `https://...onrender.com` origin and keep `NODE_ENV=production`.

## Existing account migration

Older accounts may have no server-side `privateKeyBundle` yet. For each such account:

1. Open the newly deployed app in the **original browser profile that contains that account's ML-KEM private key**.
2. Log in with the same account password. The app reads the existing local key, encrypts it with AES-256-GCM using a PBKDF2-HMAC-SHA-256 key derived from that password, and uploads only the encrypted bundle.
3. Once migration succeeds and the server has persistent storage, log in to that same account from another browser/device. The browser fetches the encrypted bundle and unlocks it locally with the password.

If an older account has no local private key and no server bundle, old messages cannot be recovered by this prototype. Do not clear browser storage before migrating an existing account.

New accounts created by this version upload a password-encrypted private-key bundle at registration time. The backend validates its structure and public-key binding but never receives the unwrapped private key.

## Local test

```powershell
npm install
npm run build
npm run dev
```

For production-shaped local testing:

```powershell
npm run build
npm start
```

Then open `http://127.0.0.1:3000`.

## Known limitations

- This is an educational prototype, not a production-secure messenger.
- Password-derived key wrapping means a lost password can mean lost access; there is no recovery key or password-change workflow.
- Public keys are not cryptographically authenticated; a malicious server could substitute a contact key.
- There is no reviewed Double Ratchet or equivalent forward-secrecy protocol.
- Sessions and login throttling remain in memory and reset on restart.
- JSON storage is not encrypted as a whole. It contains readable metadata and password hashes/salts; private-key bundles and message bodies are encrypted.
- Reconnect idempotency and duplicate-envelope checks are limited replay/retry mitigations, not full protocol-level replay protection.
