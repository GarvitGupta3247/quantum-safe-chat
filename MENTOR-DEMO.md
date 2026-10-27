# QuantumSafe Chat — Simple Demo Guide

## 60-second walkthrough

1. Register a test account and point out that an ML-KEM-768 keypair is generated in the browser.
2. Register a second account in a separate browser profile.
3. Send a message in both directions.
4. Explain the flow: ML-KEM encapsulates a shared secret for each message copy; HKDF-SHA-256 derives an AES key; AES-256-GCM encrypts/authenticates the message; the server relays encrypted envelopes.
5. Test live contact updates by registering/logging in a third test account without refreshing the first browser. Test background delivery by sending a message while the recipient has another chat selected, then click the sender's chat; history and cached messages should appear without a page reload.
6. Test cross-browser account access: after an existing account has logged in once on its original browser to migrate the key bundle, log in to that same account from a second browser with the same password. The server transfers only the password-encrypted private-key bundle; the browser unlocks it locally.
7. Test reconnection by briefly taking the network offline and restoring it; the WebSocket should reconnect and retry an unacknowledged send using the same client message ID.
8. If asked about security boundaries, explain that the ML-KEM private key is password-wrapped with PBKDF2-HMAC-SHA-256 and AES-256-GCM before local storage or upload. This helps protect a copied bundle when the attacker doesn't know the password, but cannot protect against malicious JavaScript or a compromised unlocked browser. Public keys are not authenticated, and a full forward-secrecy protocol remains future work. Duplicate envelope rejection and message-ID idempotency are limited replay/retry measures, not complete protocol replay protection.

## Useful source locations

- `src/main.js`: registration UI, browser key generation, KEM encapsulation/decapsulation, HKDF derivation, AES-GCM encrypt/decrypt, websocket client, send/receive message handling.
- `server/index.js`: Express API, scrypt password hashes, in-memory sessions, login throttling, security headers/CSP, `no-store` API responses, encrypted private-key bundle storage/migration, presence notifications, message-ID idempotency, envelope validation, optional `DATA_DIR`, WebSocket relay and production static file serving.
- `src/style.css`: Ember & Brass color palette and layout.
- `package.json`: dependencies and run/build scripts.
- `vite.config.js`: Vite development server and API/WebSocket proxies.

## Security questions to answer honestly

- ML-KEM-768 establishes a shared secret; it is not itself a bulk message-encryption algorithm.
- HKDF turns the shared secret into a symmetric key; AES-GCM protects the message and authenticates its ciphertext.
- The server is designed to relay encrypted message envelopes rather than plaintext bodies.
- No public-key authentication means a malicious server could substitute a contact key.
- Fresh encapsulation alone is not a full forward-secrecy protocol.
- The JSON store remains application-readable (password hashes/salts, public keys, ciphertext, and readable metadata) and can lose data on ephemeral hosting unless `DATA_DIR` points to a mounted persistent volume. Sessions still live in memory and reset after a server restart.
- Basic login throttling is in-memory, per app instance, and resets on restart.

Use only test accounts and non-sensitive messages. This project has not been independently audited.


Composer tip: press **Enter** to send a message, or **Shift+Enter** to start a new line.
