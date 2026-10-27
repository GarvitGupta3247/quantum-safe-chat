# QuantumSafe Chat — Simple Demo Guide

## 60-second walkthrough

1. Register a test account and point out that an ML-KEM-768 keypair is generated in the browser.
2. Register a second account in a separate browser profile.
3. Send a message in both directions.
4. Explain the flow: ML-KEM encapsulates a shared secret for each message copy; HKDF-SHA-256 derives an AES key; AES-256-GCM encrypts/authenticates the message; the server relays encrypted envelopes.
5. If asked about security boundaries, state that private keys remain in browser localStorage but are currently unencrypted, public keys are not authenticated, and a full forward-secrecy protocol is planned for Phase 2. The backend also rejects duplicate recipient envelopes already present in retained history, but this is not a complete replay defense.

## Useful source locations

- `src/main.js`: registration UI, browser key generation, KEM encapsulation/decapsulation, HKDF derivation, AES-GCM encrypt/decrypt, websocket client, send/receive message handling.
- `server/index.js`: Express API, scrypt password hashes, in-memory sessions, login throttling, envelope validation, WebSocket relay and production static file serving.
- `src/style.css`: Ember & Brass color palette and layout.
- `package.json`: dependencies and run/build scripts.
- `vite.config.js`: Vite development server and API/WebSocket proxies.

## Security questions to answer honestly

- ML-KEM-768 establishes a shared secret; it is not itself a bulk message-encryption algorithm.
- HKDF turns the shared secret into a symmetric key; AES-GCM protects the message and authenticates its ciphertext.
- The server is designed to relay encrypted message envelopes rather than plaintext bodies.
- No public-key authentication means a malicious server could substitute a contact key.
- Fresh encapsulation alone is not a full forward-secrecy protocol.
- Local JSON storage and in-memory sessions are demo-level and can lose data/session state after a hosting restart.
- Basic login throttling is in-memory, per app instance, and resets on restart.

Use only test accounts and non-sensitive messages. This project has not been independently audited.


Composer tip: press **Enter** to send a message, or **Shift+Enter** to start a new line.
