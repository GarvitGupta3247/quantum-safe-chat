# QuantumSafe Chat — minimal ML-KEM messaging PoC

A deliberately small first milestone for the proposed QuantumSafe Chat project. It gives you a browser chat UI, basic username/password accounts, a WebSocket relay, and a post-quantum key-encapsulation step for each message. It does **not** implement ML-DSA authentication or a Double Ratchet.

## What is implemented

- Register/log in with a username and password. Usernames are 3–24 characters (`A–Z`, `a–z`, digits, `_`, `-`); passwords must be at least 8 characters.
- Passwords are stored as salted Node.js `scrypt` hashes, not plaintext.
- Browser generates an **ML-KEM-768** key pair at registration. The server stores the public key only.
- For every message, the sender runs a fresh ML-KEM-768 encapsulation, derives a key with HKDF-SHA-256, and encrypts the content with AES-256-GCM using the browser Web Crypto API.
- The message is encrypted separately to the sender's own public key as well, so the sender can decrypt sent-message history after a reload.
- The WebSocket server stores and relays only encrypted envelopes and metadata. It does not receive plaintext messages or private keys.
- Encrypted message history is persisted in `data/store.json`; accounts are stored there too.

ML-KEM is a key-encapsulation mechanism, not an encryption algorithm by itself. The shared secret is used to derive an AES-GCM key for the message payload. ML-KEM-768's standardized public-key and ciphertext sizes are checked by the server.

## Run locally

Requirements: Node.js 20+ and npm.

```bash
npm install
npm run dev
```

Open the URL printed by Vite (normally `http://127.0.0.1:5173`). Create one account, then open the same URL in a second browser or a private/incognito window and create another account. Select the other user and send a message.

To run a built frontend from the Node server instead:

```bash
npm run build
npm start
```

Then open `http://127.0.0.1:3000`.

The browser crypto operations run locally; the dev server uses a Vite proxy for `/api` and `/ws`. For a demo with two users, use two separate browser profiles because accounts' private keys are saved to browser-local storage.

## Suggested first demo checklist

1. Register `alice` in Browser A and `bob` in Browser B.
2. Send messages in both directions.
3. Refresh each browser and confirm it can decrypt conversation history.
4. Inspect the WebSocket frames / `data/store.json`: message bodies should not appear as plaintext.
5. Try logging Alice in from a browser without Alice's local private key; the app should reject that login session because the private key cannot be recovered.

## Important limitations (not production-ready)

This is an educational proof of concept, not a secure messenger. Do not use it for real or sensitive messages.

- **No ML-DSA identity authentication.** A username/password login authenticates to this demo server, but does not cryptographically authenticate the chat peer's ML-KEM public key. A malicious or compromised server could substitute public keys or otherwise facilitate a man-in-the-middle attack. Add signed key binding / key verification before making security claims.
- **No forward secrecy.** Every message has a fresh encapsulation, but it is addressed to a long-term ML-KEM key. If that private key is later compromised, an attacker who retained historical ciphertexts may be able to decrypt them. This is not a Double Ratchet.
- **Private keys are stored unencrypted in `localStorage`.** That is only a temporary demo convenience. Any script running on the origin could access them. There is no key backup or recovery.
- **The server stores account records and ciphertext in a local JSON file.** It uses in-memory sessions, has no rate limiting, no password reset, and no account recovery. Sessions are lost when the server restarts.
- **Use HTTPS/WSS outside localhost.** This starter is configured for local development and has not undergone a security audit, independent cryptographic review, or penetration test.
- Message metadata (sender, recipient, timestamp, and message size) is not hidden from the server.
- Group chats, multi-device key management, attachments, deletion, abuse controls, and a production database are out of scope.

## Stack

- Frontend: vanilla JavaScript, Vite, CSS
- ML-KEM: [`mlkem`](https://www.npmjs.com/package/mlkem), using the ML-KEM-768 API
- Symmetric encryption / KDF: Web Crypto API (AES-256-GCM and HKDF-SHA-256)
- Backend: Node.js, Express, `ws`
- Password hashing: Node.js `scrypt`

## Next steps after the PoC works

1. Add a proper, reviewed key-storage strategy and identity key verification.
2. Add ML-DSA signatures and a challenge-response login / signed public-key binding.
3. Design a reviewed session protocol with forward secrecy and post-compromise recovery rather than treating per-message KEM encapsulation as a ratchet.
4. Add tests for cross-browser interoperability, invalid ciphertexts, tampering, replay behavior, server input validation, and key mismatch cases.
5. Add reproducible benchmarks for key generation, encapsulation/decapsulation, message size, and end-to-end latency.
