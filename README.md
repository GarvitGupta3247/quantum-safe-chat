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

## Let a friend on the same Wi-Fi use the app (LAN demo)

The default `npm run dev` listens only on your own computer. For a friend to connect, use the LAN mode below. **Use HTTPS:** the app relies on `crypto.subtle`, which is not generally available to browsers on an ordinary `http://192.168.x.x` LAN address.

### 1. Find your computer's LAN IP

Find your IPv4 address on the Wi-Fi adapter (for example, `192.168.1.23`). Keep your friend on the same trusted Wi-Fi network. Do not use a guest network with client isolation enabled.

### 2. Create a locally trusted HTTPS certificate

Install [mkcert](https://github.com/FiloSottile/mkcert) on the computer running the app. Then, from the project directory, run:

```bash
mkcert -install
mkdir -p certs
mkcert -key-file certs/lan-key.pem -cert-file certs/lan-cert.pem 192.168.1.23 localhost 127.0.0.1
```

Replace `192.168.1.23` with your actual LAN IP. On Windows PowerShell, use `New-Item -ItemType Directory -Force certs` instead of `mkdir -p certs` if needed.

Your friend must trust the mkcert **root certificate** on their device too, or the browser will show a certificate warning and may not expose Web Crypto. Find the root certificate directory with `mkcert -CAROOT` and securely copy only `rootCA.pem` to your friend's device, then import it into that device's trusted root certificates. **Never share `rootCA-key.pem` or `certs/lan-key.pem`.** Remove the copied `rootCA.pem` from the friend's Downloads after installing it.

### 3. Start LAN mode

In **PowerShell**, run these commands in the same terminal, replacing the example IP:

```powershell
$env:LAN_IP = "192.168.1.23"
$env:LAN_HTTPS = "1"
npm run dev:lan
```

On **macOS/Linux**, run:

```bash
LAN_IP=192.168.1.23 LAN_HTTPS=1 npm run dev:lan
```

If your OS firewall asks whether Node/Vite may accept local network connections, allow it on your **private/home network**. Only port `5173` needs to be reachable; the API/WebSocket relay stays bound to loopback behind Vite.

### 4. Connect your friend

On your computer, open `https://192.168.1.23:5173`. Your friend opens the same URL in their browser. Register different accounts in each browser and start a conversation. If it does not connect, check that both devices are on the same Wi-Fi, the LAN IP is correct, the certificate is trusted, and the firewall permits port `5173`.

This is a local educational demo, not a production-secure messenger. Use only on a trusted network and avoid real or sensitive messages.

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


## Phase 1.5 — Mentor demo build

This iteration adds the **Ember & Brass** warm palette and three practical evaluation views:

- **Crypto activity** records real ML-KEM-768 encapsulation/decapsulation, HKDF-SHA-256 derivation, AES-256-GCM encryption/decryption, byte counts, timings and abbreviated SHA-256 fingerprints of the public key, KEM ciphertext and shared secret. Raw private keys, raw shared secrets and plaintext are not logged. Download the activity trace as CSV.
- **Benchmark lab** runs 100 measured samples per supported operation in the browser: ML-KEM key generation/encapsulation/decapsulation; X25519 key generation/shared-secret derivation where Web Crypto supports it; HKDF derivation; and AES-GCM encrypt/decrypt over a 1 KiB payload. Results report median, mean and standard deviation and export to CSV.
- **Attack lab** creates real local test envelopes and verifies that altered AES-GCM ciphertext and an envelope addressed to a different ML-KEM keypair are rejected. It explicitly labels identity/key-substitution and replay protection as not implemented.

### Run locally

```bash
npm install
npm run dev
```

Open the local URL printed by Vite. For a public deployment on Render, use build command `npm install --include=dev && npm run build`, start command `npm start`, and set `NODE_ENV=production` plus `ALLOWED_ORIGINS=https://YOUR-SERVICE.onrender.com`. The server binds to `0.0.0.0` and uses Render's `PORT`.

### Important scope and limitations

This remains a research/educational prototype. Account private keys are stored unencrypted in browser localStorage; session state and the JSON database are not production-grade; identity keys are not authenticated with ML-DSA; the application does not implement replay protection or a full Double Ratchet; and forward secrecy is not provided. The UI's event log and benchmarks are observability tools, not an independent security audit. Benchmark results vary with browser and hardware. The X25519 row reports unsupported when the browser does not implement that Web Crypto algorithm.


### First deployment note

When you move from `localhost` to a Render domain, the browser treats it as a different origin. Create fresh demo accounts on the hosted domain unless you have intentionally migrated both the server account store and matching local key material. The starter project does not provide key recovery or account/key migration.
