# QuantumSafe Chat — Research Lab build (v0.5.0)

QuantumSafe Chat is an educational proof of concept for browser-side post-quantum key establishment and encrypted messaging. This build keeps the chat UI and adds a Research Lab with live cryptographic tracing, a measured ML-KEM-768/X25519 comparison, and focused security tests.

> **Scope:** experimental project, not a production-secure messenger. Public-key identity authentication, a reviewed forward-secrecy protocol, account recovery, and a full protocol replay defense are not implemented.

## Features

- Username/password accounts; password verifiers use salted Node.js `scrypt`.
- Browser-side ML-KEM-768 key generation, encapsulation and decapsulation using the `mlkem` package.
- HKDF-SHA-256 key derivation and AES-256-GCM message encryption/decryption using Web Crypto.
- Sender-history and recipient-specific encrypted message envelopes; backend stores/relays envelopes and visible metadata.
- Password-encrypted ML-KEM private-key bundles: PBKDF2-HMAC-SHA-256 with 600,000 iterations wraps the private key using AES-256-GCM. The server stores only the encrypted bundle.
- Live contacts/presence, per-conversation message cache, reconnection and pending-send retry.
- **Crypto Trace:** actual operation timings, byte sizes, public-key fingerprint, encrypted private-key bundle metadata, and a recent actual envelope preview. Raw private keys, wrapping keys, shared secrets, and plaintext are not displayed.
- **Benchmark Lab:** measured ML-KEM-768 key generation/encapsulation/decapsulation versus a browser Web Crypto X25519 ECDH baseline. Same HKDF and AES-GCM implementation is used after key establishment, with a fixed 1 KiB payload. Includes warm-up samples, mean, median, p95, standard deviation, raw-sample CSV and JSON report export.
- **Security Tests:** a valid AES-GCM round trip, modified-ciphertext rejection, wrong-password rejection for an encrypted key bundle, and mismatched ML-KEM key/decryption rejection.
- Ember & Brass warm interface.

## Requirements

- Node.js 20 or newer
- npm
- A modern browser with Web Crypto support. The X25519 benchmark depends on browser support for the Web Crypto X25519 algorithm; unsupported is reported as unavailable rather than replaced with fake values.

## Local development

```powershell
npm install
npm run dev
```

Open the local URL printed by Vite (normally `http://127.0.0.1:5173`). Create two test accounts in separate browser profiles to demonstrate messaging.

Production-shaped local run:

```powershell
npm run build
npm start
```

Then open `http://127.0.0.1:3000`.

## Research Lab walkthrough

1. Register or log in using a test account.
2. Open **Crypto Trace**. Public-key data and password-encrypted private-key bundle information are shown when available. Send a test message, then inspect the captured KEM ciphertext, salt, IV, AES-GCM ciphertext and actual timings.
3. Open **Benchmark Lab**. Run at least 100 samples after warm-up; repeat the run. Export the raw CSV and JSON report. Record browser/OS/device, date and source revision with the result.
4. Open **Security Tests** and run the tests. A PASS means the observed behavior matched that test's expected outcome; it is not a security certification.

## Benchmark methodology and caveats

- Timings are measured in the current browser/device with `performance.now()` and Web Crypto. They are implementation/API wall-clock timings, not hardware-independent primitive benchmarks.
- ML-KEM exchange is measured as encapsulation plus decapsulation. The X25519 baseline is ephemeral key generation, raw public-key export, and `deriveBits` at both modeled peers against one recipient key pair. These operation boundaries are documented in the UI.
- The baseline generates a fresh X25519 ephemeral key pair per sample. The experiment measures local cryptographic operations only; network round-trip latency is excluded.
- The symmetric payload is 1 KiB. HKDF context info is domain-separated (`ML-KEM-768` versus `X25519`) while using the same HKDF-SHA-256 implementation; AES-256-GCM and payload are the same.
- Web Crypto X25519 is asynchronous while the `mlkem` package operations are synchronous. Report this as browser API wall-clock latency; don't claim it isolates only the underlying mathematical primitive.
- Byte sizes displayed as observed are taken from actual generated arrays. Standard reference sizes can be cited separately in the report.
- No results are preloaded. If X25519 isn't available in a browser, the baseline is marked unavailable, not simulated.

## Render deployment

Use these settings for a Render Web Service:

- **Build command:** `npm install --include=dev && npm run build`
- **Start command:** `npm start`
- `NODE_ENV=production`
- `ALLOWED_ORIGINS=https://YOUR-SERVICE.onrender.com` (replace with the exact deployed origin)
- If using a persistent disk mounted at `/var/data`, set `DATA_DIR=/var/data`.

The server listens on `0.0.0.0` and uses the `PORT` environment variable. A current JSON store must be backed up before migration to a persistent volume. `DATA_DIR` does not turn JSON storage into a database; moving to PostgreSQL is reserved for a later phase.

## Storage and privacy

- Accounts and messages are stored in a JSON file (`data/store.json` by default, or under `DATA_DIR`). Render's default filesystem is ephemeral; configure persistent storage if records must survive restarts/redeploys.
- Passwords are not stored as plaintext; username, password salt/hash, public keys, message sender/recipient/timestamps and other metadata are readable to the server.
- Message bodies are encrypted in the browser. The server stores encrypted envelopes, not normally the plaintext body.
- Private-key bundles are encrypted in the browser before being uploaded. The private key is unwrapped in browser memory while in use; a malicious script running in the origin can still potentially access credentials or key material.
- Research exports include operation metadata and timings, may include usernames in trace details and short previews of ciphertext, and exclude plaintext message bodies, raw keys and shared secrets. Review the report before sharing.

## Known limitations

- Public keys are not cryptographically authenticated; a malicious server could substitute a contact key.
- ML-DSA identity authentication / signatures are not implemented.
- A reviewed Double Ratchet or equivalent forward-secrecy protocol is not implemented. Fresh KEM encapsulation alone does not provide full forward secrecy against later compromise of a long-term recipient private key.
- Duplicate-envelope detection and client message IDs provide limited duplicate/retry mitigation, not complete protocol-level replay protection.
- Sessions and login throttling are in memory and reset on server restart.
- JSON persistence is not a database and is not encrypted as a whole.
- No independent security audit or formal verification has been performed.

See `PRD.md`, `EXPERIMENT_PLAN.md`, `TEST_PLAN.md`, `THREAT_MODEL.md`, `RESEARCH-LAB.md`, and `MENTOR-DEMO.md` for the scope, methods, safety limits and demo steps.
