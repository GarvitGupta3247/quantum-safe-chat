# QuantumSafe Chat (v0.6.0)

A research prototype of post-quantum end-to-end encrypted messaging in the browser, with a live
Crypto Trace, a Benchmark Lab and in-app security tests.

> **Status:** not independently audited; not for sensitive communication. Read
> [SECURITY.md](SECURITY.md) for the exact design, the threat model, and the known limitations.

## What it does

| Layer | Implementation |
| --- | --- |
| Login | **OPAQUE** (RFC 9807) with Argon2id (64 MiB, t=3). The password never leaves the browser. |
| Key custody | Client-side vault (AES-256-GCM) under a data key wrapped by the OPAQUE export key. The server stores ciphertext only. |
| Identity | Hybrid **Ed25519 + ML-DSA-65** signing identity, pinned on first use, blocking key-change warnings, 60-digit safety numbers. |
| Session setup | **PQXDH**: X25519 + **ML-KEM-768**, signed and one-time prekeys. |
| Messages | **Double Ratchet** + AES-256-GCM; every envelope is signed and its metadata bound into the AEAD. Receiver-side replay rejection. |
| Relay | Store-and-forward; ciphertext is deleted once delivered. One active device per account. |

What it does **not** do: hide metadata from the server, protect against a server that serves
malicious JavaScript, provide post-quantum *post-compromise* security, or recover forgotten
passwords. Details in [SECURITY.md §5–7](SECURITY.md).

## Requirements
Node.js ≥ 22 (developed on 25.7) and npm. Chrome/Chromium/Edge for the optional browser test.

## Install, build, run

```bash
npm ci                 # or: npm install
npm run build          # production frontend into dist/
npm start              # API + WebSocket relay + built frontend on http://localhost:3000
```

Development with hot reload (Vite on :5173 proxying the API on :3000):

```bash
npm run dev
```

Open two different browsers (or one normal and one private window — only one session per account
is allowed), create two accounts, select the other user, and send a message. Then open
**Safety number** in both windows, compare, and mark the contact verified.

## Tests

```bash
npm test               # 40 unit, integration and attack-regression tests against the real server
npm run build && npm run test:browser   # 9-step end-to-end test in a real headless Chrome
```

`npm test` starts real server instances on random ports with temporary data directories, drives
real `ChatClient` instances over HTTP and WebSocket, and models a malicious server by editing its
database and message queue. See [TEST_PLAN.md](TEST_PLAN.md) for what each test covers.

## Upgrading from v0.5
Existing accounts must be upgraded once via **Upgrade legacy account** on the login page. See
[UPGRADE.md](UPGRADE.md).

## Configuration

| Variable | Purpose |
| --- | --- |
| `PORT` | Listen port (default 3000). |
| `DATA_DIR` | Persistent data directory (default `./data`). |
| `OPAQUE_SERVER_SETUP` | OPAQUE server secret. Keep it in a secret manager, not on the data volume. Generated into `DATA_DIR` if unset. |
| `ALLOWED_ORIGINS` | Comma-separated exact origins allowed for state-changing requests and WebSockets. |
| `NODE_ENV=production` | `Secure` cookies and HSTS. Serve only over HTTPS/WSS. |
| `QSC_LEGACY_MIGRATION=0` | Disable the v0.5 migration route once everyone has migrated. |

## Project layout

```
server/app.js            OPAQUE auth, vault storage, identity/prekey directory, relay (createServer factory)
server/index.js          entry point
src/protocol/            browser + Node protocol library
  bytes.js               canonical encoding, strict Base64
  identity.js            hybrid identities, prekeys, fingerprints, safety numbers
  pqxdh.js / ratchet.js  PQXDH and Double Ratchet
  envelope.js            signed envelopes, pinning, replay checks (encryptEnvelope / openEnvelope)
  vault.js / password.js key custody, password policy, Argon2id parameters
  client.js              ChatClient used by both the UI and the tests
  legacy.js              one-way v0.5 migration helpers
src/research/            in-app self-tests and report builder
src/main.js              UI
test/                    unit, integration/attack, and browser tests
```

## Research Lab
**Crypto Trace**, **Benchmark Lab** and **Security Tests** are described in
[RESEARCH-LAB.md](RESEARCH-LAB.md). They never display or export keys, secrets, values derived from
secrets, or plaintext.
