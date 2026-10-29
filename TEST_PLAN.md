# Test Plan — QuantumSafe Chat v0.5.0

## 1. Purpose

Verify the chat's key user flows and the new Research Lab's measured operations and controlled negative tests. Passing these checks is not a security certification or substitute for review.

## 2. Build and startup

```powershell
npm install --include=dev
npm run build
npm run dev
```

For a production-shaped local run:

```powershell
npm run build
npm start
```

Record actual command output. A successful build alone does not demonstrate messaging or cryptography works at runtime.

## 3. Functional regression tests

| ID | Test | Steps | Expected result |
|---|---|---|---|
| FUNC-01 | Registration | Register valid test account | Account is created; ML-KEM key generated; encrypted bundle stored |
| FUNC-02 | Login | Log in with correct password | Browser unlocks private-key bundle and loads chat |
| FUNC-03 | Wrong password | Enter incorrect password | Login/key unlock fails without displaying key material |
| FUNC-04 | Multi-browser account | Register and sync a test account, then log in on another browser | Same key bundle unlocks; existing messages decrypt |
| FUNC-05 | Two-user messaging | Two browser profiles exchange messages | Recipient decrypts; both users can see their history copies |
| FUNC-06 | Enter-to-send | Type message and press Enter; Shift+Enter separately | Enter sends; Shift+Enter inserts newline; focus/draft behavior is normal |
| FUNC-07 | Live presence | Register/log in second profile while first stays open | Contact/presence list updates without manual reload |
| FUNC-08 | Background messages | Receive message while another conversation is selected | New message is cached, unread count updates, opening chat shows history |
| FUNC-09 | Reconnect | Disconnect/reconnect network | Connection retries; pending send IDs are reused idempotently |
| FUNC-10 | History after refresh | Refresh both profiles, revisit history | Stored encrypted envelopes decrypt when store and key bundles remain available |
| FUNC-11 | Logout | Log out then request authenticated API | Session is no longer accepted |

## 4. Crypto Trace tests

| ID | Test | Expected result |
|---|---|---|
| TRACE-01 | Account key metadata | Public-key byte length and fingerprint reflect current browser key |
| TRACE-02 | Encrypted private-key bundle | Shows KDF, iterations, salt/IV sizes and encrypted-key preview only; never raw private key |
| TRACE-03 | Real message envelope | After send, view shows actual KEM ciphertext, salt, IV and AES-GCM ciphertext for a recent envelope |
| TRACE-04 | Operation timing | Timings are captured around actual operations; no pre-filled values |
| TRACE-05 | Report privacy | Export contains no plaintext, raw private key, wrapping key or shared secret |

## 5. Benchmark tests

| ID | Test | Expected result |
|---|---|---|
| BENCH-01 | Run default benchmark | Performs 10 warmups plus 100 measured samples per supported operation |
| BENCH-02 | User sample count | Input is clamped to 20–500 measured samples |
| BENCH-03 | ML-KEM consistency | Sender/receiver secret equality is checked; payload encrypt/decrypt round trip passes |
| BENCH-04 | X25519 availability | Browser support is tested; if unsupported, baseline is marked unavailable instead of populated with fake results |
| BENCH-05 | Statistics | Mean, median, p95, standard deviation and actual N are shown from raw timings |
| BENCH-06 | CSV export | Export includes raw timing/size rows without keys, secrets or plaintext |
| BENCH-07 | Protocol scope | UI states operation boundaries and that network latency is excluded |

## 6. Security test screen

- Valid AES-GCM round-trip must succeed.
- Mutated ciphertext must fail authenticated decryption.
- Wrong password must fail to unlock an encrypted test key bundle.
- Mismatched ML-KEM private key must not decrypt the encrypted test payload.
- Each visible PASS/FAIL must be produced from the runtime outcome.

## 7. Deployment test

- Confirm Render service is Live and serves the built frontend.
- Confirm `ALLOWED_ORIGINS` exactly matches the deployed HTTPS origin.
- Confirm storage is mounted and `DATA_DIR` points to that mount if persistence is required.
- Test from two separate browser profiles.
- Re-deploy only after backup and successful local build.

Record each test as **Pass**, **Fail**, **Not run**, or **Blocked**. Never mark a test passed solely because code exists.
