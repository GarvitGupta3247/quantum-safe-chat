# Test Plan — QuantumSafe Chat

## 1. Purpose

This plan verifies the current educational prototype's main user flows and selected failure cases. Passing these tests does not certify the application or replace an independent security review.

## 2. Test environment

- Node.js 20 or newer and npm.
- Dependencies installed from `package-lock.json` using `npm ci`.
- Browser with Web Crypto support; use separate browser profiles for separate accounts because the private key is stored in browser-local storage.
- Local development mode for functional tests; use HTTPS/WSS for a LAN demo.
- Record OS, browser version, Node version, source revision, and date.

## 3. Initial checks

Run from the project root:

```powershell
npm ci
npm run build
npm run dev
```

Record command output. `npm run build` passing proves the frontend builds, not that registration, cryptography, WebSockets, or persistence work at runtime.

## 4. Functional regression tests

| ID | Test | Steps | Expected result |
|---|---|---|---|
| FUNC-01 | Registration | Register a valid username and password | Account is created and the user can proceed to the app. |
| FUNC-02 | Username validation | Try too-short, too-long, or disallowed username characters | Invalid input is rejected with a useful error. |
| FUNC-03 | Password validation | Try a password shorter than the documented minimum | Registration is rejected. |
| FUNC-04 | Login | Log in with correct credentials | Session is established and app loads. |
| FUNC-05 | Incorrect login | Use an incorrect password | Login fails without revealing sensitive account details. |
| FUNC-06 | Two-user messaging | Register Alice and Bob in separate browser profiles; send messages both ways | Intended recipient receives and can decrypt each message. |
| FUNC-07 | History after refresh | Send a message, refresh each browser, revisit history | History behaves as documented when the store and browser key are available. |
| FUNC-08 | Logout/session | Log out, then attempt an authenticated action | Logged-out session cannot continue authenticated actions. Record actual behavior. |
| FUNC-09 | Stored envelope | Inspect `data/store.json` using demo data only | Message body is not stored as plaintext; metadata visibility is documented. |
| FUNC-10 | CSV export | Export crypto activity and benchmark data | Export opens and contains the expected columns without secrets. |

## 5. Cryptographic negative tests

| ID | Test | Expected result | Evidence to save |
|---|---|---|---|
| CRYPTO-01 | Modify ciphertext or authentication tag | AES-GCM decryption rejects the message | Attack Lab result and safe error category. |
| CRYPTO-02 | Use mismatched ML-KEM private key | No valid plaintext is accepted; failure is handled safely | Attack Lab result. |
| CRYPTO-03 | Invalid/malformed envelope | Input is rejected without crashing the app/server | Test output and server log with secrets removed. |
| CRYPTO-04 | Missing required fields | Input is rejected clearly | Expected vs actual result. |
| CRYPTO-05 | Oversized input | Request is rejected within documented limits or safe behavior is recorded | Response, service stability, and limits. |
| CRYPTO-06 | Replay same envelope | Record whether duplicate message is accepted; if deduplication is implemented, verify it | Two submission outcomes and documented interpretation. |
| CRYPTO-07 | Public-key substitution scenario | Determine whether user is warned or can verify the recipient key | Record current behavior; automatic identity authentication is not expected in the current baseline. |

## 6. Benchmark tests

- [ ] Confirm the UI labels each measured operation correctly.
- [ ] Confirm the iteration count displayed matches the collected sample count.
- [ ] Confirm warm-up behavior is documented and consistent.
- [ ] Check median, mean, standard deviation, and p95 calculations against a small known sample if the summary code is changed.
- [ ] Confirm units are consistent and non-finite values are handled.
- [ ] Confirm unsupported X25519 is reported as unavailable rather than as a zero-duration success.
- [ ] Confirm exported CSV has headers, sample count, operation, units, and configuration details.
- [ ] Repeat a run and record variability; do not require exact timing equality.
- [ ] Verify no secrets, private keys, plaintext messages, or shared-secret fingerprints are exported.

## 7. Manual test execution record

Copy this table into the test report and fill it in during execution:

| Test ID | Date / source revision | Result (PASS/FAIL/BLOCKED) | Actual observation | Evidence file / notes |
|---|---|---|---|---|
| FUNC-01 | TBD | NOT RUN | | |
| FUNC-04 | TBD | NOT RUN | | |
| FUNC-06 | TBD | NOT RUN | | |
| FUNC-07 | TBD | NOT RUN | | |
| CRYPTO-01 | TBD | NOT RUN | | |
| CRYPTO-02 | TBD | NOT RUN | | |
| CRYPTO-03 | TBD | NOT RUN | | |
| CRYPTO-06 | TBD | NOT RUN | | |
| BENCH-01 | TBD | NOT RUN | | |
| BENCH-02 | TBD | NOT RUN | | |

Do not mark a test PASS until you have run it and observed the expected result. “Not implemented” is not the same as PASS.

## 8. Bug reporting template

For each failure, record:

- **Title:** short description.
- **Environment:** OS, browser, Node version, source revision.
- **Preconditions:** account/data/setup required.
- **Steps to reproduce:** minimal ordered steps.
- **Expected result:** behavior required by the test.
- **Actual result:** what happened, including safe error text.
- **Severity:** blocker / high / medium / low.
- **Evidence:** screenshot, console output, or test log with credentials and secrets removed.

## 9. Exit criteria

The sprint test phase is complete when the P0 functional and cryptographic tests have been attempted, all results are recorded honestly, critical failures are fixed or clearly documented, benchmark exports can be reproduced, and no sensitive secret material is present in test artifacts. Any unimplemented protection remains listed as a limitation.
