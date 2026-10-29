# Threat Model — QuantumSafe Chat v0.5.0

## 1. Purpose and status

This is a practical threat model for an educational prototype, not formal verification, a penetration-test report or a production-security claim.

## 2. Architecture

- **Browser:** UI; ML-KEM-768; HKDF-SHA-256; AES-256-GCM; password-encrypted private-key bundle handling; Crypto Trace, benchmark and test screens.
- **Server:** Express API, WebSocket relay, account/session handling, in-memory rate limiting and a JSON-file store.
- **Storage:** account password verifiers, ML-KEM public keys, encrypted private-key bundles, encrypted message envelopes and readable message metadata.
- **Research tooling:** local timing samples and test outcomes; exported report excludes plaintext, raw keys and shared secrets but may contain usernames and short ciphertext previews.

## 3. Assets

1. Message plaintext and confidentiality.
2. ML-KEM private key and shared-secret material.
3. Passwords, password-derived wrapping keys and session credentials.
4. Account/key associations and public-key identity binding.
5. Message integrity and sender/recipient/conversation association.
6. Account/message store availability and integrity.
7. Integrity of benchmark samples and exported test reports.

## 4. Intended protections

- Passwords are processed using salted scrypt on the backend; plaintext passwords are not written into the JSON store.
- The browser wraps ML-KEM private key bytes with a PBKDF2-HMAC-SHA-256 derived AES-256-GCM key before local/server bundle storage.
- Message plaintext is encrypted in the browser with AES-256-GCM after ML-KEM encapsulation and HKDF-SHA-256 derivation.
- Backend stores and relays encrypted envelopes, plus sender/recipient/time and other metadata.
- HTTP security headers, CSP, login throttling and WebSocket session/origin checks reduce selected web risks.
- Research views avoid displaying raw private keys, wrapping keys, shared secrets and plaintext.

## 5. Threats and limitations

- **Malicious/compromised server or key substitution:** contact public keys are not cryptographically authenticated. A server could potentially substitute public keys. ML-DSA authentication and a trusted key-verification workflow are not implemented.
- **Compromised browser or malicious JavaScript:** a page running in the trusted origin can potentially access password input and unwrapped key material while in use. Password-encrypted local storage does not mitigate a compromised running client.
- **Later private-key compromise:** no reviewed Double Ratchet/equivalent forward-secrecy protocol is implemented. Fresh KEM encapsulation alone does not guarantee historical message secrecy after long-term private-key compromise.
- **Replay:** duplicate-envelope checking and client message IDs improve duplicate/retry handling but are not full protocol-level replay protection.
- **Availability:** JSON file persistence is not a database; sessions and login-throttle state are in memory. Default Render filesystem is ephemeral unless persistent storage is configured.
- **Metadata exposure:** usernames, sender/recipient, timestamps, ciphertext lengths and related metadata are visible to the server.
- **Password loss:** there is no separate private-key recovery mechanism; loss of the password/key bundle may permanently prevent decrypting old messages.
- **Benchmark validity:** results are browser/device/API-specific, not universal. Exported reports could include usernames and ciphertext previews and should be reviewed before sharing.

## 6. Out of scope

- Formal cryptographic verification or independent audit.
- ML-DSA identity signatures/public-key binding.
- Full forward secrecy/ratcheting and complete replay protection.
- Production-grade persistent database, account recovery, multi-factor authentication or HSM-backed key management.

## 7. Demo safety

Use non-sensitive test accounts and messages only. Do not reveal or export raw private keys, shared secrets, passwords or plaintext. Do not present a passing negative test as proof that the entire application is secure.
