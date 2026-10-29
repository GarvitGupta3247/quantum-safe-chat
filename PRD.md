# Product Requirements Document — QuantumSafe Chat v0.5.0

## 1. Product overview

**Product:** QuantumSafe Chat — experimental post-quantum messaging and evaluation prototype  
**Phase:** Research Lab build / academic proof of concept  
**Primary users:** Students, mentors and evaluators reviewing browser-side cryptography.  
**Delivery target:** A demonstrable local or Render-hosted prototype. It is not a production messenger.

## 2. Problem statement

A chat UI alone doesn't demonstrate that a cryptographic implementation performs the operations claimed, nor does it measure performance costs or failure behavior. This version keeps the messaging workflow and makes selected cryptographic operations observable and repeatable.

## 3. Goals

1. Support one-to-one messaging with browser-side ML-KEM-768 key establishment, HKDF-SHA-256 and AES-256-GCM.
2. Display live, actual crypto operation metadata without exposing raw secrets or plaintext.
3. Permit inspection of the actual encrypted message envelope and password-encrypted private-key bundle.
4. Measure ML-KEM-768 against a documented X25519 ECDH browser baseline.
5. Test expected rejection of modified AES-GCM ciphertext, incorrect bundle passwords and mismatched ML-KEM recipient keys.
6. Export sanitized, reproducible reports and raw timing samples.
7. Keep the existing warm chat design and avoid database migration in this phase.

## 4. Functional requirements

- **FR-01 Auth:** users can register/log in with username and password; passwords are verified using salted scrypt hashes.
- **FR-02 Key storage:** the browser wraps the ML-KEM private key with an AES-GCM key derived using PBKDF2-HMAC-SHA-256 before local storage/server sync.
- **FR-03 Messaging:** sender creates a recipient envelope and a separate sender-history envelope; backend relays/stores encrypted envelope objects.
- **FR-04 Trace:** record actual operation labels, outcomes, timings and byte sizes; show public-key fingerprint, encrypted key-bundle metadata, and recent envelope fields.
- **FR-05 Benchmark:** run warm-up plus user-selected measured samples (20–500), report mean/median/p95/standard deviation, export raw CSV and JSON summary.
- **FR-06 Baseline:** use Web Crypto X25519 ECDH if available; mark unavailable otherwise.
- **FR-07 Security tests:** execute real controlled tests using ephemeral test material; display outcomes observed by the runtime.
- **FR-08 Privacy:** never render/export raw private keys, password-derived wrapping keys, shared secrets, or plaintext message content in the research report.
- **FR-09 Docs:** identify implementation, measurement, assumptions and limitations separately.

## 5. Non-goals

- PostgreSQL/database migration (planned for a later phase).
- ML-DSA identity signatures or authenticated public-key binding.
- A reviewed Double Ratchet or equivalent post-quantum forward-secrecy protocol.
- Group chat, attachments, account recovery, enterprise administration, or production certification.
- A claim that the complete application is immune to quantum or conventional attacks.

## 6. Acceptance criteria

- Two test accounts can exchange and decrypt messages.
- Crypto Trace shows data captured from actual runtime operations and envelope byte lengths.
- Benchmark numbers are generated live, with raw samples and methodology metadata; no static values are presented as results.
- The benchmark clearly labels operation boundaries and marks X25519 unavailable if the browser lacks support.
- Security tests run and display actual outcomes.
- Report export excludes plaintext, raw keys and shared secrets.
- `npm run build` passes and the full manual test plan has been recorded before release.
