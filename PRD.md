# Product Requirements Document (PRD)

## 1. Product overview

**Product:** QuantumSafe Chat — Experimental Post-Quantum Messaging and Evaluation Platform  
**Status:** Educational proof of concept / Phase 1.5  
**Primary users:** Students, mentors, and developers exploring post-quantum cryptography in browser-based applications.  
**Delivery target:** A reliable, reproducible demo suitable for a short academic project sprint. This is not a production messenger.

QuantumSafe Chat combines a working one-to-one messaging prototype with visible cryptographic activity, a repeatable benchmark lab, and a small security-test lab. Its purpose is to demonstrate and evaluate an implementation—not to invent a cryptographic primitive or claim certification.

## 2. Problem statement

Post-quantum cryptographic primitives are becoming standardized, but integrating them into a complete application raises practical questions: what operations are performed, what performance and communication overhead is introduced, and what application-level risks remain even when the primitives behave as designed?

A chat demo alone cannot answer those questions. QuantumSafe Chat makes selected operations observable and provides repeatable experiments and negative tests.

## 3. Goals

1. Demonstrate one-to-one messaging using the existing browser-side cryptographic pipeline.
2. Make cryptographic operations and their non-secret metadata understandable to a reviewer.
3. Measure selected post-quantum and classical key-establishment operations under documented conditions.
4. Demonstrate that modified authenticated ciphertext and incorrect-key scenarios are rejected.
5. Document threat assumptions, test results, reproducibility details, and known limitations.
6. Keep the codebase small enough for a 3–4 day improvement sprint.

## 4. Non-goals

- Production or certified secure messaging.
- Inventing or modifying cryptographic algorithms.
- Claiming that the application is quantum-proof in every respect.
- Implementing a custom Double Ratchet or other new protocol within this sprint.
- Group chat, attachments, multi-device synchronization, account recovery, or enterprise administration.
- A comprehensive penetration test or formal cryptographic verification.
- Collecting real users' sensitive messages or private keys.

## 5. Current implementation baseline

According to the current repository README and code, the prototype includes:

- Username/password registration and login; passwords use salted Node.js `scrypt` hashes.
- Browser-side ML-KEM-768 key-pair generation.
- Per-message ML-KEM encapsulation, HKDF-SHA-256 key derivation, and AES-256-GCM payload protection.
- A sender-side encrypted copy so sent-message history can be decrypted after reload.
- An Express/WebSocket relay and JSON persistence under `data/store.json`.
- Crypto activity logging, benchmark operations, CSV export, and an Attack Lab with tampering and wrong-key tests.

These are implementation claims, not a substitute for running the application and verifying behavior on the target machine.

## 6. Users and key user stories

### Student / demonstrator
- As a demonstrator, I can register two accounts in separate browser profiles and exchange messages.
- As a demonstrator, I can explain the roles of ML-KEM, HKDF, and AES-GCM without confusing key establishment with message encryption.
- As a demonstrator, I can run benchmarks repeatedly and export results with environment information.
- As a demonstrator, I can run negative tests and see the expected outcome and actual outcome separately.

### Reviewer / mentor
- As a reviewer, I can follow setup instructions and reproduce the main demo.
- As a reviewer, I can inspect the benchmark method, raw results, and limitations.
- As a reviewer, I can distinguish implemented features from planned work and known security gaps.

## 7. Requirements and acceptance criteria

### P0 — required for the sprint

**R1. Reproducible setup**
- `npm ci` completes from a clean checkout with Node.js 20+.
- `npm run build` completes successfully.
- README describes the correct local start commands.

**R2. Messaging regression**
- Two distinct browser profiles can register separate accounts and exchange messages in both directions.
- Refreshing a browser preserves the intended history behavior when the local JSON store and browser key remain available.
- The test report records any failures; a successful build alone does not count as messaging validation.

**R3. Cryptographic negative tests**
- A ciphertext/tag modification is rejected by AES-GCM decryption.
- Decryption using a mismatched ML-KEM private key fails or is handled as an explicit test failure without exposing secrets.
- Each test reports expected behavior, observed behavior, and PASS/FAIL.

**R4. Benchmark repeatability**
- Benchmark runs include a warm-up phase or clearly explain why one is absent.
- Results use a documented number of iterations and report median, mean, and standard deviation; report p95 when enough samples exist.
- Export includes the operation name, sample count, units, timestamp, browser/runtime information where available, and configuration/payload size.
- The UI and report state that results vary by device, browser, implementation, and measurement scope.

**R5. Safe observability**
- Routine activity logs do not expose private keys, raw shared secrets, passwords, session tokens, or derived-secret fingerprints.
- Logs may show operation name, success/failure, elapsed time, byte counts, and a non-secret event/envelope reference.

**R6. Honest scope statement**
- README and demo state that identity authentication, replay protection, forward secrecy, production hardening, and independent security review are absent unless later implemented and tested.

### P1 — do if the P0 baseline is stable

**R7. Manual public-key fingerprint verification**
- Show a fingerprint of the public key and instructions for comparing it over a separate trusted channel.
- Label this as manual verification; do not describe it as automatic authentication or a complete MITM defense.

**R8. Additional malformed-input tests**
- Test malformed envelopes, missing fields, invalid encodings, and oversized input within reasonable local limits.
- The server rejects invalid input safely and remains responsive.

**R9. Replay behavior investigation**
- Submit the same valid envelope more than once and record actual behavior.
- If deduplication is added, test it and document the scope; do not imply complete replay protection from a simple UI check.

### P2 — future work, not required in four days

- A reviewed identity-authentication design, potentially including ML-DSA signatures and a defined trust/binding model.
- A reviewed forward-secrecy/session protocol with appropriate key lifecycle and erasure.
- Stronger persistence, session management, rate limiting, deployment hardening, and independent review.

## 8. Technical constraints

- Retain the existing Vite, browser JavaScript/Web Crypto, Node.js, Express, WebSocket, and `mlkem` stack for this sprint.
- Avoid a framework migration or new paid service unless a blocker is proven.
- Keep private keys and raw shared secrets out of server requests, routine logs, screenshots, and exported files.
- Do not compare unlike cryptographic operations as if they were equivalent. Explain exactly what each benchmark measures.
- Treat local JSON persistence and browser localStorage key storage as demo-only limitations.

## 9. Success metrics

The sprint is successful when:

- A clean install and production build pass.
- The two-user messaging flow is demonstrated and its result recorded.
- Required negative tests produce the expected results.
- At least one reproducible benchmark export is saved with environment notes.
- The four planning/test documents and README describe the same scope and limitations.
- A teammate can follow the setup and reproduce the demo without undocumented steps.

## 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Scope grows beyond four days | Complete P0 requirements before P1/P2 features. |
| Benchmark numbers are misleading | Document operation scope, warm-up, samples, browser, and device; publish raw data. |
| Demo is mistaken for production security | Display a clear educational-PoC warning and list missing protections. |
| Sensitive diagnostics leak | Remove secret-derived fingerprints and keep secrets out of logs/exports. |
| Local data disappears after redeploy | Treat deployed data as disposable unless persistent storage is explicitly configured. |

## 11. Definition of done

The project is done for this sprint when the P0 acceptance criteria are verified, results are reproducible, limitations are visible, documentation is current, and the demo can be repeated. “Done” does not mean production-ready or independently security-audited.
