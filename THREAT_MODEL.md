# Threat Model — QuantumSafe Chat

## 1. Purpose and status

This document describes the intended security properties and known gaps of the current educational prototype. It is a working threat model, not a formal verification, penetration-test report, or claim of production security.

## 2. System summary

- **Browser client:** UI, ML-KEM operations, HKDF-SHA-256, AES-256-GCM, and local browser key storage.
- **Server:** Node.js/Express API, WebSocket relay, account/session handling, and JSON persistence.
- **Message flow:** The sender encapsulates to a recipient public key, derives an AES-GCM key, and sends an encrypted envelope. A separate encrypted copy is created for the sender's own history. The server relays/stores envelopes and metadata.
- **Persistence:** Accounts and encrypted message records are stored in `data/store.json`; the browser stores the account's private key in localStorage according to the current project documentation.

## 3. Assets to protect

1. Message plaintext and message confidentiality.
2. ML-KEM private keys and derived shared secrets.
3. Account passwords, session credentials, and authenticated account actions.
4. Integrity and correct association of each encrypted message with its sender, recipient, and conversation.
5. Public-key identity binding: confidence that a public key belongs to the intended user.
6. Availability and integrity of account/message records.
7. Integrity of benchmark and security-test results.

## 4. Security objectives

- Keep plaintext and private keys out of the relay server during normal message handling.
- Detect modifications to AES-GCM-protected ciphertext and associated authenticated data, where used.
- Handle malformed or invalid inputs without crashing the service or exposing secrets.
- Make identity, replay, forward-secrecy, storage, and deployment limitations explicit.
- Make experiment results reproducible and avoid presenting measurements as universal.

## 5. Adversaries and trust assumptions

### Considered in the educational test scope
- A user or tester who modifies ciphertext, supplies a wrong key, or submits malformed/repeated envelopes.
- A curious relay operator who can inspect stored records and message metadata.
- A network observer, assuming correctly configured HTTPS/WSS for non-localhost demonstrations.
- A reviewer attempting to reproduce or challenge benchmark claims.

### Important assumptions and out-of-scope threats
- The browser and operating system are not compromised.
- No protection is claimed against malicious browser extensions, XSS, malware, or a compromised endpoint.
- The project has not undergone an independent cryptographic or application security review.
- The demo is not designed to withstand all malicious-server behavior or denial-of-service attacks.

## 6. Threats, current status, and mitigations

| Threat | Why it matters | Current status / mitigation |
|---|---|---|
| Public-key substitution / MITM | A malicious server could provide an attacker's public key in place of the intended recipient's key. | Cryptographic identity authentication is not implemented. A manually compared public-key fingerprint can help detect substitution only if users compare it over an independent trusted channel. |
| Long-term private-key compromise | Recorded ciphertext may become decryptable if the corresponding long-term private key is later compromised. | The current per-message encapsulation to a long-term recipient key does not provide forward secrecy. Do not claim that it does. |
| Private key exposed in localStorage | Same-origin JavaScript can access localStorage; an XSS bug or malicious script can potentially extract key material. | Current educational limitation. Never use real/sensitive messages. Avoid logging/exporting key material; evaluate a reviewed key-storage design separately. |
| Ciphertext or tag tampering | Altered encrypted content must not silently decrypt as valid plaintext. | AES-GCM should reject invalid authentication tags. Existing Attack Lab tests should be run and their expected/actual outcomes recorded. |
| Wrong-key decryption | A mismatched private key should not yield accepted plaintext. | Existing test attempts mismatched ML-KEM key behavior. Verify handling and error reporting. |
| Replay / duplicate envelopes | An attacker may resend a previously valid envelope, potentially causing duplicate message processing. | Replay protection is not implemented according to current documentation. Test duplicate behavior and document it; do not overstate simple deduplication. |
| Malformed or oversized inputs | Invalid data can trigger exceptions, resource use, or inconsistent server state. | Add validation tests for required fields, encodings, lengths, and sensible size limits. Record server behavior. |
| Password guessing / account abuse | Weak rate controls can allow repeated login attempts or resource abuse. | Do not claim production-grade account protection. Rate limiting and broader session controls remain future hardening work. |
| Session compromise | Stolen or mismanaged session credentials can allow account actions. | Session design has not been independently audited. Keep deployment limited and review cookie/session flags, expiry, logout invalidation, and origin checks before broader use. |
| Data loss / unauthorized file access | JSON persistence may be lost on ephemeral hosts or exposed through host compromise/misconfiguration. | Treat demo records as disposable; do not commit real `store.json` data. Use persistent storage only with explicit access controls and a separate review. |
| Misleading benchmark results | Warm-up, browser differences, sample size, or unequal operation scope can distort comparisons. | Record environment and configuration, repeat samples, export raw results, and describe exactly what each timing includes. |

## 7. Data-flow boundaries

1. **Browser local boundary:** plaintext, private key, and shared secret exist here during operations. This is a high-trust boundary and endpoint compromise is out of scope.
2. **Browser-to-server boundary:** encrypted message envelopes and metadata cross the network. Use HTTPS/WSS outside localhost.
3. **Server persistence boundary:** the server stores account records, encrypted envelopes, and metadata. The server should not receive plaintext or private keys in normal message flow, but metadata remains visible.
4. **Benchmark/export boundary:** exported files should contain measurements and environment details only—not credentials, private keys, plaintext, raw shared secrets, or secret-derived fingerprints.

## 8. Required verification tests

- Modify an AES-GCM ciphertext or authentication tag; decryption must reject it.
- Attempt decryption with the wrong ML-KEM private key; the operation must fail safely.
- Submit malformed and missing envelope fields; the server must reject them without crashing.
- Resubmit the same envelope and record whether duplicates are accepted.
- Inspect a stored envelope and WebSocket payload to confirm the message body is not plaintext.
- Inspect activity logs and exported CSV to confirm no credentials, private keys, raw shared secrets, or shared-secret fingerprints are present.
- Verify public-key fingerprint comparison procedure and document its reliance on an independent trusted channel.

## 9. Residual risks and prohibited claims

Until the corresponding work is implemented, tested, and reviewed, do not claim:

- “Production-ready secure messaging.”
- “Guaranteed quantum-proof communication.”
- “Forward secrecy” or “Double Ratchet support.”
- “Automatic MITM prevention” or authenticated user identities.
- “Penetration-tested” or “formally verified.”
- “The server learns no metadata.”

Preferred description: **“An educational post-quantum messaging prototype with observable cryptographic operations, benchmark experiments, and selected negative security tests.”**

## 10. Review checklist before any public deployment

- [ ] Use HTTPS/WSS with correctly managed certificates.
- [ ] Remove diagnostic secret-derived values from logs and exports.
- [ ] Review authentication, session expiry, logout, CSRF/origin protections, and rate limiting.
- [ ] Validate all API/WebSocket inputs and impose size limits.
- [ ] Review CORS, host binding, error handling, dependency updates, and secret/config management.
- [ ] Decide on persistence, backups, retention, and access controls.
- [ ] Review public-key authentication and key lifecycle with a trusted design.
- [ ] Obtain independent security review before handling sensitive messages.
