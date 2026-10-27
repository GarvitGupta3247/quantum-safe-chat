# Experiment Plan — QuantumSafe Chat

## 1. Research question

**How do selected post-quantum key-establishment operations compare with a classical baseline in execution time and communication overhead in this browser-based prototype, and what protocol-level failure cases remain despite authenticated encryption?**

This experiment evaluates this implementation and environment. It does not establish universal performance characteristics or prove that the full application is secure.

## 2. Research objectives

1. Measure ML-KEM-768 key generation, encapsulation, decapsulation, and a clearly defined combined exchange.
2. Measure the available classical X25519 baseline using a clearly stated operation scope.
3. Measure HKDF-SHA-256 and AES-256-GCM for a fixed, documented payload size (the current demo uses a 1 KiB test payload for these operations).
4. Record public-key/ciphertext/envelope sizes where possible.
5. Verify expected rejection of tampered AES-GCM data and mismatched-key decryption.
6. Preserve raw results and enough environment information for another person to reproduce the run.

## 3. Hypotheses

- **H1:** ML-KEM-768 and X25519 will have different latency and data-size profiles in the selected implementation and browser.
- **H2:** AES-GCM authentication will reject modified ciphertext/tag data.
- **H3:** Correct primitive behavior does not by itself provide identity authentication, replay protection, or forward secrecy at the application-protocol level.

These are hypotheses to test, not assumed results. Do not write conclusions before collecting data.

## 4. Environment to record

For every published run, record:

- Date/time and operating system.
- CPU/device model if known; power/performance mode if relevant.
- Browser name and version.
- Node.js and npm versions for server/build tests.
- Repository commit or source revision.
- Dependency versions (`npm ls --depth=0` output is useful).
- Browser crypto support and whether the X25519 baseline was available.
- Benchmark iteration count, warm-up count, payload size, and any configuration flags.
- Whether the run was local, LAN, or deployed; network timing must not be mixed with local crypto timing without explicit labeling.

Do not include usernames, session cookies, keys, plaintext messages, or other personal data in experiment artifacts.

## 5. Benchmark methodology

1. Start from a clean, documented repository revision and build.
2. Run each operation's warm-up phase before collecting timed samples. Record the warm-up count.
3. Use a documented fixed iteration count. The existing UI offers 100 iterations; use this for the first reproducible run unless it causes instability. Repeat the full run at least three times if time permits.
4. Use a monotonic high-resolution timer available in the browser, and keep timing boundaries consistent.
5. Report sample count, median, mean, standard deviation, and p95 when the sample count is sufficient. State the percentile calculation method.
6. Report units consistently, preferably milliseconds for duration and bytes for sizes.
7. Separate key generation, encapsulation/agreement, decapsulation/derivation, HKDF, AES-GCM encryption/decryption, and combined end-to-end operations.
8. State exactly which work is included in each combined measurement. Do not compare ML-KEM encapsulation alone with a complete X25519 handshake and call it equivalent.
9. Export raw samples when possible, plus a summary. Preserve the original CSV rather than only copying averages into a report.
10. Repeat on the same device/browser before comparing algorithms. If comparing across devices, treat each environment as a separate group.

## 6. Comparison caveats

ML-KEM-768 is a key-encapsulation mechanism; X25519 is a Diffie–Hellman key-agreement mechanism. Their protocol flows and data structures differ. Any comparison must define comparable end goals, such as establishing a shared secret, and explain setup, key-generation, public-key exchange, encapsulation/ciphertext exchange, and derivation costs included in the measurement.

Do not imply that a timing result alone measures security strength. Do not infer production-scale throughput from a local browser microbenchmark.

## 7. Data to collect

### Timing data
- Algorithm / operation name.
- Sample number and duration.
- Summary statistics: median, mean, standard deviation, and p95 where appropriate.
- Warm-up and measured iteration counts.
- Payload size and configuration.

### Size data
- Public-key bytes.
- KEM ciphertext bytes or the corresponding classical public-key material.
- Nonce/IV, authentication tag, and envelope overhead where available.
- Total serialized bytes for a representative message envelope.
- Message payload size, clearly separated from cryptographic overhead.

### Security-test data
- Test ID and description.
- Input mutation / test condition, without exposing secrets.
- Expected outcome.
- Observed outcome.
- PASS/FAIL and any safe error category.
- Source revision and test date.

## 8. Security experiment matrix

| ID | Test condition | Expected outcome | Interpretation limit |
|---|---|---|---|
| SEC-01 | Flip a ciphertext or authentication-tag bit | AES-GCM decryption rejects | Demonstrates tamper detection for this test path only. |
| SEC-02 | Attempt ML-KEM decapsulation with a mismatched private key | No accepted valid plaintext; operation fails safely | Does not prove all malformed KEM inputs are handled safely. |
| SEC-03 | Remove required envelope fields or use invalid types/encoding | Server rejects request safely | Does not replace full fuzzing or code review. |
| SEC-04 | Resend an identical valid envelope | Record actual duplicate behavior; if deduplication exists, verify it | No replay protection claim unless a defined mechanism is tested. |
| SEC-05 | Inspect persisted message records and WebSocket payloads | No plaintext body or private key in normal message path | Metadata may remain visible. |
| SEC-06 | Inspect activity logs and exported CSV | No password, token, private key, raw shared secret, or shared-secret fingerprint | Review all logging paths, not just the main screen. |
| SEC-07 | Replace a recipient public key in a controlled test | Demonstrate whether the sender can detect it | Current design lacks automatic cryptographic identity authentication. |

## 9. Reporting format

For each result, include:

- **Question:** what is being measured or tested?
- **Method:** exact operation, sample count, warm-up, payload, environment.
- **Result:** raw-data location and summary statistics.
- **Interpretation:** what the evidence supports.
- **Limitations:** what the experiment does not establish.

Graphs are optional; raw CSV/JSON and a concise summary are more important than decorative charts.

## 10. Reproducibility checklist

- [ ] Repository revision recorded.
- [ ] Setup and build commands recorded.
- [ ] Browser, OS, device, and dependency versions recorded.
- [ ] Warm-up and iteration counts recorded.
- [ ] Payload size and timing boundaries documented.
- [ ] Raw benchmark export saved.
- [ ] Security-test outcomes saved.
- [ ] No secrets or personal data included in exports.
- [ ] Results reproduced in a second run.
- [ ] Conclusions limited to the measured implementation and environment.

## 11. Deliverables

1. At least one raw benchmark export.
2. A summary table with methodology and environment.
3. A security-test matrix with expected and observed outcomes.
4. A short discussion of performance/size trade-offs and remaining protocol limitations.
5. Updated README links to the experiment and threat-model documents.
