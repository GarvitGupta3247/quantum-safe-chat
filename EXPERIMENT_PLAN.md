> **Historical document (v0.5.0).** It describes the design that the v0.6 security repair replaced
> (scrypt + PBKDF2 key bundles, unauthenticated keys, no forward secrecy). It is kept for project history
> only and does not describe the current implementation. See [README.md](README.md) and
> [SECURITY.md](SECURITY.md).

# Experiment Plan — QuantumSafe Chat v0.5.0

## 1. Research question

How do the selected ML-KEM-768 and classical X25519 key-establishment paths compare in browser API wall-clock time and key-establishment message size, and what do simple negative tests demonstrate about authenticated encryption and key handling?

This experiment characterizes one implementation and test environment only. It does not establish universal performance, security certification or a full protocol proof.

## 2. Systems under comparison

### Post-quantum path

- ML-KEM-768 key-pair generation (measured separately).
- Per-sample ML-KEM encapsulation to one benchmark recipient public key.
- Recipient decapsulation with its paired private key.
- Shared-secret equality checked locally; no secret is saved to results.

### Classical baseline

- X25519 using Web Crypto API if supported by the browser.
- One recipient key pair is generated for the run; each sample creates a fresh ephemeral key pair.
- The ephemeral public key is exported and ECDH `deriveBits` is measured at both modeled peers.
- Shared-secret equality is verified and secret bytes are discarded from the result row.

### Symmetric path

Both paths use HKDF-SHA-256 and AES-256-GCM with a fixed 1 KiB payload. HKDF `info` is domain-separated by protocol (`ML-KEM-768` or `X25519`). Encryption/decryption timings are recorded separately from key establishment.

## 3. Measurement definitions

- `ML-KEM exchange`: encapsulation + decapsulation.
- `X25519 exchange`: ephemeral key generation + raw public-key export + `deriveBits` at sender and receiver.
- `keygen`: ML-KEM key-pair generation per sample; for X25519, ephemeral pair generation per sample.
- `wire key payload size`: raw KEM ciphertext length and Base64-encoded field length versus raw ephemeral X25519 public-key length and its Base64 representation. This is not total HTTPS/WebSocket packet size.
- Timings use `performance.now()`. X25519 uses asynchronous Web Crypto; ML-KEM package calls are synchronous. Thus the results are browser API wall-clock latencies, not primitive-only timing in a normalized native harness.
- Network latency is excluded.

## 4. Sampling

- Default: 10 warm-up samples followed by 100 measured samples per supported operation; UI permits 20–500 measured samples.
- Rerun the complete experiment at least three times when possible.
- Report mean, median, p95 and population standard deviation, plus the full raw samples.
- Do not remove slow samples without documenting a reason.
- Report browser/platform and any unsupported algorithm explicitly.

## 5. Environment to record

- Date/time, OS and device/CPU if known.
- Browser name/version and `navigator.userAgent`.
- Node/npm versions and dependency versions for the deployed commit.
- Git commit/source revision.
- Sample count, warm-up count, payload size, supported cryptographic algorithms.
- Local versus hosted environment; no-network timings versus separate measured network tests.

## 6. Security experiments

1. Valid AES-GCM round trip: recovered bytes must match test payload.
2. Flip a ciphertext byte: authenticated decryption should reject modified ciphertext/tag.
3. Attempt to unlock an encrypted private-key bundle using an incorrect password: decryption should reject.
4. Decapsulate with a mismatched ML-KEM private key and attempt AES-GCM decryption: authentication should reject.

These tests use disposable sample material and do not constitute a penetration test. The UI does not currently automate a full end-to-end replay test.

## 7. Reporting

Export the JSON research report and raw benchmark CSV. Preserve result files without editing measured numbers. Include methodology and limitations. Do not claim that a run proves the entire system secure or that its results generalize to other devices.
