# Research Lab — what the screens show

## Crypto Trace

Crypto Trace reads metadata captured from actual runtime operations:

- ML-KEM-768 key generation on registration.
- Password-encrypted private-key bundle generation/unlock (PBKDF2-HMAC-SHA-256, AES-256-GCM, salt, IV and encrypted byte length).
- ML-KEM encapsulation/decapsulation and a shortened SHA-256 digest of the shared secret for comparison. It never renders raw shared-secret bytes.
- HKDF-SHA-256 and AES-256-GCM timing, plaintext/ciphertext byte counts, salt/IV lengths and serialized envelope size.
- Recent actual envelope fields: `kemCiphertext`, `salt`, `iv`, and `ciphertext`.

The shared-secret digest is a diagnostic consistency aid, not a proof of identity authentication. The full ciphertext preview is actual encrypted data; it should be used with test accounts and reviewed before copying to public reports.

## Benchmark Lab

The screen executes the current browser's real cryptographic implementations. It does not use pre-filled result numbers.

- **ML-KEM path:** key-pair generation timing, encapsulation, decapsulation, shared-secret agreement check and key-establishment payload byte lengths.
- **X25519 path:** when Web Crypto supports it, ephemeral key-pair generation, raw public-key export and shared-secret derivation at both modeled peers, with equality check.
- **Shared symmetric operations:** HKDF-SHA-256 and AES-256-GCM using a 1 KiB payload.
- **Statistics:** 10 warm-up samples, 20–500 measured samples, mean, median, p95 and population standard deviation.
- **CSV:** raw timing and byte-length samples; excludes keys, shared secrets and plaintext.
- **JSON report:** environment, methods, traces, summaries, raw benchmark timing arrays and concise ciphertext/bundle previews. Review before sharing because usernames may appear in trace details.

The ML-KEM and X25519 operation scopes are not identical mathematical primitives. ML-KEM exchange is encapsulation + decapsulation. X25519 exchange is ephemeral key generation + public-key export + both peers' deriveBits. The timings include browser API overhead. Network time is not included. Record the device/browser and repeat the experiment before drawing conclusions.

## Security Tests

The page runs controlled browser-local tests with disposable data:

1. A valid AES-GCM round trip is a positive control.
2. A single altered ciphertext byte should make GCM authentication fail.
3. The real encrypted private-key bundle helper should reject an incorrect password.
4. A KEM ciphertext decapsulated using a mismatched private key should not decrypt under AES-GCM.

PASS means only that the observed outcome matched the specified test. These checks do not evaluate identity authentication, full replay defenses, forward secrecy, a malicious server, or production hardening.
