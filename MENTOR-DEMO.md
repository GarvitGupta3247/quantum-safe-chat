# Mentor Demo — QuantumSafe Chat v0.5.0

## Before the demo

- Deploy the exact tested commit and write down the short Git commit.
- Use two test accounts in two separate browser profiles.
- Use non-sensitive test messages.
- Open **Messages**, **Crypto Trace**, **Benchmark Lab** and **Security Tests** once so the navigation is familiar.

## Suggested 5–7 minute walkthrough

### 1. Show the chat (about 1 minute)

- Log into the two test accounts.
- Exchange a short message in both directions.
- Explain that the plaintext is encrypted in the browser before the server receives the envelope.

### 2. Show Crypto Trace (about 2 minutes)

- Show the public-key fingerprint and observed public-key byte count.
- Show the encrypted private-key bundle: PBKDF2-HMAC-SHA-256 iteration count, salt/IV lengths, encrypted byte count and ciphertext preview. Explicitly say the raw private key is not shown.
- Return to Messages and send a new message.
- Reopen Crypto Trace and inspect the real KEM ciphertext, salt, IV and AES-GCM ciphertext from the captured envelope.
- Point out the measured encapsulation, HKDF and AES-GCM timings, then describe that the server sees the encrypted envelope and metadata.

### 3. Run Benchmark Lab (about 2 minutes)

- Run 100 samples after warm-up.
- Explain operation scopes: ML-KEM encapsulation + decapsulation; X25519 ephemeral key generation + public-key export + ECDH derivation at both modeled peers.
- Explain that the same HKDF implementation and same 1 KiB payload are used, with a domain-separated HKDF info string for each protocol.
- Show median, p95, standard deviation and key-establishment data sizes.
- Download the raw CSV and the JSON report. Do not claim the results generalize to every device.

### 4. Run Security Tests (about 1 minute)

- Show valid AES-GCM round trip.
- Show actual tampered ciphertext rejection.
- Show wrong-password rejection for an encrypted test key bundle.
- Show mismatched ML-KEM private-key failure.
- Explain these are focused negative tests, not a full system audit.

## Claims to make accurately

- Implemented: ML-KEM-768 key establishment, HKDF-SHA-256, AES-256-GCM, password-encrypted private-key bundle, runtime Crypto Trace, browser-local benchmark and focused security tests.
- Not implemented: ML-DSA signatures/identity authentication, a reviewed forward-secrecy protocol, complete replay protection, and the planned database migration.
- The current JSON data store is prototype-level; use a persistent Render volume if demo data must survive restarts.

## Backup presentation evidence

Keep a copy of: a screenshot of a real Crypto Trace after sending a test message; a benchmark CSV from your actual device; the JSON report; and the observed security-test results. Do not hand-edit numbers or present illustrative/synthetic values as measurements.
