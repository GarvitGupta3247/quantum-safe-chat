# QuantumSafe Chat — Mentor Demo Script (Phase 1.5)

A suggested 5–8 minute walkthrough. Use two separate browser profiles/devices and create separate accounts on the same deployed origin.

## 1. Establish that this is a live implementation

1. Log in to Alice in one browser and Bob in another.
2. Open **Crypto activity** in both browsers.
3. Point out the actual ML-KEM-768 public-key byte count and SHA-256 fingerprint. The public key can be expanded as Base64; private keys and raw shared secrets are intentionally never printed.
4. Send one message from Alice to Bob.
5. Compare the `envelope ref` and abbreviated `shared-secret SHA-256` fingerprint in Alice's **ML-KEM-768 encapsulation** event against Bob's **ML-KEM-768 decapsulation** event for that same envelope. Matching values demonstrate that both sides derived the same shared secret from the corresponding KEM ciphertext. This is diagnostic evidence only; it does not authenticate Alice or Bob.
6. Show the HKDF-SHA-256 and AES-256-GCM events and their measured execution times and byte counts.
7. Export the event log CSV if the evaluator wants the trace.

## 2. Demonstrate tamper detection

1. Open **Attack lab** and select **Run security tests**.
2. The first test creates a real local AES-GCM encrypted envelope, flips a bit in the ciphertext/tag, and tries to decrypt it. The expected result is **PASS — rejected**.
3. The second test encrypts to a different ML-KEM public key and attempts to decrypt with the account's existing private key. The expected result is **PASS — decryption rejected**.
4. Explain that these tests demonstrate authenticated-encryption and wrong-key rejection, not comprehensive security certification.

## 3. Demonstrate measured performance

1. Open **Benchmarks** and click **Run benchmarks · 100 iterations**.
2. Wait for actual browser operations to finish.
3. Explain median, mean and standard deviation. The benchmark includes ML-KEM-768 key generation, encapsulation, decapsulation and a combined exchange; X25519 timings are included only when supported by the browser; HKDF and AES-GCM use a 1 KiB test payload.
4. Export the CSV and preserve it with the browser/device details for the report.
5. Do not claim that the timings are universal or perfectly apples-to-apples; device, browser, crypto implementation and operation scope affect results.

## 4. State the current limitations clearly

- ML-DSA identity signatures and cryptographic public-key identity verification are not implemented yet.
- Replay protection and a reviewed Double Ratchet / forward-secrecy design are not implemented.
- The ML-KEM private key is stored unencrypted in browser localStorage for this educational prototype.
- Password/session/database handling and deployment storage have not received a production security audit.
- Render's ephemeral filesystem can lose the JSON account/message store after instance replacement/redeploy; this prototype should be considered demo data only unless persistent storage is configured.

## One-sentence project summary

“Phase 1.5 turns our ML-KEM-based chat proof of concept into an observable experiment: it records real cryptographic operations, tests authenticated-ciphertext rejection, and measures post-quantum versus classical key-agreement costs; Phase 2 will focus on authenticated identity and forward secrecy.”
