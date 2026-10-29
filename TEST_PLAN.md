# Test plan — QuantumSafe Chat v0.6.0

All tests are automated. Nothing in this table is a manual checklist item.

```bash
npm test                                  # unit + integration + attack regression (Node)
npm run build && npm run test:browser     # real headless Chrome against the production build
```

## Automated suite (`npm test`, 40 tests)

| File | Covers |
| --- | --- |
| `test/unit/protocol.test.js` | Canonical encoding ambiguity, strict Base64, identity self-signatures and hybrid verification (each half forged separately), safety numbers, AEAD binding independent of signatures, invalid ML-KEM ciphertext caught by AEAD with no state change (N2), bounded skipping, forged prekey rejection, signed-prekey rotation, strict packet schema, vault binding to username/version, password policy. |
| `test/unit/research.test.js` | In-app self-tests pass under Node (N4); report allow-list and redaction (N1). |
| `test/integration/messaging.test.js` | Two clients exchange messages both ways; re-login from a fresh client restores history/sessions; offline queueing and ordering; reconnection without duplicates; no plaintext/password in traffic, store or logs; third user cannot read; trace events carry no secrets (N1/N2). |
| `test/integration/attack-key-custody.test.js` | **F1** server cannot unwrap keys from DB + captured login traffic; offline guessing needs the OPAQUE setup and costs one Argon2id per guess; **F5** wrong credentials, throttling, password policy; password change rotates the DEK and revokes sessions; one active device; vault rollback detection. |
| `test/integration/attack-protocol.test.js` | **F2** key substitution detected (existing and new device), forged identity quarantined; **F3** relay refuses forged sender, 16 tampering variants rejected, misdirected packet rejected; **F7** replay and session-establishment replay rejected, reordering tolerated; dropped first message and simultaneous initiation. |
| `test/integration/session-security.test.js` | **F4** forward secrecy after device compromise; classical post-compromise healing; documented first-flight limitation without one-time prekeys. |
| `test/integration/legacy-migration.test.js` | **F9** genuine v0.5 store (built with the original `mlkem` library) migrated on a disposable copy; plaintext local keys never used and removed; migration can be disabled. |
| `test/integration/server-hardening.test.js` | Unauthenticated access, WebSocket auth/origin, CSRF (content type + origin), CSP/headers (N3), body limits, registration validation, relay frame validation, vault compare-and-swap, logout. |

## Browser test (`npm run test:browser`, 9 steps)
Registration and login in two isolated contexts; signed delivery; replies; matching safety numbers
and verification; in-app self-tests; benchmark; exported report free of secrets (N1); history
after logout/login in a fresh context; zero CSP violations, console errors, third-party requests or
passwords in any request. The test skips (exit 0) if no Chrome/Chromium/Edge is installed.

## Not automated
Mobile browsers, Safari and Firefox; deployment TLS configuration; load testing; long-running
soak tests; accessibility audit.
