# Research Lab — v0.6.0

The Research Lab views are educational. They never display or export private keys, shared
secrets, values derived from secrets (such as digests of shared secrets), passwords, or plaintext.

## Crypto Trace
A timeline of operations performed by this browser: OPAQUE registration/login, identity and prekey
generation, PQXDH session start, message signing/encryption, incoming message authentication, and
rejections with their reason codes. Events report sizes and timings only.

A PQXDH session is reported as *accepted* only after the first message has passed signature
verification **and** AES-GCM authentication. ML-KEM decapsulation never reports "success" on its
own, because an invalid ciphertext still yields a (pseudo-random) secret by design; failure only
becomes visible at AEAD authentication (audit N2).

**Export report** produces `quantumsafe-chat-research-report-v2` JSON built from an allow-list:
event titles/outcomes/details (with any long Base64/hex run redacted), benchmark samples,
self-test results, the algorithm list, and the account's **public** identity fingerprint.

## Benchmark Lab
Measures ML-KEM-768 key generation/encapsulation/decapsulation and an X25519 ECDH baseline, each
followed by the same HKDF + AES-256-GCM steps on a 1 KiB payload.

**Methodology caveat (audit N5):** ML-KEM runs as **pure JavaScript** (`@noble/post-quantum`)
whereas X25519 runs in the browser's **native Web Crypto** implementation. The numbers therefore
compare two implementation environments, not the intrinsic cost of the algorithms. The production
protocol uses both together (hybrid PQXDH), so its cost is roughly the sum. Results are
device/browser specific; record the browser, OS and source revision, and repeat runs.

## Security Tests
Runs `src/research/selftests.js`: it creates disposable identities, builds **real** envelopes with
`encryptEnvelope`, attacks them (ciphertext and KEM-ciphertext tampering, forged sender, altered
recipient, foreign signer, validly signed invalid KEM ciphertext, replay, substituted public key
for a pinned contact, wrong vault key, vault version relabelling) and checks that `openEnvelope` /
the vault reject them with the expected reason. The same file runs under `npm test`.

Attacks that need the server (relay tampering, directory substitution, replay through the queue,
password-custody attacks) are in the automated suite (`test/integration/`), not in the browser view.
A PASS means a specific attack was rejected; it does not certify the application.
