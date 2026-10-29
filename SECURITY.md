# Security design and threat model — QuantumSafe Chat v0.6.0

**Status: research prototype. Not independently audited. Do not use it for sensitive communication.**
This document describes what the code in this repository actually does, which properties it is
designed and tested to provide, and — just as importantly — what it does not protect against.

## 1. Components and trust boundaries

| Component | Holds | Trusted for |
| --- | --- | --- |
| Browser client (`src/`) | Password (transiently), OPAQUE export key, vault data key, all private keys, ratchet state, plaintext | Everything. A compromised client defeats every protection below. |
| Server (`server/app.js`) | OPAQUE registration records + server setup, encrypted vaults, public identity/prekey directory, queued ciphertext, in-memory sessions | **Availability and routing only.** It is *not* trusted for confidentiality, message integrity, sender identity, or key authenticity — with the exceptions in §6. |
| Network / TLS terminator | Transport | Hiding metadata from network observers; delivering the client code unmodified (§6.1). |

## 2. Protocol overview

### 2.1 Authentication and key custody (fixes audit F1, F5, F6)
* **OPAQUE** (RFC 9807, via `@serenity-kit/opaque` = the `opaque-ke` Rust crate compiled to WASM,
  ristretto255). Registration and login never send the password or anything from which it can be
  computed without guessing. Code: `src/protocol/client.js` (`register`, `login`), `server/app.js`
  (`/api/auth/*`).
* **Argon2id key stretching inside OPAQUE**: 64 MiB, t=3, p=1 (RFC 9106 §4 second recommendation,
  p=1 because WASM is single-threaded). Parameters are fixed in the client
  (`src/protocol/password.js`), so a server cannot request weaker stretching. Measured cost: ~160 ms
  per evaluation in Node 25 and ~0.3 s for a full browser login (Chrome 2026, development laptop).
* **Vault**: the OPAQUE *export key* (client-only) → HKDF-SHA-256 → key-encryption key (KEK) →
  wraps a random 256-bit data key (DEK) → AES-256-GCM encrypts the vault (identity keys, prekeys,
  ratchet sessions, pinned contacts, message history, outbox). The vault version and username are
  bound into the AEAD associated data. Code: `src/protocol/vault.js`.
* **Password policy** (client-side only — the server never sees the password): ≥12 characters,
  ≤256, not on a small common-password list, must not contain the username, ≥5 distinct characters.
* **Online guessing**: 10 login starts per account and 60 per IP per 15 minutes (`429`).
* **Password change**: requires a fresh OPAQUE login (< 5 minutes), registers a new OPAQUE record,
  **rotates the DEK** and re-encrypts the vault, and revokes all other sessions.
* **Forgotten password**: *no recovery.* Nobody — including the operator — can decrypt the vault
  without the password. The user must create a new account (new identity; contacts see a new key).
  Recovery codes would be a reasonable future addition; they are not implemented.
* **Multi-device**: one active device per account. A new login revokes other sessions and closes
  their sockets (`displaced`). Vault writes use compare-and-swap on the version number, so a stale
  device cannot overwrite newer ratchet state. Moving between devices works because the vault is
  stored (encrypted) on the server. Simultaneous multi-device use is not supported.

### 2.2 Identity and key authentication (fixes F2)
* Each account has a **hybrid signing identity**: Ed25519 + ML-DSA-65 (FIPS 204), plus an X25519
  identity DH key. A signature is valid only if *both* components verify (`hybridVerify`), so a
  forgery requires breaking both a classical and a post-quantum scheme (and defends against an
  implementation flaw in either library).
* The identity bundle is **self-signed and binds the username** (`QSC-IDENTITY-v1`). The server
  verifies it at registration (to reject garbage) but clients never rely on the server for trust.
* **Pinning (TOFU)**: the first identity seen for a contact is pinned in the encrypted vault, so the
  pin follows the user to new devices. Any later mismatch — in the directory, in a prekey bundle,
  or in an incoming message — is recorded as a pending change, **blocks sending**, and quarantines
  incoming messages. The user must explicitly accept the new key; it is then pinned as *unverified*.
* **Verification**: a 60-digit **safety number** (iterated SHA-512 over both identity
  fingerprints) is shown for every conversation. Users compare it out of band and mark the contact
  *verified*. Every received message shows whether its sender is verified or merely TOFU-pinned.
* **First-contact cross-check**: a session-establishment message from a never-seen sender must
  carry the same identity that the directory publishes.

### 2.3 Session establishment: PQXDH (fixes F4, part 1)
Signal's PQXDH (revision 3) with X25519, SHA-256 and ML-KEM-768 (`src/protocol/pqxdh.js`):
`SK = HKDF(0xFF·32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] ‖ SS_mlkem)`. Prekeys: signed X25519 prekey,
signed ML-KEM-768 last-resort prekey, 20 one-time X25519 prekeys and 10 signed one-time ML-KEM-768
prekeys, replenished automatically; signed prekeys rotate weekly (3 retained).
Documented deviations from the spec:
1. Prekeys are signed with the hybrid identity signature instead of XEdDSA.
2. The HKDF `info` additionally binds SHA-256 of the ML-KEM public key and ciphertext and the prekey
   identifiers (a conservative binding measure; no spec input is removed).
3. AD encodes both parties' usernames and full identity fingerprints.

### 2.4 Messaging: Double Ratchet (fixes F4, part 2; F3; F7)
Signal's Double Ratchet (`src/protocol/ratchet.js`): X25519 DH ratchet, HKDF-SHA-256 root KDF,
HMAC-SHA-256 chain KDF, AES-256-GCM. AES-GCM nonces are random 96-bit values carried in the
signed header, so even an accidental state rollback cannot cause (key, nonce) reuse.

Envelope (`src/protocol/envelope.js`), JSON on the wire, but every security-relevant input is a
**canonical, type-tagged, length-prefixed binary encoding** (`encodeCanonical`, `src/protocol/bytes.js`):
* **Signed** (hybrid Ed25519 + ML-DSA-65) over: version, type, sender, recipient, sender and
  recipient identity fingerprints, conversation ID (hash of the sorted usernames), message UUID,
  timestamp, session ID, ratchet header (DH key, PN, N), nonce, the PQXDH header (identity
  fingerprint, ephemeral key, ML-KEM ciphertext, prekey IDs), and the ciphertext.
* **AEAD associated data**: the PQXDH session AD plus all of the header fields above.
* Plaintext is padded to 256-byte buckets (ISO/IEC 7816-4) to blur message lengths.

Receiver checks, in order, all fail-closed and transactional (no state changes on failure):
strict schema → recipient name *and* fingerprint → conversation ID → timestamp skew (≤10 min in the
future) → duplicate message ID → pinned identity → session lookup / replayed session ID → identity
bundle self-signature → **hybrid signature** → ratchet decryption + **AEAD** → payload validation.
Only then are one-time prekeys deleted, the contact pinned, and the message displayed.

**Replay protection (F7)** is enforced by the receiver: message-ID cache (5,000 per contact),
consumed ratchet keys, a permanent list of seen session IDs (so a replayed session-establishment
message cannot recreate a session), and deleted one-time prekeys. Out-of-order delivery is
tolerated (up to 256 skipped keys per chain, 1,000 total).

## 3. Properties: what comes from where

| Property | Mechanism | Source |
| --- | --- | --- |
| Password never sent; server cannot unwrap keys without guessing | OPAQUE + export-key-wrapped vault | Standard (RFC 9807) + protocol design |
| Offline guessing cost after a full server breach | Argon2id 64 MiB, t=3 | Standard (RFC 9106) + parameter choice |
| Message confidentiality vs. classical and quantum attackers who record traffic | PQXDH (X25519 + ML-KEM-768) then Double Ratchet | FIPS 203 + Signal specs |
| Sender authenticity, metadata integrity | Hybrid signature + AEAD AD over canonical encoding | FIPS 204 / RFC 8032 + protocol design |
| Key-substitution detection | Self-signed bundles, vault-held pins, safety numbers | Protocol design (trust model below) |
| Forward secrecy | Ratchet key deletion, one-time prekey deletion | Signal specs |
| Post-compromise security | DH ratchet | Signal spec — **classical only** (§5) |
| Transport confidentiality of metadata, cookie, client code | TLS | **Deployment configuration** (§6.1) |

## 4. Verified by automated tests
`npm test` (40 tests, Node) and `npm run test:browser` (9 steps, real Chrome). Highlights, each
run against the real server and real `ChatClient` code paths:
* The original F1 attack (database + captured login traffic → private key) fails; neither the
  password, the export key nor any private key appears in traffic or the database; offline
  guessing requires the OPAQUE server setup and one Argon2id evaluation per guess
  (`test/integration/attack-key-custody.test.js`).
* Key substitution by the server is detected and blocks sending, including on a new device; a
  forged identity for a pinned contact is rejected and quarantined (`attack-protocol.test.js`).
* 16 tampering variants (relabelled sender, altered recipient/conversation/ID/timestamp/counter/
  ratchet key/nonce/ciphertext, corrupted or missing signatures, foreign signer, extra fields,
  wrong version) are rejected; misdirected and replayed packets are rejected; reordering works.
* AEAD binding is tested independently of signatures (sender re-signs altered metadata), and an
  invalid ML-KEM ciphertext is shown to fail at AEAD, not "succeed" (`test/unit/protocol.test.js`).
* Forward secrecy and classical post-compromise security are demonstrated with device-state
  snapshots (`session-security.test.js`).
* No plaintext, password or key material in network payloads, the server store, server logs,
  trace events or exported reports.

## 5. Known limitations (read these)
1. **First contact is trust-on-first-use.** A malicious server that lies consistently from the
   very first contact can impersonate that contact until the users compare safety numbers. There is
   no key-transparency log.
2. **Post-compromise security is classical.** The DH ratchet uses X25519 only; ML-KEM enters once
   per session through PQXDH. A quantum attacker who obtains a full state snapshot can follow later
   ratchet steps. Signal's SPQR / "triple ratchet" would address this; it is not implemented.
   Forward secrecy against a *recording* quantum attacker without a state compromise does hold,
   because the root key descends from the ML-KEM secret.
3. **First-flight exposure without a one-time prekey.** If the server has run out of (or withholds)
   one-time prekeys, a later compromise of the recipient's identity + signed prekeys, before those
   prekeys rotate out (≤ ~3 weeks), exposes the first messages of that session. This mirrors the
   PQXDH specification's own caveat and is demonstrated by a test labelled `LIMITATION`.
4. **The vault stores message history.** Anyone who obtains the password (or guesses it after
   stealing the database *and* the OPAQUE server setup) can read stored history and current
   sessions. Forward secrecy protects captured *traffic*, not the user's own saved history.
5. **OPAQUE itself is not post-quantum.** A future quantum adversary holding recorded login
   transcripts could recover the OPRF key and mount Argon2id-bounded offline guessing. Strong
   passwords remain important.
6. **Vault rollback** is detected only on a device that has previously seen a newer version.
7. **Signatures remove deniability**: a recipient can prove to a third party that the sender signed
   a message. This was a deliberate requirement (audit F3) and differs from Signal.
8. **Library maturity**: `@noble/post-quantum` (ML-KEM, ML-DSA) is self-audited only;
   `@noble/curves`/`@noble/hashes` have had independent audits; the OPAQUE WASM build wraps the
   `opaque-ke` crate. The hybrid constructions limit, but do not eliminate, this risk. All JavaScript
   cryptography is subject to timing side channels the JS engine may introduce.
9. **No independent review** of this protocol composition or implementation has been performed.

## 6. Deployment requirements and remaining server powers

### 6.1 The server delivers the client code (audit F8)
A browser-based end-to-end encrypted app **cannot protect users against the server that serves its
JavaScript**: a malicious or compromised server can ship code that steals the password, the export
key or plaintext. Mitigations implemented: strict CSP (`default-src 'self'`, `script-src 'self'
'wasm-unsafe-eval'`, no third-party origins, no inline script, no `data:` fonts), no third-party
runtime requests (fonts are bundled), `frame-ancestors 'none'`, COOP/CORP. Stronger options not
implemented: a signed/pinned desktop or extension client, or published reproducible builds with
independent hash monitoring.

### 6.2 What a malicious server can still do
* Serve malicious client code (6.1).
* See metadata (§7), drop, delay or withhold messages, and deny service.
* Impersonate a contact *at first contact* until safety numbers are compared (§5.1).
* Withhold one-time prekeys (§5.3).
* Attempt offline password guessing if it is the operator (it has the OPAQUE setup): ~one Argon2id
  evaluation per guess per user.
* Roll back a vault for a user on a new device (§5.6).

It can **no longer**: learn passwords from login, unwrap private keys without guessing, substitute
keys for pinned contacts undetected, forge or relabel senders, alter message metadata, or replay
messages.

### 6.3 Transport security (audit F6)
Application-level ML-KEM does **not** make HTTPS/WSS quantum-resistant. TLS still protects session
cookies, metadata, vault ciphertext in transit, and the integrity of the delivered client code.
* Use HTTPS/WSS only in production (`NODE_ENV=production` sets `Secure` cookies and HSTS).
* Prefer hybrid post-quantum key exchange (`X25519MLKEM768`) at whatever terminates TLS.
  Verified locally: Node 25.7 / OpenSSL 3.5.5 completes a TLS 1.3 handshake when the client offers
  *only* `X25519MLKEM768`. Whether a hosting provider's edge proxy negotiates it is a deployment
  property that must be checked there (e.g. with a current browser's security panel or
  `openssl s_client -groups X25519MLKEM768`); it has **not** been verified for any deployment.
* The password no longer crosses the network, so recorded TLS traffic no longer yields it even if
  TLS is broken later. Recorded OPAQUE transcripts are subject to limitation §5.5.

### 6.4 Operator configuration
* `OPAQUE_SERVER_SETUP`: keep the OPAQUE server secret outside the data volume (secret manager). If
  unset, it is generated into `DATA_DIR/opaque-server-setup.txt` (mode 600 on POSIX; Windows
  does not enforce that mode, so restrict the directory ACL there). Losing it locks every
  user out; leaking it together with the store enables offline guessing.
* `ALLOWED_ORIGINS`: exact HTTPS origin(s).
* `QSC_LEGACY_MIGRATION=0` once all v0.5 accounts have migrated (closes the only route that
  receives a password).
* `DATA_DIR`: persistent volume. Sessions, rate-limit counters and login states are in memory.

## 7. Metadata (audit F10)
End-to-end encryption hides message *content*, not metadata. The server sees: account names and
creation times; the identity directory; who sends to whom and when (sender is in the signed header
and authenticated by the socket); queue sizes; ciphertext sizes (padded to 256-byte buckets);
online presence (broadcast to all logged-in users); IP addresses; login times; vault sizes and
update frequency. Minimisation implemented: ciphertext is deleted as soon as the recipient
acknowledges it (30-day maximum for undelivered messages) instead of being kept as server-side
history; no per-message server logging; padding; contact lists and conversation history live only in
the encrypted vault. Not implemented: sealed sender, cover traffic, private contact discovery, or
hiding presence.

## 8. Legacy accounts (audit F9)
v0.5 accounts are converted on first start (a backup `store.v2-backup-*.json` is written first).
Their scrypt hashes and PBKDF2 key bundles are quarantined and used only by the explicit **Upgrade
legacy account** flow, which (once) sends the old password as v0.5 always did, requires a **new**
password, creates a fresh identity, imports old messages labelled *legacy — sender not
authenticated*, then erases the legacy credentials and the user's legacy ciphertext. Plaintext
private keys left in `localStorage` by pre-v0.4 builds are never used; the login page offers to
delete them, and migration deletes them.

## 9. Reporting
This is a student research project. Please open a GitHub issue for security problems in the
prototype; do not test against deployments you do not own.
