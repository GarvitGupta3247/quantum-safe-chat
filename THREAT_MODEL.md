# Threat model — QuantumSafe Chat v0.6.0

The authoritative and detailed version is [SECURITY.md](SECURITY.md). This page is a summary.

## Assets
Message plaintext; private identity, prekey and ratchet keys; passwords and the OPAQUE export key;
the binding between usernames and identity keys; message integrity and sender authenticity;
metadata about who communicates with whom; availability.

## Adversaries considered

| Adversary | Outcome in v0.6 |
| --- | --- |
| Passive network observer (now or "harvest now, decrypt later" with a future quantum computer) | Message content protected by PQXDH (ML-KEM-768 + X25519) and the ratchet. Password never transmitted. TLS still needed for metadata and cookies; hybrid PQ TLS recommended (SECURITY.md §6.3). |
| Honest-but-curious server / database thief | Sees metadata and ciphertext only. Cannot unwrap keys without guessing the password; a database thief also needs the OPAQUE server setup to test guesses. |
| Malicious relay (modifies, replays, reorders, injects, relabels) | Detected and rejected by the receiver; can drop or delay messages. |
| Malicious directory (key substitution) | Detected for pinned contacts; first contact is TOFU until safety numbers are compared. |
| Server serving malicious JavaScript | **Not defended.** Inherent to browser-delivered E2EE (SECURITY.md §6.1). |
| Device compromise | Past captured traffic stays protected (forward secrecy); future messages heal after a ratchet round trip against classical attackers only. Saved history in the vault is exposed. |
| Online password guessing | Rate limited per account and per IP. |
| Other users | Cannot read others' messages, send as someone else through the relay, or obtain vaults. |

## Out of scope / not provided
Metadata privacy (sealed sender, cover traffic), key transparency, post-quantum post-compromise
security, multi-device sync, account recovery, formal verification, independent audit, production
database and horizontal scaling.
