// PQXDH key agreement, following Signal's "The PQXDH Key Agreement Protocol" (revision 3) with
// curve = X25519, hash = SHA-256 and pqkem = ML-KEM-768 (FIPS 203).
//
// Documented deviations from the specification:
//  * Prekeys and the identity DH key are signed with the hybrid Ed25519 + ML-DSA-65 identity
//    signature instead of XEdDSA over the X25519 identity key.
//  * The HKDF info additionally binds SHA-256 of the ML-KEM public key and ciphertext and the prekey
//    identifiers. This is a conservative binding measure; it does not remove any input the spec requires.
//  * AD encodes both parties' full identity fingerprints (which cover the signing and DH identity keys).

import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, encodeCanonical, fromBase64, toBase64, wipe } from './bytes.js';
import { identityFingerprint, ProtocolError, SIZES } from './identity.js';

const PQXDH_INFO_LABEL = 'QSC_PQXDH_CURVE25519_SHA-256_ML-KEM-768';

function dh(privateB64, publicB64) {
  let shared;
  try {
    shared = x25519.getSharedSecret(fromBase64(privateB64, SIZES.x25519), fromBase64(publicB64, SIZES.x25519));
  } catch {
    throw new ProtocolError('bad_dh', 'X25519 rejected a public key.');
  }
  // Reject low-order points (all-zero output) explicitly.
  if (shared.every((byte) => byte === 0)) throw new ProtocolError('bad_dh', 'X25519 produced an all-zero secret.');
  return shared;
}

function kdf(dhOutputs, kemSecret, context) {
  const ikm = concatBytes(new Uint8Array(32).fill(0xff), ...dhOutputs, kemSecret);
  const info = encodeCanonical(PQXDH_INFO_LABEL, context);
  const sk = hkdf(sha256, ikm, new Uint8Array(32), info, 32);
  wipe(ikm);
  dhOutputs.forEach(wipe);
  return sk;
}

export function associatedData(initiatorBundle, responderBundle) {
  return encodeCanonical('QSC-PQXDH-AD-v1', [
    initiatorBundle.username, identityFingerprint(initiatorBundle),
    responderBundle.username, identityFingerprint(responderBundle),
  ]);
}

function kdfContext(pqPublicB64, kemCiphertext, header) {
  return [
    sha256(fromBase64(pqPublicB64, SIZES.kemPublic)),
    sha256(kemCiphertext),
    header.spkId, header.pqKind, header.pqId, header.opkId ?? null,
  ];
}

// Initiator side. `peer` is a server-provided prekey bundle whose signatures the caller has verified.
export function initiate({ myPrivate, myBundle, peerBundle, spk, pq, opk }) {
  const ek = x25519.keygen();
  const ekPriv = toBase64(ek.secretKey);
  const dh1 = dh(myPrivate.x25519, spk.pub);
  const dh2 = dh(ekPriv, peerBundle.x25519);
  const dh3 = dh(ekPriv, spk.pub);
  const dhOutputs = [dh1, dh2, dh3];
  if (opk) dhOutputs.push(dh(ekPriv, opk.pub));
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(fromBase64(pq.pub, SIZES.kemPublic));
  const header = {
    ek: toBase64(ek.publicKey),
    kemCt: toBase64(cipherText),
    spkId: spk.id,
    pqKind: pq.kind,
    pqId: pq.id,
    opkId: opk ? opk.id : null,
  };
  const sk = kdf(dhOutputs, sharedSecret, kdfContext(pq.pub, cipherText, header));
  wipe(sharedSecret);
  wipe(ek.secretKey);
  return { sk, ad: associatedData(myBundle, peerBundle), header, peerRatchetPublic: spk.pub };
}

// Responder side. The caller looks up the private prekeys referenced by `header`.
export function respond({ myPrivate, myBundle, peerBundle, header, spkPriv, pqPriv, pqPub, opkPriv }) {
  let kemCiphertext;
  try { kemCiphertext = fromBase64(header.kemCt, SIZES.kemCiphertext); } catch { throw new ProtocolError('malformed', 'Bad KEM ciphertext.'); }
  const dh1 = dh(spkPriv, peerBundle.x25519);
  const dh2 = dh(myPrivate.x25519, header.ek);
  const dh3 = dh(spkPriv, header.ek);
  const dhOutputs = [dh1, dh2, dh3];
  if (header.opkId !== null) {
    if (!opkPriv) throw new ProtocolError('stale_prekey', 'The one-time prekey referenced by this message is no longer available.');
    dhOutputs.push(dh(opkPriv, header.ek));
  }
  // ML-KEM decapsulation never "fails": an invalid ciphertext yields an implicit-rejection secret,
  // which is detected later when AEAD authentication of the first message fails.
  const sharedSecret = ml_kem768.decapsulate(kemCiphertext, fromBase64(pqPriv, SIZES.kemSecret));
  const sk = kdf(dhOutputs, sharedSecret, kdfContext(pqPub, kemCiphertext, header));
  wipe(sharedSecret);
  return { sk, ad: associatedData(peerBundle, myBundle) };
}
