// Long-term identities: a hybrid Ed25519 + ML-DSA-65 signing identity plus an X25519 identity DH key.
// A signature is valid only if BOTH component signatures verify, so forging one requires breaking
// Ed25519 (classical) and ML-DSA-65 (FIPS 204, post-quantum). The bundle is self-signed and binds the
// username, so a server cannot move one user's keys under another name without detection.

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { encodeCanonical, fromBase64, toBase64, toHex } from './bytes.js';

export const USERNAME_PATTERN = /^[a-z0-9_-]{3,24}$/;
export const SIZES = Object.freeze({
  ed25519Public: 32, ed25519Secret: 32, ed25519Sig: 64,
  mldsaPublic: 1952, mldsaSecret: 4032, mldsaSig: 3309,
  x25519: 32,
  kemPublic: 1184, kemSecret: 2400, kemCiphertext: 1088,
});

export class ProtocolError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'ProtocolError';
    this.code = code;
  }
}

export function validUsername(value) {
  return typeof value === 'string' && USERNAME_PATTERN.test(value);
}

function identityPayload(bundle) {
  return encodeCanonical('QSC-IDENTITY-v1', [
    bundle.username,
    fromBase64(bundle.ed25519, SIZES.ed25519Public),
    fromBase64(bundle.mldsa65, SIZES.mldsaPublic),
    fromBase64(bundle.x25519, SIZES.x25519),
    bundle.createdAt,
  ]);
}

export function hybridSign(message, privateIdentity) {
  return {
    ed25519: toBase64(ed25519.sign(message, fromBase64(privateIdentity.ed25519, SIZES.ed25519Secret))),
    mldsa65: toBase64(ml_dsa65.sign(message, fromBase64(privateIdentity.mldsa65, SIZES.mldsaSecret))),
  };
}

// Fails closed: any malformed input or either failed component returns false.
export function hybridVerify(message, signature, bundle) {
  try {
    if (!signature || typeof signature !== 'object') return false;
    const edOk = ed25519.verify(fromBase64(signature.ed25519, SIZES.ed25519Sig), message, fromBase64(bundle.ed25519, SIZES.ed25519Public));
    const mlOk = ml_dsa65.verify(fromBase64(signature.mldsa65, SIZES.mldsaSig), message, fromBase64(bundle.mldsa65, SIZES.mldsaPublic));
    return edOk === true && mlOk === true;
  } catch {
    return false;
  }
}

export function generateIdentity(username) {
  if (!validUsername(username)) throw new ProtocolError('invalid_username', 'Invalid username.');
  const ed = ed25519.keygen();
  const ml = ml_dsa65.keygen();
  const x = x25519.keygen();
  const privateIdentity = {
    ed25519: toBase64(ed.secretKey),
    mldsa65: toBase64(ml.secretKey),
    x25519: toBase64(x.secretKey),
  };
  const bundle = {
    v: 1,
    username,
    createdAt: Date.now(),
    ed25519: toBase64(ed.publicKey),
    mldsa65: toBase64(ml.publicKey),
    x25519: toBase64(x.publicKey),
  };
  bundle.sig = hybridSign(identityPayload(bundle), privateIdentity);
  return { privateIdentity, bundle };
}

// Structural + self-signature validation. A valid bundle proves key possession and the username
// binding; it does NOT prove the bundle belongs to the real person (that is what pinning and
// safety-number verification are for).
export function verifyIdentityBundle(bundle, expectedUsername) {
  if (!bundle || typeof bundle !== 'object' || bundle.v !== 1) throw new ProtocolError('malformed_identity', 'Malformed identity bundle.');
  if (!validUsername(bundle.username) || (expectedUsername !== undefined && bundle.username !== expectedUsername)) {
    throw new ProtocolError('identity_username_mismatch', 'Identity bundle is not bound to the expected username.');
  }
  if (!Number.isSafeInteger(bundle.createdAt) || bundle.createdAt < 0) throw new ProtocolError('malformed_identity', 'Malformed identity timestamp.');
  let payload;
  try { payload = identityPayload(bundle); } catch { throw new ProtocolError('malformed_identity', 'Malformed identity keys.'); }
  if (!hybridVerify(payload, bundle.sig, bundle)) throw new ProtocolError('bad_identity_signature', 'Identity bundle self-signature is invalid.');
  return identityFingerprint(bundle);
}

export function identityFingerprint(bundle) {
  return toHex(sha256(encodeCanonical('QSC-IDENTITY-FP-v1', [
    bundle.username,
    fromBase64(bundle.ed25519, SIZES.ed25519Public),
    fromBase64(bundle.mldsa65, SIZES.mldsaPublic),
    fromBase64(bundle.x25519, SIZES.x25519),
  ])));
}

// 60-digit safety number (two 30-digit halves, ordered by username) for out-of-band comparison.
export function safetyNumber(bundleA, bundleB) {
  const half = (bundle) => {
    let digest = encodeCanonical('QSC-SAFETY-NUMBER-v1', [bundle.username, identityFingerprint(bundle)]);
    for (let i = 0; i < 1024; i += 1) digest = sha512(digest);
    const groups = [];
    for (let i = 0; i < 6; i += 1) {
      const chunk = digest.subarray(i * 5, i * 5 + 5);
      const value = chunk.reduce((acc, byte) => acc * 256 + byte, 0) % 100000;
      groups.push(String(value).padStart(5, '0'));
    }
    return groups;
  };
  const [first, second] = [bundleA, bundleB].sort((a, b) => (a.username < b.username ? -1 : 1));
  return [...half(first), ...half(second)].join(' ');
}

// ----- Prekeys (PQXDH) -------------------------------------------------------------------------

export const PREKEY_KINDS = Object.freeze({ spk: 'spk', pqspk: 'pqspk', pqopk: 'pqopk' });

function prekeyPayload(record, bundle) {
  return encodeCanonical('QSC-PREKEY-v1', [
    record.kind, bundle.username, identityFingerprint(bundle), record.id,
    fromBase64(record.pub, record.kind === 'spk' ? SIZES.x25519 : SIZES.kemPublic),
    record.createdAt,
  ]);
}

// Signed prekeys: the X25519 signed prekey and the ML-KEM-768 last-resort / one-time prekeys.
export function createSignedPrekey(kind, id, privateIdentity, bundle) {
  if (!Object.hasOwn(PREKEY_KINDS, kind)) throw new ProtocolError('bad_prekey_kind');
  const pair = kind === 'spk' ? x25519.keygen() : ml_kem768.keygen();
  const record = { kind, id, pub: toBase64(pair.publicKey), createdAt: Date.now() };
  record.sig = hybridSign(prekeyPayload(record, bundle), privateIdentity);
  return { record, priv: toBase64(pair.secretKey) };
}

export function verifySignedPrekey(record, bundle, expectedKind) {
  try {
    if (!record || typeof record !== 'object' || record.kind !== expectedKind) return false;
    if (!Number.isSafeInteger(record.id) || record.id < 1 || !Number.isSafeInteger(record.createdAt)) return false;
    return hybridVerify(prekeyPayload(record, bundle), record.sig, bundle);
  } catch {
    return false;
  }
}

// One-time X25519 prekeys are unsigned, as in the PQXDH specification: substituting one cannot
// reveal the session key because DH1-DH3 and the ML-KEM secret are still required.
export function createOneTimePrekey(id) {
  const pair = x25519.keygen();
  return { record: { id, pub: toBase64(pair.publicKey) }, priv: toBase64(pair.secretKey) };
}

export function validOneTimePrekey(record) {
  try {
    return Boolean(record && Number.isSafeInteger(record.id) && record.id >= 1 && fromBase64(record.pub, SIZES.x25519));
  } catch {
    return false;
  }
}
