// One-way migration support for accounts created by v0.5.x and earlier. These helpers are used ONLY
// to read old history once during the explicit "upgrade legacy account" flow. Legacy messages carry
// no sender authentication, so migrated history is always labelled unauthenticated.
//
// Plaintext private keys left in localStorage by pre-v0.4 builds are never accepted.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { fromBase64, textDecoder, utf8 } from './bytes.js';
import { SIZES } from './identity.js';

const LEGACY_KDF_INFO = utf8('QuantumSafeChat PoC v1 | ML-KEM-768 | AES-256-GCM');
const LEGACY_ITERATIONS = 600_000;
const LOCAL_KEY_PREFIX = 'qsc:mlkem768:';

export async function unlockLegacyBundle(bundle, password) {
  if (!bundle || bundle.version !== 2 || bundle.kdf !== 'PBKDF2-HMAC-SHA-256' || bundle.iterations !== LEGACY_ITERATIONS) {
    throw new Error('Unsupported legacy key bundle.');
  }
  const subtle = globalThis.crypto.subtle;
  const material = await subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', salt: fromBase64(bundle.salt, 16), iterations: LEGACY_ITERATIONS, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  );
  try {
    const secret = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(bundle.iv, 12) }, key, fromBase64(bundle.encryptedPrivateKey, SIZES.kemSecret + 16)));
    return secret;
  } catch {
    throw new Error('Could not unlock the legacy key bundle with that password.');
  }
}

export async function decryptLegacyEnvelope(envelope, legacySecretKey) {
  const subtle = globalThis.crypto.subtle;
  const sharedSecret = ml_kem768.decapsulate(fromBase64(envelope.kemCiphertext, SIZES.kemCiphertext), legacySecretKey);
  const material = await subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  const key = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: fromBase64(envelope.salt, 16), info: LEGACY_KDF_INFO },
    material, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  );
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(envelope.iv, 12) }, key, fromBase64(envelope.ciphertext));
  return textDecoder.decode(new Uint8Array(plaintext));
}

// Classifies old localStorage entries without ever using them as key material.
export function scanLegacyLocalKeys(storage) {
  const found = [];
  if (!storage) return found;
  try {
    for (let i = 0; i < storage.length; i += 1) {
      const name = storage.key(i);
      if (!name?.startsWith(LOCAL_KEY_PREFIX)) continue;
      let kind = 'unknown';
      try {
        const parsed = JSON.parse(storage.getItem(name));
        if (typeof parsed?.privateKey === 'string') kind = 'plaintext-private-key';
        else if (parsed?.version === 2) kind = 'pbkdf2-wrapped-bundle';
      } catch { /* unparsable */ }
      found.push({ storageKey: name, username: name.slice(LOCAL_KEY_PREFIX.length), kind });
    }
  } catch { /* storage unavailable */ }
  return found;
}

export function removeLegacyLocalKey(storage, username) {
  try { storage?.removeItem(`${LOCAL_KEY_PREFIX}${username}`); } catch { /* storage unavailable */ }
}
