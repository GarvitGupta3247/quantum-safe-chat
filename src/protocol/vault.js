// Client-side key custody. The OPAQUE export key (never sent to, or derivable by, the server without
// guessing the password) derives a key-encryption key (KEK). The KEK wraps a random data-encryption
// key (DEK), and the DEK encrypts the account vault (identity keys, prekeys, ratchet sessions,
// pinned contacts and message history). The server stores only ciphertext.
//
// The vault version number is bound into the AEAD associated data, so the server cannot relabel an
// older blob as a newer version. It can still serve an older (blob, version) pair; clients detect
// that on a device where they have seen a newer version (see ChatClient rollback detection).

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { encodeCanonical, fromBase64, fromBase64Url, randomBytes, textDecoder, toBase64, utf8 } from './bytes.js';
import { ProtocolError } from './identity.js';

const subtle = () => globalThis.crypto.subtle;

export async function deriveKek(exportKey, username) {
  const raw = hkdf(sha256, fromBase64Url(exportKey), utf8('QSC-VAULT-KEK-SALT-v1'), encodeCanonical('QSC-VAULT-KEK-v1', [username]), 32);
  return subtle().importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export function generateDek() {
  return randomBytes(32);
}

async function importDek(dek) {
  return subtle().importKey('raw', dek, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function wrapDek(kek, dek, username) {
  const iv = randomBytes(12);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: encodeCanonical('QSC-VAULT-DEK-v1', [username]) }, kek, dek);
  return { iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) };
}

export async function unwrapDek(kek, wrapped, username) {
  try {
    const dek = await subtle().decrypt(
      { name: 'AES-GCM', iv: fromBase64(wrapped.iv, 12), additionalData: encodeCanonical('QSC-VAULT-DEK-v1', [username]) },
      kek, fromBase64(wrapped.ct, 48),
    );
    return new Uint8Array(dek);
  } catch {
    throw new ProtocolError('vault_unwrap_failed', 'Could not unwrap the vault key.');
  }
}

export async function sealVault(dek, username, version, vault) {
  const iv = randomBytes(12);
  const ad = encodeCanonical('QSC-VAULT-v1', [username, version]);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: ad }, await importDek(dek), utf8(JSON.stringify(vault)));
  return { iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) };
}

export async function openVault(dek, username, version, blob) {
  let plaintext;
  try {
    const ad = encodeCanonical('QSC-VAULT-v1', [username, version]);
    plaintext = await subtle().decrypt({ name: 'AES-GCM', iv: fromBase64(blob.iv, 12), additionalData: ad }, await importDek(dek), fromBase64(blob.ct));
  } catch {
    throw new ProtocolError('vault_open_failed', 'The account vault failed authentication.');
  }
  const vault = JSON.parse(textDecoder.decode(new Uint8Array(plaintext)));
  if (vault?.format !== 'qsc-vault-v1' || vault.username !== username) throw new ProtocolError('vault_open_failed', 'Vault does not belong to this account.');
  return vault;
}
