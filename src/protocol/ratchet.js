// Double Ratchet, following Signal's "The Double Ratchet Algorithm" specification (revision 4):
//   GENERATE_DH / DH = X25519, KDF_RK = HKDF-SHA-256, KDF_CK = HMAC-SHA-256 (0x01 -> message key,
//   0x02 -> next chain key), ENCRYPT = AES-256-GCM with a key derived from the message key.
//
// Properties (see SECURITY.md for precise statements):
//  * Forward secrecy: used message keys and old chain keys are deleted.
//  * Post-compromise security: each DH ratchet step mixes a fresh X25519 secret into the root key.
//    That healing is CLASSICAL ONLY: a quantum attacker who captured a full state snapshot can
//    follow later X25519 ratchet steps. The ML-KEM contribution enters once, through PQXDH.
//
// AES-GCM nonces are random 96-bit values carried in the signed header (rather than derived from
// the message key), so an accidental state rollback can never cause (key, nonce) reuse.
//
// All functions are transactional: they operate on a deep copy and return a new state, so a failed
// authentication leaves the caller's state untouched.

import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { fromBase64, randomBytes, toBase64, utf8 } from './bytes.js';
import { ProtocolError, SIZES } from './identity.js';

export const MAX_SKIP = 256;
const MAX_SKIPPED_TOTAL = 1000;
const MAX_PREVIOUS_CHAINS = 8;
const RK_INFO = utf8('QSC-DR-ROOT-v1');
const MK_INFO = utf8('QSC-DR-MESSAGE-KEY-v1');

function clone(state) {
  return structuredClone(state);
}

function generateDh() {
  const pair = x25519.keygen();
  return { pub: toBase64(pair.publicKey), priv: toBase64(pair.secretKey) };
}

function dh(pair, publicB64) {
  let out;
  try {
    out = x25519.getSharedSecret(fromBase64(pair.priv, SIZES.x25519), fromBase64(publicB64, SIZES.x25519));
  } catch {
    throw new ProtocolError('bad_dh', 'Invalid ratchet public key.');
  }
  if (out.every((byte) => byte === 0)) throw new ProtocolError('bad_dh', 'Low-order ratchet public key.');
  return out;
}

function kdfRk(rkB64, dhOut) {
  const out = hkdf(sha256, dhOut, fromBase64(rkB64, 32), RK_INFO, 64);
  return [toBase64(out.subarray(0, 32)), toBase64(out.subarray(32))];
}

function kdfCk(ckB64) {
  const ck = fromBase64(ckB64, 32);
  return [toBase64(hmac(sha256, ck, Uint8Array.of(0x02))), toBase64(hmac(sha256, ck, Uint8Array.of(0x01)))];
}

async function aeadKey(mkB64, usage) {
  const raw = hkdf(sha256, fromBase64(mkB64, 32), new Uint8Array(32), MK_INFO, 32);
  return globalThis.crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [usage]);
}

export function initInitiator(sk, peerRatchetPublic) {
  const dhs = generateDh();
  const [rk, cks] = kdfRk(toBase64(sk), dh(dhs, peerRatchetPublic));
  return { rk, dhs, dhr: peerRatchetPublic, cks, ckr: null, ns: 0, nr: 0, pn: 0, skipped: {}, previous: [] };
}

export function initResponder(sk, ownRatchetPair) {
  return { rk: toBase64(sk), dhs: { ...ownRatchetPair }, dhr: null, cks: null, ckr: null, ns: 0, nr: 0, pn: 0, skipped: {}, previous: [] };
}

// buildAd(header) must return the full associated data, including the header it is given.
export async function ratchetEncrypt(state, plaintext, buildAd) {
  const s = clone(state);
  if (!s.cks) throw new ProtocolError('no_sending_chain', 'This session cannot send yet.');
  const [nextCk, mk] = kdfCk(s.cks);
  s.cks = nextCk;
  const header = { dh: s.dhs.pub, pn: s.pn, n: s.ns, nonce: toBase64(randomBytes(12)) };
  s.ns += 1;
  const ad = buildAd(header);
  const key = await aeadKey(mk, 'encrypt');
  const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: fromBase64(header.nonce, 12), additionalData: ad }, key, plaintext,
  ));
  return { state: s, header, ciphertext };
}

function skipMessageKeys(s, until) {
  if (!s.ckr) return;
  if (until - s.nr > MAX_SKIP) throw new ProtocolError('too_many_skipped', 'Too many skipped messages in one chain.');
  while (s.nr < until) {
    const [nextCk, mk] = kdfCk(s.ckr);
    s.ckr = nextCk;
    s.skipped[`${s.dhr}:${s.nr}`] = mk;
    s.nr += 1;
  }
  const keys = Object.keys(s.skipped);
  for (let i = 0; i < keys.length - MAX_SKIPPED_TOTAL; i += 1) delete s.skipped[keys[i]];
}

function dhRatchet(s, header) {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  if (s.dhr) s.previous = [s.dhr, ...s.previous].slice(0, MAX_PREVIOUS_CHAINS);
  s.dhr = header.dh;
  [s.rk, s.ckr] = kdfRk(s.rk, dh(s.dhs, s.dhr));
  s.dhs = generateDh();
  [s.rk, s.cks] = kdfRk(s.rk, dh(s.dhs, s.dhr));
}

async function aeadDecrypt(mk, header, ciphertext, ad) {
  try {
    const key = await aeadKey(mk, 'decrypt');
    return new Uint8Array(await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(header.nonce, 12), additionalData: ad }, key, ciphertext,
    ));
  } catch {
    throw new ProtocolError('decrypt_failed', 'Message authentication failed.');
  }
}

export async function ratchetDecrypt(state, header, ciphertext, buildAd) {
  const s = clone(state);
  const ad = buildAd(header);
  const skippedId = `${header.dh}:${header.n}`;
  if (Object.hasOwn(s.skipped, skippedId)) {
    const plaintext = await aeadDecrypt(s.skipped[skippedId], header, ciphertext, ad);
    delete s.skipped[skippedId];
    return { state: s, plaintext };
  }
  // A key that was already consumed (or a chain we have moved past) is a replay, not a new chain.
  if ((header.dh === s.dhr && header.n < s.nr) || s.previous.includes(header.dh)) {
    throw new ProtocolError('replay', 'This message key has already been used.');
  }
  if (header.dh !== s.dhr) {
    skipMessageKeys(s, header.pn);
    dhRatchet(s, header);
  }
  skipMessageKeys(s, header.n);
  const [nextCk, mk] = kdfCk(s.ckr);
  s.ckr = nextCk;
  s.nr += 1;
  const plaintext = await aeadDecrypt(mk, header, ciphertext, ad);
  return { state: s, plaintext };
}
