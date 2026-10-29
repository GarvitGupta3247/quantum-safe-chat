// The authenticated message protocol: PQXDH session establishment, Double Ratchet encryption,
// hybrid identity signatures, TOFU identity pinning, and receiver-side replay rejection.
//
// Every function takes the decrypted account vault (a plain object) and returns a NEW vault on
// success. On any failure it throws a ProtocolError and the caller's vault is unchanged, so forged or
// replayed packets can never advance ratchet state, consume prekeys, or pin an identity.

import { sha256 } from '@noble/hashes/sha2.js';
import { encodeCanonical, fromBase64, randomBytes, textDecoder, toBase64, toHex, utf8 } from './bytes.js';
import {
  createOneTimePrekey, createSignedPrekey, generateIdentity, hybridSign, hybridVerify, identityFingerprint,
  ProtocolError, SIZES, validOneTimePrekey, validUsername, verifyIdentityBundle, verifySignedPrekey,
} from './identity.js';
import { initiate, respond } from './pqxdh.js';
import { initInitiator, initResponder, ratchetDecrypt, ratchetEncrypt } from './ratchet.js';

export const PROTOCOL_VERSION = 1;
export const MAX_TEXT_LENGTH = 2000;
const PAD_BLOCK = 256;
const MAX_CIPHERTEXT_BYTES = 16 * 1024;
const MAX_FUTURE_SKEW_MS = 10 * 60 * 1000;
const MAX_SEEN_IDS = 5000;
const MAX_SESSIONS_PER_PEER = 4;
const KEEP_SIGNED_PREKEYS = 3;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;

export function conversationId(userA, userB) {
  const [first, second] = [userA, userB].sort();
  return toHex(sha256(encodeCanonical('QSC-CONVERSATION-v1', [first, second])));
}

// ----- Account creation and prekeys -------------------------------------------------------------

export function createAccountVault(username, { opkCount = 20, pqopkCount = 10 } = {}) {
  const { privateIdentity, bundle } = generateIdentity(username);
  const vault = {
    format: 'qsc-vault-v1',
    username,
    createdAt: Date.now(),
    identity: { private: privateIdentity, bundle, fp: identityFingerprint(bundle) },
    prekeys: { nextId: 1, spk: [], pqspk: [], opk: {}, pqopk: {} },
    contacts: {},
    sessions: {},
    seen: {},
    history: {},
    quarantine: [],
    outbox: [],
    securityLog: [],
  };
  const { vault: withPrekeys, upload } = generatePrekeys(vault, { opkCount, pqopkCount, rotateSigned: true });
  return { vault: withPrekeys, upload: { identity: bundle, ...upload } };
}

export function generatePrekeys(vault, { opkCount = 0, pqopkCount = 0, rotateSigned = false } = {}) {
  const v = { ...vault, prekeys: structuredClone(vault.prekeys) };
  const { private: priv, bundle } = v.identity;
  const upload = { spk: null, pqspk: null, opks: [], pqopks: [] };
  const nextId = () => { const id = v.prekeys.nextId; v.prekeys.nextId += 1; return id; };
  if (rotateSigned) {
    for (const kind of ['spk', 'pqspk']) {
      const { record, priv: secret } = createSignedPrekey(kind, nextId(), priv, bundle);
      v.prekeys[kind] = [{ id: record.id, pub: record.pub, priv: secret, createdAt: record.createdAt }, ...v.prekeys[kind]].slice(0, KEEP_SIGNED_PREKEYS);
      upload[kind] = record;
    }
  }
  for (let i = 0; i < opkCount; i += 1) {
    const { record, priv: secret } = createOneTimePrekey(nextId());
    v.prekeys.opk[record.id] = secret;
    upload.opks.push(record);
  }
  for (let i = 0; i < pqopkCount; i += 1) {
    const { record, priv: secret } = createSignedPrekey('pqopk', nextId(), priv, bundle);
    v.prekeys.pqopk[record.id] = { pub: record.pub, priv: secret };
    upload.pqopks.push(record);
  }
  return { vault: v, upload };
}

// ----- Identity pinning (trust on first use + explicit verification) ----------------------------

export function contactStatus(vault, peer) {
  const contact = vault.contacts[peer];
  if (!contact) return { state: 'unknown' };
  if (contact.pendingChange) return { state: 'changed', fp: contact.fp, newFp: contact.pendingChange.fp };
  return { state: contact.verified ? 'verified' : 'unverified', fp: contact.fp };
}

// Compare a server-provided identity bundle with the pinned identity. Never re-pins on its own.
export function checkPeerIdentity(vault, peer, bundle) {
  const fp = verifyIdentityBundle(bundle, peer);
  const contact = vault.contacts[peer];
  if (!contact) return { state: 'new', fp };
  if (contact.fp === fp) return { state: 'match', fp };
  return { state: 'changed', fp, pinnedFp: contact.fp };
}

export function recordIdentityChange(vault, peer, bundle) {
  const fp = verifyIdentityBundle(bundle, peer);
  const contact = vault.contacts[peer];
  if (!contact || contact.fp === fp) return vault;
  return { ...vault, contacts: { ...vault.contacts, [peer]: { ...contact, pendingChange: { fp, bundle, detectedAt: Date.now() } } } };
}

// Explicit user decision after out-of-band verification. Old sessions are discarded because they
// are bound to the previous identity.
export function acceptIdentityChange(vault, peer) {
  const contact = vault.contacts[peer];
  if (!contact?.pendingChange) throw new ProtocolError('no_pending_change', 'There is no pending identity change for this contact.');
  const { fp, bundle } = contact.pendingChange;
  const sessions = { ...vault.sessions };
  delete sessions[peer];
  return {
    ...vault,
    sessions,
    contacts: { ...vault.contacts, [peer]: { fp, bundle, verified: false, firstSeen: Date.now(), previousFp: contact.fp } },
  };
}

export function setVerified(vault, peer, verified) {
  const contact = vault.contacts[peer];
  if (!contact || contact.pendingChange) throw new ProtocolError('cannot_verify', 'Resolve the identity change before verifying.');
  return { ...vault, contacts: { ...vault.contacts, [peer]: { ...contact, verified: Boolean(verified) } } };
}

// ----- Wire format ------------------------------------------------------------------------------

function headerFields(packet) {
  const h = packet.h;
  const pre = h.pre;
  return [
    packet.v, h.t, h.from, h.to, h.fromFp, h.toFp, h.conv, h.id, h.ts, h.sid,
    h.dh, h.pn, h.n, h.nonce,
    pre ? identityFingerprint(pre.identity) : null,
    pre ? pre.ek : null, pre ? pre.kemCt : null, pre ? pre.spkId : null,
    pre ? pre.pqKind : null, pre ? pre.pqId : null, pre ? pre.opkId : null,
  ];
}

function signaturePayload(packet) {
  return encodeCanonical('QSC-ENVELOPE-SIG-v1', [...headerFields(packet), fromBase64(packet.ct)]);
}

export function signPacket(packet, privateIdentity) {
  return hybridSign(signaturePayload(packet), privateIdentity);
}

function associatedData(sessionAd, packet) {
  return encodeCanonical('QSC-ENVELOPE-AD-v1', [fromBase64(sessionAd), ...headerFields(packet)]);
}

function isInt(value, max = 2 ** 31) {
  return Number.isSafeInteger(value) && value >= 0 && value <= max;
}

function exactKeys(object, allowed) {
  return object && typeof object === 'object' && !Array.isArray(object)
    && Object.keys(object).length === allowed.length && allowed.every((key) => Object.hasOwn(object, key));
}

function b64ok(value, length) {
  try { fromBase64(value, length); return true; } catch { return false; }
}

// Strict schema validation; unknown, missing or oversized fields fail closed.
export function validatePacket(packet) {
  const fail = () => { throw new ProtocolError('malformed', 'Malformed message envelope.'); };
  if (!exactKeys(packet, ['v', 'h', 'ct', 'sig']) || packet.v !== PROTOCOL_VERSION) fail();
  const h = packet.h;
  if (!exactKeys(h, ['t', 'from', 'to', 'fromFp', 'toFp', 'conv', 'id', 'ts', 'sid', 'dh', 'pn', 'n', 'nonce', 'pre'])) fail();
  if (!['prekey', 'msg'].includes(h.t) || !validUsername(h.from) || !validUsername(h.to) || h.from === h.to) fail();
  if (!HEX64.test(h.fromFp) || !HEX64.test(h.toFp) || !HEX64.test(h.conv) || !UUID_PATTERN.test(h.id)) fail();
  if (!isInt(h.ts, Number.MAX_SAFE_INTEGER) || !isInt(h.pn) || !isInt(h.n)) fail();
  if (!b64ok(h.sid, 16) || !b64ok(h.dh, SIZES.x25519) || !b64ok(h.nonce, 12)) fail();
  if (!b64ok(packet.ct, [16 + PAD_BLOCK, MAX_CIPHERTEXT_BYTES])) fail();
  if (!exactKeys(packet.sig, ['ed25519', 'mldsa65']) || !b64ok(packet.sig.ed25519, SIZES.ed25519Sig) || !b64ok(packet.sig.mldsa65, SIZES.mldsaSig)) fail();
  if (h.t === 'msg') {
    if (h.pre !== null) fail();
  } else {
    const p = h.pre;
    if (!exactKeys(p, ['identity', 'ek', 'kemCt', 'spkId', 'pqKind', 'pqId', 'opkId'])) fail();
    if (!b64ok(p.ek, SIZES.x25519) || !b64ok(p.kemCt, SIZES.kemCiphertext)) fail();
    if (!isInt(p.spkId) || !isInt(p.pqId) || !['pqspk', 'pqopk'].includes(p.pqKind) || !(p.opkId === null || isInt(p.opkId))) fail();
    if (!p.identity || typeof p.identity !== 'object') fail();
  }
  return packet;
}

function padPlaintext(bytes) {
  const length = Math.ceil((bytes.length + 1) / PAD_BLOCK) * PAD_BLOCK;
  const out = new Uint8Array(length);
  out.set(bytes);
  out[bytes.length] = 0x80; // ISO/IEC 7816-4 padding hides exact message length within 256-byte buckets
  return out;
}

function unpadPlaintext(bytes) {
  let end = bytes.length - 1;
  while (end >= 0 && bytes[end] === 0) end -= 1;
  if (end < 0 || bytes[end] !== 0x80) throw new ProtocolError('malformed', 'Invalid message padding.');
  return bytes.subarray(0, end);
}

function encodePayload(text) {
  return padPlaintext(utf8(JSON.stringify({ text })));
}

function decodePayload(bytes) {
  let parsed;
  try { parsed = JSON.parse(textDecoder.decode(unpadPlaintext(bytes))); } catch { throw new ProtocolError('malformed', 'Invalid message payload.'); }
  if (!exactKeys(parsed, ['text']) || typeof parsed.text !== 'string' || parsed.text.length > MAX_TEXT_LENGTH) {
    throw new ProtocolError('malformed', 'Invalid message payload.');
  }
  return parsed.text;
}

// ----- Sending ----------------------------------------------------------------------------------

export function needsPrekeys(vault, peer) {
  return !vault.sessions[peer]?.active;
}

function verifyPeerPrekeys(prekeys, peer) {
  const peerBundle = prekeys?.identity;
  const fp = verifyIdentityBundle(peerBundle, peer);
  if (!verifySignedPrekey(prekeys.spk, peerBundle, 'spk')) throw new ProtocolError('bad_prekey_signature', 'Signed prekey signature is invalid.');
  const pqKind = prekeys.pq?.kind;
  if (!['pqspk', 'pqopk'].includes(pqKind) || !verifySignedPrekey(prekeys.pq, peerBundle, pqKind)) {
    throw new ProtocolError('bad_prekey_signature', 'ML-KEM prekey signature is invalid.');
  }
  if (prekeys.opk !== null && !validOneTimePrekey(prekeys.opk)) throw new ProtocolError('malformed', 'Invalid one-time prekey.');
  return fp;
}

export async function encryptEnvelope(vault, { peer, text, prekeys = null, messageId = globalThis.crypto.randomUUID(), sentAt = Date.now() }) {
  if (typeof text !== 'string' || !text.length || text.length > MAX_TEXT_LENGTH) throw new ProtocolError('bad_text', 'Messages must be 1-2000 characters.');
  if (!validUsername(peer) || peer === vault.username) throw new ProtocolError('bad_peer', 'Invalid recipient.');
  const contact = vault.contacts[peer];
  if (contact?.pendingChange) throw new ProtocolError('identity_changed', `${peer}'s identity key changed. Verify it before sending.`);

  const contacts = { ...vault.contacts };
  const peerSessions = structuredClone(vault.sessions[peer] ?? { active: null, list: {} });
  let session = peerSessions.active ? peerSessions.list[peerSessions.active] : null;

  if (!session) {
    if (!prekeys) throw new ProtocolError('needs_prekeys', 'Prekeys are required to start a session.');
    const fp = verifyPeerPrekeys(prekeys, peer);
    if (contact && contact.fp !== fp) throw new ProtocolError('identity_changed', `${peer}'s identity key changed. Verify it before sending.`);
    const { sk, ad, header, peerRatchetPublic } = initiate({
      myPrivate: vault.identity.private, myBundle: vault.identity.bundle, peerBundle: prekeys.identity,
      spk: prekeys.spk, pq: prekeys.pq, opk: prekeys.opk,
    });
    const sid = toBase64(randomBytes(16));
    session = {
      sid, role: 'initiator', peerFp: fp, ad: toBase64(ad), createdAt: Date.now(),
      ratchet: initInitiator(sk, peerRatchetPublic),
      pre: { identity: vault.identity.bundle, ...header },
    };
    peerSessions.list[sid] = session;
    peerSessions.active = sid;
    if (!contact) contacts[peer] = { fp, bundle: prekeys.identity, verified: false, firstSeen: Date.now() };
  } else if (contacts[peer]?.fp !== session.peerFp) {
    throw new ProtocolError('identity_changed', `${peer}'s identity does not match the active session.`);
  }

  const base = {
    t: session.pre ? 'prekey' : 'msg',
    from: vault.username, to: peer,
    fromFp: vault.identity.fp, toFp: session.peerFp,
    conv: conversationId(vault.username, peer),
    id: messageId, ts: sentAt, sid: session.sid,
  };
  const pre = session.pre ?? null;
  const { state, header, ciphertext } = await ratchetEncrypt(session.ratchet, encodePayload(text), (rh) => (
    associatedData(session.ad, { v: PROTOCOL_VERSION, h: { ...base, ...rh, pre }, ct: '' })
  ));
  const packet = { v: PROTOCOL_VERSION, h: { ...base, ...header, pre }, ct: toBase64(ciphertext) };
  packet.sig = signPacket(packet, vault.identity.private);

  peerSessions.list[session.sid] = { ...session, ratchet: state };
  return {
    vault: { ...vault, contacts, sessions: { ...vault.sessions, [peer]: peerSessions } },
    packet,
  };
}

// ----- Receiving --------------------------------------------------------------------------------

function findSignedPrekey(vault, kind, id) {
  return vault.prekeys[kind].find((entry) => entry.id === id) ?? null;
}

export async function openEnvelope(vault, packet, { now = Date.now() } = {}) {
  validatePacket(packet);
  const h = packet.h;
  const me = vault.username;
  if (h.to !== me || h.toFp !== vault.identity.fp) throw new ProtocolError('wrong_recipient', 'This message is not addressed to this identity.');
  if (h.conv !== conversationId(h.from, h.to)) throw new ProtocolError('conversation_mismatch', 'Conversation identifier does not match the sender and recipient.');
  if (h.ts > now + MAX_FUTURE_SKEW_MS) throw new ProtocolError('bad_timestamp', 'Message timestamp is too far in the future.');

  const peer = h.from;
  const seen = vault.seen[peer] ?? { ids: [], sessions: [] };
  if (seen.ids.includes(h.id)) throw new ProtocolError('replay', 'Duplicate message identifier.');

  const contact = vault.contacts[peer];
  const peerSessions = structuredClone(vault.sessions[peer] ?? { active: null, list: {} });
  const existing = peerSessions.list[h.sid] ?? null;
  let senderBundle;
  if (contact && contact.fp !== h.fromFp) {
    const error = new ProtocolError('identity_changed', `Message claims a different identity key for ${peer}.`);
    if (h.t === 'prekey') error.bundle = h.pre.identity;
    throw error;
  }
  if (existing) {
    if (existing.peerFp !== h.fromFp) throw new ProtocolError('identity_changed', 'Session identity mismatch.');
    senderBundle = contact.bundle;
  } else {
    if (h.t !== 'prekey') throw new ProtocolError('unknown_session', 'No session exists for this message.');
    if (seen.sessions.includes(h.sid)) throw new ProtocolError('replay', 'Session-establishment message replayed.');
    senderBundle = h.pre.identity;
    const fp = verifyIdentityBundle(senderBundle, peer);
    if (fp !== h.fromFp) throw new ProtocolError('bad_signature', 'Sender identity does not match the claimed fingerprint.');
  }
  if (!hybridVerify(signaturePayload(packet), packet.sig, senderBundle)) {
    throw new ProtocolError('bad_signature', 'Sender signature is invalid.');
  }

  const buildAd = (sessionAd) => () => associatedData(sessionAd, packet);
  const ratchetHeader = { dh: h.dh, pn: h.pn, n: h.n, nonce: h.nonce };
  let prekeys = vault.prekeys;
  let session;
  let plaintext;
  const ciphertext = fromBase64(packet.ct);

  if (existing) {
    const result = await ratchetDecrypt(existing.ratchet, ratchetHeader, ciphertext, buildAd(existing.ad));
    plaintext = result.plaintext;
    // A message from the responder in this session proves they hold it: stop sending prekey headers.
    session = { ...existing, ratchet: result.state, pre: h.t === 'msg' ? null : existing.pre };
  } else {
    const pre = h.pre;
    const spk = findSignedPrekey(vault, 'spk', pre.spkId);
    const pq = pre.pqKind === 'pqspk' ? findSignedPrekey(vault, 'pqspk', pre.pqId) : vault.prekeys.pqopk[pre.pqId];
    const opkPriv = pre.opkId === null ? null : vault.prekeys.opk[pre.opkId];
    if (!spk || !pq || (pre.opkId !== null && !opkPriv)) throw new ProtocolError('stale_prekey', 'Referenced prekeys are not available (already used or rotated out).');
    const { sk, ad } = respond({
      myPrivate: vault.identity.private, myBundle: vault.identity.bundle, peerBundle: senderBundle,
      header: pre, spkPriv: spk.priv, pqPriv: pq.priv, pqPub: pq.pub, opkPriv,
    });
    const adB64 = toBase64(ad);
    const result = await ratchetDecrypt(initResponder(sk, { pub: spk.pub, priv: spk.priv }), ratchetHeader, ciphertext, buildAd(adB64));
    plaintext = result.plaintext;
    session = { sid: h.sid, role: 'responder', peerFp: h.fromFp, ad: adB64, createdAt: now, ratchet: result.state, pre: null };
    // One-time prekeys are deleted only after the first message authenticated successfully.
    prekeys = { ...vault.prekeys, opk: { ...vault.prekeys.opk }, pqopk: { ...vault.prekeys.pqopk } };
    if (pre.opkId !== null) delete prekeys.opk[pre.opkId];
    if (pre.pqKind === 'pqopk') delete prekeys.pqopk[pre.pqId];
  }

  const text = decodePayload(plaintext);
  peerSessions.list[h.sid] = session;
  peerSessions.active = h.sid;
  const ordered = Object.values(peerSessions.list).sort((a, b) => b.createdAt - a.createdAt);
  for (const stale of ordered.slice(MAX_SESSIONS_PER_PEER)) {
    if (stale.sid !== h.sid) delete peerSessions.list[stale.sid];
  }
  const newSeen = {
    ids: [...seen.ids, h.id].slice(-MAX_SEEN_IDS),
    sessions: seen.sessions.includes(h.sid) ? seen.sessions : [...seen.sessions, h.sid],
  };
  const contacts = contact ? vault.contacts : {
    ...vault.contacts,
    [peer]: { fp: h.fromFp, bundle: senderBundle, verified: false, firstSeen: now },
  };
  return {
    vault: {
      ...vault, prekeys, contacts,
      sessions: { ...vault.sessions, [peer]: peerSessions },
      seen: { ...vault.seen, [peer]: newSeen },
    },
    message: { id: h.id, from: peer, to: me, text, sentAt: h.ts, receivedAt: now, sessionId: h.sid, senderFp: h.fromFp },
  };
}
