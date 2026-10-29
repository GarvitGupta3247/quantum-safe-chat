import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeCanonical, fromBase64, toBase64 } from '../../src/protocol/bytes.js';
import {
  createAccountVault, encryptEnvelope, generatePrekeys, openEnvelope, signPacket, validatePacket,
} from '../../src/protocol/envelope.js';
import {
  generateIdentity, hybridSign, hybridVerify, identityFingerprint, safetyNumber, verifyIdentityBundle,
} from '../../src/protocol/identity.js';
import { MAX_SKIP } from '../../src/protocol/ratchet.js';
import { deriveKek, generateDek, openVault, sealVault, unwrapDek, wrapDek } from '../../src/protocol/vault.js';
import { checkPassword } from '../../src/protocol/password.js';

// Re-signs a packet with the sender's real identity: models a sender-side inconsistency so the AEAD
// binding is tested independently of the signature check.
function resign(packet, vault) {
  return signPacket(packet, vault.identity.private);
}

function pair() {
  const a = createAccountVault('alice');
  const b = createAccountVault('bob');
  const prekeys = { identity: b.upload.identity, spk: b.upload.spk, pq: b.upload.pqopks[0], opk: b.upload.opks[0] };
  return { alice: a.vault, bob: b.vault, prekeys, bobUpload: b.upload };
}

test('canonical encoding is unambiguous across field boundaries and types', () => {
  const variants = [
    encodeCanonical('L', ['ab', 'c']),
    encodeCanonical('L', ['a', 'bc']),
    encodeCanonical('L', ['abc']),
    encodeCanonical('L', ['1']),
    encodeCanonical('L', [1]),
    encodeCanonical('L', [new Uint8Array([0x31])]),
    encodeCanonical('L', [null]),
    encodeCanonical('L', ['']),
    encodeCanonical('L2', ['abc']),
  ];
  const unique = new Set(variants.map((bytes) => toBase64(bytes)));
  assert.equal(unique.size, variants.length);
  assert.throws(() => encodeCanonical('L', [-1]));
  assert.throws(() => encodeCanonical('L', [1.5]));
  assert.throws(() => encodeCanonical('L', [{}]));
});

test('strict Base64 decoding rejects non-canonical and wrong-length input', () => {
  assert.deepEqual([...fromBase64('AAE=')], [0, 1]);
  assert.throws(() => fromBase64('AAF='), /Non-canonical/);
  assert.throws(() => fromBase64('AA E='));
  assert.throws(() => fromBase64('AAE=', 3));
});

test('identity bundles: self-signature binds username and keys; hybrid verification needs both signatures', () => {
  const { privateIdentity, bundle } = generateIdentity('alice');
  const fp = verifyIdentityBundle(bundle, 'alice');
  assert.equal(fp, identityFingerprint(bundle));
  assert.throws(() => verifyIdentityBundle(bundle, 'bob'), /expected username/);
  assert.throws(() => verifyIdentityBundle({ ...bundle, username: 'mallory' }), (e) => e.code === 'bad_identity_signature');
  const other = generateIdentity('alice').bundle;
  assert.throws(() => verifyIdentityBundle({ ...bundle, x25519: other.x25519 }), (e) => e.code === 'bad_identity_signature');

  const message = new Uint8Array([9, 9, 9]);
  const signature = hybridSign(message, privateIdentity);
  assert.equal(hybridVerify(message, signature, bundle), true);
  const otherSig = hybridSign(message, generateIdentity('alice').privateIdentity);
  assert.equal(hybridVerify(message, { ...signature, ed25519: otherSig.ed25519 }, bundle), false, 'Ed25519 alone forged');
  assert.equal(hybridVerify(message, { ...signature, mldsa65: otherSig.mldsa65 }, bundle), false, 'ML-DSA alone forged');
  assert.equal(hybridVerify(message, { ed25519: signature.ed25519 }, bundle), false);
  assert.equal(hybridVerify(message, null, bundle), false);

  const bob = generateIdentity('bob').bundle;
  const sn = safetyNumber(bundle, bob);
  assert.match(sn, /^(\d{5} ){11}\d{5}$/);
  assert.equal(sn, safetyNumber(bob, bundle), 'symmetric');
  assert.notEqual(sn, safetyNumber(other, bob));
});

test('AEAD associated data binds metadata even when the signature is valid (sender-side inconsistency)', async () => {
  const { alice, bob, prekeys } = pair();
  const { packet } = await encryptEnvelope(alice, { peer: 'bob', text: 'bound', prekeys });
  for (const mutate of [(p) => { p.h.ts += 1; }, (p) => { p.h.id = crypto.randomUUID(); }]) {
    const copy = structuredClone(packet);
    mutate(copy);
    copy.sig = resign(copy, alice);
    await assert.rejects(openEnvelope(bob, copy), (e) => e.code === 'decrypt_failed');
  }
  // State is untouched by the failures: the genuine packet still opens.
  assert.equal((await openEnvelope(bob, packet)).message.text, 'bound');
});

test('N2: an invalid ML-KEM ciphertext does not "succeed": implicit rejection is caught by AEAD and nothing is pinned or consumed', async () => {
  const { alice, bob, prekeys } = pair();
  const { packet } = await encryptEnvelope(alice, { peer: 'bob', text: 'kem', prekeys });
  const copy = structuredClone(packet);
  const kemCt = fromBase64(copy.h.pre.kemCt);
  kemCt[0] ^= 0xff;
  copy.h.pre.kemCt = toBase64(kemCt);
  copy.sig = resign(copy, alice);
  await assert.rejects(openEnvelope(bob, copy), (e) => e.code === 'decrypt_failed');
  assert.equal(Object.keys(bob.contacts).length, 0, 'no identity pinned from a failed message');
  assert.ok(bob.prekeys.opk[prekeys.opk.id], 'one-time prekey not consumed by a failed message');
  assert.equal((await openEnvelope(bob, packet)).message.text, 'kem');
});

test('ratchet: bounded skipping, and prekey verification failures are rejected before any state changes', async () => {
  let { alice, bob, prekeys } = pair();
  let r = await encryptEnvelope(alice, { peer: 'bob', text: 'm0', prekeys });
  alice = r.vault;
  let last;
  for (let i = 0; i <= MAX_SKIP + 1; i += 1) {
    r = await encryptEnvelope(alice, { peer: 'bob', text: `m${i + 1}` });
    alice = r.vault;
    last = r.packet;
  }
  await assert.rejects(openEnvelope(bob, last), (e) => e.code === 'too_many_skipped');

  const forgedPrekeys = { ...prekeys, spk: { ...prekeys.spk, pub: createAccountVault('mallory').upload.spk.pub } };
  await assert.rejects(encryptEnvelope(createAccountVault('carol').vault, { peer: 'bob', text: 'x', prekeys: forgedPrekeys }), (e) => e.code === 'bad_prekey_signature');
});

test('signed prekey rotation keeps recent prekeys usable for in-flight session starts', async () => {
  const { alice, bob, prekeys } = pair();
  const { packet } = await encryptEnvelope(alice, { peer: 'bob', text: 'old spk', prekeys });
  const rotated = generatePrekeys(bob, { rotateSigned: true }).vault;
  assert.notEqual(rotated.prekeys.spk[0].id, prekeys.spk.id);
  assert.equal((await openEnvelope(rotated, packet)).message.text, 'old spk');
});

test('validatePacket fails closed on malformed shapes', async () => {
  const { alice, prekeys } = pair();
  const { packet } = await encryptEnvelope(alice, { peer: 'bob', text: 'shape', prekeys });
  validatePacket(structuredClone(packet));
  const mutations = [
    (p) => { delete p.h.nonce; }, (p) => { p.h.n = -1; }, (p) => { p.h.n = '1'; }, (p) => { p.h.t = 'admin'; },
    (p) => { p.h.from = 'BOB'; }, (p) => { p.h.to = p.h.from; }, (p) => { p.h.sid = 'AAAA'; }, (p) => { p.ct = 'AAAA'; },
    (p) => { p.h.pre = null; }, (p) => { p.h.pre.pqKind = 'other'; }, (p) => { p.h.pre.extra = 1; }, (p) => { p.h.id = 'not-a-uuid'; },
    (p) => { p.sig = []; }, (p) => { p.h = null; },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(packet);
    mutate(copy);
    assert.throws(() => validatePacket(copy), (e) => e.code === 'malformed', mutate.toString());
  }
  for (const value of [null, 1, 'x', [], {}]) assert.throws(() => validatePacket(value), (e) => e.code === 'malformed');
});

test('vault: authenticated encryption bound to username and version; wrong keys fail', async () => {
  const exportKey = toBase64(crypto.getRandomValues(new Uint8Array(64))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const kek = await deriveKek(exportKey, 'alice');
  const dek = generateDek();
  const wrapped = await wrapDek(kek, dek, 'alice');
  assert.deepEqual([...await unwrapDek(kek, wrapped, 'alice')], [...dek]);
  await assert.rejects(unwrapDek(kek, wrapped, 'bob'), (e) => e.code === 'vault_unwrap_failed');
  await assert.rejects(unwrapDek(await deriveKek(exportKey, 'bob'), wrapped, 'alice'));
  const vault = createAccountVault('alice').vault;
  const blob = await sealVault(dek, 'alice', 7, vault);
  assert.equal((await openVault(dek, 'alice', 7, blob)).identity.fp, vault.identity.fp);
  await assert.rejects(openVault(dek, 'alice', 8, blob), (e) => e.code === 'vault_open_failed', 'version relabelling detected');
  await assert.rejects(openVault(generateDek(), 'alice', 7, blob));
});

test('password policy', () => {
  assert.equal(checkPassword('violet-harbor-sunrise-71', 'alice'), null);
  assert.match(checkPassword('short', 'alice'), /at least/);
  assert.match(checkPassword('Password1234', 'alice'), /too common/);
  assert.match(checkPassword('my-name-is-alice!', 'alice'), /username/);
  assert.match(checkPassword('aaaaaaaaaaaaaaa', 'bob'), /distinct|common/);
  assert.match(checkPassword('x'.repeat(300), 'bob'), /at most/);
});
