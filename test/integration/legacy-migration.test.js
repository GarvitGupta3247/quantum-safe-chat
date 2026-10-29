// F9 + migration: a genuine v0.5 data store (built with the original `mlkem` library and the exact
// v0.5 client/server constructions) is migrated on a disposable copy.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, scryptSync } from 'node:crypto';
import { createMlKem768 } from 'mlkem';
import { scanLegacyLocalKeys } from '../../src/protocol/legacy.js';
import { makeClient, startServer } from '../helpers.js';

const enc = new TextEncoder();
const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const OLD = { alice: 'alice-old-pass-1', bob: 'bob-old-pass-12', carol: 'carol-old-pass-1' };
const NEW = { alice: 'saffron-glacier-pivot-27', bob: 'marble-tundra-falcon-83' };

async function v05Bundle(publicKey, secretKey, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, secretKey);
  return { version: 2, publicKey: b64(publicKey), kdf: 'PBKDF2-HMAC-SHA-256', iterations: 600000, salt: b64(salt), iv: b64(iv), encryptedPrivateKey: b64(new Uint8Array(ct)) };
}

async function v05Envelope(kem, publicKey, text) {
  const [kemCiphertext, sharedSecret] = kem.encap(publicKey);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('QuantumSafeChat PoC v1 | ML-KEM-768 | AES-256-GCM') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  return { kemCiphertext: b64(kemCiphertext), salt: b64(salt), iv: b64(iv), ciphertext: b64(new Uint8Array(ct)) };
}

async function buildV05Store(dir) {
  const kem = await createMlKem768();
  const users = {};
  const keys = {};
  for (const name of ['alice', 'bob', 'carol']) {
    const [pk, sk] = kem.generateKeyPair();
    keys[name] = { pk, sk };
    const salt = randomBytes(16).toString('hex');
    users[name] = {
      salt, passwordHash: scryptSync(OLD[name], salt, 64).toString('hex'), kemPublicKey: b64(pk),
      // carol predates v0.4 server-side bundles: no bundle on the server.
      privateKeyBundle: name === 'carol' ? undefined : await v05Bundle(pk, sk, OLD[name]),
      createdAt: new Date().toISOString(),
    };
  }
  const messages = [];
  for (const [sender, recipient, text] of [['alice', 'bob', 'legacy hello bob'], ['bob', 'alice', 'legacy reply'], ['carol', 'alice', 'from carol']]) {
    messages.push({
      id: crypto.randomUUID(), clientMessageId: crypto.randomUUID(), sender, recipient, envelopeFingerprint: 'x',
      envelopes: { [sender]: await v05Envelope(kem, keys[sender].pk, text), [recipient]: await v05Envelope(kem, keys[recipient].pk, text) },
      createdAt: new Date().toISOString(),
    });
  }
  writeFileSync(join(dir, 'store.json'), JSON.stringify({ users, messages }, null, 2));
  return keys;
}

test('v0.5 accounts migrate explicitly: history imported as unauthenticated, legacy secrets erased, password replaced', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'qsc-legacy-'));
  try {
    const keys = await buildV05Store(dir);
    const env = await startServer({ dataDir: dir });
    try {
      assert.ok(readdirSync(dir).some((name) => name.startsWith('store.v2-backup-')), 'original store backed up before conversion');
      assert.ok(env.server.store.users.alice.legacy && !env.server.store.users.alice.opaqueRecord);

      // Old credentials no longer log in normally.
      const alice = makeClient(env.base);
      await assert.rejects(alice.login('alice', OLD.alice), /Incorrect username or password/);
      // Migration requires a NEW password (the old one was exposed to the v0.5 server).
      await assert.rejects(alice.migrateLegacy('alice', OLD.alice, OLD.alice), /Choose a new password/);
      await assert.rejects(alice.migrateLegacy('alice', 'wrong-old-password', NEW.alice), /incorrect/i);

      // F9: a plaintext private key left by an old build is detected but never used.
      alice.storage.setItem('qsc:mlkem768:alice', JSON.stringify({ publicKey: b64(keys.alice.pk), privateKey: b64(keys.alice.sk) }));
      assert.deepEqual(scanLegacyLocalKeys(alice.storage).map((k) => k.kind), ['plaintext-private-key']);

      const result = await alice.migrateLegacy('alice', OLD.alice, NEW.alice);
      assert.deepEqual(result, { migrated: 3, unreadable: 0 }); // to bob, from bob, from carol
      assert.deepEqual(scanLegacyLocalKeys(alice.storage), [], 'legacy local key removed after migration');
      const fromBob = alice.history('bob');
      assert.deepEqual(fromBob.map((m) => m.text).sort(), ['legacy hello bob', 'legacy reply']);
      assert.ok(fromBob.every((m) => m.legacy === true && m.authenticated === false), 'legacy history is never shown as authenticated');
      assert.equal(alice.history('carol')[0].text, 'from carol');

      const row = env.server.store.users.alice;
      assert.equal(row.legacy, undefined, 'scrypt hash and PBKDF2 bundle erased');
      assert.ok(env.server.store.legacyMessages.every((m) => !m.envelopes.alice), "alice's legacy envelopes erased");
      const again = await fetch(`${env.base}/api/legacy/start`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: OLD.alice }) });
      assert.equal(again.status, 401, 'legacy route closed for migrated account');

      // New password works via OPAQUE from another browser; migrated history is in the vault.
      await alice.logout();
      const elsewhere = makeClient(env.base);
      await elsewhere.login('alice', NEW.alice);
      assert.equal(elsewhere.history('bob').length, 2);
      const listed = await elsewhere.listUsers();
      assert.deepEqual(listed.map((u) => [u.username, u.legacy]), [['bob', true], ['carol', true]]);
      // Legacy (unmigrated) users cannot receive new-protocol messages.
      await assert.rejects(elsewhere.sendText('bob', 'hi'), (error) => error.status === 404);

      // Carol had no server-side bundle: migration works but old history is unreadable (stated, not hidden).
      const carol = makeClient(env.base);
      assert.deepEqual(await carol.migrateLegacy('carol', OLD.carol, 'ochre-lattice-summit-19'), { migrated: 0, unreadable: 1 });

      const bob = makeClient(env.base);
      await bob.migrateLegacy('bob', OLD.bob, NEW.bob);
      assert.equal(env.server.store.legacyMessages.length, 0, 'legacy ciphertext fully removed once every party migrated');
    } finally {
      await env.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('legacy migration route can be disabled by the operator', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'qsc-legacy-off-'));
  try {
    await buildV05Store(dir);
    const env = await startServer({ dataDir: dir, legacyMigration: false });
    try {
      const response = await fetch(`${env.base}/api/legacy/start`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: OLD.alice }) });
      assert.equal(response.status, 404);
      assert.ok(existsSync(join(dir, 'store.json')));
    } finally {
      await env.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
