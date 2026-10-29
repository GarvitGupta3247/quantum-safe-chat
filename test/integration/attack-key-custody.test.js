// F1 / F5 / F6 regression: a server holding its full database, its OPAQUE secret, and every byte of
// captured normal registration + login traffic must not be able to unwrap a user's private keys
// without guessing the password (and each guess costs a full Argon2id evaluation).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as opaque from '@serenity-kit/opaque';
import { KEY_STRETCHING } from '../../src/protocol/password.js';
import { deriveKek, openVault, unwrapDek } from '../../src/protocol/vault.js';
import { openEnvelope } from '../../src/protocol/envelope.js';
import { connected, makeClient, networkText, PASSWORDS, sentPackets, startServer, waitFor } from '../helpers.js';

// Runs the OPAQUE client against the server's own stored record: this is exactly the offline
// guessing attack available to someone holding the database AND the OPAQUE server setup.
function offlineGuess(serverSetup, username, registrationRecord, guess) {
  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password: guess });
  const { loginResponse } = opaque.server.startLogin({ serverSetup, userIdentifier: username, registrationRecord, startLoginRequest });
  return opaque.client.finishLogin({ clientLoginState, loginResponse, password: guess, keyStretching: KEY_STRETCHING })?.exportKey ?? null;
}

test('F1: captured normal login traffic + server database do not reveal the vault key or private keys', async () => {
  await opaque.ready;
  const env = await startServer();
  try {
    const alice = makeClient(env.base);
    await alice.register('alice', PASSWORDS.alice);
    await connected(alice);
    const bob = makeClient(env.base);
    await bob.register('bob', PASSWORDS.bob);
    await bob.logout();
    // "Normal authentication traffic": a fresh login whose every request/response is captured.
    const bobAgain = makeClient(env.base);
    await bobAgain.login('bob', PASSWORDS.bob);
    await connected(bobAgain);
    bobAgain.disconnect();

    await alice.sendText('bob', 'TOP SECRET: meet at 9');
    const captured = sentPackets(alice).at(-1);
    await waitFor(() => env.server.store.queue.length === 1, { message: 'queued' });

    const stolenDb = JSON.parse(readFileSync(env.server.dataFile, 'utf8'));
    const bobRecord = stolenDb.users.bob;
    const traffic = networkText(bob) + networkText(bobAgain);

    // 1. The baseline attack needed the password from the login request. It is no longer sent.
    assert.ok(!traffic.includes(PASSWORDS.bob));
    for (const entry of [...bob.network, ...bobAgain.network]) {
      if (entry.request) assert.ok(!/"password"/.test(entry.request), `password field present in ${entry.url}`);
    }

    // 2. Neither the OPAQUE export key nor any private key appears in traffic or the database.
    const legitExportKey = offlineGuess(env.server.serverSetup, 'bob', bobRecord.opaqueRecord, PASSWORDS.bob);
    assert.ok(legitExportKey, 'sanity: the real password opens the record');
    const vaultContents = bobAgain.snapshotForTesting();
    const secrets = [
      legitExportKey,
      vaultContents.identity.private.ed25519, vaultContents.identity.private.mldsa65, vaultContents.identity.private.x25519,
      ...vaultContents.prekeys.spk.map((k) => k.priv), ...vaultContents.prekeys.pqspk.map((k) => k.priv),
      ...Object.values(vaultContents.prekeys.opk),
    ];
    const dbText = JSON.stringify(stolenDb);
    for (const secret of secrets) {
      assert.ok(!traffic.includes(secret), 'secret present in captured traffic');
      assert.ok(!dbText.includes(secret), 'secret present in server database');
    }

    // 3. Using only what the server has, the captured ciphertext cannot be opened: there is no key
    //    material for bob anywhere in the database, so the attacker must guess the password.
    const dictionary = ['password1234', 'granite-meadow-lantern-37', 'bob-password-12', 'Summer2026!!', 'letmein12345'];
    const started = performance.now();
    for (const guess of dictionary) {
      assert.equal(offlineGuess(env.server.serverSetup, 'bob', bobRecord.opaqueRecord, guess), null, `guess ${guess} must fail`);
    }
    const perGuessMs = (performance.now() - started) / dictionary.length;
    assert.ok(perGuessMs > 100, `each offline guess should cost a full Argon2id evaluation (measured ${perGuessMs.toFixed(0)} ms)`);

    // 4. Residual risk, stated honestly: with the password in the dictionary, the vault opens.
    const kek = await deriveKek(legitExportKey, 'bob');
    const dek = await unwrapDek(kek, bobRecord.vault.wrappedDek, 'bob');
    const vault = await openVault(dek, 'bob', bobRecord.vault.version, bobRecord.vault.blob);
    assert.equal(vault.identity.fp, bobRecord.identityFp);
    // ... and a vault snapshot from before delivery can decrypt the queued message (expected).
    const opened = await openEnvelope(vault, captured);
    assert.equal(opened.message.text, 'TOP SECRET: meet at 9');
    console.log(`F1 evidence: ${dictionary.length} wrong offline guesses failed; ${perGuessMs.toFixed(0)} ms per guess (Argon2id 64 MiB, t=3).`);
  } finally {
    await env.close();
  }
});

test('F1: the OPAQUE secret is required for offline guessing; a database-only leak cannot even test guesses', async () => {
  await opaque.ready;
  const env = await startServer();
  try {
    const bob = makeClient(env.base);
    await bob.register('bob', PASSWORDS.bob);
    const record = env.server.store.users.bob.opaqueRecord;
    const otherSetup = opaque.server.createSetup();
    // Without the real server setup (OPRF seed), even the correct password fails to open the record.
    assert.equal(offlineGuess(otherSetup, 'bob', record, PASSWORDS.bob), null);
  } finally {
    await env.close();
  }
});

test('F5: wrong credentials fail safely and online guessing is throttled per account', async () => {
  await opaque.ready;
  const env = await startServer();
  try {
    const bob = makeClient(env.base);
    await bob.register('bob', PASSWORDS.bob);
    await bob.logout();
    const attacker = makeClient(env.base);
    await assert.rejects(attacker.login('bob', 'not-the-password-123'), /Incorrect username or password/);
    assert.equal(attacker.jar.cookie, null, 'no session cookie after a failed login');
    await assert.rejects(attacker.login('nobody', 'not-the-password-123'), /Incorrect username or password/);
    // Forged finish without a valid transcript is rejected by the server.
    const forged = await fetch(`${env.base}/api/auth/login/finish`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ loginId: 'x', finishLoginRequest: 'AAAA' }) });
    assert.equal(forged.status, 401);
    let limited = false;
    for (let i = 0; i < 12 && !limited; i += 1) {
      const { startLoginRequest } = opaque.client.startLogin({ password: `guess-${i}-xxxxxxxx` });
      const response = await fetch(`${env.base}/api/auth/login/start`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'bob', startLoginRequest }) });
      limited = response.status === 429;
    }
    assert.ok(limited, 'per-account login throttle engaged');
  } finally {
    await env.close();
  }
});

test('F5: client-side password policy rejects short, common and username-containing passwords', async () => {
  const env = await startServer();
  try {
    const client = makeClient(env.base);
    await assert.rejects(client.register('dave', 'short-pw'), /at least 12/);
    await assert.rejects(client.register('dave', 'password1234'), /too common/);
    await assert.rejects(client.register('dave', 'dave-is-my-name-ok'), /must not contain the username/);
    assert.equal(client.network.length, 0, 'policy failures happen before any network request');
  } finally {
    await env.close();
  }
});

test('password change: old password stops working, the data key rotates, history survives, other sessions are revoked', async () => {
  await opaque.ready;
  const env = await startServer();
  try {
    const alice = makeClient(env.base);
    await alice.register('alice', PASSWORDS.alice);
    await connected(alice);
    const bob = makeClient(env.base);
    await bob.register('bob', PASSWORDS.bob);
    await connected(bob);
    await alice.sendText('bob', 'before password change');
    await waitFor(() => bob.history('alice').length === 1, { message: 'delivery' });
    await bob.idle();

    // Attacker who knew the OLD password and copied the OLD database row.
    const oldRow = structuredClone(env.server.store.users.bob);
    const oldExportKey = offlineGuess(env.server.serverSetup, 'bob', oldRow.opaqueRecord, PASSWORDS.bob);
    const oldDek = await unwrapDek(await deriveKek(oldExportKey, 'bob'), oldRow.vault.wrappedDek, 'bob');

    const otherDevice = makeClient(env.base);
    const newPassword = 'tidal-ember-quarry-64';
    await bob.changePassword(PASSWORDS.bob, newPassword);
    await waitFor(() => bob.connected, { message: 'reconnect after password change' });

    const newRow = env.server.store.users.bob;
    await assert.rejects(openVault(oldDek, 'bob', newRow.vault.version, newRow.vault.blob), /failed authentication/);
    assert.equal(offlineGuess(env.server.serverSetup, 'bob', newRow.opaqueRecord, PASSWORDS.bob), null);
    await assert.rejects(otherDevice.login('bob', PASSWORDS.bob), /Incorrect/);

    const fresh = makeClient(env.base);
    await fresh.login('bob', newPassword);
    assert.deepEqual(fresh.history('alice').map((m) => m.text), ['before password change']);
    await assert.rejects(bob.sendText('alice', 'old session'), (error) => error.status === 401 || /log in/i.test(error.message));
  } finally {
    await env.close();
  }
});

test('one active device per account; a server rollback of the vault is detected on a device that saw a newer version', async () => {
  const env = await startServer();
  try {
    const alice = makeClient(env.base);
    await alice.register('alice', PASSWORDS.alice);
    await connected(alice);
    const bob = makeClient(env.base);
    await bob.register('bob', PASSWORDS.bob);
    await connected(bob);
    const oldVault = structuredClone(env.server.store.users.alice.vault);
    await alice.sendText('bob', 'advance the vault');
    await waitFor(() => env.server.store.users.alice.vault.version > oldVault.version + 1, { message: 'vault advanced' });
    await alice.idle();

    // A second login displaces the first device.
    const displaced = new Promise((resolve) => alice.on('displaced', resolve));
    const second = makeClient(env.base, { storage: alice.storage });
    await second.login('alice', PASSWORDS.alice);
    await displaced;
    await second.logout();

    // Malicious server restores the old (validly encrypted) vault to roll back ratchet state.
    env.server.store.users.alice.vault = oldVault;
    const third = makeClient(env.base, { storage: alice.storage });
    await assert.rejects(third.login('alice', PASSWORDS.alice), (error) => error.code === 'vault_rollback');
  } finally {
    await env.close();
  }
});
