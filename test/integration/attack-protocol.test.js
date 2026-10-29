// F2 / F3 / F7 / N4 regression: key substitution, sender impersonation, envelope tampering and replay,
// performed by a malicious relay against real envelopes produced by ChatClient (encryptEnvelope) and
// delivered through the real server queue and WebSocket path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { conversationId, createAccountVault, encryptEnvelope } from '../../src/protocol/envelope.js';
import { hybridSign } from '../../src/protocol/identity.js';
import { toBase64, fromBase64 } from '../../src/protocol/bytes.js';
import { deliver, injectAndProcess, interceptNext, makeClient, nextEvent, PASSWORDS, setupUsers, startServer, waitFor } from '../helpers.js';

// Replaces `victim`'s directory entry with attacker-generated keys (a server-side key substitution).
function substituteIdentity(env, victim) {
  const { vault, upload } = createAccountVault(victim);
  const user = env.server.store.users[victim];
  user.identity = upload.identity;
  user.identityFp = vault.identity.fp;
  user.prekeys = { spk: upload.spk, pqspk: upload.pqspk, opks: upload.opks, pqopks: upload.pqopks };
  return vault;
}

function flipLastByte(b64) {
  const bytes = fromBase64(b64);
  bytes[bytes.length - 1] ^= 0x01;
  return toBase64(bytes);
}

test('F2: server key substitution for a pinned contact is detected and sending is blocked', async () => {
  const env = await startServer();
  try {
    const { alice, bob } = await setupUsers(env.base);
    await deliver(alice, bob, 'pin each other');
    await deliver(bob, alice, 'pinned');
    const realSafety = alice.safetyNumber('bob');

    substituteIdentity(env, 'bob');
    const status = await alice.checkContactIdentity('bob');
    assert.equal(status.state, 'changed');
    await assert.rejects(alice.sendText('bob', 'should not be sent'), (error) => error.code === 'identity_changed');
    assert.notEqual(alice.safetyNumber('bob'), realSafety, 'safety number exposes the substituted key');
    assert.ok(alice.securityLog().some((entry) => entry.code === 'identity_changed'));
  } finally {
    await env.close();
  }
});

test('F2: the pin travels in the encrypted vault, so a new device of the victim still blocks the substituted key', async () => {
  const env = await startServer();
  try {
    const { alice, bob } = await setupUsers(env.base);
    await deliver(alice, bob, 'first contact');
    substituteIdentity(env, 'bob');
    // Alice logs in from a brand-new browser: the pin comes from her vault, not from the server.
    const fresh = makeClient(env.base);
    await fresh.login('alice', PASSWORDS.alice);
    const changed = nextEvent(fresh, 'identity-changed');
    const result = await fresh.checkContactIdentity('bob');
    await changed;
    assert.equal(result.state, 'changed');
    await assert.rejects(fresh.sendText('bob', 'blocked'), (error) => error.code === 'identity_changed');
    // Explicit acceptance (after out-of-band verification) re-pins the key as UNVERIFIED.
    const accepted = await fresh.acceptIdentityChange('bob');
    assert.equal(accepted.state, 'unverified');
  } finally {
    await env.close();
  }
});

test('F2/F3: an injected session from a fake identity for a pinned contact is rejected and quarantined', async () => {
  const env = await startServer();
  try {
    const { alice, bob } = await setupUsers(env.base);
    await deliver(alice, bob, 'real alice');
    // Attacker-generated "alice" identity starts a session to bob using bob's real prekeys.
    const { vault: fakeAlice } = createAccountVault('alice');
    const prekeys = { identity: env.server.store.users.bob.identity, spk: env.server.store.users.bob.prekeys.spk, pq: env.server.store.users.bob.prekeys.pqspk, opk: null };
    const { packet } = await encryptEnvelope(fakeAlice, { peer: 'bob', text: 'I am alice, send money', prekeys });
    const outcomes = await injectAndProcess(env, bob, [packet]);
    assert.deepEqual(outcomes, [{ kind: 'rejected', code: 'identity_changed' }]);
    assert.ok(!bob.history('alice').some((m) => m.text.includes('send money')));
    assert.equal(bob.quarantined('alice'), 1);
    assert.equal(bob.contact('alice').state, 'changed');
  } finally {
    await env.close();
  }
});

test('F3: the relay refuses to forward a packet whose sender differs from the authenticated account', async () => {
  const env = await startServer();
  try {
    const { alice, bob, mallory } = await setupUsers(env.base, ['alice', 'bob', 'mallory']);
    await deliver(alice, bob, 'hello');
    const { vault: fakeAlice } = createAccountVault('alice');
    const user = env.server.store.users.bob;
    const { packet } = await encryptEnvelope(fakeAlice, { peer: 'bob', text: 'forged', prekeys: { identity: user.identity, spk: user.prekeys.spk, pq: user.prekeys.pqspk, opk: null } });
    const ws = await import('ws');
    const socket = new ws.WebSocket(`${env.base.replace('http', 'ws')}/ws`, { headers: { cookie: mallory.jar.cookie } });
    const reply = await new Promise((resolve, reject) => {
      socket.on('message', (data) => { const frame = JSON.parse(data.toString()); if (frame.type === 'rejected') resolve(frame); });
      socket.on('open', () => socket.send(JSON.stringify({ type: 'send', packet })));
      socket.on('error', reject);
    });
    socket.close();
    assert.match(reply.error, /Sender does not match/);
  } finally {
    await env.close();
  }
});

test('F3/F7/N4: a malicious relay cannot relabel, re-sign, alter, misdirect or replay real envelopes', async () => {
  const env = await startServer();
  try {
    const { alice, bob, carol } = await setupUsers(env.base, ['alice', 'bob', 'carol']);
    await deliver(alice, bob, 'establish session');
    await deliver(bob, alice, 'ack session');
    const original = await interceptNext(env, alice, bob, 'genuine message');
    const mallory = createAccountVault('mallory').vault;

    const variants = {
      'relabel sender (conversation id unchanged)': (p) => { p.h.from = 'carol'; },
      'relabel sender + recompute conversation and fingerprint': (p) => { p.h.from = 'carol'; p.h.fromFp = env.server.store.users.carol.identityFp; p.h.conv = conversationId('carol', 'bob'); },
      'alter recipient fingerprint': (p) => { p.h.toFp = 'f'.repeat(64); },
      'alter conversation id': (p) => { p.h.conv = '0'.repeat(64); },
      'alter message id': (p) => { p.h.id = crypto.randomUUID(); },
      'alter timestamp': (p) => { p.h.ts += 1; },
      'alter ratchet counter': (p) => { p.h.n += 1; },
      'alter ratchet public key': (p) => { p.h.dh = flipLastByte(p.h.dh); },
      'alter AES-GCM nonce': (p) => { p.h.nonce = flipLastByte(p.h.nonce); },
      'alter ciphertext / GCM tag': (p) => { p.ct = flipLastByte(p.ct); },
      'corrupt Ed25519 signature': (p) => { p.sig.ed25519 = flipLastByte(p.sig.ed25519); },
      'corrupt ML-DSA-65 signature': (p) => { p.sig.mldsa65 = flipLastByte(p.sig.mldsa65); },
      'drop one signature': (p) => { delete p.sig.mldsa65; },
      're-sign with a different identity': (p) => { p.sig = hybridSign(new Uint8Array([1, 2, 3]), mallory.identity.private); },
      'extra unknown field': (p) => { p.h.admin = true; },
      'wrong protocol version': (p) => { p.v = 2; },
    };
    const packets = Object.values(variants).map((mutate) => { const copy = structuredClone(original); mutate(copy); return copy; });
    const outcomes = await injectAndProcess(env, bob, packets);
    const names = Object.keys(variants);
    outcomes.forEach((outcome, index) => assert.equal(outcome.kind, 'rejected', `${names[index]} must be rejected`));
    console.log('Tamper outcomes:', Object.fromEntries(names.map((name, i) => [name, outcomes[i].code])));

    // Misdirect the genuine packet to carol: wrong recipient.
    const misdirected = await injectAndProcess(env, carol, [structuredClone(original)]);
    assert.deepEqual(misdirected, [{ kind: 'rejected', code: 'wrong_recipient' }]);

    // The untouched packet is still accepted after all the rejected variants (state was not corrupted).
    const genuine = await injectAndProcess(env, bob, [structuredClone(original)]);
    assert.deepEqual(genuine, [{ kind: 'message', text: 'genuine message', from: 'alice' }]);

    // F7: the relay replays it: the receiver rejects the duplicate.
    const replay = await injectAndProcess(env, bob, [structuredClone(original)]);
    assert.deepEqual(replay, [{ kind: 'rejected', code: 'replay' }]);
    assert.equal(bob.history('alice').filter((m) => m.text === 'genuine message').length, 1);
  } finally {
    await env.close();
  }
});

test('F7: replay of a session-establishment message and of old messages is rejected; reordering is tolerated', async () => {
  const env = await startServer();
  try {
    const { alice, bob } = await setupUsers(env.base);
    const first = await interceptNext(env, alice, bob, 'm1 (prekey)');
    const second = await interceptNext(env, alice, bob, 'm2 (prekey)');
    const third = await interceptNext(env, alice, bob, 'm3 (prekey)');
    assert.equal(first.h.t, 'prekey');
    // Malicious relay delivers in reverse order, with a duplicate in the middle.
    const outcomes = await injectAndProcess(env, bob, [third, first, structuredClone(third), second]);
    assert.deepEqual(outcomes.map((o) => o.kind === 'message' ? o.text : o.code), ['m3 (prekey)', 'm1 (prekey)', 'replay', 'm2 (prekey)']);
    assert.deepEqual(bob.history('alice').map((m) => m.text), ['m1 (prekey)', 'm2 (prekey)', 'm3 (prekey)']);
    // Replaying the session-establishment message later (even with the seen-ID cache bypassed by a
    // brand-new message ID) does not re-create a session: the signature covers the ID.
    const later = await injectAndProcess(env, bob, [structuredClone(first)]);
    assert.deepEqual(later, [{ kind: 'rejected', code: 'replay' }]);
  } finally {
    await env.close();
  }
});

test('session robustness: a dropped first message, simultaneous initiation, and continued conversation', async () => {
  const env = await startServer();
  try {
    const { alice, bob } = await setupUsers(env.base);
    // The relay drops alice's first (session-establishing) message; the next one still establishes it.
    await interceptNext(env, alice, bob, 'lost forever');
    bob.connect();
    await waitFor(() => bob.connected, { message: 'bob reconnect' });
    await deliver(alice, bob, 'second attempt');
    assert.deepEqual(bob.history('alice').map((m) => m.text), ['second attempt']);

    // Simultaneous initiation between carol and mallory: both sides start sessions concurrently.
    const { carol, mallory } = await setupUsers(env.base, ['carol', 'mallory']);
    const toMallory = nextEvent(mallory, 'message');
    const toCarol = nextEvent(carol, 'message');
    await Promise.all([carol.sendText('mallory', 'hi from carol'), mallory.sendText('carol', 'hi from mallory')]);
    assert.equal((await toMallory).message.text, 'hi from carol');
    assert.equal((await toCarol).message.text, 'hi from mallory');
    await carol.idle(); await mallory.idle();
    for (let i = 0; i < 3; i += 1) {
      await deliver(carol, mallory, `c${i}`);
      await deliver(mallory, carol, `m${i}`);
    }
    // 1 sent + 1 received during simultaneous initiation, then 3 rounds of (received, sent).
    assert.deepEqual(mallory.history('carol').map((m) => m.text).sort(), ['c0', 'c1', 'c2', 'hi from carol', 'hi from mallory', 'm0', 'm1', 'm2']);
  } finally {
    await env.close();
  }
});
