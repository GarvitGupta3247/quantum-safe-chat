import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { connected, deliver, makeClient, networkText, nextEvent, PASSWORDS, sentPackets, setupUsers, startServer, waitFor } from '../helpers.js';

test('two independent clients register, exchange messages in both directions, and log in again', async () => {
  const env = await startServer();
  try {
    const { alice, bob } = await setupUsers(env.base);
    const first = await deliver(alice, bob, 'hello bob');
    assert.equal(first.message.text, 'hello bob');
    assert.equal(first.message.from, 'alice');
    const reply = await deliver(bob, alice, 'hi alice');
    assert.equal(reply.message.text, 'hi alice');
    await deliver(alice, bob, 'third message');

    await waitFor(() => alice.history('bob').every((m) => m.status !== 'sending'), { message: 'sent acknowledgements' });
    assert.deepEqual(alice.history('bob').map((m) => m.text), ['hello bob', 'hi alice', 'third message']);
    assert.ok(bob.history('alice').every((m) => m.authenticated));

    // Server deletes delivered ciphertext once acknowledged (no long-term server-side history).
    await waitFor(() => env.server.store.queue.length === 0, { message: 'queue drained' });

    // Log out and back in from a fresh client (another browser): history and sessions come from the vault.
    await bob.logout();
    const bob2 = makeClient(env.base);
    await bob2.login('bob', PASSWORDS.bob);
    assert.deepEqual(bob2.history('alice').map((m) => m.text), ['hello bob', 'hi alice', 'third message']);
    await connected(bob2);
    const after = await deliver(alice, bob2, 'after re-login');
    assert.equal(after.message.text, 'after re-login');
    const back = await deliver(bob2, alice, 'still here');
    assert.equal(back.message.text, 'still here');
    await alice.logout();
    await bob2.logout();
  } finally {
    await env.close();
  }
});

test('offline recipient receives queued messages in order after connecting', async () => {
  const env = await startServer();
  try {
    const alice = makeClient(env.base);
    await alice.register('alice', PASSWORDS.alice);
    await connected(alice);
    const bob = makeClient(env.base);
    await bob.register('bob', PASSWORDS.bob);
    await bob.logout(); // offline

    for (let i = 1; i <= 5; i += 1) await alice.sendText('bob', `queued ${i}`);
    await waitFor(() => env.server.store.queue.length === 5, { message: 'five queued messages' });

    const bob2 = makeClient(env.base);
    await bob2.login('bob', PASSWORDS.bob);
    let count = 0;
    bob2.on('message', () => { count += 1; });
    await connected(bob2);
    await waitFor(() => count === 5, { message: 'five deliveries' });
    await bob2.idle();
    assert.deepEqual(bob2.history('alice').map((m) => m.text), ['queued 1', 'queued 2', 'queued 3', 'queued 4', 'queued 5']);
    await waitFor(() => env.server.store.queue.length === 0, { message: 'queue drained after ack' });
  } finally {
    await env.close();
  }
});

test('reconnection retransmits unacknowledged packets without duplicating messages', async () => {
  const env = await startServer();
  try {
    const { alice, bob } = await setupUsers(env.base);
    await deliver(alice, bob, 'warm-up');
    // Send while the socket is being replaced: the packet stays in the encrypted outbox.
    alice.connect(); // replace socket; send during the reconnect window
    const sent = alice.sendText('bob', 'sent during reconnect');
    const received = nextEvent(bob, 'message');
    await sent;
    await waitFor(() => alice.connected, { message: 'alice reconnect' });
    const event = await received;
    assert.equal(event.message.text, 'sent during reconnect');
    // Force a second reconnect: outbox retransmission must not create a duplicate.
    alice.connect();
    await waitFor(() => alice.connected, { message: 'alice reconnect 2' });
    await new Promise((resolve) => setTimeout(resolve, 300));
    await bob.idle();
    assert.equal(bob.history('alice').filter((m) => m.text === 'sent during reconnect').length, 1);
  } finally {
    await env.close();
  }
});

test('no plaintext, password, or export key appears in network payloads, server store, or server logs', async () => {
  const env = await startServer();
  try {
    const { alice, bob } = await setupUsers(env.base);
    const secret = 'PLAINTEXT-CANARY-7f3a91 meet at the old mill';
    await deliver(alice, bob, secret);
    await deliver(bob, alice, `${secret} reply`);
    await alice.idle();
    const wire = networkText(alice) + networkText(bob);
    const storeText = readFileSync(env.server.dataFile, 'utf8');
    const logs = env.logLines.join('\n');
    for (const haystack of [wire, storeText, logs]) {
      assert.ok(!haystack.includes('PLAINTEXT-CANARY'), 'plaintext leaked');
      assert.ok(!haystack.includes(PASSWORDS.alice) && !haystack.includes(PASSWORDS.bob), 'password leaked');
    }
    // Network bodies never contain a "password" field during OPAQUE registration/login.
    for (const entry of [...alice.network, ...bob.network]) {
      if (entry.request) assert.ok(!/"password"\s*:/.test(entry.request), `password field sent to ${entry.url}`);
    }
  } finally {
    await env.close();
  }
});

test('an unauthorized third user cannot read or receive another pair\'s messages', async () => {
  const env = await startServer();
  try {
    const { alice, bob, carol } = await setupUsers(env.base, ['alice', 'bob', 'carol']);
    await deliver(alice, bob, 'for bob only');
    assert.equal(carol.history('alice').length, 0);
    // Even if a malicious relay forwards Bob's packet to Carol, it is rejected as misaddressed.
    const [packet] = sentPackets(alice);
    const rejected = nextEvent(carol, 'rejected');
    env.server.store.queue.push({ qid: crypto.randomUUID(), to: 'carol', packet, at: Date.now() });
    carol.connect();
    const event = await rejected;
    assert.equal(event.code, 'wrong_recipient');
    assert.equal(carol.history('alice').length, 0);
  } finally {
    await env.close();
  }
});
