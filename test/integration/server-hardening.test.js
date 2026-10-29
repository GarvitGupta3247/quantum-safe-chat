// Milestone F: authorization, input validation, CSRF defences, headers and relay validation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket } from 'ws';
import { createAccountVault } from '../../src/protocol/envelope.js';
import { CONTENT_SECURITY_POLICY } from '../../server/app.js';
import { makeClient, PASSWORDS, setupUsers, startServer } from '../helpers.js';

const json = (body, extra = {}) => ({ method: 'POST', headers: { 'content-type': 'application/json', ...extra }, body: JSON.stringify(body) });

function wsAttempt(base, headers = {}) {
  return new Promise((resolve) => {
    const socket = new WebSocket(`${base.replace('http', 'ws')}/ws`, { headers });
    socket.on('open', () => { socket.close(); resolve('open'); });
    socket.on('unexpected-response', (_req, res) => resolve(res.statusCode));
    socket.on('error', () => resolve('error'));
  });
}

function wsFrames(base, cookie, frames) {
  return new Promise((resolve, reject) => {
    const replies = [];
    const socket = new WebSocket(`${base.replace('http', 'ws')}/ws`, { headers: { cookie } });
    socket.on('message', (data) => {
      const frame = JSON.parse(data.toString());
      if (frame.type === 'error' || frame.type === 'rejected') replies.push(frame);
      if (replies.length === frames.length) { socket.close(); resolve(replies); }
    });
    socket.on('open', () => frames.forEach((frame) => socket.send(typeof frame === 'string' ? frame : JSON.stringify(frame))));
    socket.on('close', () => resolve(replies));
    socket.on('error', reject);
  });
}

test('unauthenticated access is refused for API routes and the WebSocket', async () => {
  const env = await startServer();
  try {
    for (const path of ['/api/users', '/api/vault', '/api/me', '/api/users/alice/identity']) {
      assert.equal((await fetch(`${env.base}${path}`)).status, 401, path);
    }
    assert.equal((await fetch(`${env.base}/api/vault`, { ...json({ expectedVersion: 1, blob: {} }), method: 'PUT' })).status, 401);
    assert.equal(await wsAttempt(env.base), 401);
    assert.equal(await wsAttempt(env.base, { cookie: 'qsc_session=forged' }), 401);
  } finally {
    await env.close();
  }
});

test('CSRF defences, strict headers, and safe error handling', async () => {
  const env = await startServer();
  try {
    const { alice } = await setupUsers(env.base, ['alice']);
    const plain = await fetch(`${env.base}/api/auth/logout`, { method: 'POST', headers: { 'content-type': 'text/plain', cookie: alice.jar.cookie }, body: '{}' });
    assert.equal(plain.status, 415);
    const foreign = await fetch(`${env.base}/api/auth/logout`, json({}, { origin: 'https://evil.example', cookie: alice.jar.cookie }));
    assert.equal(foreign.status, 403);
    assert.equal(await wsAttempt(env.base, { cookie: alice.jar.cookie, origin: 'https://evil.example' }), 401);

    const response = await fetch(`${env.base}/api/health`);
    const csp = response.headers.get('content-security-policy');
    assert.equal(csp, CONTENT_SECURITY_POLICY);
    assert.ok(!/googleapis|gstatic|https?:/.test(csp), 'no third-party origins in CSP');
    assert.match(csp, /connect-src 'self'/);
    assert.match(csp, /script-src 'self' 'wasm-unsafe-eval'/);
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
    assert.equal(response.headers.get('cache-control'), 'no-store');

    const malformed = await fetch(`${env.base}/api/auth/login/start`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"username": "alice", ' });
    assert.equal(malformed.status, 400);
    assert.deepEqual(await malformed.json(), { error: 'Invalid request body.' });
    const huge = await fetch(`${env.base}/api/auth/login/start`, json({ username: 'alice', startLoginRequest: 'A'.repeat(300_000) }));
    assert.equal(huge.status, 413);
  } finally {
    await env.close();
  }
});

test('registration rejects invalid identities, prekeys, usernames and duplicates', async () => {
  const env = await startServer();
  try {
    const { upload } = createAccountVault('dave');
    const base = { username: 'dave', registrationRecord: 'A'.repeat(100), identity: upload.identity, prekeys: { spk: upload.spk, pqspk: upload.pqspk, opks: [], pqopks: [] }, vault: { wrappedDek: { iv: 'AAAAAAAAAAAAAAAA', ct: 'AAAA' }, blob: { iv: 'AAAAAAAAAAAAAAAA', ct: 'AAAA' } } };
    const tamperedIdentity = { ...base, identity: { ...upload.identity, username: 'erin' } };
    assert.equal((await fetch(`${env.base}/api/auth/register/finish`, json(tamperedIdentity))).status, 400);
    const otherUser = { ...base, username: 'erin' };
    assert.equal((await fetch(`${env.base}/api/auth/register/finish`, json(otherUser))).status, 400, 'identity bound to another username');
    const badSpk = { ...base, prekeys: { ...base.prekeys, spk: { ...upload.spk, id: upload.spk.id + 1 } } };
    assert.equal((await fetch(`${env.base}/api/auth/register/finish`, json(badSpk))).status, 400);
    assert.equal((await fetch(`${env.base}/api/auth/register/start`, json({ username: 'x', registrationRequest: 'AAAA' }))).status, 400);

    await setupUsers(env.base, ['alice']);
    const duplicate = makeClient(env.base);
    await assert.rejects(duplicate.register('alice', PASSWORDS.mallory), /already registered/);
  } finally {
    await env.close();
  }
});

test('relay validates frames and packets; vault writes use compare-and-swap; logout ends the session', async () => {
  const env = await startServer();
  try {
    const { alice } = await setupUsers(env.base, ['alice', 'bob']);
    const replies = await wsFrames(env.base, alice.jar.cookie, [
      'not json',
      { type: 'nonsense' },
      { type: 'send', packet: { v: 1 } },
      { type: 'send', packet: { v: 1, h: {}, ct: 'A'.repeat(100_000), sig: {} } },
    ]);
    assert.deepEqual(replies.map((r) => r.error), ['Invalid message format.', 'Unknown message type.', 'Malformed envelope.', 'Packet too large.']);

    const stale = await fetch(`${env.base}/api/vault`, { ...json({ expectedVersion: 0, blob: { iv: 'AAAAAAAAAAAAAAAA', ct: 'AAAA' } }, { cookie: alice.jar.cookie }), method: 'PUT' });
    assert.equal(stale.status, 409);

    const cookie = alice.jar.cookie;
    await alice.logout();
    assert.equal((await fetch(`${env.base}/api/users`, { headers: { cookie } })).status, 401);
    assert.equal(await wsAttempt(env.base, { cookie }), 401);
  } finally {
    await env.close();
  }
});
