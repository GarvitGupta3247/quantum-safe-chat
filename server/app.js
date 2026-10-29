import express from 'express';
import { createServer as createHttpServer } from 'node:http';
import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as opaque from '@serenity-kit/opaque';
import { WebSocketServer, WebSocket } from 'ws';
import { validatePacket } from '../src/protocol/envelope.js';
import {
  validOneTimePrekey, validUsername, verifyIdentityBundle, verifySignedPrekey,
} from '../src/protocol/identity.js';

// Server role: OPAQUE authentication, encrypted-vault storage, public identity/prekey directory, and a
// store-and-forward relay for signed, end-to-end encrypted envelopes. The server never receives
// passwords, OPAQUE export keys, vault keys, private keys or plaintext.

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const FRESH_AUTH_MS = 5 * 60 * 1000;
const LOGIN_STATE_TTL_MS = 60 * 1000;
const MIGRATION_TOKEN_TTL_MS = 10 * 60 * 1000;
const QUEUE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_QUEUE_PER_RECIPIENT = 1000;
const MAX_OPKS = 100;
const MAX_PQOPKS = 50;
const MAX_VAULT_CT_CHARS = 8 * 1024 * 1024;
const MAX_PACKET_BYTES = 64 * 1024;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'", // WebAssembly is required by the OPAQUE/Argon2id client
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "worker-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

function emptyStore() {
  return { format: 3, users: Object.create(null), queue: [], legacyMessages: [] };
}

// Converts a v0.5 store (scrypt password hashes, PBKDF2 key bundles, server-side message history)
// into the v3 layout. Legacy credentials are quarantined under `legacy` and used only for the
// explicit one-time migration flow; a backup of the original file is written first.
export function migrateStoreObject(parsed) {
  const store = emptyStore();
  if (parsed?.format === 3) {
    for (const [name, user] of Object.entries(parsed.users ?? {})) store.users[name] = user;
    store.queue = Array.isArray(parsed.queue) ? parsed.queue : [];
    store.legacyMessages = Array.isArray(parsed.legacyMessages) ? parsed.legacyMessages : [];
    return { store, migrated: false };
  }
  for (const [name, user] of Object.entries(parsed?.users ?? {})) {
    if (!validUsername(name) || !user || typeof user !== 'object') continue;
    store.users[name] = {
      createdAt: user.createdAt ?? null,
      legacy: {
        salt: user.salt, passwordHash: user.passwordHash,
        kemPublicKey: user.kemPublicKey, privateKeyBundle: user.privateKeyBundle ?? null,
      },
    };
  }
  for (const message of Array.isArray(parsed?.messages) ? parsed.messages : []) {
    if (!message?.envelopes || !store.users[message.sender] || !store.users[message.recipient]) continue;
    store.legacyMessages.push({
      id: message.id, sender: message.sender, recipient: message.recipient, createdAt: message.createdAt,
      envelopes: { ...message.envelopes },
    });
  }
  return { store, migrated: true };
}

export async function createServer({
  dataDir = resolve(process.env.DATA_DIR || 'data'),
  opaqueServerSetup = process.env.OPAQUE_SERVER_SETUP,
  allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:3000,http://localhost:3000').split(','),
  legacyMigration = process.env.QSC_LEGACY_MIGRATION !== '0',
  production = process.env.NODE_ENV === 'production',
  distDir = null,
  log = console,
} = {}) {
  await opaque.ready;
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const dataFile = join(dataDir, 'store.json');

  // ----- Persistence -------------------------------------------------------------------------
  let store = emptyStore();
  if (existsSync(dataFile)) {
    let parsed;
    try { parsed = JSON.parse(readFileSync(dataFile, 'utf8')); } catch {
      throw new Error(`Could not read ${dataFile}. Back up or remove the invalid file before restarting.`);
    }
    const result = migrateStoreObject(parsed);
    store = result.store;
    if (result.migrated) {
      const backup = join(dataDir, `store.v2-backup-${Date.now()}.json`);
      copyFileSync(dataFile, backup);
      try { chmodSync(backup, 0o600); } catch { /* best effort on Windows */ }
      log.log(`Migrated legacy store format; original saved as ${backup}`);
    }
  }
  function saveStore() {
    const tempFile = `${dataFile}.tmp`;
    writeFileSync(tempFile, JSON.stringify(store), { mode: 0o600 });
    renameSync(tempFile, dataFile);
  }
  saveStore();

  // The OPAQUE server setup holds the OPRF seed and server AKE key. Anyone holding it AND the store
  // can mount an offline guessing attack (Argon2id per guess), so keep it outside the data volume
  // via OPAQUE_SERVER_SETUP in production.
  let serverSetup = opaqueServerSetup;
  const setupFile = join(dataDir, 'opaque-server-setup.txt');
  if (!serverSetup) {
    if (existsSync(setupFile)) {
      serverSetup = readFileSync(setupFile, 'utf8').trim();
    } else {
      serverSetup = opaque.server.createSetup();
      writeFileSync(setupFile, serverSetup, { mode: 0o600 });
    }
  }

  // ----- In-memory state ----------------------------------------------------------------------
  const sessions = new Map();
  const loginStates = new Map();
  const migrationTokens = new Map();
  const socketsByUser = new Map();
  const recentAccepted = new Map();
  const counters = new Map();
  const origins = new Set(allowedOrigins.map((origin) => origin.trim()).filter(Boolean));

  function rateLimited(bucket, key, max, windowMs) {
    const id = `${bucket}:${key}`;
    const now = Date.now();
    let entry = counters.get(id);
    if (!entry || now - entry.start >= windowMs) entry = { start: now, count: 0 };
    entry.count += 1;
    counters.set(id, entry);
    if (counters.size > 20_000) {
      for (const [k, v] of counters) if (now - v.start > 60 * 60 * 1000) counters.delete(k);
    }
    return entry.count > max;
  }
  function resetLimit(bucket, key) {
    counters.delete(`${bucket}:${key}`);
  }

  function parseCookies(header = '') {
    const cookies = {};
    for (const item of header.split(';')) {
      const separator = item.indexOf('=');
      if (separator > 0) {
        try { cookies[item.slice(0, separator).trim()] = decodeURIComponent(item.slice(separator + 1).trim()); } catch { /* ignore */ }
      }
    }
    return cookies;
  }

  function sessionFor(req) {
    const token = parseCookies(req.headers.cookie).qsc_session;
    if (!token) return null;
    const session = sessions.get(token);
    if (!session || session.expiresAt <= Date.now() || !store.users[session.username]?.opaqueRecord) {
      sessions.delete(token);
      return null;
    }
    return { token, ...session };
  }

  function cookie(res, token, maxAgeSeconds) {
    const secure = production ? '; Secure' : '';
    res.setHeader('Set-Cookie', `qsc_session=${encodeURIComponent(token)}; Max-Age=${maxAgeSeconds}; Path=/; HttpOnly; SameSite=Strict${secure}`);
  }

  function closeSockets(username, predicate = () => true, code = 4001, reason = 'Signed in elsewhere') {
    for (const socket of socketsByUser.get(username) ?? []) {
      if (predicate(socket)) socket.close(code, reason);
    }
  }

  // One active device per account: a new login revokes every other session for that user. This
  // prevents two clients from forking the shared ratchet/vault state.
  function startSession(username, res) {
    const now = Date.now();
    for (const [token, session] of sessions) {
      if (session.expiresAt <= now || session.username === username) sessions.delete(token);
    }
    closeSockets(username);
    const token = randomBytes(32).toString('base64url');
    sessions.set(token, { username, expiresAt: now + SESSION_TTL_MS, authAt: now });
    cookie(res, token, SESSION_TTL_MS / 1000);
  }

  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
    if (production) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });
  app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      // CSRF defence in depth (cookies are already SameSite=Strict): JSON only, allowed origins only.
      if (!req.is('application/json')) return res.status(415).json({ error: 'Expected application/json.' });
      const origin = req.headers.origin;
      if (origin && !origins.has(origin)) return res.status(403).json({ error: 'Origin not allowed.' });
    }
    next();
  });
  const smallJson = express.json({ limit: '256kb' });
  const largeJson = express.json({ limit: '12mb' });

  function requireUser(req, res, next) {
    const session = sessionFor(req);
    if (!session) return res.status(401).json({ error: 'Please log in first.' });
    req.username = session.username;
    req.session = session;
    next();
  }

  function requireFreshAuth(req, res, next) {
    if (Date.now() - req.session.authAt > FRESH_AUTH_MS) return res.status(401).json({ error: 'Please confirm your current password again.' });
    next();
  }

  const clientIp = (req) => req.ip || req.socket?.remoteAddress || 'unknown';
  const str = (value, max, pattern) => typeof value === 'string' && value.length > 0 && value.length <= max && (!pattern || pattern.test(value));
  const normalUser = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : '');

  function validVaultBlob(blob) {
    return blob && typeof blob === 'object' && str(blob.iv, 16, B64) && str(blob.ct, MAX_VAULT_CT_CHARS, B64);
  }
  function validWrappedDek(wrapped) {
    return wrapped && typeof wrapped === 'object' && str(wrapped.iv, 16, B64) && str(wrapped.ct, 64, B64);
  }

  function validatePrekeyUpload(upload, identity, { requireSigned }) {
    if (!upload || typeof upload !== 'object') return 'Missing prekeys.';
    if (requireSigned && (!upload.spk || !upload.pqspk)) return 'Signed prekeys are required.';
    if (upload.spk && !verifySignedPrekey(upload.spk, identity, 'spk')) return 'Invalid signed prekey.';
    if (upload.pqspk && !verifySignedPrekey(upload.pqspk, identity, 'pqspk')) return 'Invalid ML-KEM last-resort prekey.';
    const opks = upload.opks ?? [];
    const pqopks = upload.pqopks ?? [];
    if (!Array.isArray(opks) || !Array.isArray(pqopks) || opks.length > MAX_OPKS || pqopks.length > MAX_PQOPKS) return 'Too many prekeys.';
    if (!opks.every(validOneTimePrekey)) return 'Invalid one-time prekey.';
    if (!pqopks.every((record) => verifySignedPrekey(record, identity, 'pqopk'))) return 'Invalid ML-KEM one-time prekey.';
    return null;
  }

  function applyPrekeys(user, upload) {
    user.prekeys ??= { spk: null, pqspk: null, opks: [], pqopks: [] };
    if (upload.spk) user.prekeys.spk = upload.spk;
    if (upload.pqspk) user.prekeys.pqspk = upload.pqspk;
    const opkIds = new Set(user.prekeys.opks.map((record) => record.id));
    const pqIds = new Set(user.prekeys.pqopks.map((record) => record.id));
    user.prekeys.opks.push(...(upload.opks ?? []).filter((record) => !opkIds.has(record.id)).map(({ id, pub }) => ({ id, pub })));
    user.prekeys.pqopks.push(...(upload.pqopks ?? []).filter((record) => !pqIds.has(record.id)));
    user.prekeys.opks = user.prekeys.opks.slice(-MAX_OPKS);
    user.prekeys.pqopks = user.prekeys.pqopks.slice(-MAX_PQOPKS);
  }

  function persistOr500(res, rollback) {
    try { saveStore(); return true; } catch {
      rollback?.();
      res.status(500).json({ error: 'Could not save data.' });
      return false;
    }
  }

  function consumeMigrationToken(token, username, { consume }) {
    const entry = typeof token === 'string' ? migrationTokens.get(token) : null;
    if (!entry || entry.username !== username || entry.expiresAt <= Date.now()) return false;
    if (consume) migrationTokens.delete(token);
    return true;
  }

  // ----- Routes ------------------------------------------------------------------------------
  app.get('/api/health', (_req, res) => res.json({ ok: true, protocol: 'qsc-v1: OPAQUE + PQXDH(X25519, ML-KEM-768) + Double Ratchet + Ed25519/ML-DSA-65' }));

  app.post('/api/auth/register/start', smallJson, (req, res) => {
    if (rateLimited('register', clientIp(req), 20, 15 * 60 * 1000)) return res.status(429).json({ error: 'Too many registration attempts.' });
    const username = normalUser(req.body?.username);
    const { registrationRequest, migrationToken } = req.body ?? {};
    if (!validUsername(username)) return res.status(400).json({ error: 'Username must be 3–24 characters: letters, numbers, _ or -.' });
    if (!str(registrationRequest, 512, B64URL)) return res.status(400).json({ error: 'Invalid registration request.' });
    const existing = store.users[username];
    if (existing && !(existing.legacy && consumeMigrationToken(migrationToken, username, { consume: false }))) {
      return res.status(409).json({ error: 'That username is already registered.' });
    }
    try {
      const { registrationResponse } = opaque.server.createRegistrationResponse({ serverSetup, userIdentifier: username, registrationRequest });
      res.json({ registrationResponse });
    } catch {
      res.status(400).json({ error: 'Invalid registration request.' });
    }
  });

  app.post('/api/auth/register/finish', largeJson, (req, res) => {
    const username = normalUser(req.body?.username);
    const { registrationRecord, identity, prekeys, vault, migrationToken } = req.body ?? {};
    if (!validUsername(username)) return res.status(400).json({ error: 'Invalid username.' });
    if (!str(registrationRecord, 512, B64URL)) return res.status(400).json({ error: 'Invalid registration record.' });
    let identityFp;
    try { identityFp = verifyIdentityBundle(identity, username); } catch {
      return res.status(400).json({ error: 'Invalid identity bundle.' });
    }
    const prekeyError = validatePrekeyUpload(prekeys, identity, { requireSigned: true });
    if (prekeyError) return res.status(400).json({ error: prekeyError });
    if (!vault || !validWrappedDek(vault.wrappedDek) || !validVaultBlob(vault.blob)) return res.status(400).json({ error: 'Invalid encrypted vault.' });

    const existing = store.users[username];
    const migrating = Boolean(existing?.legacy);
    if (existing && !(migrating && consumeMigrationToken(migrationToken, username, { consume: true }))) {
      return res.status(409).json({ error: 'That username is already registered.' });
    }
    const user = {
      createdAt: existing?.createdAt ?? new Date().toISOString(),
      opaqueRecord: registrationRecord,
      identity, identityFp,
      prekeys: null,
      vault: { version: 1, wrappedDek: vault.wrappedDek, blob: vault.blob },
    };
    applyPrekeys(user, prekeys);
    const previousLegacyMessages = store.legacyMessages;
    store.users[username] = user;
    if (migrating) {
      // Remove this user's legacy envelope copies; drop messages nobody can read any more.
      store.legacyMessages = store.legacyMessages
        .map((message) => {
          if (message.sender !== username && message.recipient !== username) return message;
          const envelopes = { ...message.envelopes };
          delete envelopes[username];
          return { ...message, envelopes };
        })
        .filter((message) => Object.keys(message.envelopes).some((owner) => store.users[owner]?.legacy));
    }
    if (!persistOr500(res, () => {
      if (existing) store.users[username] = existing; else delete store.users[username];
      store.legacyMessages = previousLegacyMessages;
    })) return;
    startSession(username, res);
    broadcastUsersChanged();
    res.status(201).json({ username, identityFp, vaultVersion: 1 });
  });

  app.post('/api/auth/login/start', smallJson, (req, res) => {
    const username = normalUser(req.body?.username);
    const { startLoginRequest } = req.body ?? {};
    // Online-guessing throttles: per client address and per account.
    if (rateLimited('login-ip', clientIp(req), 60, 15 * 60 * 1000) || rateLimited('login-user', username, 10, 15 * 60 * 1000)) {
      res.setHeader('Retry-After', '900');
      return res.status(429).json({ error: 'Too many login attempts. Please wait 15 minutes.' });
    }
    if (!validUsername(username) || !str(startLoginRequest, 512, B64URL)) return res.status(400).json({ error: 'Invalid login request.' });
    // Unknown and not-yet-migrated users get a simulated response, so login does not reveal which
    // usernames exist (registration still does; that is an accepted limitation of open signup).
    const registrationRecord = store.users[username]?.opaqueRecord ?? null;
    try {
      const { serverLoginState, loginResponse } = opaque.server.startLogin({ serverSetup, userIdentifier: username, registrationRecord, startLoginRequest });
      const loginId = randomBytes(24).toString('base64url');
      const now = Date.now();
      for (const [id, state] of loginStates) if (state.expiresAt <= now) loginStates.delete(id);
      if (loginStates.size > 10_000) return res.status(503).json({ error: 'Server busy.' });
      loginStates.set(loginId, { username, serverLoginState, expiresAt: now + LOGIN_STATE_TTL_MS, real: Boolean(registrationRecord) });
      res.json({ loginId, loginResponse });
    } catch {
      res.status(400).json({ error: 'Invalid login request.' });
    }
  });

  app.post('/api/auth/login/finish', smallJson, (req, res) => {
    const { loginId, finishLoginRequest } = req.body ?? {};
    const state = typeof loginId === 'string' ? loginStates.get(loginId) : null;
    if (state) loginStates.delete(loginId);
    if (!state || state.expiresAt <= Date.now() || !state.real || !str(finishLoginRequest, 512, B64URL)) {
      return res.status(401).json({ error: 'Incorrect username or password.' });
    }
    try {
      opaque.server.finishLogin({ finishLoginRequest, serverLoginState: state.serverLoginState });
    } catch {
      return res.status(401).json({ error: 'Incorrect username or password.' });
    }
    resetLimit('login-user', state.username);
    startSession(state.username, res);
    const user = store.users[state.username];
    res.json({ username: state.username, identityFp: user.identityFp, vault: user.vault });
  });

  app.post('/api/auth/logout', (req, res) => {
    const session = sessionFor(req);
    if (session) {
      sessions.delete(session.token);
      closeSockets(session.username, (socket) => socket.sessionToken === session.token, 1000, 'Logged out');
    }
    cookie(res, '', 0);
    res.json({ ok: true });
  });

  app.post('/api/auth/password/start', smallJson, requireUser, requireFreshAuth, (req, res) => {
    const { registrationRequest } = req.body ?? {};
    if (!str(registrationRequest, 512, B64URL)) return res.status(400).json({ error: 'Invalid registration request.' });
    try {
      const { registrationResponse } = opaque.server.createRegistrationResponse({ serverSetup, userIdentifier: req.username, registrationRequest });
      res.json({ registrationResponse });
    } catch {
      res.status(400).json({ error: 'Invalid registration request.' });
    }
  });

  app.post('/api/auth/password/finish', largeJson, requireUser, requireFreshAuth, (req, res) => {
    const { registrationRecord, wrappedDek, blob, expectedVersion } = req.body ?? {};
    const user = store.users[req.username];
    if (!str(registrationRecord, 512, B64URL) || !validWrappedDek(wrappedDek) || !validVaultBlob(blob)) return res.status(400).json({ error: 'Invalid password change.' });
    if (expectedVersion !== user.vault.version) return res.status(409).json({ error: 'Vault changed; reload before changing the password.', version: user.vault.version });
    const previous = { record: user.opaqueRecord, vault: user.vault };
    user.opaqueRecord = registrationRecord;
    user.vault = { version: expectedVersion + 1, wrappedDek, blob };
    if (!persistOr500(res, () => { user.opaqueRecord = previous.record; user.vault = previous.vault; })) return;
    startSession(req.username, res); // revokes every other session for this account
    res.json({ ok: true, vaultVersion: user.vault.version });
  });

  // Lets a reloaded page pre-fill the username; reveals nothing beyond the caller's own cookie.
  app.get('/api/session', (req, res) => {
    res.json({ username: sessionFor(req)?.username ?? null });
  });

  app.get('/api/me', requireUser, (req, res) => {
    const user = store.users[req.username];
    res.json({
      username: req.username,
      identityFp: user.identityFp,
      prekeys: {
        opks: user.prekeys?.opks.length ?? 0,
        pqopks: user.prekeys?.pqopks.length ?? 0,
        spkCreatedAt: user.prekeys?.spk?.createdAt ?? null,
        pqspkCreatedAt: user.prekeys?.pqspk?.createdAt ?? null,
      },
    });
  });

  app.get('/api/vault', requireUser, (req, res) => {
    res.json(store.users[req.username].vault);
  });

  app.put('/api/vault', largeJson, requireUser, (req, res) => {
    const { expectedVersion, blob } = req.body ?? {};
    const user = store.users[req.username];
    if (!Number.isSafeInteger(expectedVersion) || !validVaultBlob(blob)) return res.status(400).json({ error: 'Invalid vault update.' });
    // Compare-and-swap: a stale client must reload instead of overwriting newer ratchet state.
    if (expectedVersion !== user.vault.version) return res.status(409).json({ error: 'Vault version conflict.', version: user.vault.version });
    const previous = user.vault;
    user.vault = { ...previous, version: expectedVersion + 1, blob };
    if (!persistOr500(res, () => { user.vault = previous; })) return;
    res.json({ version: user.vault.version });
  });

  app.post('/api/prekeys', largeJson, requireUser, (req, res) => {
    const user = store.users[req.username];
    const error = validatePrekeyUpload(req.body, user.identity, { requireSigned: false });
    if (error) return res.status(400).json({ error });
    const previous = structuredClone(user.prekeys);
    applyPrekeys(user, req.body);
    if (!persistOr500(res, () => { user.prekeys = previous; })) return;
    res.json({ opks: user.prekeys.opks.length, pqopks: user.prekeys.pqopks.length });
  });

  app.get('/api/users', requireUser, (req, res) => {
    const users = Object.entries(store.users)
      .filter(([username]) => username !== req.username)
      .map(([username, user]) => ({
        username,
        legacy: !user.opaqueRecord,
        online: (socketsByUser.get(username)?.size ?? 0) > 0,
      }))
      .sort((a, b) => a.username.localeCompare(b.username));
    res.json({ users });
  });

  app.get('/api/users/:name/identity', requireUser, (req, res) => {
    const user = store.users[normalUser(req.params.name)];
    if (!user?.identity) return res.status(404).json({ error: 'No identity published for that user.' });
    res.json({ identity: user.identity });
  });

  // Consumes one X25519 and one ML-KEM one-time prekey when available (POST: not idempotent).
  app.post('/api/users/:name/prekeys', smallJson, requireUser, (req, res) => {
    const name = normalUser(req.params.name);
    const user = store.users[name];
    if (!user?.identity || name === req.username) return res.status(404).json({ error: 'No prekeys published for that user.' });
    if (rateLimited('prekey-fetch', `${req.username}:${name}`, 20, 60 * 60 * 1000)) return res.status(429).json({ error: 'Too many session starts with this contact.' });
    const opk = user.prekeys.opks.shift() ?? null;
    const pqopk = user.prekeys.pqopks.shift() ?? null;
    try { saveStore(); } catch { /* the keys stay consumed in memory; a reused key is still safe-by-design */ }
    res.json({ identity: user.identity, spk: user.prekeys.spk, pq: pqopk ?? user.prekeys.pqspk, opk });
  });

  // Explicit, one-time legacy migration. This is the ONLY route that still receives a password,
  // and only from accounts that have not migrated yet. The client then sets a new password via
  // OPAQUE. Disable with QSC_LEGACY_MIGRATION=0 once the migration window closes.
  app.post('/api/legacy/start', smallJson, (req, res) => {
    if (!legacyMigration) return res.status(404).json({ error: 'Legacy migration is disabled on this server.' });
    if (rateLimited('login-ip', clientIp(req), 60, 15 * 60 * 1000)) return res.status(429).json({ error: 'Too many attempts.' });
    const username = normalUser(req.body?.username);
    const { password } = req.body ?? {};
    const legacy = store.users[username]?.legacy;
    if (rateLimited('login-user', username, 10, 15 * 60 * 1000)) return res.status(429).json({ error: 'Too many attempts.' });
    let ok = false;
    if (legacy && typeof password === 'string' && password.length <= 200) {
      try {
        const expected = Buffer.from(legacy.passwordHash, 'hex');
        const actual = scryptSync(password, legacy.salt, expected.length);
        ok = expected.length > 0 && timingSafeEqual(expected, actual);
      } catch { ok = false; }
    }
    if (!ok) return res.status(401).json({ error: 'Legacy username or password is incorrect, or the account was already upgraded.' });
    resetLimit('login-user', username);
    const migrationToken = randomBytes(32).toString('base64url');
    migrationTokens.set(migrationToken, { username, expiresAt: Date.now() + MIGRATION_TOKEN_TTL_MS });
    const messages = store.legacyMessages
      .filter((message) => message.envelopes?.[username])
      .map((message) => ({ id: message.id, sender: message.sender, recipient: message.recipient, createdAt: message.createdAt, envelope: message.envelopes[username] }));
    res.json({ migrationToken, privateKeyBundle: legacy.privateKeyBundle ?? null, messages });
  });

  // ----- WebSocket relay -----------------------------------------------------------------------
  const httpServer = createHttpServer(app);
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PACKET_BYTES * 2 });

  function safeSend(socket, message) {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
  }
  function broadcastUsersChanged() {
    for (const set of socketsByUser.values()) for (const socket of set) safeSend(socket, { type: 'users-changed' });
  }
  function deliverQueued(username, socket) {
    const items = store.queue.filter((item) => item.to === username).map(({ qid, packet }) => ({ qid, packet }));
    if (items.length) safeSend(socket, { type: 'deliver', items });
  }
  function purgeQueue() {
    const cutoff = Date.now() - QUEUE_TTL_MS;
    const before = store.queue.length;
    store.queue = store.queue.filter((item) => item.at > cutoff && store.users[item.to]);
    if (store.queue.length !== before) { try { saveStore(); } catch { /* retry next run */ } }
    const now = Date.now();
    for (const [key, value] of recentAccepted) if (value.at < now - 24 * 60 * 60 * 1000) recentAccepted.delete(key);
  }
  purgeQueue();
  const purgeTimer = setInterval(purgeQueue, 60 * 60 * 1000);
  purgeTimer.unref();

  httpServer.on('upgrade', (req, socket, head) => {
    const path = new URL(req.url, 'http://localhost').pathname;
    const origin = req.headers.origin;
    const session = sessionFor(req);
    if (path !== '/ws' || (origin && !origins.has(origin)) || !session) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.username = session.username;
      ws.sessionToken = session.token;
      wss.emit('connection', ws);
    });
  });

  wss.on('connection', (socket) => {
    const username = socket.username;
    if (!socketsByUser.has(username)) socketsByUser.set(username, new Set());
    socketsByUser.get(username).add(socket);
    safeSend(socket, { type: 'ready', username });
    broadcastUsersChanged();
    deliverQueued(username, socket);

    socket.on('message', (raw) => {
      if (!sessions.has(socket.sessionToken)) return socket.close(4002, 'Session ended');
      if (raw.length > MAX_PACKET_BYTES * 2) return safeSend(socket, { type: 'error', error: 'Packet too large.' });
      let message;
      try { message = JSON.parse(raw.toString()); } catch {
        return safeSend(socket, { type: 'error', error: 'Invalid message format.' });
      }
      if (message?.type === 'ack') {
        const qids = Array.isArray(message.qids) ? message.qids.filter((id) => typeof id === 'string').slice(0, 1000) : [];
        const remove = new Set(qids);
        const before = store.queue.length;
        store.queue = store.queue.filter((item) => !(item.to === username && remove.has(item.qid)));
        if (store.queue.length !== before) { try { saveStore(); } catch { /* entries are redelivered later */ } }
        return;
      }
      if (message?.type === 'sync') return deliverQueued(username, socket);
      if (message?.type !== 'send') return safeSend(socket, { type: 'error', error: 'Unknown message type.' });
      if (rateLimited('send', username, 120, 60 * 1000)) return safeSend(socket, { type: 'error', error: 'Sending too fast.' });

      const packet = message.packet;
      const messageId = packet?.h?.id;
      const reject = (error) => safeSend(socket, { type: 'rejected', id: typeof messageId === 'string' && UUID_PATTERN.test(messageId) ? messageId : null, error });
      const serialized = JSON.stringify(packet ?? null);
      if (serialized.length > MAX_PACKET_BYTES) return reject('Packet too large.');
      try { validatePacket(packet); } catch { return reject('Malformed envelope.'); }
      // Routing sanity checks only. Receivers verify signatures; the server is not trusted for this.
      if (packet.h.from !== username) return reject('Sender does not match the authenticated account.');
      const recipient = store.users[packet.h.to];
      if (!recipient?.identity) return reject('Unknown recipient.');
      const digest = createHash('sha256').update(serialized).digest('hex');
      const dedupeKey = `${username}:${messageId}`;
      const prior = recentAccepted.get(dedupeKey);
      if (prior) return prior.digest === digest ? safeSend(socket, { type: 'accepted', id: messageId }) : reject('Message ID already used.');
      if (store.queue.filter((item) => item.to === packet.h.to).length >= MAX_QUEUE_PER_RECIPIENT) return reject('Recipient queue is full.');

      const item = { qid: randomUUID(), to: packet.h.to, packet, at: Date.now() };
      store.queue.push(item);
      try { saveStore(); } catch {
        store.queue = store.queue.filter((entry) => entry.qid !== item.qid);
        return reject('Could not persist the message.');
      }
      recentAccepted.set(dedupeKey, { digest, at: Date.now() });
      safeSend(socket, { type: 'accepted', id: messageId });
      for (const peer of socketsByUser.get(packet.h.to) ?? []) safeSend(peer, { type: 'deliver', items: [{ qid: item.qid, packet }] });
    });

    socket.on('close', () => {
      const set = socketsByUser.get(username);
      set?.delete(socket);
      if (set?.size === 0) socketsByUser.delete(username);
      broadcastUsersChanged();
    });
  });

  if (distDir && existsSync(distDir)) {
    distDir = resolve(distDir); // sendFile requires an absolute path
    app.use(express.static(distDir, { index: false }));
    app.use((req, res, next) => {
      if (req.method === 'GET' && !req.path.startsWith('/api') && req.path !== '/ws') return res.sendFile(join(distDir, 'index.html'));
      next();
    });
  }
  app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found.' }));
  // Never echo internal errors (they could include request data).
  app.use((error, _req, res, _next) => {
    const status = error?.type === 'entity.too.large' ? 413 : error?.type === 'entity.parse.failed' ? 400 : 500;
    res.status(status).json({ error: status === 500 ? 'Internal error.' : 'Invalid request body.' });
  });

  return {
    app,
    httpServer,
    // Exposed for tests that model a malicious or compromised server.
    get store() { return store; },
    serverSetup,
    dataFile,
    async listen(port = 0, host = '127.0.0.1') {
      await new Promise((resolveListen) => httpServer.listen(port, host, resolveListen));
      return httpServer.address().port;
    },
    async close() {
      clearInterval(purgeTimer);
      for (const set of socketsByUser.values()) for (const socket of set) socket.terminate();
      wss.close();
      await new Promise((resolveClose) => httpServer.close(resolveClose));
    },
  };
}
