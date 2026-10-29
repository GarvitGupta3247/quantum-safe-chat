import express from 'express';
import { createServer } from 'node:http';
import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, copyFileSync, chmodSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(__dirname, '..');
// Point DATA_DIR at a mounted persistent volume in production when one is configured.
const dataDir = resolve(process.env.DATA_DIR || join(projectRoot, 'data'));
const dataFile = join(dataDir, 'store.json');
const legacyDataFile = join(projectRoot, 'data', 'store.json');
mkdirSync(dataDir, { recursive: true, mode: 0o700 });
// Best-effort one-time copy when DATA_DIR is changed to a persistent mount and the old file is still present.
if (dataFile !== legacyDataFile && !existsSync(dataFile) && existsSync(legacyDataFile)) {
  copyFileSync(legacyDataFile, dataFile);
  chmodSync(dataFile, 0o600);
}

function loadStore() {
  if (!existsSync(dataFile)) return { users: Object.create(null), messages: [] };
  try {
    const parsed = JSON.parse(readFileSync(dataFile, 'utf8'));
    const users = Object.create(null);
    if (parsed.users && typeof parsed.users === 'object' && !Array.isArray(parsed.users)) {
      for (const [username, user] of Object.entries(parsed.users)) users[username] = user;
    }
    return {
      users,
      messages: Array.isArray(parsed.messages) ? parsed.messages : [],
    };
  } catch {
    throw new Error(`Could not read ${dataFile}. Back up or remove the invalid file before restarting.`);
  }
}

const store = loadStore();
function saveStore() {
  const tempFile = `${dataFile}.tmp`;
  writeFileSync(tempFile, JSON.stringify(store, null, 2), { mode: 0o600 });
  renameSync(tempFile, dataFile);
}

const app = express();
// Render places the app behind one trusted reverse proxy; this enables client-IP-aware throttling.
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self' ws: wss:");
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  }
  next();
});
// Authenticated API responses contain account data or ciphertext; do not cache them in browsers or proxies.
app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
});
app.use(express.json({ limit: '256kb' }));
const httpServer = createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });
const sessions = new Map();
const socketsByUser = new Map();
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 8;
const LOGIN_BLOCK_MS = 15 * 60 * 1000;
const loginFailures = new Map();
const allowedOrigins = new Set([
  ...(process.env.ALLOWED_ORIGINS || 'http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:3000,http://localhost:3000').split(',').map((origin) => origin.trim()).filter(Boolean),
  ...(process.env.LAN_IP ? [`https://${process.env.LAN_IP.trim()}:5173`] : []),
]);

function parseCookies(header = '') {
  const cookies = {};
  for (const item of header.split(';')) {
    const separator = item.indexOf('=');
    if (separator > 0) {
      const name = item.slice(0, separator).trim();
      const value = item.slice(separator + 1).trim();
      try { cookies[name] = decodeURIComponent(value); } catch { /* ignore malformed cookie */ }
    }
  }
  return cookies;
}

function sessionForRequest(req) {
  const token = parseCookies(req.headers.cookie).qsc_session;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function requireUser(req, res, next) {
  const session = sessionForRequest(req);
  if (!session || !store.users[session.username]) {
    return res.status(401).json({ error: 'Please log in first.' });
  }
  req.username = session.username;
  req.sessionToken = session.token;
  next();
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `qsc_session=${encodeURIComponent(token)}; Max-Age=${SESSION_TTL_MS / 1000}; Path=/; HttpOnly; SameSite=Strict${secure}`);
}

function createSession(username, res) {
  const now = Date.now();
  // Opportunistically remove expired entries so abandoned sessions do not grow the in-memory map forever.
  for (const [token, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(token);
  }
  const token = randomBytes(32).toString('base64url');
  sessions.set(token, { username, expiresAt: now + SESSION_TTL_MS });
  setSessionCookie(res, token);
}

function validUsername(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9_-]{3,24}$/.test(value.trim());
}

function isCanonicalBase64(value, minBytes, maxBytes = minBytes) {
  if (typeof value !== 'string' || value.length > Math.ceil(maxBytes * 4 / 3) + 8) return false;
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length >= minBytes && bytes.length <= maxBytes && bytes.toString('base64') === value;
}

function validPrivateKeyBundle(bundle, expectedPublicKey) {
  // The browser wraps a 2,400-byte ML-KEM-768 private key with AES-GCM (16-byte tag).
  return Boolean(bundle && typeof bundle === 'object'
    && bundle.version === 2
    && bundle.kdf === 'PBKDF2-HMAC-SHA-256'
    && bundle.iterations === 600_000
    && bundle.publicKey === expectedPublicKey
    && isCanonicalBase64(bundle.publicKey, 1184)
    && isCanonicalBase64(bundle.salt, 16)
    && isCanonicalBase64(bundle.iv, 12)
    && isCanonicalBase64(bundle.encryptedPrivateKey, 2416));
}

function passwordRecord(password) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return { salt, passwordHash: hash };
}

function passwordMatches(password, record) {
  try {
    const expected = Buffer.from(record.passwordHash, 'hex');
    const actual = scryptSync(password, record.salt, expected.length);
    return expected.length > 0 && expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

function publicUser(username, user) {
  return { username, kemPublicKey: user.kemPublicKey };
}

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function loginBlockRemaining(req) {
  const entry = loginFailures.get(clientIp(req));
  if (!entry) return 0;
  const now = Date.now();
  if (entry.blockedUntil > now) return entry.blockedUntil - now;
  if (now - entry.windowStarted >= LOGIN_WINDOW_MS || (entry.blockedUntil && entry.blockedUntil <= now)) {
    loginFailures.delete(clientIp(req));
  }
  return 0;
}

function recordLoginFailure(req) {
  const key = clientIp(req);
  const now = Date.now();
  let entry = loginFailures.get(key);
  if (!entry || now - entry.windowStarted >= LOGIN_WINDOW_MS || (entry.blockedUntil && entry.blockedUntil <= now)) {
    entry = { windowStarted: now, failures: 0, blockedUntil: 0 };
  }
  entry.failures += 1;
  if (entry.failures >= LOGIN_MAX_FAILURES) entry.blockedUntil = now + LOGIN_BLOCK_MS;
  loginFailures.set(key, entry);

  // Avoid unbounded growth if many source IPs hit this demo service.
  if (loginFailures.size > 5000) {
    for (const [ip, record] of loginFailures) {
      if (record.windowStarted + LOGIN_WINDOW_MS < now || (record.blockedUntil && record.blockedUntil < now)) loginFailures.delete(ip);
      if (loginFailures.size <= 4000) break;
    }
  }
}

function clearLoginFailures(req) {
  loginFailures.delete(clientIp(req));
}


app.get('/api/health', (_req, res) => res.json({ ok: true, crypto: 'ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM' }));

app.post('/api/register', (req, res) => {
  const { username: rawUsername, password, kemPublicKey, privateKeyBundle } = req.body ?? {};
  if (!validUsername(rawUsername)) {
    return res.status(400).json({ error: 'Username must be 3–24 characters: letters, numbers, _ or -.' });
  }
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  // ML-KEM-768 public keys are 1184 bytes (FIPS 203).
  if (!isCanonicalBase64(kemPublicKey, 1184)) {
    return res.status(400).json({ error: 'Invalid ML-KEM-768 public key.' });
  }
  if (!validPrivateKeyBundle(privateKeyBundle, kemPublicKey)) {
    return res.status(400).json({ error: 'Invalid encrypted private-key bundle.' });
  }
  const username = rawUsername.trim().toLowerCase();
  if (store.users[username]) return res.status(409).json({ error: 'That username is already registered.' });

  store.users[username] = {
    ...passwordRecord(password), kemPublicKey, privateKeyBundle,
    createdAt: new Date().toISOString(),
  };
  try {
    saveStore();
  } catch {
    delete store.users[username];
    return res.status(500).json({ error: 'Could not save the account data.' });
  }
  createSession(username, res);
  broadcastUsersChanged();
  res.status(201).json({ username, kemPublicKey });
});

app.post('/api/login', (req, res) => {
  const blockedForMs = loginBlockRemaining(req);
  if (blockedForMs > 0) {
    res.setHeader('Retry-After', String(Math.ceil(blockedForMs / 1000)));
    return res.status(429).json({ error: 'Too many failed login attempts. Please wait 15 minutes before trying again.' });
  }

  const { username: rawUsername, password } = req.body ?? {};
  const username = typeof rawUsername === 'string' ? rawUsername.trim().toLowerCase() : '';
  const user = store.users[username];
  if (!user || typeof password !== 'string' || !passwordMatches(password, user)) {
    recordLoginFailure(req);
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }
  clearLoginFailures(req);
  createSession(username, res);
  res.json({ username, kemPublicKey: user.kemPublicKey, privateKeyBundle: user.privateKeyBundle ?? null });
});

// Existing accounts are migrated once from their original browser. Never silently replace a set bundle.
app.post('/api/me/key-bundle', requireUser, (req, res) => {
  const user = store.users[req.username];
  const bundle = req.body?.privateKeyBundle;
  if (!validPrivateKeyBundle(bundle, user.kemPublicKey)) {
    return res.status(400).json({ error: 'Invalid encrypted private-key bundle.' });
  }
  if (user.privateKeyBundle) {
    // Another concurrent legacy-login may have completed the one-time migration first. Never overwrite it.
    return res.json({ ok: true, alreadyExists: true });
  }
  user.privateKeyBundle = bundle;
  try { saveStore(); } catch {
    delete user.privateKeyBundle;
    return res.status(500).json({ error: 'Could not save the encrypted private-key bundle.' });
  }
  res.status(201).json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const session = sessionForRequest(req);
  if (session) {
    sessions.delete(session.token);
    for (const userSockets of socketsByUser.values()) {
      for (const socket of userSockets) {
        if (socket.sessionToken === session.token) socket.close(1000, 'Logged out');
      }
    }
  }
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `qsc_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict${secure}`);
  res.json({ ok: true });
});

app.get('/api/me', requireUser, (req, res) => {
  res.json(publicUser(req.username, store.users[req.username]));
});

app.get('/api/users', requireUser, (req, res) => {
  const users = Object.entries(store.users)
    .filter(([username]) => username !== req.username)
    .map(([username, user]) => ({
      ...publicUser(username, user),
      online: (socketsByUser.get(username)?.size ?? 0) > 0,
    }))
    .sort((a, b) => a.username.localeCompare(b.username));
  res.json({ users });
});

app.get('/api/messages', requireUser, (req, res) => {
  const other = typeof req.query.with === 'string' ? req.query.with.toLowerCase() : '';
  if (!other || !store.users[other] || other === req.username) {
    return res.status(400).json({ error: 'Choose a valid conversation partner.' });
  }
  const messages = store.messages
    .filter((m) => (m.sender === req.username && m.recipient === other) || (m.sender === other && m.recipient === req.username))
    .slice(-200);
  res.json({ messages });
});

function validEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') return false;
  return isCanonicalBase64(envelope.kemCiphertext, 1088)
    && isCanonicalBase64(envelope.salt, 16)
    && isCanonicalBase64(envelope.iv, 12)
    && isCanonicalBase64(envelope.ciphertext, 16, 150_000);
}

// Fingerprint a recipient's encrypted envelope to catch repeated delivery of the same copy.
// This is duplicate-envelope detection, not a complete protocol-level replay defense.
function fingerprintRecipientEnvelope(sender, recipient, envelopes) {
  const canonical = { sender, recipient, envelope: envelopes?.[recipient] };
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

function safeSend(socket, message) {
  if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
}

function broadcastUsersChanged() {
  for (const userSockets of socketsByUser.values()) {
    for (const socket of userSockets) safeSend(socket, { type: 'users-changed' });
  }
}

httpServer.on('upgrade', (req, socket, head) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  const origin = req.headers.origin;
  const session = sessionForRequest(req);
  if (path !== '/ws' || (origin && !allowedOrigins.has(origin)) || !session || !store.users[session.username]) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.username = session.username;
    ws.sessionToken = session.token;
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (socket) => {
  const username = socket.username;
  if (!socketsByUser.has(username)) socketsByUser.set(username, new Set());
  socketsByUser.get(username).add(socket);
  safeSend(socket, { type: 'ready', username });
  broadcastUsersChanged();

  socket.on('message', (raw) => {
    let packet;
    try { packet = JSON.parse(raw.toString()); } catch {
      return safeSend(socket, { type: 'error', error: 'Invalid message format.' });
    }
    if (packet?.type !== 'send') return safeSend(socket, { type: 'error', error: 'Unknown message type.' });

    const recipient = typeof packet.to === 'string' ? packet.to.toLowerCase() : '';
    const envelopes = packet.envelopes;
    const clientMessageId = packet.clientMessageId;
    if (typeof clientMessageId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clientMessageId)) {
      return safeSend(socket, { type: 'error', error: 'Invalid client message ID.' });
    }
    if (!recipient || recipient === username || !store.users[recipient]) {
      return safeSend(socket, { type: 'error', error: 'Unknown recipient.', clientMessageId });
    }
    if (!envelopes || typeof envelopes !== 'object'
      || Object.keys(envelopes).length !== 2
      || !validEnvelope(envelopes[username])
      || !validEnvelope(envelopes[recipient])) {
      return safeSend(socket, { type: 'error', error: 'Invalid encrypted envelope. No message was saved.', clientMessageId });
    }

    const envelopeFingerprint = fingerprintRecipientEnvelope(username, recipient, envelopes);
    const priorRequest = store.messages.find((existing) => existing.sender === username && existing.clientMessageId === clientMessageId);
    if (priorRequest) {
      if (priorRequest.recipient === recipient && priorRequest.envelopeFingerprint === envelopeFingerprint) {
        return safeSend(socket, { type: 'sent', message: priorRequest, clientMessageId });
      }
      return safeSend(socket, { type: 'error', error: 'This client message ID was already used.', clientMessageId });
    }
    const duplicateEnvelope = store.messages.some((existing) => {
      if (existing.sender !== username || existing.recipient !== recipient) return false;
      const fingerprint = existing.envelopeFingerprint
        || fingerprintRecipientEnvelope(existing.sender, existing.recipient, existing.envelopes);
      return fingerprint === envelopeFingerprint;
    });
    if (duplicateEnvelope) {
      return safeSend(socket, { type: 'error', error: 'Duplicate encrypted envelope rejected.', clientMessageId });
    }

    const message = {
      id: randomUUID(),
      clientMessageId,
      sender: username,
      recipient,
      envelopeFingerprint,
      envelopes: { [username]: envelopes[username], [recipient]: envelopes[recipient] },
      createdAt: new Date().toISOString(),
    };
    store.messages.push(message);
    if (store.messages.length > 10_000) store.messages.splice(0, store.messages.length - 10_000);
    try { saveStore(); } catch (error) {
      store.messages = store.messages.filter((m) => m.id !== message.id);
      return safeSend(socket, { type: 'error', error: 'Could not persist the encrypted message.', clientMessageId });
    }

    safeSend(socket, { type: 'sent', message, clientMessageId });
    for (const peer of socketsByUser.get(recipient) ?? []) {
      safeSend(peer, { type: 'message', message });
    }
  });

  socket.on('close', () => {
    const userSockets = socketsByUser.get(username);
    userSockets?.delete(socket);
    if (userSockets?.size === 0) socketsByUser.delete(username);
    broadcastUsersChanged();
  });
});


const distDir = join(projectRoot, 'dist');
if (existsSync(distDir)) {
  app.use(express.static(distDir));
  app.use((req, res, next) => {
    if (req.method === 'GET' && !req.path.startsWith('/api') && req.path !== '/ws') {
      return res.sendFile(join(distDir, 'index.html'));
    }
    next();
  });
}

const port = Number(process.env.PORT || 3000);
httpServer.listen(port, '0.0.0.0', () => {
  console.log(`QuantumSafe Chat API + WebSocket relay listening on port ${port}`);
  console.log('Demo only: messages are encrypted in the browser; this is not a production-secure messenger.');
});
