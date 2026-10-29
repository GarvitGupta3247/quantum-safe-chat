import { createMlKem768 } from 'mlkem';
import './style.css';

const root = document.querySelector('#app');
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KDF_INFO = encoder.encode('QuantumSafeChat PoC v1 | ML-KEM-768 | AES-256-GCM');
const X25519_BENCHMARK_INFO = encoder.encode('QuantumSafeChat Benchmark | X25519 | AES-256-GCM');
const PRIVATE_KEY_STORAGE_VERSION = 2;
// PBKDF2-HMAC-SHA-256 work factor used to wrap the local private key with the user's password.
const PRIVATE_KEY_PBKDF2_ITERATIONS = 600_000;

const state = {
  kem: null,
  me: null,
  keys: null,
  users: [],
  active: null,
  messages: [],
  conversations: new Map(),
  drafts: {},
  socket: null,
  reconnectTimer: null,
  reconnectAttempts: 0,
  conversationLoadId: 0,
  pendingSends: new Map(),
  unread: {},
  status: 'Connecting…',
  draft: '',
  busy: false,
  view: 'chat',
  cryptoEvents: [],
  recentEnvelopes: [],
  latestPrivateKeyBundle: null,
  publicKeyFingerprint: null,
  benchmarkResult: null,
  benchmarkRunning: false,
  benchmarkProgress: 0,
  securityTests: [],
  securityTestsRunning: false,
};

function bytesToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function recordCryptoEvent(title, outcome = 'success', details = '') {
  if (state.securityTestsRunning && title === 'Private-key bundle protected at rest') {
    title = 'Ephemeral test key bundle wrapped';
    outcome = 'info';
    details = `Disposable key material for the wrong-password test; not the account's bundle. ${details}`;
  }
  if (state.securityTestsRunning && title === 'Encrypted private-key bundle unlock rejected') {
    outcome = 'info';
    details = `Expected negative-test outcome: ${details}`;
  }
  state.cryptoEvents.unshift({
    at: new Date().toISOString(),
    title: String(title),
    outcome: ['success', 'failure', 'info'].includes(outcome) ? outcome : 'info',
    details: String(details ?? ''),
  });
  state.cryptoEvents = state.cryptoEvents.slice(0, 120);
}

async function fingerprintBytes(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...digest].map((value) => value.toString(16).padStart(2, '0')).join('').slice(0, 24);
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return '—';
  return `${value.toLocaleString()} B`;
}

function formatMs(value) {
  return Number.isFinite(value) ? `${value.toFixed(value < 1 ? 3 : 2)} ms` : '—';
}

function asBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw new TypeError('Expected an ArrayBuffer or byte array.');
}

function bytesEqual(leftValue, rightValue) {
  const left = asBytes(leftValue);
  const right = asBytes(rightValue);
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i += 1) difference |= left[i] ^ right[i];
  return difference === 0;
}

function downloadText(filename, content, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function sanitizedEnvelopeSummary(entry) {
  return {
    capturedAt: entry.capturedAt,
    label: entry.label,
    publicKeyFingerprint: entry.publicKeyFingerprint,
    sizes: entry.sizes,
    // Keep previews short in exported reports; the complete ciphertext remains inspectable in the UI.
    previews: {
      kemCiphertext: `${entry.envelope.kemCiphertext.slice(0, 32)}…`,
      salt: entry.envelope.salt,
      iv: entry.envelope.iv,
      ciphertext: `${entry.envelope.ciphertext.slice(0, 48)}…`,
    },
  };
}

function buildResearchReport() {
  return {
    schema: 'quantumsafe-chat-research-report-v1',
    generatedAt: new Date().toISOString(),
    project: 'QuantumSafe Chat',
    reportType: 'sanitized evaluation report',
    environment: {
      userAgent: navigator.userAgent,
      platform: navigator.platform || 'not reported',
      language: navigator.language,
      secureContext: window.isSecureContext,
      sourceRevision: import.meta.env?.VITE_GIT_COMMIT || 'not embedded in this build',
    },
    algorithms: {
      postQuantum: 'ML-KEM-768',
      keyDerivation: 'HKDF-SHA-256',
      messageEncryption: 'AES-256-GCM',
      classicalBaseline: 'X25519 via Web Crypto API when supported',
    },
    cryptoEvents: state.cryptoEvents.map(({ at, title, outcome, details }) => ({ at, title, outcome, details })),
    encryptedEnvelopeSummaries: state.recentEnvelopes.slice(0, 10).map(sanitizedEnvelopeSummary),
    encryptedPrivateKeyBundle: state.latestPrivateKeyBundle?.encryptedPrivateKey ? {
      version: state.latestPrivateKeyBundle.version,
      kdf: state.latestPrivateKeyBundle.kdf,
      iterations: state.latestPrivateKeyBundle.iterations,
      saltBytes: base64ToBytes(state.latestPrivateKeyBundle.salt).length,
      ivBytes: base64ToBytes(state.latestPrivateKeyBundle.iv).length,
      encryptedPrivateKeyBytes: base64ToBytes(state.latestPrivateKeyBundle.encryptedPrivateKey).length,
      publicKeyFingerprint: state.publicKeyFingerprint,
      preview: `${state.latestPrivateKeyBundle.encryptedPrivateKey.slice(0, 40)}…`,
    } : null,
    benchmark: state.benchmarkResult ? {
      ...state.benchmarkResult,
      // Raw timings and byte counts only: no keys, shared secrets, plaintext or message bodies.
    } : null,
    securityTests: state.securityTests,
    privacyNotice: 'This report excludes passwords, raw public/private key material, shared secrets, and plaintext message contents. It may include usernames in trace descriptions and previews of ciphertext; review before sharing.',
  };
}

function exportResearchReport() {
  downloadText(`quantumsafe-research-${new Date().toISOString().replace(/[:.]/g, '-')}.json`, JSON.stringify(buildResearchReport(), null, 2), 'application/json;charset=utf-8');
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers ?? {}) },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function localKeyName(username) {
  return `qsc:mlkem768:${username}`;
}

async function derivePrivateKeyWrappingKey(password, saltBytes) {
  const passwordMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: PRIVATE_KEY_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    passwordMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function createPrivateKeyBundle(keys, password) {
  const operationStart = performance.now();
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const kdfStart = performance.now();
  const wrappingKey = await derivePrivateKeyWrappingKey(password, saltBytes);
  const kdfMs = performance.now() - kdfStart;
  const encryptionStart = performance.now();
  const encryptedPrivateKey = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivBytes },
    wrappingKey,
    base64ToBytes(keys.privateKey),
  );
  const encryptionMs = performance.now() - encryptionStart;
  const bundle = {
    version: PRIVATE_KEY_STORAGE_VERSION,
    publicKey: keys.publicKey,
    kdf: 'PBKDF2-HMAC-SHA-256',
    iterations: PRIVATE_KEY_PBKDF2_ITERATIONS,
    salt: bytesToBase64(saltBytes),
    iv: bytesToBase64(ivBytes),
    encryptedPrivateKey: bytesToBase64(new Uint8Array(encryptedPrivateKey)),
  };
  recordCryptoEvent('Private-key bundle protected at rest', 'success',
    `PBKDF2-HMAC-SHA-256 (${PRIVATE_KEY_PBKDF2_ITERATIONS.toLocaleString()} iterations, ${formatMs(kdfMs)}); AES-256-GCM (${formatMs(encryptionMs)}); salt ${saltBytes.length} B; IV ${ivBytes.length} B; encrypted private key ${encryptedPrivateKey.byteLength} B; total ${formatMs(performance.now() - operationStart)}.`);
  return bundle;
}

function readLocalKeyBundle(username) {
  try {
    const parsed = JSON.parse(localStorage.getItem(localKeyName(username)) || 'null');
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function storeLocalKeyBundle(username, bundle) {
  localStorage.setItem(localKeyName(username), JSON.stringify(bundle));
}

async function unlockPrivateKeyBundle(bundle, password) {
  if (!bundle || bundle.version !== PRIVATE_KEY_STORAGE_VERSION
    || bundle.kdf !== 'PBKDF2-HMAC-SHA-256'
    || bundle.iterations !== PRIVATE_KEY_PBKDF2_ITERATIONS
    || typeof bundle.publicKey !== 'string'
    || typeof bundle.salt !== 'string' || typeof bundle.iv !== 'string'
    || typeof bundle.encryptedPrivateKey !== 'string') {
    throw new Error('The encrypted private-key bundle is invalid or unsupported.');
  }

  try {
    const saltBytes = base64ToBytes(bundle.salt);
    const ivBytes = base64ToBytes(bundle.iv);
    if (saltBytes.length !== 16 || ivBytes.length !== 12) throw new Error('Invalid key metadata.');
    const wrappingKey = await derivePrivateKeyWrappingKey(password, saltBytes);
    const privateKeyBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      wrappingKey,
      base64ToBytes(bundle.encryptedPrivateKey),
    );
    recordCryptoEvent('Encrypted private-key bundle unlocked', 'success',
      `PBKDF2-HMAC-SHA-256 (${bundle.iterations.toLocaleString()} iterations) and AES-256-GCM authenticated decryption succeeded. Raw private key is not displayed.`);
    return {
      publicKey: bundle.publicKey,
      privateKey: bytesToBase64(new Uint8Array(privateKeyBytes)),
      storageVersion: PRIVATE_KEY_STORAGE_VERSION,
    };
  } catch {
    recordCryptoEvent('Encrypted private-key bundle unlock rejected', 'failure', 'Password or bundle authentication failed; no private key was returned.');
    throw new Error('Could not unlock the encrypted private key. Check your password or key bundle.');
  }
}

async function readLocalKeys(username, password) {
  const parsed = readLocalKeyBundle(username);
  if (!parsed || typeof parsed.publicKey !== 'string') return null;

  // Backward compatibility: old versions saved the private key as plain Base64 in localStorage.
  if (typeof parsed.privateKey === 'string') {
    return { publicKey: parsed.publicKey, privateKey: parsed.privateKey, storageVersion: 1 };
  }

  if (parsed.version === PRIVATE_KEY_STORAGE_VERSION) return unlockPrivateKeyBundle(parsed, password);
  return null;
}

function localKeyMatches(serverPublicKey, keys) {
  return Boolean(keys && keys.publicKey === serverPublicKey);
}

function showAuth(errorMessage = '', usernameValue = '') {
  state.busy = false;
  root.innerHTML = `
    <main class="auth-layout">
      <section class="auth-card">
        <div class="brand-mark">Q<span>+</span></div>
        <p class="eyebrow">PRIVATE MESSAGING PROTOTYPE</p>
        <h1>QuantumSafe Chat</h1>
        <p class="subhead">A simple messaging app with experimental post-quantum encryption.</p>
        <div class="crypto-note"><span class="dot"></span> ML-KEM-768 + AES-256-GCM in your browser</div>
        <div class="auth-tabs"><button class="tab active" data-mode="login" type="button">Log in</button><button class="tab" data-mode="register" type="button">Create account</button></div>
        ${errorMessage ? `<div class="error-banner" role="alert">${escapeHtml(errorMessage)}</div>` : ''}
        <form id="authForm">
          <label for="username">Username</label>
          <input id="username" name="username" autocomplete="username" minlength="3" maxlength="24" pattern="[A-Za-z0-9_-]{3,24}" placeholder="e.g. alice_01" value="${escapeHtml(usernameValue)}" required />
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" minlength="8" maxlength="200" placeholder="At least 8 characters" required />
          <button id="authSubmit" class="primary-button" type="submit">Log in <span>→</span></button>
        </form>
        <p class="auth-footnote">Demo accounts only. Your ML-KEM private key is encrypted with your password before local storage or server sync. The server stores only the encrypted key bundle. If you lose the password or the bundle, key recovery is not available.</p>
      </section>
      <p class="page-caption">NOT FOR REAL OR SENSITIVE MESSAGES</p>
    </main>`;

  let mode = 'login';
  const form = root.querySelector('#authForm');
  const submitButton = root.querySelector('#authSubmit');
  root.querySelectorAll('[data-mode]').forEach((button) => button.addEventListener('click', () => {
    mode = button.dataset.mode;
    root.querySelectorAll('[data-mode]').forEach((tab) => tab.classList.toggle('active', tab.dataset.mode === mode));
    submitButton.innerHTML = mode === 'login' ? 'Log in <span>→</span>' : 'Create account <span>→</span>';
    root.querySelector('#password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  }));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (state.busy) return;
    const username = form.username.value.trim().toLowerCase();
    const password = form.password.value;
    state.busy = true;
    submitButton.disabled = true;
    submitButton.textContent = mode === 'login' ? 'Logging in…' : 'Generating keys…';
    try {
      let profile;
      let keys;
      if (mode === 'register') {
        // Generate the ML-KEM keypair locally and password-encrypt the private key before upload.
        const keygenStart = performance.now();
        const [publicKeyBytes, privateKeyBytes] = state.kem.generateKeyPair();
        const keygenMs = performance.now() - keygenStart;
        keys = { publicKey: bytesToBase64(publicKeyBytes), privateKey: bytesToBase64(privateKeyBytes) };
        const publicFingerprint = await fingerprintBytes(publicKeyBytes);
        recordCryptoEvent('ML-KEM-768 key pair generated', 'success',
          `Measured ${formatMs(keygenMs)}; public key ${formatBytes(publicKeyBytes.length)}; private key ${formatBytes(privateKeyBytes.length)} (never shown); public-key SHA-256 fingerprint ${publicFingerprint}.`);
        const privateKeyBundle = await createPrivateKeyBundle(keys, password);
        profile = await api('/api/register', {
          method: 'POST',
          body: JSON.stringify({ username, password, kemPublicKey: keys.publicKey, privateKeyBundle }),
        });
        storeLocalKeyBundle(profile.username, privateKeyBundle);
      } else {
        profile = await api('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) });
        if (profile.privateKeyBundle) {
          // Cross-browser login: fetch the password-encrypted key bundle and unlock it locally.
          keys = await unlockPrivateKeyBundle(profile.privateKeyBundle, password);
          if (!localKeyMatches(profile.kemPublicKey, keys)) {
            await api('/api/logout', { method: 'POST' }).catch(() => {});
            throw new Error('The stored private key does not match this account public key.');
          }
          storeLocalKeyBundle(profile.username, profile.privateKeyBundle);
        } else {
          // Legacy account: migrate the key from its original browser into a password-encrypted server bundle.
          keys = await readLocalKeys(profile.username, password);
          if (!localKeyMatches(profile.kemPublicKey, keys)) {
            await api('/api/logout', { method: 'POST' }).catch(() => {});
            throw new Error('This account has not synced its private key yet. Log in once on the original browser to migrate it, then you can use other devices.');
          }
          const privateKeyBundle = await createPrivateKeyBundle(keys, password);
          storeLocalKeyBundle(profile.username, privateKeyBundle);
          await api('/api/me/key-bundle', {
            method: 'POST',
            body: JSON.stringify({ privateKeyBundle }),
          });
        }
      }
      state.latestPrivateKeyBundle = profile.privateKeyBundle ?? readLocalKeyBundle(profile.username);
      await enterChat(profile, { publicKey: keys.publicKey, privateKey: keys.privateKey });
    } catch (error) {
      showAuth(error.message || 'Something went wrong.', username);
    }
  });
}

async function enterChat(profile, keys) {
  if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
  state.reconnectTimer = null;
  state.reconnectAttempts = 0;
  state.me = profile.username;
  state.view = 'chat';
  state.keys = { ...keys, privateKeyBytes: base64ToBytes(keys.privateKey), publicKeyBytes: base64ToBytes(keys.publicKey) };
  state.publicKeyFingerprint = await fingerprintBytes(state.keys.publicKeyBytes);
  recordCryptoEvent('Account cryptographic identity loaded', 'success',
    `Current account public-key SHA-256 fingerprint ${state.publicKeyFingerprint}. The raw private key is unwrapped in browser memory for cryptographic operations and is not displayed.`);
  state.messages = [];
  state.conversations = new Map();
  state.drafts = {};
  state.pendingSends = new Map();
  state.conversationLoadId = 0;
  state.unread = {};
  state.draft = '';
  state.status = 'Loading contacts…';
  const response = await api('/api/users');
  state.users = response.users;
  state.active = state.users[0]?.username ?? null;
  connectSocket();
  renderChat();
  if (state.active) await loadConversation(state.active);
}

function scheduleReconnect() {
  if (!state.me || state.reconnectTimer) return;
  const delay = Math.min(1000 * (2 ** state.reconnectAttempts), 15000);
  state.reconnectAttempts += 1;
  state.status = `Disconnected — reconnecting in ${Math.ceil(delay / 1000)}s`;
  renderChat();
  state.reconnectTimer = setTimeout(() => {
    state.reconnectTimer = null;
    if (state.me) connectSocket();
  }, delay);
}

function connectSocket() {
  if (!state.me) return;
  if (state.socket) {
    const previous = state.socket;
    state.socket = null;
    previous.close();
  }
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${scheme}//${location.host}/ws`);
  state.socket = socket;
  socket.addEventListener('open', () => {
    if (state.socket !== socket || !state.me) return;
    state.reconnectAttempts = 0;
    state.status = 'Connected';
    renderChat();
    refreshUsers().catch(() => {});
    // Re-send unacknowledged packets with the same id; the server treats them idempotently.
    for (const pending of state.pendingSends.values()) {
      try { socket.send(JSON.stringify(pending.packet)); } catch { /* close handler will retry */ }
    }
  });
  socket.addEventListener('close', () => {
    if (state.socket !== socket) return;
    state.socket = null;
    if (state.me) scheduleReconnect();
  });
  socket.addEventListener('error', () => {
    if (state.socket === socket) state.status = 'Connection error — reconnecting…';
  });
  socket.addEventListener('message', async (event) => {
    if (state.socket !== socket) return;
    let packet;
    try { packet = JSON.parse(event.data); } catch { return; }
    if (packet.type === 'ready') {
      state.status = 'Connected';
      refreshUsers().catch(() => {});
      renderChat();
    } else if (packet.type === 'users-changed') {
      refreshUsers().catch(() => {});
    } else if (packet.type === 'error') {
      if (packet.clientMessageId) state.pendingSends.delete(packet.clientMessageId);
      state.status = packet.error || 'Message error';
      renderChat();
    } else if (packet.type === 'sent') {
      await handleWireMessage(packet.message);
      handleSentAcknowledgement(packet.clientMessageId, packet.message);
    } else if (packet.type === 'message') {
      await handleWireMessage(packet.message);
    }
  });
}

async function refreshUsers() {
  const result = await api('/api/users');
  if (!state.me) return;
  state.users = result.users;
  renderChat();
}

async function deriveKeyWithInfo(sharedSecret, saltBytes, info) {
  const material = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function deriveMessageKey(sharedSecret, saltBytes) {
  return deriveKeyWithInfo(sharedSecret, saltBytes, KDF_INFO);
}

async function encryptEnvelope(publicKeyBase64, plaintext, recipientLabel = 'recipient') {
  const totalStart = performance.now();
  const publicKey = base64ToBytes(publicKeyBase64);
  const kemStart = performance.now();
  const [kemCiphertext, sharedSecret] = state.kem.encap(publicKey);
  const encapsulationMs = performance.now() - kemStart;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const kdfStart = performance.now();
  const key = await deriveMessageKey(sharedSecret, salt);
  const kdfMs = performance.now() - kdfStart;
  const plaintextBytes = encoder.encode(plaintext);
  const encryptionStart = performance.now();
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextBytes);
  const encryptionMs = performance.now() - encryptionStart;
  const sharedSecretFingerprint = await fingerprintBytes(sharedSecret);
  const publicKeyFingerprint = await fingerprintBytes(publicKey);
  const envelope = {
    kemCiphertext: bytesToBase64(kemCiphertext),
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
  const record = {
    capturedAt: new Date().toISOString(),
    label: recipientLabel,
    publicKeyFingerprint,
    sharedSecretFingerprint,
    timingsMs: { encapsulation: encapsulationMs, hkdf: kdfMs, aesGcmEncrypt: encryptionMs, total: performance.now() - totalStart },
    sizes: {
      publicKeyBytes: publicKey.length,
      kemCiphertextBytes: kemCiphertext.length,
      saltBytes: salt.length,
      ivBytes: iv.length,
      plaintextBytes: plaintextBytes.length,
      aesGcmCiphertextBytes: ciphertext.byteLength,
      base64EnvelopeBytes: encoder.encode(JSON.stringify(envelope)).length,
    },
    envelope,
  };
  state.recentEnvelopes.unshift(record);
  state.recentEnvelopes = state.recentEnvelopes.slice(0, 10);
  recordCryptoEvent('ML-KEM-768 encapsulation', 'success',
    `Target ${recipientLabel}; public key ${formatBytes(publicKey.length)}; KEM ciphertext ${formatBytes(kemCiphertext.length)}; ${formatMs(encapsulationMs)}; public-key fingerprint ${publicKeyFingerprint}.`);
  recordCryptoEvent('HKDF-SHA-256 message-key derivation', 'success',
    `${formatMs(kdfMs)}; input is the ML-KEM shared secret; salt ${formatBytes(salt.length)}; derived key is AES-256-GCM. Shared-secret diagnostic fingerprint ${sharedSecretFingerprint} (digest only, not the secret).`);
  recordCryptoEvent('AES-256-GCM message encryption', 'success',
    `${formatMs(encryptionMs)}; plaintext ${formatBytes(plaintextBytes.length)}; authenticated ciphertext ${formatBytes(ciphertext.byteLength)} including GCM tag; IV ${formatBytes(iv.length)}; serialized envelope ${formatBytes(record.sizes.base64EnvelopeBytes)}.`);
  return envelope;
}

async function decryptEnvelope(envelope) {
  if (!envelope) throw new Error('Missing encrypted copy for this account.');
  const totalStart = performance.now();
  const kemCiphertext = base64ToBytes(envelope.kemCiphertext);
  const decapStart = performance.now();
  const sharedSecret = state.kem.decap(kemCiphertext, state.keys.privateKeyBytes);
  const decapsulationMs = performance.now() - decapStart;
  const salt = base64ToBytes(envelope.salt);
  const kdfStart = performance.now();
  const key = await deriveMessageKey(sharedSecret, salt);
  const kdfMs = performance.now() - kdfStart;
  const iv = base64ToBytes(envelope.iv);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  const sharedSecretFingerprint = await fingerprintBytes(sharedSecret);
  recordCryptoEvent('ML-KEM-768 decapsulation', 'success',
    `KEM ciphertext ${formatBytes(kemCiphertext.length)}; ${formatMs(decapsulationMs)}; shared-secret diagnostic fingerprint ${sharedSecretFingerprint} (digest only, not the secret).`);
  recordCryptoEvent('HKDF-SHA-256 recipient key derivation', 'success',
    `${formatMs(kdfMs)}; salt ${formatBytes(salt.length)}; derived AES key remains non-extractable in Web Crypto.`);
  const decryptStart = performance.now();
  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    const text = decoder.decode(plaintext);
    const decryptMs = performance.now() - decryptStart;
    recordCryptoEvent('AES-256-GCM authenticated decryption', 'success',
      `${formatMs(decryptMs)}; authenticated ciphertext ${formatBytes(ciphertext.length)}; plaintext ${formatBytes(plaintext.byteLength)}; total receive crypto ${formatMs(performance.now() - totalStart)}.`);
    return text;
  } catch {
    recordCryptoEvent('AES-256-GCM authenticated decryption', 'failure',
      `Authentication/decryption rejected after ${formatMs(performance.now() - decryptStart)}. Ciphertext, IV, key or authentication tag did not validate.`);
    throw new Error('AES-GCM authentication failed.');
  }
}

function cacheConversationMessage(username, message) {
  const existing = state.conversations.get(username) ?? [];
  const index = existing.findIndex((item) => item.id === message.id);
  if (index >= 0) {
    // Prefer a successfully decrypted version over an earlier transient decrypt error.
    if (existing[index].decryptError && !message.decryptError) existing[index] = message;
  } else {
    existing.push(message);
  }
  existing.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  state.conversations.set(username, existing);
  if (state.active === username) state.messages = existing;
}

async function handleWireMessage(message) {
  if (!message || !message.id || !state.me) return;
  const other = message.sender === state.me ? message.recipient : message.sender;
  recordCryptoEvent('Encrypted message envelope received', 'info',
    `Conversation with ${other}; server record ${String(message.id).slice(0, 12)}; serialized envelope metadata received over WebSocket. Decryption happens in this browser.`);
  let decoded;
  try {
    const text = await decryptEnvelope(message.envelopes?.[state.me]);
    decoded = { ...message, text, decryptError: false };
  } catch {
    decoded = { ...message, text: 'Could not decrypt this message. The local key may not match.', decryptError: true };
  }
  // Cache by conversation, even if the user switched chats while decryption was running.
  cacheConversationMessage(other, decoded);
  if (other !== state.active) {
    if (message.sender !== state.me) state.unread[other] = (state.unread[other] || 0) + 1;
    renderChat();
    return;
  }
  state.unread[other] = 0;
  state.messages = state.conversations.get(other) ?? [];
  renderMessages();
}

function handleSentAcknowledgement(clientMessageId, message) {
  const pending = state.pendingSends.get(clientMessageId);
  if (!pending) return;
  state.pendingSends.delete(clientMessageId);
  const savedDraft = state.drafts[pending.recipient] ?? '';
  if (savedDraft === pending.draftSnapshot) state.drafts[pending.recipient] = '';
  if (state.active === pending.recipient && state.draft === pending.draftSnapshot) {
    state.draft = '';
  }
  state.status = 'Message saved and relayed';
  recordCryptoEvent('Server acknowledged encrypted message', 'success', `Client message ID ${String(clientMessageId).slice(0, 8)}…; saved record ${message?.id ?? 'identifier unavailable'}; message body remains in encrypted envelopes.`);
  renderChat();
}

async function loadConversation(username) {
  if (state.active) state.drafts[state.active] = state.draft;
  state.active = username;
  state.unread[username] = 0;
  state.draft = state.drafts[username] ?? '';
  state.messages = state.conversations.get(username) ?? [];
  const loadId = ++state.conversationLoadId;
  renderChat();
  if (!username) return;
  try {
    const result = await api(`/api/messages?with=${encodeURIComponent(username)}`);
    const fetchedMessages = [];
    for (const message of result.messages) {
      try {
        const text = await decryptEnvelope(message.envelopes?.[state.me]);
        fetchedMessages.push({ ...message, text, decryptError: false });
      } catch {
        fetchedMessages.push({ ...message, text: 'Could not decrypt this message. The local key may not match.', decryptError: true });
      }
    }
    // Merge history with messages delivered live during the request, deduplicating by server message ID.
    const liveMessages = state.conversations.get(username) ?? [];
    const merged = new Map(fetchedMessages.map((message) => [message.id, message]));
    for (const message of liveMessages) {
      const previous = merged.get(message.id);
      if (!previous || (previous.decryptError && !message.decryptError)) merged.set(message.id, message);
    }
    const ordered = [...merged.values()].sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    state.conversations.set(username, ordered);
    if (state.active === username && state.conversationLoadId === loadId) {
      state.messages = ordered;
      renderChat();
    }
  } catch (error) {
    if (state.active === username && state.conversationLoadId === loadId) {
      state.status = error.message;
      renderChat();
    }
  }
}

async function sendMessage() {
  const draftSnapshot = state.draft;
  const text = draftSnapshot.trim();
  const recipientName = state.active;
  if (!text || !recipientName) return;
  if (text.length > 2000) {
    state.status = 'Messages are limited to 2,000 characters.';
    renderChat();
    return;
  }
  const recipient = state.users.find((user) => user.username === recipientName);
  if (!recipient) return;
  if ([...state.pendingSends.values()].some((pending) => pending.recipient === recipientName && pending.draftSnapshot === draftSnapshot)) return;
  const button = root.querySelector('#sendButton');
  if (button) button.disabled = true;
  state.status = 'Encrypting in browser…';
  try {
    // Fresh ML-KEM encapsulation and a fresh AES-GCM key for each recipient/sender copy.
    const [recipientEnvelope, senderEnvelope] = await Promise.all([
      encryptEnvelope(recipient.kemPublicKey, text, recipient.username),
      encryptEnvelope(state.keys.publicKey, text, `${state.me} (sent history copy)`),
    ]);
    const clientMessageId = crypto.randomUUID();
    const packet = {
      type: 'send',
      clientMessageId,
      to: recipient.username,
      envelopes: { [recipient.username]: recipientEnvelope, [state.me]: senderEnvelope },
    };
    state.pendingSends.set(clientMessageId, {
      text, recipient: recipient.username, draftSnapshot, packet,
    });
    state.status = 'Waiting for server confirmation…';
    const serializedPacket = JSON.stringify(packet);
    recordCryptoEvent('Encrypted envelope submitted to relay', 'info',
      `Client message ID ${clientMessageId.slice(0, 8)}…; packet size ${formatBytes(encoder.encode(serializedPacket).length)}; recipient and sender-history copies are encrypted separately; plaintext is not included in the packet.`);
    if (state.socket?.readyState === WebSocket.OPEN) {
      state.socket.send(serializedPacket);
    } else {
      scheduleReconnect();
    }
    // Keep the draft until the server confirms persistence; an acknowledgement clears only the exact sent draft.
    renderChat();
  } catch (error) {
    state.status = `Could not encrypt/send: ${error.message}`;
    renderChat();
  } finally {
    const currentButton = root.querySelector('#sendButton');
    if (currentButton) currentButton.disabled = false;
  }
}

function formatTime(value) {
  try {
    return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(new Date(value));
  } catch { return ''; }
}

function renderMessages() {
  const list = root.querySelector('#messageList');
  if (!list) return;
  if (!state.active) {
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">✳</div><h3>No conversations yet</h3><p>Create another account in a second browser or private window to test messaging.</p></div>';
    return;
  }
  if (state.messages.length === 0) {
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">↗</div><h3>Start a conversation</h3><p>Your messages are encrypted in this browser before the server receives them.</p></div>';
    return;
  }
  list.innerHTML = state.messages.map((message) => {
    const mine = message.sender === state.me;
    const who = mine ? 'You' : message.sender;
    const className = `${mine ? 'mine' : 'theirs'}${message.decryptError ? ' decrypt-error' : ''}`;
    return `<article class="message-row ${className}"><div class="message-meta"><span>${escapeHtml(who)}</span><time>${escapeHtml(formatTime(message.createdAt))}</time></div><div class="bubble">${escapeHtml(message.text ?? 'Decrypting…')}</div></article>`;
  }).join('');
  list.scrollTop = list.scrollHeight;
}

function renderChatWorkspace() {
  const activeUser = state.users.find((user) => user.username === state.active);
  return `
    <main class="workspace">
      <aside class="sidebar">
        <div class="sidebar-heading"><div><p class="eyebrow">YOUR SPACE</p><h2>Messages</h2></div><span class="count-pill">${state.users.length}</span></div>
        <div class="contact-list">
          ${state.users.length ? state.users.map((user) => `
            <button class="contact ${user.username === state.active ? 'selected' : ''}" data-user="${escapeHtml(user.username)}" type="button">
              <span class="contact-avatar avatar-${Math.abs([...user.username].reduce((acc, char) => acc + char.charCodeAt(0), 0)) % 5}">${escapeHtml(user.username.slice(0, 1).toUpperCase())}</span>
              <span class="contact-copy"><strong>${escapeHtml(user.username)}</strong><small><i class="presence ${user.online ? 'online' : ''}"></i>${user.online ? 'Online' : 'Offline'}</small></span>
              ${state.unread[user.username] ? `<span class="unread-count">${state.unread[user.username]}</span>` : ''}
            </button>`).join('') : '<div class="sidebar-empty">No other accounts yet.<br/><br/>Open another browser and create a second account.</div>'}
        </div>
        <div class="sidebar-footer"><span class="shield-icon">⌑</span><div><strong>Client-side encryption</strong><small>Server relays ciphertext envelopes</small></div></div>
      </aside>
      <section class="chat-panel">
        <div class="conversation-header">
          <div class="conversation-person">${activeUser ? `<span class="contact-avatar large">${escapeHtml(activeUser.username.slice(0, 1).toUpperCase())}</span><div><h2>${escapeHtml(activeUser.username)}</h2><p><span class="presence ${activeUser.online ? 'online' : ''}"></span>${activeUser.online ? 'Available now' : 'Not connected'}</p></div>` : `<div><h2>Select a conversation</h2><p>Create two accounts to test the prototype</p></div>`}</div>
          <div class="crypto-badge"><span>⌁</span><div><strong>ML-KEM-768</strong><small>KEY ENCAPSULATION</small></div></div>
        </div>
        <div class="privacy-banner"><span class="lock-glyph">▣</span><p><strong>Experimental encryption enabled</strong><span>ML-KEM-768 establishes a shared secret for each message copy, then HKDF and AES-GCM protect the content. Identity authentication and forward secrecy remain Phase 2 work.</span></p></div>
        <div id="messageList" class="message-list"></div>
        <form id="composer" class="composer">
          <div class="composer-top"><span class="composer-lock">⌑</span><span>Plaintext stays in this browser before encryption</span><span class="char-count">${state.draft.length}/2000</span></div>
          <div class="composer-row"><textarea id="messageInput" maxlength="2000" rows="1" placeholder="Write an encrypted message…" ${activeUser ? '' : 'disabled'}></textarea><button id="sendButton" class="send-button" type="submit" aria-label="Send message" ${activeUser ? '' : 'disabled'}><span>Send</span><b>↑</b></button></div>
        </form>
      </section>
    </main>`;
}

function renderTraceView() {
  const bundle = state.latestPrivateKeyBundle;
  const bundleValid = bundle && typeof bundle.encryptedPrivateKey === 'string';
  const bundleMarkup = bundleValid ? `
    <div class="panel-card">
      <div class="panel-heading"><div><p class="eyebrow">KEY STORAGE EVIDENCE</p><h2>Password-encrypted private-key bundle</h2></div><span class="status-tag">ENCRYPTED AT REST</span></div>
      <div class="metric-grid">
        <div class="metric-card"><span>Key derivation</span><strong>${escapeHtml(bundle.kdf)}</strong><small>${Number(bundle.iterations).toLocaleString()} iterations</small></div>
        <div class="metric-card"><span>Salt / IV</span><strong>${escapeHtml(formatBytes(base64ToBytes(bundle.salt).length))} / ${escapeHtml(formatBytes(base64ToBytes(bundle.iv).length))}</strong><small>Generated for this bundle</small></div>
        <div class="metric-card"><span>Encrypted private key</span><strong>${escapeHtml(formatBytes(base64ToBytes(bundle.encryptedPrivateKey).length))}</strong><small>Raw private key is not displayed</small></div>
        <div class="metric-card"><span>Public-key fingerprint</span><strong>${escapeHtml(state.publicKeyFingerprint || 'Available after login')}</strong><small>SHA-256 prefix, 96 bits shown</small></div>
      </div>
      <details class="public-key-details"><summary>Inspect the actual encrypted private-key bundle (sensitive ciphertext preview)</summary>
        <pre>${escapeHtml(JSON.stringify({version: bundle.version, kdf: bundle.kdf, iterations: bundle.iterations, salt: bundle.salt, iv: bundle.iv, encryptedPrivateKeyPreview: `${bundle.encryptedPrivateKey.slice(0, 180)}…`, publicKeyBase64Preview: `${String(bundle.publicKey || '').slice(0, 100)}…`}, null, 2))}</pre>
        <p class="panel-note">The raw private key and password-derived wrapping key are never rendered. This preview is encrypted key material; use test accounts only during evaluation.</p>
      </details>
    </div>` : `
    <div class="panel-card warning-card"><div class="empty-lab"><div class="empty-lab-icon">⌁</div><h3>No encrypted key bundle available to inspect</h3><p>Log in with an account that has a password-encrypted key bundle. Older accounts may require one-time migration from their original browser.</p></div></div>`;
  const publicKeyMarkup = state.keys ? `
    <div class="panel-card fingerprint-card">
      <div class="panel-heading"><div><p class="eyebrow">LIVE ACCOUNT KEY</p><h2>ML-KEM-768 public key</h2></div><span class="status-tag">PUBLIC MATERIAL</span></div>
      <strong class="fingerprint-value">SHA-256: ${escapeHtml(state.publicKeyFingerprint || 'calculating…')}</strong>
      <p class="panel-note">Observed public key length: ${escapeHtml(formatBytes(state.keys.publicKeyBytes.length))}. The private key is required locally for decapsulation but is never displayed by this inspector.</p>
      <details class="public-key-details"><summary>Show public-key Base64 preview</summary><pre>${escapeHtml(`${state.keys.publicKey.slice(0, 220)}…`)}</pre></details>
    </div>` : '';
  const envelopeMarkup = state.recentEnvelopes.length ? state.recentEnvelopes.slice(0, 6).map((entry, index) => `
    <details class="public-key-details envelope-details" ${index === 0 ? 'open' : ''}>
      <summary>${escapeHtml(entry.label)} · ${escapeHtml(entry.capturedAt)} · KEM ${escapeHtml(formatBytes(entry.sizes.kemCiphertextBytes))} · AES ciphertext ${escapeHtml(formatBytes(entry.sizes.aesGcmCiphertextBytes))}</summary>
      <div class="metric-grid compact-grid">
        <div class="metric-card"><span>Encapsulation</span><strong>${escapeHtml(formatMs(entry.timingsMs.encapsulation))}</strong></div>
        <div class="metric-card"><span>HKDF</span><strong>${escapeHtml(formatMs(entry.timingsMs.hkdf))}</strong></div>
        <div class="metric-card"><span>AES-GCM encrypt</span><strong>${escapeHtml(formatMs(entry.timingsMs.aesGcmEncrypt))}</strong></div>
        <div class="metric-card"><span>Envelope JSON bytes</span><strong>${escapeHtml(formatBytes(entry.sizes.base64EnvelopeBytes))}</strong></div>
      </div>
      <p class="panel-note">Recipient public-key fingerprint: ${escapeHtml(entry.publicKeyFingerprint)} · shared-secret digest only: ${escapeHtml(entry.sharedSecretFingerprint)}</p>
      <pre>${escapeHtml(JSON.stringify(entry.envelope, null, 2))}</pre>
      <p class="panel-note">This is the actual serialized cryptographic envelope from a recent send, not a sample. It contains KEM ciphertext, salt, IV and AES-GCM ciphertext; it does not contain plaintext or the shared secret.</p>
    </details>`).join('') : '<div class="event-empty">Send a message in the Messages tab to capture a real encrypted envelope.</div>';
  const eventMarkup = state.cryptoEvents.length ? state.cryptoEvents.slice(0, 60).map((event) => `
    <div class="event-row"><time>${escapeHtml(new Date(event.at).toLocaleTimeString())}</time><i class="event-indicator ${event.outcome === 'failure' ? 'failure' : event.outcome === 'info' ? 'info' : ''}"></i><div class="event-copy"><strong>${escapeHtml(event.title)}</strong><p>${escapeHtml(event.details)}</p></div><span class="event-status ${event.outcome === 'failure' ? 'failure' : event.outcome === 'info' ? 'info' : ''}">${escapeHtml(event.outcome)}</span></div>`).join('') : '<div class="event-empty">No cryptographic events yet. Register or send a message to populate this timeline.</div>';
  return `
    <main class="tool-page">
      <div class="tool-heading"><div><p class="eyebrow">LIVE CRYPTOGRAPHIC OBSERVABILITY</p><h1>Crypto Trace</h1><p>Inspect actual key metadata, encrypted key storage, message envelopes, operation timings, and receive-side decryption. Secret key material and plaintext are intentionally excluded.</p></div><div class="heading-actions"><button class="secondary-button" data-action="clear-trace" type="button">Clear timeline</button><button class="primary-button" data-action="export-report" type="button">Export report ↗</button></div></div>
      <div class="note-grid"><div class="note-card"><span class="note-kicker">01 / KEY ESTABLISHMENT</span><h3>ML-KEM-768</h3><p>Key generation, encapsulation and decapsulation are recorded from live browser operations. Standard reference sizes are separate from measured timings.</p></div><div class="note-card"><span class="note-kicker">02 / KEY DERIVATION</span><h3>HKDF-SHA-256</h3><p>The 32-byte ML-KEM shared secret becomes input key material. The inspector shows only a short SHA-256 diagnostic digest—not the secret.</p></div><div class="note-card"><span class="note-kicker">03 / MESSAGE PROTECTION</span><h3>AES-256-GCM</h3><p>Each envelope shows its random IV, salt, byte sizes and actual Base64 ciphertext for reproducible inspection.</p></div></div>
      ${publicKeyMarkup}
      ${bundleMarkup}
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">REAL WIRE FORMAT</p><h2>Recent encrypted envelopes</h2></div><span class="status-tag">${state.recentEnvelopes.length} CAPTURED</span></div>${envelopeMarkup}</div>
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">EVENT TIMELINE</p><h2>Cryptographic operations</h2></div><span class="status-tag">${state.cryptoEvents.length} EVENTS</span></div><div class="event-list">${eventMarkup}</div></div>
      <p class="disclaimer-line">This trace is an educational observability aid, not a formal audit. Public-key fingerprints and shared-secret digests are diagnostic values. Do not export or share test-account data without reviewing it first.</p>
    </main>`;
}

function percentile(sorted, percent) {
  if (!sorted.length) return null;
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(percent * sorted.length) - 1))];
}

function summarizeSamples(samples) {
  const valid = samples.filter(Number.isFinite);
  if (!valid.length) return { n: 0, mean: null, median: null, p95: null, standardDeviation: null };
  const sorted = [...valid].sort((a, b) => a - b);
  const mean = valid.reduce((sum, value) => sum + value, 0) / valid.length;
  const variance = valid.reduce((sum, value) => sum + ((value - mean) ** 2), 0) / valid.length;
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  return { n: valid.length, mean, median, p95: percentile(sorted, 0.95), standardDeviation: Math.sqrt(variance) };
}

const BENCHMARK_METRICS = [
  ['kemKeygen', 'ML-KEM-768 key generation', 'ms'],
  ['kemEncap', 'ML-KEM-768 encapsulation', 'ms'],
  ['kemDecap', 'ML-KEM-768 decapsulation', 'ms'],
  ['kemExchange', 'ML-KEM exchange (encap + decap)', 'ms'],
  ['xKeygen', 'X25519 ephemeral key generation', 'ms'],
  ['xExport', 'X25519 public-key export', 'ms'],
  ['xDeriveBoth', 'X25519 shared-secret derivation (both sides)', 'ms'],
  ['xExchange', 'X25519 exchange (keygen + export + both derives)', 'ms'],
  ['kemKdf', 'HKDF-SHA-256 using ML-KEM secret (both peers)', 'ms'],
  ['xKdf', 'HKDF-SHA-256 using X25519 secret (both peers)', 'ms'],
  ['kemEncrypt', 'AES-256-GCM encrypt, 1 KiB payload (ML-KEM path)', 'ms'],
  ['xEncrypt', 'AES-256-GCM encrypt, 1 KiB payload (X25519 path)', 'ms'],
  ['kemDecrypt', 'AES-256-GCM decrypt, 1 KiB payload (ML-KEM path)', 'ms'],
  ['xDecrypt', 'AES-256-GCM decrypt, 1 KiB payload (X25519 path)', 'ms'],
];

function renderBenchmarkView() {
  const result = state.benchmarkResult;
  const summaries = result ? BENCHMARK_METRICS.map(([key, label, unit]) => ({ key, label, unit, stats: summarizeSamples(result.metrics[key] ?? []) })) : [];
  const table = result ? `
    <div class="table-wrap"><table class="results-table"><thead><tr><th>Operation</th><th>N</th><th>Mean</th><th>Median</th><th>P95</th><th>Std dev</th></tr></thead><tbody>
      ${summaries.map(({key, label, unit, stats}) => `<tr><td>${escapeHtml(label)}${key.startsWith('x') && !result.x25519Supported ? '<br/><small>X25519 not supported</small>' : ''}</td><td>${stats.n}</td><td class="mono-cell">${stats.n ? escapeHtml(formatMs(stats.mean)) : '—'}</td><td class="mono-cell">${stats.n ? escapeHtml(formatMs(stats.median)) : '—'}</td><td class="mono-cell">${stats.n ? escapeHtml(formatMs(stats.p95)) : '—'}</td><td class="mono-cell">${stats.n ? escapeHtml(formatMs(stats.standardDeviation)) : '—'}</td></tr>`).join('')}
    </tbody></table></div>` : '<div class="empty-lab"><div class="empty-lab-icon">↗</div><h3>No benchmark results yet</h3><p>Run the benchmark on this device. Results will be measured live; the application does not preload or fabricate performance numbers.</p></div>';
  const kemMedian = result ? summarizeSamples(result.metrics.kemExchange).median : null;
  const xMedian = result?.x25519Supported ? summarizeSamples(result.metrics.xExchange).median : null;
  const chartMax = Math.max(kemMedian || 0, xMedian || 0, 0.001);
  const chart = result ? `<div class="chart-list"><div class="chart-row"><div class="chart-label"><span>ML-KEM-768 encapsulation + decapsulation</span><strong>${kemMedian == null ? '—' : escapeHtml(formatMs(kemMedian))}</strong></div><progress class="research-progress chart-progress" max="100" value="${Math.max(kemMedian ? 1 : 0, (kemMedian || 0) / chartMax * 100)}">${Math.max(kemMedian ? 1 : 0, (kemMedian || 0) / chartMax * 100)}%</progress></div><div class="chart-row"><div class="chart-label"><span>X25519 ephemeral key setup + ECDH both sides</span><strong>${xMedian == null ? (result.x25519Supported ? '—' : 'Not supported') : escapeHtml(formatMs(xMedian))}</strong></div><progress class="research-progress chart-progress classical-progress" max="100" value="${xMedian == null ? 0 : Math.max(1, xMedian / chartMax * 100)}">${xMedian == null ? 0 : Math.max(1, xMedian / chartMax * 100)}%</progress></div></div>` : '';
  const sizeCards = result ? `
    <div class="metric-grid"><div class="metric-card"><span>ML-KEM public key (observed)</span><strong>${escapeHtml(formatBytes(result.sizes.kemPublicKeyBytes))}</strong><small>Actual generated byte array length</small></div><div class="metric-card"><span>ML-KEM ciphertext (observed)</span><strong>${escapeHtml(formatBytes(result.sizes.kemCiphertextBytes))}</strong><small>Base64 field: ${escapeHtml(formatBytes(result.sizes.kemCiphertextBase64Bytes))}</small></div><div class="metric-card"><span>X25519 ephemeral public key</span><strong>${result.x25519Supported ? escapeHtml(formatBytes(result.sizes.xPublicKeyBytes)) : 'Not supported'}</strong><small>${result.x25519Supported ? `Base64 field: ${formatBytes(result.sizes.xEncodedPublicKeyBytes)}` : escapeHtml(result.x25519Error || 'Unavailable in this browser')}</small></div><div class="metric-card"><span>Mean serialized 1 KiB envelope</span><strong>ML-KEM ${escapeHtml(formatBytes(result.sizes.kemEnvelopeJsonBytes))}</strong><small>X25519 ${result.x25519Supported ? escapeHtml(formatBytes(result.sizes.xEnvelopeJsonBytes)) : 'not supported'} · JSON/Base64, excludes chat metadata</small></div></div>` : '';
  return `
    <main class="tool-page">
      <div class="tool-heading"><div><p class="eyebrow">REPRODUCIBLE CLIENT-SIDE EXPERIMENT</p><h1>Benchmark Lab</h1><p>Compare ML-KEM-768 against an X25519 ECDH baseline on this browser and device. The same HKDF and AES-GCM code is used after key establishment. Your actual measurements may show the PQC path is slower or larger; that is a valid result.</p></div><div class="heading-actions"><label class="sample-control">Samples <input id="benchmarkIterations" type="number" min="20" max="500" step="10" value="${result?.sampleCount ?? 100}" ${state.benchmarkRunning ? 'disabled' : ''}></label><button id="runBenchmarks" class="primary-button" type="button" ${state.benchmarkRunning ? 'disabled' : ''}>${state.benchmarkRunning ? 'Running…' : 'Run benchmark ↗'}</button>${result ? '<button class="secondary-button" data-action="download-benchmark-csv" type="button">Download raw CSV</button>' : ''}<button class="secondary-button" data-action="export-report" type="button">Export report</button></div></div>
      <div class="note-grid"><div class="note-card"><span class="note-kicker">POST-QUANTUM</span><h3>ML-KEM-768</h3><p>Encapsulation produces KEM ciphertext and shared-secret material; recipient decapsulation reproduces that secret.</p></div><div class="note-card"><span class="note-kicker">CLASSICAL BASELINE</span><h3>X25519 ECDH</h3><p>Each sample generates an ephemeral key pair and derives shared bits on both sides against a fixed recipient key pair. Unsupported browsers are reported as unsupported.</p></div><div class="note-card"><span class="note-kicker">FAIR COMPARISON</span><h3>Same environment</h3><p>Runs in the same browser tab, payload, device and timing API. The cryptographic operation scope is labelled; this is not a universal performance claim.</p></div></div>
      ${state.benchmarkRunning ? `<div class="panel-card"><div class="benchmark-progress"><div class="spinner"></div><div><strong id="benchmarkProgressText">Running ${state.benchmarkProgress}%</strong><p>Executing real cryptographic operations; this may take a short while.</p><progress id="benchmarkProgressBar" class="research-progress progress-track" max="100" value="${state.benchmarkProgress}">${state.benchmarkProgress}%</progress></div></div></div>` : ''}
      ${result ? `<div class="benchmark-summary"><div><span>Samples per operation</span><strong>${result.sampleCount}</strong></div><div><span>Warm-up samples</span><strong>${result.warmupCount}</strong></div><div><span>Payload</span><strong>${formatBytes(result.payloadBytes)}</strong></div><div><span>Completed at</span><strong>${escapeHtml(new Date(result.completedAt).toLocaleString())}</strong></div><div><span>X25519 support</span><strong>${result.x25519Supported ? 'Available' : 'Not available'}</strong></div></div>` : ''}
      ${sizeCards}
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">KEY ESTABLISHMENT COMPARISON</p><h2>Median per-message exchange time</h2></div><span class="status-tag">LIVE RESULTS</span></div>${chart || '<div class="event-empty">Run the benchmark to generate measured results.</div>'}<p class="panel-note">ML-KEM exchange is measured as encapsulation + decapsulation. The X25519 baseline is ephemeral key generation + public-key export + shared-secret derivation at both peers. HKDF timings include deriving both sender and receiver AES keys. Network latency is excluded. These are intentionally described as different operation scopes.</p></div>
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">STATISTICAL SUMMARY</p><h2>Measurements per operation</h2></div><span class="status-tag">MEAN / MEDIAN / P95 / SD</span></div>${table}</div>
      ${result?.x25519Error ? `<div class="panel-card warning-card"><strong>X25519 baseline unavailable in this browser</strong><p class="panel-note">${escapeHtml(result.x25519Error)} No X25519 timings have been invented or substituted.</p></div>` : ''}
      <p class="disclaimer-line">Results are device/browser-specific. Raw samples include timing values and byte lengths only, never keys, shared secrets or plaintext. For a report, record OS, browser version, source revision, and run the experiment more than once.</p>
    </main>`;
}

async function runBenchmarks() {
  if (state.benchmarkRunning) return;
  const input = root.querySelector('#benchmarkIterations');
  const sampleCount = Math.max(20, Math.min(500, Math.trunc(Number(input?.value) || 100)));
  const warmupCount = 10;
  const payloadBytes = 1024;
  const startedAt = new Date().toISOString();
  const payload = crypto.getRandomValues(new Uint8Array(payloadBytes));
  const metrics = Object.fromEntries(BENCHMARK_METRICS.map(([key]) => [key, []]));
  const rawRows = [];
  let x25519Supported = true;
  let x25519Error = '';
  let kemRecipient;
  let xRecipient;
  let sizes = { kemPublicKeyBytes: null, kemPrivateKeyBytes: null, kemCiphertextBytes: null, xPublicKeyBytes: null, xEncodedPublicKeyBytes: null };
  state.benchmarkRunning = true;
  state.benchmarkProgress = 0;
  state.benchmarkResult = null;
  renderChat();
  await new Promise((resolve) => requestAnimationFrame(resolve));
  try {
    kemRecipient = state.kem.generateKeyPair();
    sizes.kemPublicKeyBytes = kemRecipient[0].length;
    sizes.kemPrivateKeyBytes = kemRecipient[1].length;
    try {
      xRecipient = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
      const rawRecipientPublic = new Uint8Array(await crypto.subtle.exportKey('raw', xRecipient.publicKey));
      sizes.xPublicKeyBytes = rawRecipientPublic.length;
    } catch (error) {
      x25519Supported = false;
      x25519Error = error?.message || 'This browser does not support Web Crypto X25519 key generation/derivation.';
    }
    for (let i = 0; i < warmupCount + sampleCount; i += 1) {
      const row = { sample: i - warmupCount + 1, payloadBytes, x25519Supported };
      let started = performance.now();
      state.kem.generateKeyPair();
      const kemKeygenMs = performance.now() - started;
      started = performance.now();
      const [kemCt, kemSecretSender] = state.kem.encap(kemRecipient[0]);
      const kemEncapMs = performance.now() - started;
      started = performance.now();
      const kemSecretRecipient = state.kem.decap(kemCt, kemRecipient[1]);
      const kemDecapMs = performance.now() - started;
      if (!bytesEqual(kemSecretSender, kemSecretRecipient)) throw new Error('ML-KEM sender and recipient shared secrets differed during benchmarking.');
      sizes.kemCiphertextBytes = kemCt.length;
      sizes.kemCiphertextBase64Bytes = encoder.encode(bytesToBase64(kemCt)).length;
      row.kemKeygenMs = kemKeygenMs;
      row.kemEncapMs = kemEncapMs;
      row.kemDecapMs = kemDecapMs;
      row.kemExchangeMs = kemEncapMs + kemDecapMs;
      row.kemCiphertextBytes = kemCt.length;
      row.kemPublicKeyBytes = kemRecipient[0].length;
      started = performance.now();
      const kemSalt = crypto.getRandomValues(new Uint8Array(16));
      const kemSenderKey = await deriveMessageKey(kemSecretSender, kemSalt);
      const kemReceiverKey = await deriveMessageKey(kemSecretRecipient, kemSalt);
      row.kemKdfMs = performance.now() - started;
      const kemIv = crypto.getRandomValues(new Uint8Array(12));
      started = performance.now();
      const kemCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: kemIv }, kemSenderKey, payload);
      row.kemEncryptMs = performance.now() - started;
      started = performance.now();
      const kemPlaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: kemIv }, kemReceiverKey, kemCiphertext));
      row.kemDecryptMs = performance.now() - started;
      row.kemSharedSecretMatch = true;
      row.kemEnvelopeJsonBytes = encoder.encode(JSON.stringify({
        kemCiphertext: bytesToBase64(kemCt),
        salt: bytesToBase64(kemSalt),
        iv: bytesToBase64(kemIv),
        ciphertext: bytesToBase64(new Uint8Array(kemCiphertext)),
      })).length;
      if (!bytesEqual(kemPlaintext, payload)) throw new Error('ML-KEM-path AES-GCM benchmark round trip did not match the payload.');

      if (x25519Supported) {
        started = performance.now();
        const xEphemeral = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        const xKeygenMs = performance.now() - started;
        started = performance.now();
        const ephemeralRaw = new Uint8Array(await crypto.subtle.exportKey('raw', xEphemeral.publicKey));
        const xExportMs = performance.now() - started;
        sizes.xPublicKeyBytes = ephemeralRaw.length;
        sizes.xEncodedPublicKeyBytes = encoder.encode(bytesToBase64(ephemeralRaw)).length;
        started = performance.now();
        const xSecretSender = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: xRecipient.publicKey }, xEphemeral.privateKey, 256));
        const xSenderDeriveMs = performance.now() - started;
        started = performance.now();
        const xSecretRecipient = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: xEphemeral.publicKey }, xRecipient.privateKey, 256));
        const xRecipientDeriveMs = performance.now() - started;
        if (!bytesEqual(xSecretSender, xSecretRecipient)) throw new Error('X25519 sender and recipient shared secrets differed during benchmarking.');
        row.xKeygenMs = xKeygenMs;
        row.xExportMs = xExportMs;
        row.xDeriveBothMs = xSenderDeriveMs + xRecipientDeriveMs;
        row.xExchangeMs = xKeygenMs + xExportMs + xSenderDeriveMs + xRecipientDeriveMs;
        row.xPublicKeyBytes = ephemeralRaw.length;
        row.xEncodedPublicKeyBytes = sizes.xEncodedPublicKeyBytes;
        started = performance.now();
        const xSalt = crypto.getRandomValues(new Uint8Array(16));
        const xSenderKey = await deriveKeyWithInfo(xSecretSender, xSalt, X25519_BENCHMARK_INFO);
        const xReceiverKey = await deriveKeyWithInfo(xSecretRecipient, xSalt, X25519_BENCHMARK_INFO);
        row.xKdfMs = performance.now() - started;
        const xIv = crypto.getRandomValues(new Uint8Array(12));
        started = performance.now();
        const xCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: xIv }, xSenderKey, payload);
        row.xEncryptMs = performance.now() - started;
        started = performance.now();
        const xPlaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: xIv }, xReceiverKey, xCiphertext));
        row.xDecryptMs = performance.now() - started;
        row.xSharedSecretMatch = true;
        row.xEnvelopeJsonBytes = encoder.encode(JSON.stringify({
          ephemeralPublicKey: bytesToBase64(ephemeralRaw),
          salt: bytesToBase64(xSalt),
          iv: bytesToBase64(xIv),
          ciphertext: bytesToBase64(new Uint8Array(xCiphertext)),
        })).length;
        if (!bytesEqual(xPlaintext, payload)) throw new Error('X25519-path AES-GCM benchmark round trip did not match the payload.');
      }
      if (i >= warmupCount) rawRows.push(row);
      if ((i + 1) % 5 === 0 || i === warmupCount + sampleCount - 1) {
        const completed = Math.min(sampleCount, Math.max(0, i + 1 - warmupCount));
        state.benchmarkProgress = Math.round((completed / sampleCount) * 100);
        const progressText = root.querySelector('#benchmarkProgressText');
        const progressBar = root.querySelector('#benchmarkProgressBar');
        if (progressText) progressText.textContent = `Running ${state.benchmarkProgress}% (${completed}/${sampleCount} measured samples)`;
        if (progressBar) progressBar.value = state.benchmarkProgress;
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
    for (const row of rawRows) {
      for (const [metricKey, rowKey] of Object.entries({
        kemKeygen: 'kemKeygenMs', kemEncap: 'kemEncapMs', kemDecap: 'kemDecapMs', kemExchange: 'kemExchangeMs',
        xKeygen: 'xKeygenMs', xExport: 'xExportMs', xDeriveBoth: 'xDeriveBothMs', xExchange: 'xExchangeMs',
        kemKdf: 'kemKdfMs', xKdf: 'xKdfMs', kemEncrypt: 'kemEncryptMs', xEncrypt: 'xEncryptMs', kemDecrypt: 'kemDecryptMs', xDecrypt: 'xDecryptMs',
      })) {
        if (Number.isFinite(row[rowKey])) metrics[metricKey].push(row[rowKey]);
      }
    }
    const meanByteSize = (key) => {
      const values = rawRows.map((row) => row[key]).filter(Number.isFinite);
      return values.length ? Math.round(values.reduce((sum, value) => sum + value, 0) / values.length) : null;
    };
    sizes.kemEnvelopeJsonBytes = meanByteSize('kemEnvelopeJsonBytes');
    sizes.xEnvelopeJsonBytes = x25519Supported ? meanByteSize('xEnvelopeJsonBytes') : null;
    state.benchmarkResult = {
      createdAt: startedAt, completedAt: new Date().toISOString(), sampleCount, warmupCount,
      payloadBytes, x25519Supported, x25519Error, sizes, metrics, rawRows,
      methodology: 'Browser-local measurements; no network time. ML-KEM exchange = encapsulation + decapsulation. X25519 exchange = ephemeral key generation + raw public-key export + ECDH deriveBits at both peers. HKDF timings include deriving both sender and receiver AES keys. Serialized envelope size includes JSON fields plus Base64 key-establishment data, salt, IV and AES-GCM ciphertext, but excludes chat metadata and WebSocket/HTTP framing. Network latency is excluded.',
      browser: navigator.userAgent,
      sourceRevision: import.meta.env?.VITE_GIT_COMMIT || 'not embedded in this build',
    };
    recordCryptoEvent('Benchmark run completed', 'success', `${sampleCount} measured samples per supported operation after ${warmupCount} warm-up iterations; payload ${formatBytes(payloadBytes)}; X25519 ${x25519Supported ? 'available' : `unavailable (${x25519Error})`}.`);
  } catch (error) {
    recordCryptoEvent('Benchmark run failed', 'failure', error?.message || 'Unknown benchmark failure.');
    state.status = `Benchmark failed: ${error?.message || 'unknown error'}`;
  } finally {
    state.benchmarkRunning = false;
    state.benchmarkProgress = 100;
    renderChat();
  }
}

function downloadBenchmarkCsv() {
  if (!state.benchmarkResult) return;
  const rows = state.benchmarkResult.rawRows;
  const headers = [...new Set(rows.flatMap((row) => Object.keys(row)))];
  const quote = (value) => {
    const text = value == null ? '' : String(value);
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const csv = [headers.join(','), ...rows.map((row) => headers.map((header) => quote(row[header])).join(','))].join('\r\n');
  downloadText(`quantumsafe-benchmark-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`, csv, 'text/csv;charset=utf-8');
}

function renderSecurityTestsView() {
  const results = state.securityTests;
  const rows = results.length ? `<div class="test-results">${results.map((test) => `
    <div class="test-result"><span class="test-symbol ${test.status === 'FAIL' ? 'fail' : test.status === 'RUNNING' ? 'info' : ''}">${test.status === 'PASS' ? '✓' : test.status === 'FAIL' ? '!' : test.status === 'RUNNING' ? '…' : '·'}</span><div><strong>${escapeHtml(test.name)}</strong><p>${escapeHtml(test.details)}</p><small>${escapeHtml(test.durationMs == null ? 'not timed' : formatMs(test.durationMs))}</small></div><span class="event-status ${test.status === 'FAIL' ? 'failure' : test.status === 'RUNNING' ? 'info' : ''}">${escapeHtml(test.status)}</span></div>`).join('')}</div>` : '<div class="empty-lab"><div class="empty-lab-icon">✓</div><h3>No test results yet</h3><p>Run the checks. Each result is based on an actual Web Crypto or ML-KEM operation performed in this browser.</p></div>';
  const passed = results.filter((test) => test.status === 'PASS').length;
  const failed = results.filter((test) => test.status === 'FAIL').length;
  return `
    <main class="tool-page">
      <div class="tool-heading"><div><p class="eyebrow">NEGATIVE TESTS AND FAILURE HANDLING</p><h1>Security Tests</h1><p>Run controlled tests on test-only cryptographic material. A PASS means the observed behavior matched the expected result; it does not certify the whole application as secure.</p></div><div class="heading-actions"><button id="runSecurityTests" class="primary-button" type="button" ${state.securityTestsRunning ? 'disabled' : ''}>${state.securityTestsRunning ? 'Running tests…' : 'Run security tests ↗'}</button><button class="secondary-button" data-action="export-report" type="button">Export report</button></div></div>
      <div class="metric-grid"><div class="metric-card"><span>Passed checks</span><strong>${passed}</strong><small>Observed expected outcomes</small></div><div class="metric-card"><span>Failed checks</span><strong>${failed}</strong><small>A failure means unexpected test behavior</small></div><div class="metric-card"><span>Test material</span><strong>Ephemeral</strong><small>No real account keys or messages intentionally used</small></div><div class="metric-card"><span>Full protocol audit</span><strong>Not performed</strong><small>These are focused functional checks</small></div></div>
      <div class="panel-card warning-card"><div class="panel-heading"><div><p class="eyebrow">SCOPE WARNING</p><h2>What these tests can prove</h2></div><span class="status-tag">LIMITED SCOPE</span></div><p class="panel-note">These tests can verify rejection of modified AES-GCM ciphertext, wrong-password private-key bundle unlock, and mismatched ML-KEM decapsulation. They do not test public-key authentication, full replay protection, server compromise, forward secrecy, or production deployment security.</p></div>
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">OBSERVED RESULTS</p><h2>Execution results</h2></div><span class="status-tag">${results.length} TESTS</span></div>${rows}</div>
    </main>`;
}

async function runSecurityTests() {
  if (state.securityTestsRunning) return;
  state.securityTestsRunning = true;
  state.securityTests = [];
  renderChat();
  const append = (name, status, details, durationMs = null) => {
    state.securityTests.push({ name, status, details, durationMs, at: new Date().toISOString() });
    recordCryptoEvent(`Security test: ${name}`, status === 'PASS' ? 'success' : status === 'FAIL' ? 'failure' : 'info', details);
    renderChat();
  };
  try {
    // Test 1: control case — a valid AES-GCM round trip must succeed.
    let started = performance.now();
    const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const message = encoder.encode('QuantumSafe Chat security-test sample; not a real user message.');
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, message));
    const recovered = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext));
    const roundTrip = bytesEqual(recovered, message);
    append('Valid AES-256-GCM round trip', roundTrip ? 'PASS' : 'FAIL', roundTrip ? 'The decrypted bytes exactly match the test message.' : 'The valid test ciphertext did not recover the original bytes.', performance.now() - started);

    // Test 2: flip a real ciphertext bit and verify authenticated decryption rejects it.
    started = performance.now();
    const tampered = ciphertext.slice();
    tampered[0] ^= 0x01;
    let tamperRejected = false;
    try { await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, tampered); } catch { tamperRejected = true; }
    append('Tampered AES-GCM ciphertext rejected', tamperRejected ? 'PASS' : 'FAIL', tamperRejected ? 'A modified ciphertext/tag failed authenticated decryption, as expected.' : 'The browser unexpectedly accepted modified ciphertext.', performance.now() - started);

    // Test 3: run the actual private-key bundle helpers using a one-off ML-KEM key, never a user's key.
    started = performance.now();
    const [testPublic, testPrivate] = state.kem.generateKeyPair();
    const bundle = await createPrivateKeyBundle({ publicKey: bytesToBase64(testPublic), privateKey: bytesToBase64(testPrivate) }, `valid-test-password-${crypto.randomUUID()}`);
    let wrongPasswordRejected = false;
    try { await unlockPrivateKeyBundle(bundle, `wrong-test-password-${crypto.randomUUID()}`); } catch { wrongPasswordRejected = true; }
    append('Wrong password rejected for encrypted private-key bundle', wrongPasswordRejected ? 'PASS' : 'FAIL', wrongPasswordRejected ? 'The existing bundle-unlock helper rejected an incorrect password. Only ephemeral test key material was used.' : 'The bundle unexpectedly unlocked with a wrong password.', performance.now() - started);

    // Test 4: recipient-key mismatch should lead to a different secret and then GCM authentication failure.
    started = performance.now();
    const [correctPub] = state.kem.generateKeyPair();
    const [, incorrectPrivate] = state.kem.generateKeyPair();
    const [kemCt, senderSecret] = state.kem.encap(correctPub);
    const testSalt = crypto.getRandomValues(new Uint8Array(16));
    const testIv = crypto.getRandomValues(new Uint8Array(12));
    const senderKey = await deriveMessageKey(senderSecret, testSalt);
    const testCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: testIv }, senderKey, encoder.encode('recipient mismatch test only'));
    let wrongKeyRejected = false;
    try {
      const wrongSecret = state.kem.decap(kemCt, incorrectPrivate);
      const wrongKey = await deriveMessageKey(wrongSecret, testSalt);
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: testIv }, wrongKey, testCiphertext);
    } catch { wrongKeyRejected = true; }
    append('Mismatched ML-KEM private key rejected by authenticated decryption', wrongKeyRejected ? 'PASS' : 'FAIL', wrongKeyRejected ? 'Decapsulation with a mismatched key did not recover the valid message; AES-GCM authentication rejected the resulting key.' : 'Unexpectedly decrypted with a mismatched private key.', performance.now() - started);
  } catch (error) {
    append('Security test runner', 'FAIL', error?.message || 'Unexpected test runner failure.');
  } finally {
    state.securityTestsRunning = false;
    renderChat();
  }
}

function bindResearchActions() {
  root.querySelectorAll('[data-action="export-report"]').forEach((button) => button.addEventListener('click', exportResearchReport));
  root.querySelector('[data-action="clear-trace"]')?.addEventListener('click', () => {
    state.cryptoEvents = [];
    state.recentEnvelopes = [];
    renderChat();
  });
  root.querySelector('#runBenchmarks')?.addEventListener('click', runBenchmarks);
  root.querySelector('[data-action="download-benchmark-csv"]')?.addEventListener('click', downloadBenchmarkCsv);
  root.querySelector('#runSecurityTests')?.addEventListener('click', runSecurityTests);
}

function renderResearchView() {
  if (state.view === 'trace') return renderTraceView();
  if (state.view === 'benchmark') return renderBenchmarkView();
  return renderSecurityTestsView();
}

function renderChat() {
  if (!state.me) return;
  const previousTextarea = root.querySelector('#messageInput');
  const restoreComposerFocus = Boolean(previousTextarea && document.activeElement === previousTextarea);
  const selectionStart = previousTextarea?.selectionStart ?? state.draft.length;
  const selectionEnd = previousTextarea?.selectionEnd ?? state.draft.length;
  const statusClass = state.status === 'Connected' ? 'good' : 'neutral';
  root.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <div class="brand-lockup"><div class="brand-mark small">Q<span>+</span></div><div><strong>QuantumSafe <span>Chat</span></strong><small>MESSAGING + RESEARCH LAB</small></div></div>
        <nav class="main-nav" aria-label="Application sections">
          <button class="nav-item ${state.view === 'chat' ? 'active' : ''}" data-view="chat" type="button">Messages</button>
          <button class="nav-item ${state.view === 'trace' ? 'active' : ''}" data-view="trace" type="button">Crypto Trace</button>
          <button class="nav-item ${state.view === 'benchmark' ? 'active' : ''}" data-view="benchmark" type="button">Benchmark Lab</button>
          <button class="nav-item ${state.view === 'tests' ? 'active' : ''}" data-view="tests" type="button">Security Tests</button>
        </nav>
        <div class="topbar-right"><div class="connection-pill ${statusClass}"><i></i>${escapeHtml(state.status)}</div><div class="account-chip"><span class="avatar">${escapeHtml(state.me.slice(0, 1).toUpperCase())}</span><span>${escapeHtml(state.me)}</span></div><button id="logoutButton" class="logout-button" type="button">Log out</button></div>
      </header>
      ${state.view === 'chat' ? renderChatWorkspace() : renderResearchView()}
      <footer class="app-footer"><span><i class="footer-dot"></i> EXPERIMENTAL PQC PROTOTYPE</span><span>Live measurements only · no benchmark results are pre-filled</span></footer>
    </div>`;

  root.querySelector('#logoutButton').addEventListener('click', async () => {
    if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
    state.me = null; // Prevent the close handler from scheduling another connection.
    try { await api('/api/logout', { method: 'POST' }); } catch { /* sign out locally anyway */ }
    const oldSocket = state.socket;
    state.socket = null;
    oldSocket?.close();
    state.keys = null; state.users = []; state.active = null; state.messages = [];
    state.conversations = new Map(); state.drafts = {}; state.pendingSends = new Map();
    // Clear account-specific diagnostic artifacts so the next account cannot see prior account traces.
    state.cryptoEvents = []; state.recentEnvelopes = []; state.latestPrivateKeyBundle = null; state.publicKeyFingerprint = null; state.securityTests = [];
    state.view = 'chat';
    showAuth();
  });
  root.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => {
    if (state.active) state.drafts[state.active] = state.draft;
    state.view = button.dataset.view;
    renderChat();
  }));
  if (state.view !== 'chat') {
    bindResearchActions();
    return;
  }
  root.querySelectorAll('[data-user]').forEach((button) => button.addEventListener('click', () => {
    loadConversation(button.dataset.user);
  }));
  const textarea = root.querySelector('#messageInput');
  if (textarea) textarea.value = state.draft;
  textarea?.addEventListener('input', () => {
    state.draft = textarea.value;
    if (state.active) state.drafts[state.active] = state.draft;
    const count = root.querySelector('.char-count');
    if (count) count.textContent = `${state.draft.length}/2000`;
  });
  if (restoreComposerFocus && textarea && !textarea.disabled) {
    textarea.focus({ preventScroll: true });
    try {
      const start = Math.min(selectionStart, textarea.value.length);
      const end = Math.min(selectionEnd, textarea.value.length);
      textarea.setSelectionRange(start, end);
    } catch { /* Some browsers do not expose selection on a disabled/non-text input. */ }
  }
  textarea?.addEventListener('keydown', (event) => {
    // Enter sends; Shift+Enter inserts a newline. Ignore Enter while an IME composition is active.
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      root.querySelector('#composer')?.requestSubmit();
    }
  });
  root.querySelector('#composer').addEventListener('submit', (event) => {
    event.preventDefault();
    sendMessage();
  });
  renderMessages();
}

async function start() {
  try {
    state.kem = await createMlKem768();
    recordCryptoEvent('ML-KEM-768 implementation initialized', 'success', 'Initialized the mlkem npm library in this browser. No remote cryptography API is used.');
  } catch (error) {
    root.innerHTML = `<main class="fatal"><h1>Crypto library failed to load</h1><p>${escapeHtml(error.message || 'The ML-KEM module could not be initialized.')}</p><p>Run <code>npm install</code>, then restart the development server.</p></main>`;
    return;
  }

  // The key is password-wrapped at rest, so a returning user must re-enter the password to unlock it.
  try {
    const profile = await api('/api/me');
    showAuth('Enter your password to unlock your encrypted private key.', profile.username);
    return;
  } catch { /* No active server session. */ }
  showAuth();
}

start();
