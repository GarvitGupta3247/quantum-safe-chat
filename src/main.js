import { createMlKem768 } from 'mlkem';
import './style.css';

const root = document.querySelector('#app');
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KDF_INFO = encoder.encode('QuantumSafeChat PoC v1 | ML-KEM-768 | AES-256-GCM');

const state = {
  kem: null,
  me: null,
  keys: null,
  users: [],
  active: null,
  messages: [],
  socket: null,
  unread: {},
  status: 'Connecting…',
  draft: '',
  busy: false,
  page: 'chat',
  cryptoEvents: [],
  keyFingerprint: '',
  benchmark: null,
  benchmarkRunning: false,
  benchmarkProgress: '',
  attackResults: [],
  attackRunning: false,
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

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) mismatch |= a[i] ^ b[i];
  return mismatch === 0;
}

async function fingerprintBytes(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function shortFingerprint(value) {
  return value ? `${value.slice(0, 24)}…` : 'unavailable';
}

function logCrypto(operation, status = 'success', details = '') {
  const event = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    time: new Date().toISOString(),
    operation,
    status,
    details: String(details),
  };
  state.cryptoEvents.unshift(event);
  if (state.cryptoEvents.length > 120) state.cryptoEvents.length = 120;
  const list = root.querySelector('#cryptoEventList');
  if (list) {
    list.insertAdjacentHTML('afterbegin', renderCryptoEvent(event));
    while (list.children.length > 120) list.lastElementChild.remove();
    const empty = list.querySelector('.event-empty');
    if (empty) empty.remove();
  }
  return event;
}

function renderCryptoEvent(event) {
  const time = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(event.time));
  return `<article class="event-row"><time>${escapeHtml(time)}</time><span class="event-indicator ${escapeHtml(event.status)}"></span><div class="event-copy"><strong>${escapeHtml(event.operation)}</strong><p>${escapeHtml(event.details || 'No additional details.')}</p></div><span class="event-status ${escapeHtml(event.status)}">${escapeHtml(event.status)}</span></article>`;
}

function formatMs(value) {
  return Number.isFinite(value) ? `${value.toFixed(value < 1 ? 3 : 2)} ms` : '—';
}

function summarizeSamples(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const mean = samples.reduce((sum, value) => sum + value, 0) / samples.length;
  const median = sorted.length % 2
    ? sorted[Math.floor(sorted.length / 2)]
    : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;
  const variance = samples.reduce((sum, value) => sum + ((value - mean) ** 2), 0) / samples.length;
  return { median, mean, stdDev: Math.sqrt(variance), samples: samples.length };
}

function csvCell(value) {
  const text = String(value ?? '');
  return `"${text.replace(/"/g, '""')}"`;
}

function downloadCsv(filename, rows) {
  const csv = rows.map((row) => row.map(csvCell).join(',')).join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
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

function readLocalKeys(username) {
  try {
    const parsed = JSON.parse(localStorage.getItem(localKeyName(username)) || 'null');
    if (parsed && typeof parsed.publicKey === 'string' && typeof parsed.privateKey === 'string') return parsed;
  } catch { /* Ignore malformed local storage. */ }
  return null;
}

function storeLocalKeys(username, keys) {
  // Demo shortcut only: this stores the private key unencrypted in localStorage.
  localStorage.setItem(localKeyName(username), JSON.stringify(keys));
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
        <p class="eyebrow">PHASE 1.5 · CRYPTO OBSERVABILITY</p>
        <h1>QuantumSafe Chat</h1>
        <p class="subhead">A tiny messaging app experimenting with post-quantum key encapsulation.</p>
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
        <p class="auth-footnote">Demo accounts only. Your ML-KEM private key stays in this browser's local storage; there is no recovery flow.</p>
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
        // ML-KEM keypair is generated in the browser; only its public key is sent to the server.
        const keygenStarted = performance.now();
        const [publicKeyBytes, privateKeyBytes] = state.kem.generateKeyPair();
        const keygenMs = performance.now() - keygenStarted;
        keys = { publicKey: bytesToBase64(publicKeyBytes), privateKey: bytesToBase64(privateKeyBytes) };
        logCrypto('ML-KEM-768 key-pair generation', 'success', `Public key ${publicKeyBytes.length.toLocaleString()} B · private key ${privateKeyBytes.length.toLocaleString()} B · ${formatMs(keygenMs)}. Private key is stored locally for this demo.`);
        profile = await api('/api/register', {
          method: 'POST',
          body: JSON.stringify({ username, password, kemPublicKey: keys.publicKey }),
        });
        storeLocalKeys(profile.username, keys);
      } else {
        profile = await api('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) });
        keys = readLocalKeys(profile.username);
        if (!localKeyMatches(profile.kemPublicKey, keys)) {
          await api('/api/logout', { method: 'POST' }).catch(() => {});
          throw new Error('This browser does not have the matching ML-KEM private key. Log in on the browser where you created the account; key recovery is not implemented.');
        }
      }
      await enterChat(profile, keys);
    } catch (error) {
      showAuth(error.message || 'Something went wrong.', username);
    }
  });
}

async function enterChat(profile, keys) {
  state.me = profile.username;
  state.keys = { ...keys, privateKeyBytes: base64ToBytes(keys.privateKey), publicKeyBytes: base64ToBytes(keys.publicKey) };
  state.page = 'chat';
  state.keyFingerprint = await fingerprintBytes(state.keys.publicKeyBytes).catch(() => 'Fingerprint unavailable in this browser context');
  logCrypto('Local ML-KEM-768 key loaded', 'success', `Public-key SHA-256 fingerprint ${shortFingerprint(state.keyFingerprint)} · public key ${state.keys.publicKeyBytes.length.toLocaleString()} B. Private key remains local to this browser.`);
  state.messages = [];
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

function connectSocket() {
  if (state.socket) state.socket.close();
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${scheme}//${location.host}/ws`);
  state.socket = socket;
  socket.addEventListener('open', () => {
    state.status = 'Connected';
    renderChat();
  });
  socket.addEventListener('close', () => {
    state.status = 'Disconnected — refresh to reconnect';
    if (state.me) renderChat();
  });
  socket.addEventListener('error', () => {
    state.status = 'Connection error';
  });
  socket.addEventListener('message', async (event) => {
    let packet;
    try { packet = JSON.parse(event.data); } catch { return; }
    if (packet.type === 'ready') {
      state.status = 'Connected';
      refreshUsers().catch(() => {});
      renderChat();
    } else if (packet.type === 'error') {
      state.status = packet.error || 'Message error';
      renderChat();
    } else if (packet.type === 'sent' || packet.type === 'message') {
      await handleWireMessage(packet.message);
    }
  });
}

async function refreshUsers() {
  const result = await api('/api/users');
  state.users = result.users;
  renderChat();
}

async function deriveMessageKey(sharedSecret, saltBytes) {
  const material = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: KDF_INFO },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptEnvelope(publicKeyBase64, plaintext) {
  const publicKey = base64ToBytes(publicKeyBase64);
  const kemStarted = performance.now();
  const [kemCiphertext, sharedSecret] = state.kem.encap(publicKey);
  const kemMs = performance.now() - kemStarted;
  const envelopeRef = shortFingerprint(await fingerprintBytes(kemCiphertext));
  const sharedSecretFingerprint = shortFingerprint(await fingerprintBytes(sharedSecret));
  logCrypto('ML-KEM-768 encapsulation', 'success', `Recipient public key ${publicKey.length.toLocaleString()} B · KEM ciphertext ${kemCiphertext.length.toLocaleString()} B · envelope ref ${envelopeRef} · shared-secret SHA-256 ${sharedSecretFingerprint} · ${formatMs(kemMs)}`);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const kdfStarted = performance.now();
  const key = await deriveMessageKey(sharedSecret, salt);
  logCrypto('HKDF-SHA-256 key derivation', 'success', `32-byte AES key derived · salt ${salt.length} B · ${formatMs(performance.now() - kdfStarted)}`);
  const plaintextBytes = encoder.encode(plaintext);
  const encryptStarted = performance.now();
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextBytes);
  logCrypto('AES-256-GCM encryption', 'success', `Plaintext ${plaintextBytes.length.toLocaleString()} B · authenticated ciphertext ${ciphertext.byteLength.toLocaleString()} B · nonce ${iv.length} B · ${formatMs(performance.now() - encryptStarted)}`);
  return {
    kemCiphertext: bytesToBase64(kemCiphertext),
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptEnvelope(envelope) {
  if (!envelope) throw new Error('Missing encrypted copy for this account.');
  const kemCiphertext = base64ToBytes(envelope.kemCiphertext);
  const envelopeRef = shortFingerprint(await fingerprintBytes(kemCiphertext));
  const decapStarted = performance.now();
  const sharedSecret = state.kem.decap(kemCiphertext, state.keys.privateKeyBytes);
  logCrypto('ML-KEM-768 decapsulation', 'success', `Envelope ref ${envelopeRef} · KEM ciphertext ${kemCiphertext.length.toLocaleString()} B · shared-secret SHA-256 ${shortFingerprint(await fingerprintBytes(sharedSecret))} · ${formatMs(performance.now() - decapStarted)}`);
  const salt = base64ToBytes(envelope.salt);
  const kdfStarted = performance.now();
  const key = await deriveMessageKey(sharedSecret, salt);
  logCrypto('HKDF-SHA-256 key derivation', 'success', `32-byte AES key derived · salt ${salt.length} B · ${formatMs(performance.now() - kdfStarted)}`);
  const iv = base64ToBytes(envelope.iv);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  const decryptStarted = performance.now();
  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    logCrypto('AES-256-GCM authenticated decryption', 'success', `Ciphertext ${ciphertext.length.toLocaleString()} B · plaintext ${plaintext.byteLength.toLocaleString()} B · authentication tag valid · ${formatMs(performance.now() - decryptStarted)}`);
    return decoder.decode(plaintext);
  } catch {
    logCrypto('AES-256-GCM authentication check', 'failure', `Ciphertext rejected for envelope ${envelopeRef}; wrong key or modified/invalid ciphertext · ${formatMs(performance.now() - decryptStarted)}`);
    throw new Error('AES-GCM authentication failed.');
  }
}

async function handleWireMessage(message) {
  if (!message || !message.id || !state.me) return;
  const other = message.sender === state.me ? message.recipient : message.sender;
  if (other !== state.active) {
    if (message.sender !== state.me) state.unread[other] = (state.unread[other] || 0) + 1;
    renderChat();
    return;
  }
  try {
    const text = await decryptEnvelope(message.envelopes?.[state.me]);
    appendMessage({ ...message, text, decryptError: false });
  } catch {
    appendMessage({ ...message, text: 'Could not decrypt this message. The local key may not match.', decryptError: true });
  }
}

function appendMessage(message) {
  if (state.messages.some((existing) => existing.id === message.id)) return;
  state.messages.push(message);
  state.messages.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  renderMessages();
}

async function loadConversation(username) {
  state.active = username;
  state.unread[username] = 0;
  state.messages = [];
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
    // Keep live messages that arrived while history was loading, and de-duplicate by message id.
    const merged = new Map([...fetchedMessages, ...state.messages].map((message) => [message.id, message]));
    state.messages = [...merged.values()].sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    renderChat();
  } catch (error) {
    state.status = error.message;
    renderChat();
  }
}

async function sendMessage() {
  const text = state.draft.trim();
  if (!text || !state.active || !state.socket || state.socket.readyState !== WebSocket.OPEN) return;
  if (text.length > 2000) {
    state.status = 'Messages are limited to 2,000 characters.';
    renderChat();
    return;
  }
  const recipient = state.users.find((user) => user.username === state.active);
  if (!recipient) return;
  const button = root.querySelector('#sendButton');
  if (button) button.disabled = true;
  state.status = 'Encrypting in browser…';
  try {
    // Fresh ML-KEM encapsulation and fresh AES-GCM key for each copy of each message.
    // One encrypted envelope is for the recipient; a second lets the sender read its history.
    const [recipientEnvelope, senderEnvelope] = await Promise.all([
      encryptEnvelope(recipient.kemPublicKey, text),
      encryptEnvelope(state.keys.publicKey, text),
    ]);
    const packet = {
      type: 'send',
      to: recipient.username,
      envelopes: { [recipient.username]: recipientEnvelope, [state.me]: senderEnvelope },
    };
    const wireBytes = encoder.encode(JSON.stringify(packet)).length;
    state.socket.send(JSON.stringify(packet));
    logCrypto('Encrypted envelope sent to relay', 'success', `Recipient ${recipient.username} · serialized WebSocket packet ${wireBytes.toLocaleString()} B · plaintext is not included in the packet.`);
    state.draft = '';
    state.status = 'Encrypted message sent';
    renderChat();
  } catch (error) {
    state.status = `Could not encrypt/send: ${error.message}`;
    renderChat();
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

function renderCryptoPage() {
  const successful = state.cryptoEvents.filter((event) => event.status === 'success').length;
  const failures = state.cryptoEvents.filter((event) => event.status === 'failure').length;
  const eventHtml = state.cryptoEvents.length
    ? state.cryptoEvents.map(renderCryptoEvent).join('')
    : '<div class="event-empty">No cryptographic events recorded yet. Register a test account or send a message to populate this trace.</div>';
  const publicKeyBase64 = state.keys?.publicKey || '';
  return `
    <main class="tool-page">
      <section class="tool-heading"><div><p class="eyebrow">PROTOCOL OBSERVABILITY / 01</p><h1>Crypto activity</h1><p>Runtime evidence from real operations in this browser. Secret key material and plaintext are intentionally excluded from the log.</p></div><div class="heading-actions"><button id="exportCrypto" class="secondary-button" type="button">Export event log CSV</button></div></section>
      <section class="metric-grid">
        <article class="metric-card"><span>Key encapsulation</span><strong>ML-KEM-768</strong><small>NIST FIPS 203 parameter set</small></article>
        <article class="metric-card"><span>Message protection</span><strong>AES-256-GCM</strong><small>Authenticated symmetric encryption</small></article>
        <article class="metric-card"><span>Observed events</span><strong>${state.cryptoEvents.length}</strong><small>${successful} successful · ${failures} rejected/failed</small></article>
        <article class="metric-card"><span>Public key</span><strong>${state.keys.publicKeyBytes.length.toLocaleString()} B</strong><small>Private key is not displayed</small></article>
      </section>
      <section class="panel-card fingerprint-card"><div class="panel-heading"><div><p class="eyebrow">LOCAL IDENTITY MATERIAL</p><h2>Public-key fingerprint</h2></div><span class="status-tag">Actual runtime value</span></div><code class="fingerprint-value">${escapeHtml(state.keyFingerprint || 'Calculating…')}</code><p class="panel-note">SHA-256 of this account's actual ML-KEM-768 public key. For a live demo, compare the envelope reference and abbreviated shared-secret fingerprint in the sender's encapsulation event and the recipient's decapsulation event. Matching values show both sides derived the same secret for that envelope; this fingerprint is diagnostic only and does not authenticate the user or key.</p><details class="public-key-details"><summary>Inspect public key (Base64)</summary><pre>${escapeHtml(publicKeyBase64)}</pre></details></section>
      <section class="panel-card"><div class="panel-heading"><div><p class="eyebrow">LIVE OPERATION TRACE</p><h2>Cryptographic event log</h2></div><span class="status-tag">Newest first</span></div><div id="cryptoEventList" class="event-list">${eventHtml}</div></section>
      <p class="disclaimer-line">Diagnostic logs include operation timing, sizes and abbreviated SHA-256 fingerprints only. They do not prove identity, prevent key substitution, or replace an independent security audit.</p>
    </main>`;
}

function renderBenchmarkPage() {
  const results = state.benchmark;
  let resultContent = '';
  if (state.benchmarkRunning) {
    resultContent = `<div class="benchmark-progress"><span class="spinner"></span><div><strong>Running browser benchmarks</strong><p>${escapeHtml(state.benchmarkProgress || 'Preparing cryptographic test cases…')}</p></div></div>`;
  } else if (!results) {
    resultContent = `<div class="empty-lab"><div class="empty-lab-icon">↗</div><h3>Run the first experiment</h3><p>Benchmarks execute in this browser using the real ML-KEM implementation and Web Crypto. Results are not pre-filled or simulated.</p></div>`;
  } else {
    const available = results.rows.filter((row) => row.status === 'ok' && Number.isFinite(row.medianMs));
    const maxMs = Math.max(0.001, ...available.map((row) => row.medianMs));
    resultContent = `
      <div class="benchmark-summary"><div><span>Runs per operation</span><strong>${results.iterations}</strong></div><div><span>Completed</span><strong>${escapeHtml(new Date(results.ranAt).toLocaleString())}</strong></div><div><span>Environment</span><strong>${results.secureContext ? 'Secure context' : 'Insecure context'}</strong></div><div><span>Browser / user agent</span><strong>${escapeHtml((navigator.userAgentData?.brands?.filter((brand) => !/Not.A.Brand/i.test(brand.brand)).map((brand) => `${brand.brand} ${brand.version}`).join(', ') || navigator.userAgent).slice(0, 100))}</strong></div></div>
      <div class="chart-list">${available.map((row) => `<div class="chart-row"><div class="chart-label"><span>${escapeHtml(row.operation)}</span><strong>${formatMs(row.medianMs)}</strong></div><div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, row.medianMs / maxMs * 100)}%"></div></div></div>`).join('')}</div>
      <div class="table-wrap"><table class="results-table"><thead><tr><th>Operation</th><th>Median</th><th>Mean</th><th>Std. dev.</th><th>Size / notes</th></tr></thead><tbody>${results.rows.map((row) => row.status === 'ok'
        ? `<tr><td>${escapeHtml(row.operation)}</td><td class="mono-cell">${formatMs(row.medianMs)}</td><td class="mono-cell">${formatMs(row.meanMs)}</td><td class="mono-cell">${formatMs(row.stdDevMs)}</td><td>${escapeHtml(row.note || '—')}</td></tr>`
        : `<tr><td>${escapeHtml(row.operation)}</td><td colspan="3"><span class="event-status ${row.status === 'unsupported' ? 'info' : 'failure'}">${escapeHtml(row.status)}</span></td><td>${escapeHtml(row.note || 'Not available')}</td></tr>`).join('')}</tbody></table></div>
      <p class="panel-note">These are browser/device microbenchmarks, not formal security proofs. The combined ML-KEM exchange and bilateral X25519 derivation are the closest comparison, but the constructions and implementation paths differ. Document conditions and repeat runs. X25519 availability depends on browser Web Crypto support.</p>`;
  }
  return `
    <main class="tool-page">
      <section class="tool-heading"><div><p class="eyebrow">EXPERIMENTS / 02</p><h1>Benchmark lab</h1><p>Measure actual cryptographic operations, compare the post-quantum KEM with a classical key-agreement baseline, and export reproducible results.</p></div><div class="heading-actions"><button id="runBenchmarks" class="primary-button" type="button" ${state.benchmarkRunning ? 'disabled' : ''}>${state.benchmarkRunning ? 'Running…' : results ? 'Run again · 100 iterations' : 'Run benchmarks · 100 iterations'}</button>${results && !state.benchmarkRunning ? '<button id="exportBenchmarks" class="secondary-button" type="button">Export CSV</button>' : ''}</div></section>
      <section class="panel-card"><div class="panel-heading"><div><p class="eyebrow">MEASURED IN THIS TAB</p><h2>Operation timing</h2></div><span class="status-tag">${results ? 'Measured results' : 'Awaiting run'}</span></div>${resultContent}</section>
      <section class="note-grid"><article class="note-card"><span class="note-kicker">POST-QUANTUM</span><h3>ML-KEM-768</h3><p>Measures keypair generation, encapsulation and decapsulation via the project's <code>mlkem</code> library.</p></article><article class="note-card"><span class="note-kicker">CLASSICAL BASELINE</span><h3>X25519</h3><p>Uses browser Web Crypto where supported. If not supported, the test records that fact instead of inventing numbers.</p></article><article class="note-card"><span class="note-kicker">SYMMETRIC LAYER</span><h3>HKDF + AES-GCM</h3><p>Measures 32-byte key derivation and AES-GCM encrypt/decrypt on a 1 KiB payload.</p></article></section>
      <p class="disclaimer-line">Benchmark values vary with hardware, browser, thermal state and background load. Include environment details and repeat runs in the report.</p>
    </main>`;
}

function renderAttackPage() {
  const tests = state.attackResults;
  return `
    <main class="tool-page">
      <section class="tool-heading"><div><p class="eyebrow">VALIDATION / 03</p><h1>Security attack lab</h1><p>Run active checks against locally generated encrypted test envelopes. A green result means that specific test behaved as expected—not that the whole app is secure.</p></div><div class="heading-actions"><button id="runSecurityTests" class="primary-button" type="button" ${state.attackRunning ? 'disabled' : ''}>${state.attackRunning ? 'Testing…' : 'Run security tests'}</button></div></section>
      <section class="note-grid"><article class="note-card"><span class="note-kicker">TEST 01</span><h3>Ciphertext tampering</h3><p>Flip a bit in a valid AES-GCM ciphertext and verify authenticated decryption rejects it.</p></article><article class="note-card"><span class="note-kicker">TEST 02</span><h3>Wrong private key</h3><p>Create an envelope for a different ML-KEM keypair, then attempt decryption with the current account's private key.</p></article><article class="note-card warning-card"><span class="note-kicker">NOT IMPLEMENTED</span><h3>Identity / replay attacks</h3><p>Key-substitution protection, ML-DSA identity verification and replay protection are not implemented in this phase.</p></article></section>
      <section class="panel-card"><div class="panel-heading"><div><p class="eyebrow">TEST EXECUTION</p><h2>Observed test outcomes</h2></div><span class="status-tag">${tests.length ? `${tests.length} results` : 'No tests run'}</span></div>${state.attackRunning ? '<div class="benchmark-progress"><span class="spinner"></span><div><strong>Executing checks</strong><p>Generating test keys and authenticating encrypted payloads…</p></div></div>' : ''}${tests.length ? `<div class="test-results">${tests.map((test) => `<article class="test-result"><span class="test-symbol ${test.status}">${test.status === 'pass' ? '✓' : test.status === 'fail' ? '!' : '·'}</span><div><strong>${escapeHtml(test.name)}</strong><p>${escapeHtml(test.details)}</p><small>${escapeHtml(new Date(test.time).toLocaleTimeString())}</small></div><span class="event-status ${test.status === 'pass' ? 'success' : test.status === 'fail' ? 'failure' : 'info'}">${escapeHtml(test.status)}</span></article>`).join('')}</div><button id="exportAttackTests" class="secondary-button export-tests" type="button">Export results CSV</button>` : `<div class="empty-lab"><div class="empty-lab-icon">⌁</div><h3>No results yet</h3><p>Run the tests to generate the encrypted payloads and observe real verification outcomes.</p></div>`}</section>
      <p class="disclaimer-line">This is a small educational test harness, not a penetration test or security certification. The current system does not authenticate contact keys and does not provide forward secrecy.</p>
    </main>`;
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

function renderChat() {
  if (!state.me) return;
  const statusClass = state.status === 'Connected' ? 'good' : 'neutral';
  let pageContent = state.page === 'crypto' ? renderCryptoPage()
    : state.page === 'benchmarks' ? renderBenchmarkPage()
      : state.page === 'attacks' ? renderAttackPage()
        : renderChatWorkspace();
  root.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <div class="brand-lockup"><div class="brand-mark small">Q<span>+</span></div><div><strong>QuantumSafe <span>Chat</span></strong><small>POST-QUANTUM LAB · PHASE 1.5</small></div></div>
        <nav class="main-nav" aria-label="Application sections">
          <button class="nav-item ${state.page === 'chat' ? 'active' : ''}" data-page="chat" type="button">Messages</button>
          <button class="nav-item ${state.page === 'crypto' ? 'active' : ''}" data-page="crypto" type="button">Crypto activity</button>
          <button class="nav-item ${state.page === 'benchmarks' ? 'active' : ''}" data-page="benchmarks" type="button">Benchmarks</button>
          <button class="nav-item ${state.page === 'attacks' ? 'active' : ''}" data-page="attacks" type="button">Attack lab</button>
        </nav>
        <div class="topbar-right"><div class="connection-pill ${statusClass}"><i></i>${escapeHtml(state.status)}</div><div class="account-chip"><span class="avatar">${escapeHtml(state.me.slice(0, 1).toUpperCase())}</span><span>${escapeHtml(state.me)}</span></div><button id="logoutButton" class="logout-button" type="button">Log out</button></div>
      </header>
      ${pageContent}
      <footer class="app-footer"><span><i class="footer-dot"></i> EXPERIMENTAL PQC PROTOTYPE</span><span>ML-DSA identity verification + forward secrecy planned for Phase 2</span></footer>
    </div>`;

  root.querySelector('#logoutButton').addEventListener('click', async () => {
    try { await api('/api/logout', { method: 'POST' }); } catch { /* sign out locally anyway */ }
    state.socket?.close();
    state.me = null; state.keys = null; state.users = []; state.active = null; state.messages = []; state.page = 'chat';
    showAuth();
  });
  root.querySelectorAll('[data-page]').forEach((button) => button.addEventListener('click', () => {
    state.page = button.dataset.page;
    renderChat();
  }));
  if (state.page === 'chat') {
    root.querySelectorAll('[data-user]').forEach((button) => button.addEventListener('click', () => {
      state.draft = '';
      loadConversation(button.dataset.user);
    }));
    const textarea = root.querySelector('#messageInput');
    if (textarea) textarea.value = state.draft;
    textarea?.addEventListener('input', () => {
      state.draft = textarea.value;
      const count = root.querySelector('.char-count');
      if (count) count.textContent = `${state.draft.length}/2000`;
    });
    root.querySelector('#composer').addEventListener('submit', (event) => {
      event.preventDefault();
      sendMessage();
    });
    renderMessages();
  }
  root.querySelector('#exportCrypto')?.addEventListener('click', () => {
    downloadCsv('quantumsafe-crypto-events.csv', [['Timestamp', 'Operation', 'Status', 'Details'], ...state.cryptoEvents.slice().reverse().map((event) => [event.time, event.operation, event.status, event.details])]);
  });
  root.querySelector('#runBenchmarks')?.addEventListener('click', runBenchmarks);
  root.querySelector('#exportBenchmarks')?.addEventListener('click', () => {
    if (!state.benchmark) return;
    downloadCsv('quantumsafe-benchmark-results.csv', [['Run time', state.benchmark.ranAt], ['Browser', state.benchmark.userAgent], ['Secure context', state.benchmark.secureContext], ['Iterations', state.benchmark.iterations], [], ['Operation', 'Status', 'Median ms', 'Mean ms', 'Standard deviation ms', 'Sample count', 'Notes'], ...state.benchmark.rows.map((row) => [row.operation, row.status, row.medianMs ?? '', row.meanMs ?? '', row.stdDevMs ?? '', row.samples ?? '', row.note || ''])]);
  });
  root.querySelector('#runSecurityTests')?.addEventListener('click', runSecurityTests);
  root.querySelector('#exportAttackTests')?.addEventListener('click', () => {
    downloadCsv('quantumsafe-security-tests.csv', [['Timestamp', 'Test', 'Status', 'Details'], ...state.attackResults.map((test) => [test.time, test.name, test.status, test.details])]);
  });
}

function addBenchmarkRow(rows, operation, samples, note) {
  const stats = summarizeSamples(samples);
  rows.push({ operation, status: 'ok', ...stats, note });
}

async function runBenchmarks() {
  if (state.benchmarkRunning) return;
  state.benchmarkRunning = true;
  state.benchmarkProgress = 'Warming up ML-KEM-768 operations…';
  state.benchmark = null;
  renderChat();
  const iterations = 100;
  const rows = [];
  const update = (message) => { state.benchmarkProgress = message; if (state.page === 'benchmarks') renderChat(); };
  try {
    state.kem.generateKeyPair();
    for (let i = 0; i < 3; i += 1) state.kem.generateKeyPair();
    const keygenSamples = [];
    let pair;
    for (let i = 0; i < iterations; i += 1) {
      const started = performance.now();
      pair = state.kem.generateKeyPair();
      keygenSamples.push(performance.now() - started);
    }
    const [publicKey, privateKey] = pair;
    addBenchmarkRow(rows, 'ML-KEM-768 keypair generation', keygenSamples, `Public key ${publicKey.length} B · private key ${privateKey.length} B`);
    update('Measuring encapsulation and decapsulation…');

    for (let i = 0; i < 3; i += 1) state.kem.encap(publicKey);
    const encapSamples = [];
    let lastEncapsulation;
    for (let i = 0; i < iterations; i += 1) {
      const started = performance.now();
      lastEncapsulation = state.kem.encap(publicKey);
      encapSamples.push(performance.now() - started);
    }
    addBenchmarkRow(rows, 'ML-KEM-768 encapsulation', encapSamples, `KEM ciphertext ${lastEncapsulation[0].length} B · shared secret ${lastEncapsulation[1].length} B`);

    const decapSamples = [];
    let kemCorrect = true;
    for (let i = 0; i < iterations; i += 1) {
      const [ciphertext, expectedSecret] = state.kem.encap(publicKey);
      const started = performance.now();
      const actualSecret = state.kem.decap(ciphertext, privateKey);
      decapSamples.push(performance.now() - started);
      if (!bytesEqual(expectedSecret, actualSecret)) kemCorrect = false;
    }
    if (kemCorrect) addBenchmarkRow(rows, 'ML-KEM-768 decapsulation', decapSamples, `Shared secret ${lastEncapsulation[1].length} B · ${iterations}/${iterations} secret-match checks passed`);
    else rows.push({ operation: 'ML-KEM-768 decapsulation', status: 'fail', note: 'Shared-secret consistency check failed.' });

    const kemExchangeSamples = [];
    let kemExchangeCorrect = true;
    for (let i = 0; i < iterations; i += 1) {
      const started = performance.now();
      const [ciphertext, expectedSecret] = state.kem.encap(publicKey);
      const actualSecret = state.kem.decap(ciphertext, privateKey);
      kemExchangeSamples.push(performance.now() - started);
      if (!bytesEqual(expectedSecret, actualSecret)) kemExchangeCorrect = false;
    }
    if (kemExchangeCorrect) addBenchmarkRow(rows, 'ML-KEM-768 encapsulate + decapsulate', kemExchangeSamples, `One full KEM exchange · ${iterations}/${iterations} shared-secret match checks passed`);
    else rows.push({ operation: 'ML-KEM-768 encapsulate + decapsulate', status: 'fail', note: 'Shared-secret consistency check failed.' });

    update('Measuring X25519 baseline (if supported by this browser)…');
    try {
      const xKeygenSamples = [];
      let xA;
      for (let i = 0; i < iterations; i += 1) {
        const started = performance.now();
        xA = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
        xKeygenSamples.push(performance.now() - started);
      }
      addBenchmarkRow(rows, 'X25519 keypair generation', xKeygenSamples, 'Browser Web Crypto · one keypair');
      const x25519Samples = [];
      let xSecretLength = 32;
      let xAgreementCorrect = true;
      for (let i = 0; i < iterations; i += 1) {
        const a = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
        const b = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
        const started = performance.now();
        const [secretA, secretB] = await Promise.all([
          crypto.subtle.deriveBits({ name: 'X25519', public: b.publicKey }, a.privateKey, 256),
          crypto.subtle.deriveBits({ name: 'X25519', public: a.publicKey }, b.privateKey, 256),
        ]);
        x25519Samples.push(performance.now() - started);
        xSecretLength = secretA.byteLength;
        if (!bytesEqual(new Uint8Array(secretA), new Uint8Array(secretB))) xAgreementCorrect = false;
      }
      if (xAgreementCorrect) addBenchmarkRow(rows, 'X25519 bilateral shared-secret derivation', x25519Samples, `Two deriveBits calls · ${xSecretLength} B secret · ${iterations}/${iterations} match checks passed`);
      else rows.push({ operation: 'X25519 bilateral shared-secret derivation', status: 'fail', note: 'The two derived secrets did not match.' });
    } catch (error) {
      rows.push({ operation: 'X25519 classical baseline', status: 'unsupported', note: `${error?.name || 'Error'}: ${error?.message || 'Web Crypto X25519 is unavailable in this browser.'}` });
    }

    update('Measuring HKDF and AES-GCM on a 1 KiB payload…');
    const sharedSecret = lastEncapsulation[1];
    const kdfSamples = [];
    let aesKey;
    for (let i = 0; i < iterations; i += 1) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const started = performance.now();
      aesKey = await deriveMessageKey(sharedSecret, salt);
      kdfSamples.push(performance.now() - started);
    }
    addBenchmarkRow(rows, 'HKDF-SHA-256 derivation', kdfSamples, '16 B random salt · 256-bit AES key');
    const payload = crypto.getRandomValues(new Uint8Array(1024));
    const encryptionSamples = [];
    const encryptionCases = [];
    for (let i = 0; i < iterations; i += 1) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const started = performance.now();
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, payload);
      encryptionSamples.push(performance.now() - started);
      encryptionCases.push({ iv, encrypted });
    }
    addBenchmarkRow(rows, 'AES-256-GCM encrypt (1 KiB)', encryptionSamples, `Plaintext 1,024 B · ciphertext ${encryptionCases[0].encrypted.byteLength.toLocaleString()} B`);
    const decryptionSamples = [];
    let aesCorrect = true;
    for (const item of encryptionCases) {
      const started = performance.now();
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: item.iv }, aesKey, item.encrypted);
      decryptionSamples.push(performance.now() - started);
      if (!bytesEqual(new Uint8Array(decrypted), payload)) aesCorrect = false;
    }
    if (aesCorrect) addBenchmarkRow(rows, 'AES-256-GCM decrypt (1 KiB)', decryptionSamples, `${iterations}/${iterations} plaintext verification checks passed`);
    else rows.push({ operation: 'AES-256-GCM decrypt (1 KiB)', status: 'fail', note: 'Decrypted bytes did not match the original payload.' });

    state.benchmark = {
      ranAt: new Date().toISOString(),
      iterations,
      secureContext: window.isSecureContext,
      userAgent: navigator.userAgent,
      rows,
    };
    logCrypto('Benchmark experiment completed', 'success', `${iterations} samples per supported operation · ${rows.filter((row) => row.status === 'ok').length} measured operation rows · results are available for CSV export.`);
  } catch (error) {
    logCrypto('Benchmark experiment failed', 'failure', `${error?.name || 'Error'}: ${error?.message || 'Unexpected test failure.'}`);
    state.benchmark = {
      ranAt: new Date().toISOString(), iterations, secureContext: window.isSecureContext,
      userAgent: navigator.userAgent,
      rows: [{ operation: 'Benchmark run', status: 'fail', note: `${error?.name || 'Error'}: ${error?.message || 'Unexpected test failure.'}` }],
    };
  } finally {
    state.benchmarkRunning = false;
    state.benchmarkProgress = '';
    renderChat();
  }
}

function addAttackResult(name, status, details) {
  const result = { name, status, details, time: new Date().toISOString() };
  state.attackResults.unshift(result);
  logCrypto(`Security test: ${name}`, status === 'pass' ? 'success' : status === 'fail' ? 'failure' : 'info', details);
  return result;
}

async function runSecurityTests() {
  if (state.attackRunning) return;
  state.attackRunning = true;
  state.attackResults = [];
  renderChat();
  try {
    const originalEnvelope = await encryptEnvelope(state.keys.publicKey, 'QuantumSafe Chat test payload: integrity probe');
    const alteredEnvelope = { ...originalEnvelope };
    const altered = base64ToBytes(alteredEnvelope.ciphertext);
    altered[altered.length - 1] ^= 0x01;
    alteredEnvelope.ciphertext = bytesToBase64(altered);
    try {
      await decryptEnvelope(alteredEnvelope);
      addAttackResult('Ciphertext tampering', 'fail', 'Modified ciphertext decrypted unexpectedly. Investigate the authenticated-encryption test.');
    } catch (error) {
      if (error?.message === 'AES-GCM authentication failed.') {
        addAttackResult('Ciphertext tampering', 'pass', 'Modified a byte in the AES-GCM ciphertext/tag. Authenticated decryption rejected the altered envelope as expected.');
      } else {
        addAttackResult('Ciphertext tampering', 'fail', `The test failed before the expected AES-GCM rejection: ${error?.message || 'unknown error'}`);
      }
    }

    const [otherPublicKey] = state.kem.generateKeyPair();
    const otherKeyEnvelope = await encryptEnvelope(bytesToBase64(otherPublicKey), 'Wrong-recipient key test payload');
    try {
      await decryptEnvelope(otherKeyEnvelope);
      addAttackResult('Wrong private key', 'fail', 'Decryption succeeded with a private key that does not match the encapsulation public key.');
    } catch {
      addAttackResult('Wrong private key', 'pass', 'An envelope encapsulated to a different ML-KEM public key could not be authenticated/decrypted with this account’s private key.');
    }
    addAttackResult('Identity / replay protection', 'info', 'Not implemented in this version: public-key authenticity, ML-DSA signatures and replay identifiers still require Phase 2 design work.');
  } catch (error) {
    addAttackResult('Security test harness', 'fail', `${error?.name || 'Error'}: ${error?.message || 'Unexpected test setup failure.'}`);
  } finally {
    state.attackRunning = false;
    renderChat();
  }
}

async function start() {
  try {
    state.kem = await createMlKem768();
  } catch (error) {
    root.innerHTML = `<main class="fatal"><h1>Crypto library failed to load</h1><p>${escapeHtml(error.message || 'The ML-KEM module could not be initialized.')}</p><p>Run <code>npm install</code>, then restart the development server.</p></main>`;
    return;
  }

  try {
    const profile = await api('/api/me');
    const keys = readLocalKeys(profile.username);
    if (localKeyMatches(profile.kemPublicKey, keys)) {
      await enterChat(profile, keys);
      return;
    }
    await api('/api/logout', { method: 'POST' }).catch(() => {});
  } catch { /* Not logged in yet. */ }
  showAuth();
}

start();
