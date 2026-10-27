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
        <p class="auth-footnote">Demo accounts only. Your ML-KEM private key is kept in this browser's local storage. Do not use sensitive messages.</p>
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
        const [publicKeyBytes, privateKeyBytes] = state.kem.generateKeyPair();
        keys = { publicKey: bytesToBase64(publicKeyBytes), privateKey: bytesToBase64(privateKeyBytes) };
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
  const [kemCiphertext, sharedSecret] = state.kem.encap(publicKey);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveMessageKey(sharedSecret, salt);
  const plaintextBytes = encoder.encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextBytes);
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
  const sharedSecret = state.kem.decap(kemCiphertext, state.keys.privateKeyBytes);
  const salt = base64ToBytes(envelope.salt);
  const key = await deriveMessageKey(sharedSecret, salt);
  const iv = base64ToBytes(envelope.iv);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return decoder.decode(plaintext);
  } catch {
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
    state.socket.send(JSON.stringify(packet));
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
  root.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <div class="brand-lockup"><div class="brand-mark small">Q<span>+</span></div><div><strong>QuantumSafe <span>Chat</span></strong><small>MESSAGING PROTOTYPE</small></div></div>
        <div class="topbar-right"><div class="connection-pill ${statusClass}"><i></i>${escapeHtml(state.status)}</div><div class="account-chip"><span class="avatar">${escapeHtml(state.me.slice(0, 1).toUpperCase())}</span><span>${escapeHtml(state.me)}</span></div><button id="logoutButton" class="logout-button" type="button">Log out</button></div>
      </header>
      ${renderChatWorkspace()}
      <footer class="app-footer"><span><i class="footer-dot"></i> EXPERIMENTAL PQC PROTOTYPE</span><span>ML-DSA identity verification + forward secrecy planned for Phase 2</span></footer>
    </div>`;

  root.querySelector('#logoutButton').addEventListener('click', async () => {
    try { await api('/api/logout', { method: 'POST' }); } catch { /* sign out locally anyway */ }
    state.socket?.close();
    state.me = null; state.keys = null; state.users = []; state.active = null; state.messages = [];
    showAuth();
  });
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
