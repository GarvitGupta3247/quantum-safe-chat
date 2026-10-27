import { createMlKem768 } from 'mlkem';
import './style.css';

const root = document.querySelector('#app');
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KDF_INFO = encoder.encode('QuantumSafeChat PoC v1 | ML-KEM-768 | AES-256-GCM');
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
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await derivePrivateKeyWrappingKey(password, saltBytes);
  const encryptedPrivateKey = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivBytes },
    wrappingKey,
    base64ToBytes(keys.privateKey),
  );
  return {
    version: PRIVATE_KEY_STORAGE_VERSION,
    publicKey: keys.publicKey,
    kdf: 'PBKDF2-HMAC-SHA-256',
    iterations: PRIVATE_KEY_PBKDF2_ITERATIONS,
    salt: bytesToBase64(saltBytes),
    iv: bytesToBase64(ivBytes),
    encryptedPrivateKey: bytesToBase64(new Uint8Array(encryptedPrivateKey)),
  };
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
    return {
      publicKey: bundle.publicKey,
      privateKey: bytesToBase64(new Uint8Array(privateKeyBytes)),
      storageVersion: PRIVATE_KEY_STORAGE_VERSION,
    };
  } catch {
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
        const [publicKeyBytes, privateKeyBytes] = state.kem.generateKeyPair();
        keys = { publicKey: bytesToBase64(publicKeyBytes), privateKey: bytesToBase64(privateKeyBytes) };
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
  state.keys = { ...keys, privateKeyBytes: base64ToBytes(keys.privateKey), publicKeyBytes: base64ToBytes(keys.publicKey) };
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
      encryptEnvelope(recipient.kemPublicKey, text),
      encryptEnvelope(state.keys.publicKey, text),
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
    if (state.socket?.readyState === WebSocket.OPEN) {
      state.socket.send(JSON.stringify(packet));
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
        <div class="brand-lockup"><div class="brand-mark small">Q<span>+</span></div><div><strong>QuantumSafe <span>Chat</span></strong><small>MESSAGING PROTOTYPE</small></div></div>
        <div class="topbar-right"><div class="connection-pill ${statusClass}"><i></i>${escapeHtml(state.status)}</div><div class="account-chip"><span class="avatar">${escapeHtml(state.me.slice(0, 1).toUpperCase())}</span><span>${escapeHtml(state.me)}</span></div><button id="logoutButton" class="logout-button" type="button">Log out</button></div>
      </header>
      ${renderChatWorkspace()}
      <footer class="app-footer"><span><i class="footer-dot"></i> EXPERIMENTAL PQC PROTOTYPE</span><span>ML-DSA identity verification + forward secrecy planned for Phase 2</span></footer>
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
    showAuth();
  });
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
