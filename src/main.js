import '@fontsource/dm-sans/400.css';
import '@fontsource/dm-sans/500.css';
import '@fontsource/dm-sans/600.css';
import '@fontsource/dm-sans/700.css';
import '@fontsource/dm-mono/400.css';
import '@fontsource/dm-mono/500.css';
import '@fontsource/manrope/700.css';
import '@fontsource/manrope/800.css';
import './style.css';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ChatClient } from './protocol/client.js';
import { MAX_TEXT_LENGTH } from './protocol/envelope.js';
import { checkPassword, PASSWORD_MIN_LENGTH } from './protocol/password.js';
import { removeLegacyLocalKey, scanLegacyLocalKeys } from './protocol/legacy.js';
import { runSelfTests } from './research/selftests.js';
import { ALGORITHMS, buildResearchReport } from './research/report.js';

const root = document.querySelector('#app');
const encoder = new TextEncoder();
const storage = (() => { try { return window.localStorage; } catch { return null; } })();

const state = {
  client: null,
  me: null,
  users: [],
  active: null,
  draft: '',
  drafts: {},
  unread: {},
  status: 'Connecting…',
  view: 'chat',
  showSafety: false,
  notices: [],
  cryptoEvents: [],
  benchmarkResult: null,
  benchmarkRunning: false,
  benchmarkProgress: 0,
  securityTests: [],
  securityTestsRunning: false,
  sending: false,
};

// ----- small helpers --------------------------------------------------------------------------

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function recordCryptoEvent(title, outcome = 'info', details = '') {
  state.cryptoEvents.unshift({
    at: new Date().toISOString(),
    title: String(title),
    outcome: ['success', 'failure', 'info'].includes(outcome) ? outcome : 'info',
    details: String(details ?? ''),
  });
  state.cryptoEvents = state.cryptoEvents.slice(0, 150);
}

function formatBytes(value) {
  return Number.isFinite(value) ? `${value.toLocaleString()} B` : '—';
}

function formatMs(value) {
  return Number.isFinite(value) ? `${value.toFixed(value < 1 ? 3 : 2)} ms` : '—';
}

function formatTime(value) {
  try {
    return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(new Date(value));
  } catch { return ''; }
}

function bytesEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i += 1) difference |= left[i] ^ right[i];
  return difference === 0;
}

function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function downloadText(filename, content, mime = 'text/plain;charset=utf-8') {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function shortFp(fp) {
  return fp ? fp.slice(0, 24).replace(/(.{4})/g, '$1 ').trim() : '—';
}

function addNotice(text, kind = 'danger') {
  state.notices = [{ text, kind, at: Date.now() }, ...state.notices].slice(0, 4);
}

const REJECTION_TEXT = {
  identity_changed: 'claimed a different identity key than the one you trust',
  directory_mismatch: 'used an identity that does not match the published directory',
  bad_signature: 'had an invalid sender signature',
  conversation_mismatch: 'had altered conversation metadata',
  wrong_recipient: 'was not addressed to your identity',
  replay: 'was a duplicate (replay)',
  decrypt_failed: 'failed authenticated decryption',
  malformed: 'was malformed',
  unknown_session: 'referenced an unknown session',
  stale_prekey: 'referenced prekeys that are no longer available',
};

// ----- authentication -------------------------------------------------------------------------

function legacyKeyBanner() {
  const plaintext = scanLegacyLocalKeys(storage).filter((entry) => entry.kind === 'plaintext-private-key');
  if (!plaintext.length) return '';
  return `<div class="error-banner" role="alert">This browser still holds an UNENCRYPTED private key from an old version (${plaintext.map((entry) => escapeHtml(entry.username)).join(', ')}). It is never used. <button class="small-button danger" data-action="delete-legacy-keys" type="button">Delete it</button></div>`;
}

function showAuth(errorMessage = '', usernameValue = '', initialMode = 'login') {
  root.innerHTML = `
    <main class="auth-layout">
      <section class="auth-card">
        <div class="brand-mark">Q<span>+</span></div>
        <p class="eyebrow">POST-QUANTUM MESSAGING RESEARCH PROTOTYPE</p>
        <h1>QuantumSafe Chat</h1>
        <p class="subhead">End-to-end encrypted messaging with PQXDH (X25519 + ML-KEM-768), the Double Ratchet, and Ed25519 + ML-DSA-65 identities.</p>
        <div class="crypto-note"><span class="dot"></span> OPAQUE login: your password never leaves this browser</div>
        <div class="auth-tabs">
          <button class="tab" data-mode="login" type="button">Log in</button>
          <button class="tab" data-mode="register" type="button">Create account</button>
          <button class="tab" data-mode="legacy" type="button">Upgrade legacy account</button>
        </div>
        ${errorMessage ? `<div class="error-banner" role="alert">${escapeHtml(errorMessage)}</div>` : ''}
        ${legacyKeyBanner()}
        <form id="authForm">
          <label for="username">Username</label>
          <input id="username" name="username" autocomplete="username" minlength="3" maxlength="24" pattern="[A-Za-z0-9_\\-]{3,24}" placeholder="e.g. alice_01" value="${escapeHtml(usernameValue)}" required />
          <label for="password" id="passwordLabel">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" maxlength="256" required />
          <div id="newPasswordField" hidden>
            <label for="newPassword">New password (at least ${PASSWORD_MIN_LENGTH} characters, must differ from the old one)</label>
            <input id="newPassword" name="newPassword" type="password" autocomplete="new-password" maxlength="256" />
          </div>
          <button id="authSubmit" class="primary-button" type="submit">Log in <span>→</span></button>
        </form>
        <p class="auth-footnote" id="authFootnote"></p>
      </section>
      <p class="page-caption">RESEARCH PROTOTYPE · NOT INDEPENDENTLY AUDITED · DO NOT USE FOR SENSITIVE MESSAGES</p>
    </main>`;

  const form = root.querySelector('#authForm');
  const submit = root.querySelector('#authSubmit');
  const footnotes = {
    login: 'Login uses OPAQUE: the server verifies you without ever receiving your password, and your keys are decrypted only in this browser. Only one device or tab can be signed in at a time.',
    register: `Use a long passphrase (${PASSWORD_MIN_LENGTH}+ characters). There is NO password recovery: if you forget it, your keys and history cannot be recovered by anyone, including the server operator.`,
    legacy: 'For accounts created before v0.6. This is the only time your old password is sent to the server (as the old version always did). You must choose a new password; your account gets new identity keys and old messages are imported but marked as unauthenticated.',
  };
  const setMode = (mode) => {
    form.dataset.mode = mode;
    root.querySelectorAll('[data-mode]').forEach((tab) => tab.classList.toggle('active', tab.dataset.mode === mode));
    root.querySelector('#newPasswordField').hidden = mode !== 'legacy';
    root.querySelector('#newPassword').required = mode === 'legacy';
    root.querySelector('#passwordLabel').textContent = mode === 'legacy' ? 'Old password' : 'Password';
    root.querySelector('#password').autocomplete = mode === 'register' ? 'new-password' : 'current-password';
    submit.innerHTML = { login: 'Log in <span>→</span>', register: 'Create account <span>→</span>', legacy: 'Upgrade account <span>→</span>' }[mode];
    root.querySelector('#authFootnote').textContent = footnotes[mode];
  };
  setMode(initialMode);
  root.querySelectorAll('[data-mode]').forEach((button) => button.addEventListener('click', () => setMode(button.dataset.mode)));
  root.querySelector('[data-action="delete-legacy-keys"]')?.addEventListener('click', () => {
    for (const entry of scanLegacyLocalKeys(storage)) if (entry.kind === 'plaintext-private-key') removeLegacyLocalKey(storage, entry.username);
    showAuth('The unencrypted legacy key was deleted from this browser.', form.username.value, form.dataset.mode);
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const mode = form.dataset.mode;
    const username = form.username.value.trim().toLowerCase();
    const password = form.password.value;
    const newPassword = form.newPassword.value;
    if (mode === 'register') {
      const problem = checkPassword(password, username);
      if (problem) return showAuth(problem, username, mode);
    }
    submit.disabled = true;
    submit.textContent = { login: 'Authenticating (Argon2id)…', register: 'Generating keys…', legacy: 'Upgrading account…' }[mode];
    // Let the button repaint before the CPU-heavy Argon2id / key generation work starts.
    await new Promise((resolve) => setTimeout(resolve, 30));
    const client = createClient();
    try {
      if (mode === 'register') await client.register(username, password);
      else if (mode === 'login') await client.login(username, password);
      else {
        const result = await client.migrateLegacy(username, password, newPassword);
        addNotice(`Account upgraded: ${result.migrated} old messages imported as unauthenticated history${result.unreadable ? `, ${result.unreadable} could not be decrypted` : ''}. Your contacts will see a new identity key.`, 'info');
      }
      await enterChat(client);
    } catch (error) {
      await client.logout().catch(() => {});
      showAuth(error.message || 'Something went wrong.', username, mode);
    }
  });
}

function createClient() {
  const client = new ChatClient({ storage });
  client.on('trace', (event) => {
    state.cryptoEvents.unshift(event);
    state.cryptoEvents = state.cryptoEvents.slice(0, 150);
    if (state.view === 'trace') renderApp();
  });
  client.on('message', ({ peer }) => {
    if (peer !== state.active || state.view !== 'chat') state.unread[peer] = (state.unread[peer] || 0) + 1;
    if (!state.users.some((user) => user.username === peer)) refreshUsers();
    renderApp();
  });
  client.on('history', () => renderApp());
  client.on('sent', () => { state.status = 'Delivered to relay'; renderApp(); });
  client.on('send-failed', ({ error }) => { state.status = `Relay rejected a message: ${error ?? 'unknown error'}`; renderApp(); });
  client.on('rejected', ({ code, claimedFrom }) => {
    addNotice(`A message claiming to be from ${claimedFrom} was discarded: it ${REJECTION_TEXT[code] ?? `failed verification (${code})`}.`, code === 'replay' ? 'info' : 'danger');
    renderApp();
  });
  client.on('identity-changed', ({ peer }) => {
    addNotice(`${peer}'s identity key changed. Sending to ${peer} is blocked until you compare safety numbers and accept the new key.`);
    renderApp();
  });
  client.on('users', () => refreshUsers());
  client.on('status', ({ connected }) => {
    state.status = connected ? 'Connected' : 'Disconnected — reconnecting…';
    renderApp();
  });
  client.on('server-error', ({ message }) => { state.status = message; renderApp(); });
  client.on('displaced', ({ message }) => signOut(message));
  client.on('conflict', ({ message }) => signOut(message));
  client.on('error', (error) => { state.status = error?.message ?? 'Error'; renderApp(); });
  return client;
}

async function enterChat(client) {
  Object.assign(state, {
    client, me: client.username, view: 'chat', drafts: {}, unread: {}, draft: '', showSafety: false, status: 'Connecting…',
  });
  state.users = await client.listUsers();
  state.active = state.users.find((user) => !user.legacy)?.username ?? null;
  client.connect();
  renderApp();
  if (state.active) openConversation(state.active);
}

async function signOut(message = '') {
  const { client, me } = state;
  state.client = null;
  state.me = null;
  await client?.logout().catch(() => {});
  Object.assign(state, {
    users: [], active: null, draft: '', drafts: {}, unread: {}, notices: [], cryptoEvents: [], securityTests: [], showSafety: false, view: 'chat',
  });
  showAuth(message, me ?? '');
}

async function refreshUsers() {
  if (!state.client) return;
  try {
    state.users = await state.client.listUsers();
    renderApp();
  } catch { /* transient */ }
}

function openConversation(username) {
  if (state.active) state.drafts[state.active] = state.draft;
  state.active = username;
  state.unread[username] = 0;
  state.draft = state.drafts[username] ?? '';
  state.showSafety = false;
  renderApp();
  // Detect server-side key substitution even while an old session is still active.
  state.client?.checkContactIdentity(username).then(() => renderApp()).catch(() => {});
}

async function sendMessage() {
  const text = state.draft.trim();
  const peer = state.active;
  if (!text || !peer || state.sending) return;
  if (text.length > MAX_TEXT_LENGTH) {
    state.status = `Messages are limited to ${MAX_TEXT_LENGTH.toLocaleString()} characters.`;
    return renderApp();
  }
  state.sending = true;
  state.status = 'Signing and encrypting…';
  renderApp();
  try {
    await state.client.sendText(peer, text);
    if (state.active === peer) state.draft = '';
    state.drafts[peer] = '';
    state.status = 'Waiting for relay confirmation…';
  } catch (error) {
    state.status = error.code === 'identity_changed' ? `Not sent: ${error.message}` : `Could not send: ${error.message}`;
  } finally {
    state.sending = false;
    renderApp();
  }
}

// ----- chat rendering -------------------------------------------------------------------------

function contactBadge(username) {
  const user = state.users.find((entry) => entry.username === username);
  if (user?.legacy) return '<span class="badge legacy">needs upgrade</span>';
  const contact = state.client?.contact(username) ?? { state: 'unknown' };
  return {
    verified: '<span class="badge verified">✓ verified</span>',
    unverified: '<span class="badge unverified">unverified</span>',
    changed: '<span class="badge changed">⚠ key changed</span>',
    unknown: '<span class="badge legacy">not contacted</span>',
  }[contact.state];
}

function messageBadges(message, mine) {
  if (message.legacy) return '<span class="badge legacy">legacy · sender NOT authenticated</span>';
  if (mine) {
    const label = { sending: 'sending…', sent: 'sent', failed: 'failed', received: '' }[message.status] ?? '';
    return label ? `<span class="badge ${message.status === 'failed' ? 'danger' : 'legacy'}">${label}</span>` : '';
  }
  return `<span class="badge verified" title="Ed25519 + ML-DSA-65 signature and AES-GCM authentication verified">signature ✓</span>${message.verifiedContact ? '' : '<span class="badge unverified" title="This contact\'s key was trusted on first use, not verified by safety number">unverified contact</span>'}`;
}

function renderMessages() {
  const list = root.querySelector('#messageList');
  if (!list) return;
  if (!state.active) {
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">✳</div><h3>No conversations yet</h3><p>Create another account in a second browser or private window to test messaging.</p></div>';
    return;
  }
  const history = state.client.history(state.active);
  if (!history.length) {
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">↗</div><h3>Start a conversation</h3><p>Messages are signed and encrypted in this browser. The relay only stores ciphertext until it is delivered.</p></div>';
    return;
  }
  list.innerHTML = history.map((message) => {
    const mine = message.from === state.me;
    return `<article class="message-row ${mine ? 'mine' : 'theirs'}${message.status === 'failed' ? ' decrypt-error' : ''}"><div class="message-meta"><span>${escapeHtml(mine ? 'You' : message.from)}</span><span class="message-badges">${messageBadges(message, mine)}</span><time>${escapeHtml(formatTime(message.sentAt))}</time></div><div class="bubble">${escapeHtml(message.text)}</div></article>`;
  }).join('');
  list.scrollTop = list.scrollHeight;
}

function renderIdentityPanels(activeUser) {
  if (!activeUser || activeUser.legacy) {
    return activeUser ? `<div class="alert-banner info"><span><strong>${escapeHtml(activeUser.username)}</strong> has not upgraded to v0.6 yet and cannot receive end-to-end authenticated messages.</span></div>` : '';
  }
  const name = escapeHtml(activeUser.username);
  const contact = state.client.contact(activeUser.username);
  const quarantined = state.client.quarantined(activeUser.username);
  let banner = '';
  if (contact.state === 'changed') {
    banner = `<div class="alert-banner" role="alert"><span><strong>${name}'s identity key changed.</strong> This happens if they reinstalled or upgraded, but it is also exactly what a server-side key substitution looks like. Sending is blocked${quarantined ? ` and ${quarantined} incoming message(s) are held` : ''}. Compare the new safety number with ${name} over another channel before accepting.</span><span class="actions"><button class="small-button" data-action="toggle-safety" type="button">Show new safety number</button><button class="small-button danger" data-action="accept-identity" type="button">I verified it — accept new key</button></span></div>`;
  } else if (contact.state === 'unknown') {
    banner = `<div class="alert-banner info"><span>Your first message will pin ${name}'s identity key (trust on first use). Compare safety numbers afterwards to protect against a malicious server.</span></div>`;
  }
  const safety = state.showSafety ? state.client.safetyNumber(activeUser.username) : null;
  const panel = state.showSafety ? `<div class="safety-panel">${safety ? `Safety number for you and ${name}${contact.state === 'changed' ? ' (with the NEW key)' : ''}. Read it aloud or compare it in person; if it matches on both devices, nobody substituted keys.<div class="safety-number">${safety.split(' ').map((group) => `<span>${group}</span>`).join('')}</div>${contact.state === 'unverified' ? '<button class="small-button" data-action="mark-verified" type="button">Numbers match — mark verified</button>' : contact.state === 'verified' ? '<button class="small-button" data-action="mark-unverified" type="button">Clear verification</button>' : ''}` : `No identity key is pinned for ${name} yet. Exchange a message first.`}</div>` : '';
  return banner + panel;
}

function renderChatWorkspace() {
  const activeUser = state.users.find((user) => user.username === state.active);
  const contact = activeUser && !activeUser.legacy ? state.client.contact(activeUser.username) : null;
  const canSend = Boolean(activeUser && !activeUser.legacy && contact?.state !== 'changed');
  const notices = state.notices.map((notice, index) => `<div class="alert-banner ${notice.kind === 'info' ? 'info' : ''}"><span>${escapeHtml(notice.text)}</span><span class="actions"><button class="small-button" data-dismiss="${index}" type="button">Dismiss</button></span></div>`).join('');
  return `
    <main class="workspace">
      <aside class="sidebar">
        <div class="sidebar-heading"><div><p class="eyebrow">YOUR SPACE</p><h2>Messages</h2></div><span class="count-pill">${state.users.length}</span></div>
        <div class="contact-list">
          ${state.users.length ? state.users.map((user) => `
            <button class="contact ${user.username === state.active ? 'selected' : ''} ${user.legacy ? 'legacy-contact' : ''}" data-user="${escapeHtml(user.username)}" type="button">
              <span class="contact-avatar avatar-${[...user.username].reduce((acc, char) => acc + char.charCodeAt(0), 0) % 5}">${escapeHtml(user.username.slice(0, 1).toUpperCase())}</span>
              <span class="contact-copy"><strong>${escapeHtml(user.username)}</strong><small><i class="presence ${user.online ? 'online' : ''}"></i>${user.online ? 'Online' : 'Offline'} · ${contactBadge(user.username)}</small></span>
              ${state.unread[user.username] ? `<span class="unread-count">${state.unread[user.username]}</span>` : ''}
            </button>`).join('') : '<div class="sidebar-empty">No other accounts yet.<br/><br/>Open another browser and create a second account.</div>'}
        </div>
        <div class="sidebar-footer"><span class="shield-icon">⌑</span><div><strong>End-to-end encrypted</strong><small>Relay sees metadata, not content</small></div></div>
      </aside>
      <section class="chat-panel">
        <div class="conversation-header">
          <div class="conversation-person">${activeUser ? `<span class="contact-avatar large">${escapeHtml(activeUser.username.slice(0, 1).toUpperCase())}</span><div><h2>${escapeHtml(activeUser.username)}</h2><p>${contactBadge(activeUser.username)}</p></div>` : '<div><h2>Select a conversation</h2><p>Create two accounts to test the prototype</p></div>'}</div>
          ${activeUser && !activeUser.legacy ? '<button class="secondary-button" data-action="toggle-safety" type="button">Safety number</button>' : ''}
        </div>
        ${notices}
        ${renderIdentityPanels(activeUser)}
        <div class="privacy-banner"><span class="lock-glyph">▣</span><p><strong>PQXDH + Double Ratchet, signed with Ed25519 + ML-DSA-65</strong><span>Content is end-to-end encrypted with forward secrecy. The server still sees who messages whom, when, and approximate sizes. Research prototype: not audited.</span></p></div>
        <div id="messageList" class="message-list"></div>
        <form id="composer" class="composer">
          <div class="composer-top"><span class="composer-lock">⌑</span><span>Plaintext never leaves this browser unencrypted</span><span class="char-count">${state.draft.length}/${MAX_TEXT_LENGTH}</span></div>
          <div class="composer-row"><textarea id="messageInput" maxlength="${MAX_TEXT_LENGTH}" rows="1" placeholder="${canSend ? 'Write an end-to-end encrypted message…' : 'Sending is unavailable for this contact'}" ${canSend ? '' : 'disabled'}></textarea><button id="sendButton" class="send-button" type="submit" aria-label="Send message" ${canSend && !state.sending ? '' : 'disabled'}><span>Send</span><b>↑</b></button></div>
        </form>
      </section>
    </main>`;
}

// ----- account view ---------------------------------------------------------------------------

function renderAccountView() {
  const log = state.client.securityLog().reverse();
  return `
    <main class="tool-page">
      <div class="tool-heading"><div><p class="eyebrow">ACCOUNT AND KEY CUSTODY</p><h1>Account</h1><p>Your private keys live only inside an encrypted vault that this browser unlocks with a key derived from your password through OPAQUE. The server stores the vault as ciphertext.</p></div></div>
      <div class="panel-card fingerprint-card"><div class="panel-heading"><div><p class="eyebrow">YOUR IDENTITY</p><h2>Identity fingerprint</h2></div><span class="status-tag">PUBLIC</span></div><strong class="fingerprint-value">${escapeHtml(shortFp(state.client.fingerprint))}</strong><p class="panel-note">SHA-256 over your username and Ed25519, ML-DSA-65 and X25519 identity public keys (first 96 bits shown). Contacts verify you with the per-conversation safety number.</p></div>
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">CHANGE PASSWORD</p><h2>Re-wrap the vault</h2></div></div>
        <form id="passwordForm" class="inline-form">
          <label for="currentPassword">Current password</label><input id="currentPassword" type="password" autocomplete="current-password" required />
          <label for="nextPassword">New password (${PASSWORD_MIN_LENGTH}+ characters)</label><input id="nextPassword" type="password" autocomplete="new-password" required />
          <button class="primary-button" type="submit">Change password</button>
        </form>
        <p class="panel-note">A fresh OPAQUE login proves the current password, then a new OPAQUE record is registered and the vault is re-encrypted under a new data key. Other sessions are signed out. There is no password recovery: a forgotten password means a new account.</p>
      </div>
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">SECURITY EVENTS</p><h2>Rejected messages and key changes</h2></div><span class="status-tag">${log.length}</span></div>
        ${log.length ? `<ul class="security-log">${log.map((entry) => `<li><strong>${escapeHtml(new Date(entry.at).toLocaleString())}</strong> · ${escapeHtml(entry.code)} · claimed sender ${escapeHtml(entry.claimedFrom)}</li>`).join('')}</ul>` : '<div class="event-empty">No security events.</div>'}
      </div>
    </main>`;
}

// ----- crypto trace ---------------------------------------------------------------------------

function renderTraceView() {
  const events = state.cryptoEvents.slice(0, 80).map((event) => `
    <div class="event-row"><time>${escapeHtml(new Date(event.at).toLocaleTimeString())}</time><i class="event-indicator ${event.outcome === 'failure' ? 'failure' : event.outcome === 'info' ? 'info' : ''}"></i><div class="event-copy"><strong>${escapeHtml(event.title)}</strong><p>${escapeHtml(event.details)}</p></div><span class="event-status ${event.outcome === 'failure' ? 'failure' : event.outcome === 'info' ? 'info' : ''}">${escapeHtml(event.outcome)}</span></div>`).join('');
  return `
    <main class="tool-page">
      <div class="tool-heading"><div><p class="eyebrow">LIVE PROTOCOL OBSERVABILITY</p><h1>Crypto Trace</h1><p>Operations performed by this browser, with sizes and timings. Keys, shared secrets, values derived from secrets, and plaintext are never shown or exported.</p></div><div class="heading-actions"><button class="secondary-button" data-action="clear-trace" type="button">Clear timeline</button><button class="primary-button" data-action="export-report" type="button">Export report ↗</button></div></div>
      <div class="note-grid">
        <div class="note-card"><span class="note-kicker">01 / LOGIN</span><h3>OPAQUE</h3><p>${escapeHtml(ALGORITHMS.authentication)}.</p></div>
        <div class="note-card"><span class="note-kicker">02 / SESSION</span><h3>PQXDH</h3><p>${escapeHtml(ALGORITHMS.sessionSetup)}. A session is reported as established only after the first message authenticates.</p></div>
        <div class="note-card"><span class="note-kicker">03 / MESSAGES</span><h3>Double Ratchet</h3><p>${escapeHtml(ALGORITHMS.messaging)}; ${escapeHtml(ALGORITHMS.identity)}.</p></div>
      </div>
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">EVENT TIMELINE</p><h2>Cryptographic operations</h2></div><span class="status-tag">${state.cryptoEvents.length} EVENTS</span></div><div class="event-list">${events || '<div class="event-empty">No events yet. Send or receive a message to populate this timeline.</div>'}</div></div>
      <p class="disclaimer-line">An educational observability aid, not an audit. Timings of the whole receive pipeline are shown only locally and are not secret-dependent per operation.</p>
    </main>`;
}

function exportResearchReport() {
  const report = buildResearchReport({
    events: state.cryptoEvents,
    benchmark: state.benchmarkResult,
    securityTests: state.securityTests,
    fingerprint: state.client?.fingerprint ?? null,
    environment: { userAgent: navigator.userAgent, secureContext: window.isSecureContext, sourceRevision: import.meta.env?.VITE_GIT_COMMIT },
  });
  downloadText(`quantumsafe-research-${new Date().toISOString().replace(/[:.]/g, '-')}.json`, JSON.stringify(report, null, 2), 'application/json;charset=utf-8');
}

// ----- benchmark lab --------------------------------------------------------------------------

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
  ['kemKeygen', 'ML-KEM-768 key generation (pure JavaScript)'],
  ['kemEncap', 'ML-KEM-768 encapsulation (pure JavaScript)'],
  ['kemDecap', 'ML-KEM-768 decapsulation (pure JavaScript)'],
  ['kemExchange', 'ML-KEM exchange: encap + decap (pure JavaScript)'],
  ['xKeygen', 'X25519 ephemeral key generation (native Web Crypto)'],
  ['xExport', 'X25519 public-key export (native Web Crypto)'],
  ['xDeriveBoth', 'X25519 derivation, both sides (native Web Crypto)'],
  ['xExchange', 'X25519 exchange: keygen + export + both derives (native)'],
  ['kemKdf', 'HKDF-SHA-256 on ML-KEM secret, both peers (Web Crypto)'],
  ['xKdf', 'HKDF-SHA-256 on X25519 secret, both peers (Web Crypto)'],
  ['kemEncrypt', 'AES-256-GCM encrypt 1 KiB (ML-KEM path)'],
  ['xEncrypt', 'AES-256-GCM encrypt 1 KiB (X25519 path)'],
  ['kemDecrypt', 'AES-256-GCM decrypt 1 KiB (ML-KEM path)'],
  ['xDecrypt', 'AES-256-GCM decrypt 1 KiB (X25519 path)'],
];
const KDF_INFO = encoder.encode('QuantumSafeChat Benchmark | ML-KEM-768 | AES-256-GCM');
const X25519_BENCHMARK_INFO = encoder.encode('QuantumSafeChat Benchmark | X25519 | AES-256-GCM');
const BENCHMARK_METHODOLOGY = 'Browser-local measurements; no network time. IMPORTANT: ML-KEM-768 runs as pure JavaScript (@noble/post-quantum) while X25519 runs in the browser\'s native Web Crypto implementation, so the comparison measures two different implementation environments, not the intrinsic cost of the algorithms. Native or WASM ML-KEM implementations are typically much faster. ML-KEM exchange = encapsulation + decapsulation. X25519 exchange = ephemeral key generation + raw export + deriveBits at both peers. HKDF timings include both peers. Envelope sizes are JSON/Base64 and exclude chat metadata and framing.';

async function deriveKeyWithInfo(sharedSecret, saltBytes, info) {
  const material = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function renderBenchmarkView() {
  const result = state.benchmarkResult;
  const summaries = result ? BENCHMARK_METRICS.map(([key, label]) => ({ key, label, stats: summarizeSamples(result.metrics[key] ?? []) })) : [];
  const table = result ? `
    <div class="table-wrap"><table class="results-table"><thead><tr><th>Operation</th><th>N</th><th>Mean</th><th>Median</th><th>P95</th><th>Std dev</th></tr></thead><tbody>
      ${summaries.map(({ key, label, stats }) => `<tr><td>${escapeHtml(label)}${key.startsWith('x') && !result.x25519Supported ? '<br/><small>X25519 not supported</small>' : ''}</td><td>${stats.n}</td><td class="mono-cell">${stats.n ? escapeHtml(formatMs(stats.mean)) : '—'}</td><td class="mono-cell">${stats.n ? escapeHtml(formatMs(stats.median)) : '—'}</td><td class="mono-cell">${stats.n ? escapeHtml(formatMs(stats.p95)) : '—'}</td><td class="mono-cell">${stats.n ? escapeHtml(formatMs(stats.standardDeviation)) : '—'}</td></tr>`).join('')}
    </tbody></table></div>` : '<div class="empty-lab"><div class="empty-lab-icon">↗</div><h3>No benchmark results yet</h3><p>Run the benchmark on this device. Results are measured live; nothing is preloaded.</p></div>';
  const kemMedian = result ? summarizeSamples(result.metrics.kemExchange).median : null;
  const xMedian = result?.x25519Supported ? summarizeSamples(result.metrics.xExchange).median : null;
  const chartMax = Math.max(kemMedian || 0, xMedian || 0, 0.001);
  const bar = (value) => (value == null ? 0 : Math.max(1, (value / chartMax) * 100));
  const chart = result ? `<div class="chart-list"><div class="chart-row"><div class="chart-label"><span>ML-KEM-768 encap + decap (pure JS)</span><strong>${kemMedian == null ? '—' : escapeHtml(formatMs(kemMedian))}</strong></div><progress class="research-progress chart-progress" max="100" value="${bar(kemMedian)}"></progress></div><div class="chart-row"><div class="chart-label"><span>X25519 setup + ECDH both sides (native)</span><strong>${xMedian == null ? (result.x25519Supported ? '—' : 'Not supported') : escapeHtml(formatMs(xMedian))}</strong></div><progress class="research-progress chart-progress classical-progress" max="100" value="${bar(xMedian)}"></progress></div></div>` : '';
  const sizeCards = result ? `
    <div class="metric-grid"><div class="metric-card"><span>ML-KEM public key</span><strong>${escapeHtml(formatBytes(result.sizes.kemPublicKeyBytes))}</strong><small>Observed byte length</small></div><div class="metric-card"><span>ML-KEM ciphertext</span><strong>${escapeHtml(formatBytes(result.sizes.kemCiphertextBytes))}</strong><small>Base64: ${escapeHtml(formatBytes(result.sizes.kemCiphertextBase64Bytes))}</small></div><div class="metric-card"><span>X25519 public key</span><strong>${result.x25519Supported ? escapeHtml(formatBytes(result.sizes.xPublicKeyBytes)) : 'Not supported'}</strong><small>${result.x25519Supported ? 'Observed byte length' : escapeHtml(result.x25519Error || 'Unavailable')}</small></div><div class="metric-card"><span>1 KiB envelope (JSON)</span><strong>ML-KEM ${escapeHtml(formatBytes(result.sizes.kemEnvelopeJsonBytes))}</strong><small>X25519 ${result.x25519Supported ? escapeHtml(formatBytes(result.sizes.xEnvelopeJsonBytes)) : 'not supported'}</small></div></div>` : '';
  return `
    <main class="tool-page">
      <div class="tool-heading"><div><p class="eyebrow">REPRODUCIBLE CLIENT-SIDE EXPERIMENT</p><h1>Benchmark Lab</h1><p>Measure ML-KEM-768 and an X25519 baseline in this browser. Read the methodology note: the two run in different implementation environments.</p></div><div class="heading-actions"><label class="sample-control">Samples <input id="benchmarkIterations" type="number" min="20" max="500" step="10" value="${result?.sampleCount ?? 100}" ${state.benchmarkRunning ? 'disabled' : ''}></label><button id="runBenchmarks" class="primary-button" type="button" ${state.benchmarkRunning ? 'disabled' : ''}>${state.benchmarkRunning ? 'Running…' : 'Run benchmark ↗'}</button>${result ? '<button class="secondary-button" data-action="download-benchmark-csv" type="button">Download raw CSV</button>' : ''}<button class="secondary-button" data-action="export-report" type="button">Export report</button></div></div>
      <div class="panel-card warning-card"><div class="panel-heading"><div><p class="eyebrow">METHODOLOGY</p><h2>Not an apples-to-apples comparison</h2></div><span class="status-tag">READ FIRST</span></div><p class="panel-note">${escapeHtml(BENCHMARK_METHODOLOGY)} The production protocol uses X25519 and ML-KEM-768 together (hybrid), so its cost is roughly the sum, not a choice between them.</p></div>
      ${state.benchmarkRunning ? `<div class="panel-card"><div class="benchmark-progress"><div class="spinner"></div><div><strong id="benchmarkProgressText">Running ${state.benchmarkProgress}%</strong><p>Executing real cryptographic operations.</p><progress id="benchmarkProgressBar" class="research-progress progress-track" max="100" value="${state.benchmarkProgress}"></progress></div></div></div>` : ''}
      ${result ? `<div class="benchmark-summary"><div><span>Samples per operation</span><strong>${result.sampleCount}</strong></div><div><span>Warm-up samples</span><strong>${result.warmupCount}</strong></div><div><span>Payload</span><strong>${formatBytes(result.payloadBytes)}</strong></div><div><span>Completed at</span><strong>${escapeHtml(new Date(result.completedAt).toLocaleString())}</strong></div><div><span>X25519 support</span><strong>${result.x25519Supported ? 'Available' : 'Not available'}</strong></div></div>` : ''}
      ${sizeCards}
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">KEY ESTABLISHMENT</p><h2>Median per-exchange time</h2></div><span class="status-tag">LIVE RESULTS</span></div>${chart || '<div class="event-empty">Run the benchmark to generate measured results.</div>'}</div>
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">STATISTICAL SUMMARY</p><h2>Measurements per operation</h2></div><span class="status-tag">MEAN / MEDIAN / P95 / SD</span></div>${table}</div>
      <p class="disclaimer-line">Results are device/browser-specific. Raw samples contain timings and byte lengths only.</p>
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
  let xRecipient;
  const sizes = { kemPublicKeyBytes: null, kemCiphertextBytes: null, kemCiphertextBase64Bytes: null, xPublicKeyBytes: null };
  state.benchmarkRunning = true;
  state.benchmarkProgress = 0;
  state.benchmarkResult = null;
  renderApp();
  await new Promise((resolve) => requestAnimationFrame(resolve));
  try {
    const kemRecipient = ml_kem768.keygen();
    sizes.kemPublicKeyBytes = kemRecipient.publicKey.length;
    try {
      xRecipient = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    } catch (error) {
      x25519Supported = false;
      x25519Error = error?.message || 'This browser does not support Web Crypto X25519.';
    }
    for (let i = 0; i < warmupCount + sampleCount; i += 1) {
      const row = { sample: i - warmupCount + 1, payloadBytes, x25519Supported };
      let started = performance.now();
      ml_kem768.keygen();
      row.kemKeygenMs = performance.now() - started;
      started = performance.now();
      const { cipherText, sharedSecret: senderSecret } = ml_kem768.encapsulate(kemRecipient.publicKey);
      row.kemEncapMs = performance.now() - started;
      started = performance.now();
      const recipientSecret = ml_kem768.decapsulate(cipherText, kemRecipient.secretKey);
      row.kemDecapMs = performance.now() - started;
      if (!bytesEqual(senderSecret, recipientSecret)) throw new Error('ML-KEM shared secrets differed during benchmarking.');
      row.kemExchangeMs = row.kemEncapMs + row.kemDecapMs;
      sizes.kemCiphertextBytes = cipherText.length;
      sizes.kemCiphertextBase64Bytes = encoder.encode(toBase64(cipherText)).length;
      started = performance.now();
      const kemSalt = crypto.getRandomValues(new Uint8Array(16));
      const kemSenderKey = await deriveKeyWithInfo(senderSecret, kemSalt, KDF_INFO);
      const kemReceiverKey = await deriveKeyWithInfo(recipientSecret, kemSalt, KDF_INFO);
      row.kemKdfMs = performance.now() - started;
      const kemIv = crypto.getRandomValues(new Uint8Array(12));
      started = performance.now();
      const kemCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: kemIv }, kemSenderKey, payload);
      row.kemEncryptMs = performance.now() - started;
      started = performance.now();
      const kemPlaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: kemIv }, kemReceiverKey, kemCiphertext));
      row.kemDecryptMs = performance.now() - started;
      if (!bytesEqual(kemPlaintext, payload)) throw new Error('ML-KEM-path round trip mismatch.');
      row.kemEnvelopeJsonBytes = encoder.encode(JSON.stringify({ kemCiphertext: toBase64(cipherText), salt: toBase64(kemSalt), iv: toBase64(kemIv), ciphertext: toBase64(new Uint8Array(kemCiphertext)) })).length;

      if (x25519Supported) {
        started = performance.now();
        const xEphemeral = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        row.xKeygenMs = performance.now() - started;
        started = performance.now();
        const ephemeralRaw = new Uint8Array(await crypto.subtle.exportKey('raw', xEphemeral.publicKey));
        row.xExportMs = performance.now() - started;
        sizes.xPublicKeyBytes = ephemeralRaw.length;
        started = performance.now();
        const xSecretSender = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: xRecipient.publicKey }, xEphemeral.privateKey, 256));
        const xSecretRecipient = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: xEphemeral.publicKey }, xRecipient.privateKey, 256));
        row.xDeriveBothMs = performance.now() - started;
        if (!bytesEqual(xSecretSender, xSecretRecipient)) throw new Error('X25519 shared secrets differed during benchmarking.');
        row.xExchangeMs = row.xKeygenMs + row.xExportMs + row.xDeriveBothMs;
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
        if (!bytesEqual(xPlaintext, payload)) throw new Error('X25519-path round trip mismatch.');
        row.xEnvelopeJsonBytes = encoder.encode(JSON.stringify({ ephemeralPublicKey: toBase64(ephemeralRaw), salt: toBase64(xSalt), iv: toBase64(xIv), ciphertext: toBase64(new Uint8Array(xCiphertext)) })).length;
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
      for (const [metric] of BENCHMARK_METRICS) {
        if (Number.isFinite(row[`${metric}Ms`])) metrics[metric].push(row[`${metric}Ms`]);
      }
    }
    const meanOf = (key) => {
      const values = rawRows.map((row) => row[key]).filter(Number.isFinite);
      return values.length ? Math.round(values.reduce((sum, value) => sum + value, 0) / values.length) : null;
    };
    sizes.kemEnvelopeJsonBytes = meanOf('kemEnvelopeJsonBytes');
    sizes.xEnvelopeJsonBytes = x25519Supported ? meanOf('xEnvelopeJsonBytes') : null;
    state.benchmarkResult = {
      createdAt: startedAt, completedAt: new Date().toISOString(), sampleCount, warmupCount, payloadBytes,
      x25519Supported, x25519Error, sizes, metrics, rawRows,
      implementations: { mlKem768: '@noble/post-quantum (pure JavaScript)', x25519: 'Web Crypto API (native browser implementation)', hkdfAesGcm: 'Web Crypto API (native)' },
      methodology: BENCHMARK_METHODOLOGY,
      browser: navigator.userAgent,
      sourceRevision: import.meta.env?.VITE_GIT_COMMIT || 'not embedded in this build',
    };
    recordCryptoEvent('Benchmark run completed', 'success', `${sampleCount} samples after ${warmupCount} warm-ups; X25519 ${x25519Supported ? 'available' : 'unavailable'}.`);
  } catch (error) {
    recordCryptoEvent('Benchmark run failed', 'failure', error?.message || 'Unknown failure.');
  } finally {
    state.benchmarkRunning = false;
    state.benchmarkProgress = 100;
    renderApp();
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

// ----- security self-tests --------------------------------------------------------------------

function renderSecurityTestsView() {
  const results = state.securityTests;
  const rows = results.length ? `<div class="test-results">${results.map((test) => `
    <div class="test-result"><span class="test-symbol ${test.status === 'FAIL' ? 'fail' : ''}">${test.status === 'PASS' ? '✓' : '!'}</span><div><strong>${escapeHtml(test.name)}</strong><p>${escapeHtml(test.details)}</p><small>${escapeHtml(formatMs(test.durationMs))}</small></div><span class="event-status ${test.status === 'FAIL' ? 'failure' : ''}">${escapeHtml(test.status)}</span></div>`).join('')}</div>` : '<div class="empty-lab"><div class="empty-lab-icon">✓</div><h3>No test results yet</h3><p>Each check builds real protocol envelopes with the production code, attacks them, and records what actually happened.</p></div>';
  const passed = results.filter((test) => test.status === 'PASS').length;
  const failed = results.filter((test) => test.status === 'FAIL').length;
  return `
    <main class="tool-page">
      <div class="tool-heading"><div><p class="eyebrow">ATTACKS ON REAL ENVELOPES</p><h1>Security Tests</h1><p>These tests call the same encryptEnvelope / openEnvelope / vault functions the chat uses, on disposable identities. A PASS means the attack was rejected as expected; it does not certify the application.</p></div><div class="heading-actions"><button id="runSecurityTests" class="primary-button" type="button" ${state.securityTestsRunning ? 'disabled' : ''}>${state.securityTestsRunning ? 'Running tests…' : 'Run security tests ↗'}</button><button class="secondary-button" data-action="export-report" type="button">Export report</button></div></div>
      <div class="metric-grid"><div class="metric-card"><span>Passed</span><strong>${passed}</strong><small>Attack rejected as expected</small></div><div class="metric-card"><span>Failed</span><strong>${failed}</strong><small>Unexpected behaviour</small></div><div class="metric-card"><span>Test material</span><strong>Disposable</strong><small>No account keys or messages used</small></div><div class="metric-card"><span>Server path</span><strong>npm test</strong><small>Relay attacks run in the automated suite</small></div></div>
      <div class="panel-card"><div class="panel-heading"><div><p class="eyebrow">OBSERVED RESULTS</p><h2>Execution results</h2></div><span class="status-tag">${results.length} TESTS</span></div>${rows}</div>
    </main>`;
}

async function runSecurityTests() {
  if (state.securityTestsRunning) return;
  state.securityTestsRunning = true;
  state.securityTests = [];
  renderApp();
  await new Promise((resolve) => setTimeout(resolve, 30));
  try {
    await runSelfTests((entry) => {
      state.securityTests.push(entry);
      recordCryptoEvent(`Security test: ${entry.name}`, entry.status === 'PASS' ? 'success' : 'failure', entry.details);
      renderApp();
    });
  } catch (error) {
    state.securityTests.push({ name: 'Security test runner', status: 'FAIL', details: error?.message ?? 'Runner failure', durationMs: 0 });
  } finally {
    state.securityTestsRunning = false;
    renderApp();
  }
}

// ----- shell ----------------------------------------------------------------------------------

function renderView() {
  if (state.view === 'trace') return renderTraceView();
  if (state.view === 'benchmark') return renderBenchmarkView();
  if (state.view === 'tests') return renderSecurityTestsView();
  if (state.view === 'account') return renderAccountView();
  return renderChatWorkspace();
}

function bindView() {
  root.querySelectorAll('[data-action="export-report"]').forEach((button) => button.addEventListener('click', exportResearchReport));
  root.querySelector('[data-action="clear-trace"]')?.addEventListener('click', () => { state.cryptoEvents = []; renderApp(); });
  root.querySelector('#runBenchmarks')?.addEventListener('click', runBenchmarks);
  root.querySelector('[data-action="download-benchmark-csv"]')?.addEventListener('click', downloadBenchmarkCsv);
  root.querySelector('#runSecurityTests')?.addEventListener('click', runSecurityTests);
  root.querySelector('#passwordForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button');
    button.disabled = true;
    button.textContent = 'Changing password…';
    try {
      await state.client.changePassword(form.currentPassword.value, form.nextPassword.value);
      addNotice('Password changed. Other sessions were signed out.', 'info');
      state.view = 'chat';
    } catch (error) {
      addNotice(`Password not changed: ${error.message}`);
    }
    renderApp();
  });

  root.querySelectorAll('[data-user]').forEach((button) => button.addEventListener('click', () => openConversation(button.dataset.user)));
  root.querySelectorAll('[data-dismiss]').forEach((button) => button.addEventListener('click', () => {
    state.notices.splice(Number(button.dataset.dismiss), 1);
    renderApp();
  }));
  root.querySelectorAll('[data-action="toggle-safety"]').forEach((button) => button.addEventListener('click', () => {
    state.showSafety = !state.showSafety;
    renderApp();
  }));
  root.querySelector('[data-action="mark-verified"]')?.addEventListener('click', async () => {
    await state.client.setVerified(state.active, true).catch((error) => addNotice(error.message));
    renderApp();
  });
  root.querySelector('[data-action="mark-unverified"]')?.addEventListener('click', async () => {
    await state.client.setVerified(state.active, false).catch((error) => addNotice(error.message));
    renderApp();
  });
  root.querySelector('[data-action="accept-identity"]')?.addEventListener('click', async () => {
    const peer = state.active;
    // eslint-disable-next-line no-alert
    if (!window.confirm(`Accept ${peer}'s NEW identity key?\n\nOnly do this after comparing the new safety number with ${peer} in person or over another trusted channel. If you skip that, a malicious server could be reading your messages.`)) return;
    try {
      await state.client.acceptIdentityChange(peer);
      addNotice(`${peer}'s new key was accepted and pinned as unverified.`, 'info');
    } catch (error) {
      addNotice(error.message);
    }
    renderApp();
  });

  const textarea = root.querySelector('#messageInput');
  if (!textarea) return;
  textarea.value = state.draft;
  textarea.addEventListener('input', () => {
    state.draft = textarea.value;
    if (state.active) state.drafts[state.active] = state.draft;
    const count = root.querySelector('.char-count');
    if (count) count.textContent = `${state.draft.length}/${MAX_TEXT_LENGTH}`;
  });
  textarea.addEventListener('keydown', (event) => {
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

function renderApp() {
  if (!state.me || !state.client) return;
  const previousTextarea = root.querySelector('#messageInput');
  const restoreFocus = Boolean(previousTextarea && document.activeElement === previousTextarea);
  const statusClass = state.status === 'Connected' || state.status === 'Delivered to relay' ? 'good' : 'neutral';
  const nav = [['chat', 'Messages'], ['trace', 'Crypto Trace'], ['benchmark', 'Benchmark Lab'], ['tests', 'Security Tests'], ['account', 'Account']];
  root.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <div class="brand-lockup"><div class="brand-mark small">Q<span>+</span></div><div><strong>QuantumSafe <span>Chat</span></strong><small>MESSAGING + RESEARCH LAB</small></div></div>
        <nav class="main-nav" aria-label="Application sections">${nav.map(([view, label]) => `<button class="nav-item ${state.view === view ? 'active' : ''}" data-view="${view}" type="button">${label}</button>`).join('')}</nav>
        <div class="topbar-right"><div class="connection-pill ${statusClass}"><i></i>${escapeHtml(state.status)}</div><div class="account-chip"><span class="avatar">${escapeHtml(state.me.slice(0, 1).toUpperCase())}</span><span>${escapeHtml(state.me)}</span></div><button id="logoutButton" class="logout-button" type="button">Log out</button></div>
      </header>
      ${renderView()}
      <footer class="app-footer"><span><i class="footer-dot"></i> RESEARCH PROTOTYPE · NOT INDEPENDENTLY AUDITED</span><span>See SECURITY.md for the threat model and limitations</span></footer>
    </div>`;
  root.querySelector('#logoutButton').addEventListener('click', () => signOut());
  root.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => {
    if (state.active) state.drafts[state.active] = state.draft;
    state.view = button.dataset.view;
    if (state.view === 'chat' && state.active) state.unread[state.active] = 0;
    renderApp();
  }));
  bindView();
  if (restoreFocus) root.querySelector('#messageInput')?.focus({ preventScroll: true });
}

async function start() {
  // A server session cookie may survive a reload, but the vault key does not: ask for the password again.
  try {
    const response = await fetch('/api/session', { credentials: 'same-origin' });
    const { username } = response.ok ? await response.json() : {};
    if (username) return showAuth('Enter your password to unlock your encrypted keys on this device.', username);
  } catch { /* offline or no session */ }
  showAuth();
}

start();
