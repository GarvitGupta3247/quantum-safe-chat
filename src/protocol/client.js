// Headless client: OPAQUE authentication, encrypted vault custody, identity pinning, the messaging
// protocol and the relay connection. The browser UI and the automated tests both drive this class,
// so the tests exercise the same code path users run.

import * as opaque from '@serenity-kit/opaque';
import { identityFingerprint, ProtocolError, safetyNumber as computeSafetyNumber } from './identity.js';
import {
  acceptIdentityChange, checkPeerIdentity, contactStatus, createAccountVault, encryptEnvelope, generatePrekeys,
  needsPrekeys, openEnvelope, recordIdentityChange, setVerified,
} from './envelope.js';
import { deriveKek, generateDek, openVault, sealVault, unwrapDek, wrapDek } from './vault.js';
import { checkPassword, KEY_STRETCHING } from './password.js';
import { decryptLegacyEnvelope, removeLegacyLocalKey, unlockLegacyBundle } from './legacy.js';
import { wipe } from './bytes.js';

const MAX_HISTORY_PER_CONTACT = 1000;
const MAX_QUARANTINE = 50;
const MAX_SECURITY_LOG = 100;
const SPK_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;

export class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

export class ChatClient {
  #vault = null;
  #dek = null;
  #version = 0;
  #chain = Promise.resolve();
  #socket = null;
  #reconnectTimer = null;
  #reconnectAttempts = 0;
  #listeners = new Map();
  #stopped = true;
  #inflight = new Set();

  constructor({ baseUrl = '', fetch: fetchImpl, createWebSocket, wsUrl, storage = null } = {}) {
    this.baseUrl = baseUrl;
    this.fetchImpl = fetchImpl ?? ((...args) => globalThis.fetch(...args));
    this.createWebSocket = createWebSocket ?? ((url) => new globalThis.WebSocket(url));
    this.wsUrl = wsUrl ?? (() => {
      const origin = baseUrl || globalThis.location.origin;
      return `${origin.replace(/^http/, 'ws')}/ws`;
    })();
    this.storage = storage;
    this.username = null;
    this.connected = false;
  }

  // ----- events -------------------------------------------------------------------------------
  on(event, handler) {
    if (!this.#listeners.has(event)) this.#listeners.set(event, new Set());
    this.#listeners.get(event).add(handler);
    return () => this.#listeners.get(event)?.delete(handler);
  }

  #emit(event, data) {
    for (const handler of this.#listeners.get(event) ?? []) {
      try { handler(data); } catch { /* listeners must not break the protocol */ }
    }
  }

  // Trace events describe operations and sizes only: never keys, secrets, digests of secrets or plaintext.
  #trace(title, outcome, details) {
    this.#emit('trace', { at: new Date().toISOString(), title, outcome, details });
  }

  // Serialises every vault mutation, so concurrent sends/receives cannot fork ratchet state.
  #exclusive(task) {
    const run = this.#chain.then(task);
    this.#chain = run.catch(() => {});
    return run;
  }

  async #request(path, { method = 'GET', body } = {}) {
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        credentials: 'same-origin',
        headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new ApiError(0, 'Network error: the server could not be reached.');
    }
    const parsed = await response.json().catch(() => ({}));
    if (!response.ok) throw new ApiError(response.status, parsed.error || `Request failed (${response.status})`, parsed);
    return parsed;
  }

  // ----- account lifecycle ---------------------------------------------------------------------
  async register(username, password, { migration = null } = {}) {
    username = String(username).trim().toLowerCase();
    const policyError = checkPassword(password, username);
    if (policyError) throw new Error(policyError);
    await opaque.ready;
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password });
    const { registrationResponse } = await this.#request('/api/auth/register/start', {
      method: 'POST', body: { username, registrationRequest, migrationToken: migration?.token },
    });
    const { registrationRecord, exportKey } = opaque.client.finishRegistration({
      clientRegistrationState, registrationResponse, password, keyStretching: KEY_STRETCHING,
    });
    this.#trace('OPAQUE registration completed', 'success', 'Password processed locally with Argon2id (64 MiB, t=3) inside OPAQUE; only the registration record is sent. The password and export key never leave this device.');
    const { vault, upload } = createAccountVault(username);
    this.#trace('Identity and prekeys generated', 'success', `Ed25519 + ML-DSA-65 signing identity, X25519 identity key, signed X25519 and ML-KEM-768 prekeys, ${upload.opks.length} one-time X25519 and ${upload.pqopks.length} one-time ML-KEM-768 prekeys.`);
    if (migration?.history) vault.history = migration.history;
    const dek = generateDek();
    const wrappedDek = await wrapDek(await deriveKek(exportKey, username), dek, username);
    const blob = await sealVault(dek, username, 1, vault);
    await this.#request('/api/auth/register/finish', {
      method: 'POST',
      body: {
        username, registrationRecord, identity: upload.identity, migrationToken: migration?.token,
        prekeys: { spk: upload.spk, pqspk: upload.pqspk, opks: upload.opks, pqopks: upload.pqopks },
        vault: { wrappedDek, blob },
      },
    });
    this.#trace('Encrypted vault stored', 'success', 'Identity keys, prekeys and sessions are stored on the server only as AES-256-GCM ciphertext under a key wrapped by the OPAQUE export key.');
    this.#activate(username, vault, dek, 1);
    return { username, fingerprint: vault.identity.fp };
  }

  async login(username, password) {
    username = String(username).trim().toLowerCase();
    await opaque.ready;
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
    const { loginId, loginResponse } = await this.#request('/api/auth/login/start', { method: 'POST', body: { username, startLoginRequest } });
    const result = opaque.client.finishLogin({ clientLoginState, loginResponse, password, keyStretching: KEY_STRETCHING });
    if (!result) {
      this.#trace('OPAQUE login rejected locally', 'failure', 'The server response did not authenticate with this password; nothing further was sent.');
      throw new Error('Incorrect username or password. Accounts created before v0.6 must use "Upgrade legacy account" once.');
    }
    const response = await this.#request('/api/auth/login/finish', { method: 'POST', body: { loginId, finishLoginRequest: result.finishLoginRequest } });
    const { vault, dek } = await this.#unlockVault(username, result.exportKey, response.vault);
    this.#trace('OPAQUE login and vault unlock', 'success', `Mutual authentication completed without sending the password. Vault version ${response.vault.version} decrypted locally.`);
    this.#activate(username, vault, dek, response.vault.version);
    await this.#maintainPrekeys().catch((error) => this.#trace('Prekey maintenance failed', 'failure', error.message));
    return { username, fingerprint: vault.identity.fp };
  }

  async #unlockVault(username, exportKey, serverVault) {
    const kek = await deriveKek(exportKey, username);
    const dek = await unwrapDek(kek, serverVault.wrappedDek, username);
    const vault = await openVault(dek, username, serverVault.version, serverVault.blob);
    const seenVersion = Number(this.#storageGet(`qsc:vault-version:${username}`) ?? 0);
    if (serverVault.version < seenVersion) {
      await this.#request('/api/auth/logout', { method: 'POST', body: {} }).catch(() => {});
      throw new ProtocolError('vault_rollback', `The server returned vault version ${serverVault.version}, older than version ${seenVersion} already seen on this device. Possible rollback; refusing to continue.`);
    }
    return { vault, dek };
  }

  #activate(username, vault, dek, version) {
    this.username = username;
    this.#vault = vault;
    this.#dek = dek;
    this.#version = version;
    this.#storageSet(`qsc:vault-version:${username}`, version);
    this.#stopped = false;
  }

  async migrateLegacy(username, oldPassword, newPassword) {
    username = String(username).trim().toLowerCase();
    if (newPassword === oldPassword) throw new Error('Choose a new password. The old one was sent to the server by the previous version and must be retired.');
    const policyError = checkPassword(newPassword, username);
    if (policyError) throw new Error(policyError);
    const legacy = await this.#request('/api/legacy/start', { method: 'POST', body: { username, password: oldPassword } });
    const history = {};
    let migrated = 0;
    let unreadable = 0;
    if (legacy.privateKeyBundle) {
      const legacyKey = await unlockLegacyBundle(legacy.privateKeyBundle, oldPassword);
      for (const message of legacy.messages) {
        const other = message.sender === username ? message.recipient : message.sender;
        try {
          const text = await decryptLegacyEnvelope(message.envelope, legacyKey);
          (history[other] ??= []).push({
            id: `legacy-${message.id}`, from: message.sender, to: message.recipient, text,
            sentAt: Date.parse(message.createdAt) || 0, legacy: true, authenticated: false, status: 'legacy',
          });
          migrated += 1;
        } catch {
          unreadable += 1;
        }
      }
      wipe(legacyKey);
    } else {
      unreadable = legacy.messages.length;
    }
    await this.register(username, newPassword, { migration: { token: legacy.migrationToken, history } });
    removeLegacyLocalKey(this.storage, username);
    this.#trace('Legacy account upgraded', 'info', `${migrated} legacy messages imported as UNAUTHENTICATED history; ${unreadable} could not be decrypted. A new identity was created, so contacts will see a new key.`);
    return { migrated, unreadable };
  }

  async changePassword(currentPassword, newPassword) {
    const username = this.#requireSession();
    const policyError = checkPassword(newPassword, username);
    if (policyError) throw new Error(policyError);
    if (newPassword === currentPassword) throw new Error('The new password must be different.');
    return this.#exclusive(async () => {
      // The fresh login below revokes this account's sessions, including ours; detach our socket
      // first so its close is not mistaken for being displaced by another device.
      const ownSocket = this.#socket;
      this.#socket = null;
      ownSocket?.close(1000, 'Re-authenticating');
      // Fresh OPAQUE login proves knowledge of the current password (server requires auth < 5 min old).
      const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password: currentPassword });
      const { loginId, loginResponse } = await this.#request('/api/auth/login/start', { method: 'POST', body: { username, startLoginRequest } });
      const result = opaque.client.finishLogin({ clientLoginState, loginResponse, password: currentPassword, keyStretching: KEY_STRETCHING });
      if (!result) throw new Error('The current password is incorrect.');
      await this.#request('/api/auth/login/finish', { method: 'POST', body: { loginId, finishLoginRequest: result.finishLoginRequest } });
      const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password: newPassword });
      const { registrationResponse } = await this.#request('/api/auth/password/start', { method: 'POST', body: { registrationRequest } });
      const { registrationRecord, exportKey } = opaque.client.finishRegistration({ clientRegistrationState, registrationResponse, password: newPassword, keyStretching: KEY_STRETCHING });
      // Rotate the data key as well, so an old wrapped key plus the old password opens nothing new.
      const dek = generateDek();
      const wrappedDek = await wrapDek(await deriveKek(exportKey, username), dek, username);
      const blob = await sealVault(dek, username, this.#version + 1, this.#vault);
      const response = await this.#request('/api/auth/password/finish', { method: 'POST', body: { registrationRecord, wrappedDek, blob, expectedVersion: this.#version } });
      wipe(this.#dek);
      this.#dek = dek;
      this.#version = response.vaultVersion;
      this.#storageSet(`qsc:vault-version:${username}`, this.#version);
      this.#trace('Password changed', 'success', 'New OPAQUE record registered; vault re-encrypted under a new data key. Other sessions were signed out.');
      return true;
    }).then((result) => { this.connect(); return result; });
  }

  async logout() {
    this.#stopped = true;
    clearTimeout(this.#reconnectTimer);
    const socket = this.#socket;
    this.#socket = null;
    socket?.close(1000, 'Logged out');
    await this.#request('/api/auth/logout', { method: 'POST', body: {} }).catch(() => {});
    if (this.#dek) wipe(this.#dek);
    this.#vault = null;
    this.#dek = null;
    this.username = null;
    this.connected = false;
  }

  // ----- vault persistence --------------------------------------------------------------------
  #requireSession() {
    if (!this.#vault) throw new Error('Not logged in.');
    return this.username;
  }

  async #save() {
    const blob = await sealVault(this.#dek, this.username, this.#version + 1, this.#vault);
    try {
      const { version } = await this.#request('/api/vault', { method: 'PUT', body: { expectedVersion: this.#version, blob } });
      this.#version = version;
      this.#storageSet(`qsc:vault-version:${this.username}`, version);
    } catch (error) {
      if (error.status === 409 || error.status === 401) {
        this.#emit('conflict', { message: 'This account changed in another session. Log in again to continue.' });
        this.#stopped = true;
        this.#socket?.close(1000, 'Conflict');
      }
      throw error;
    }
  }

  #storageGet(key) {
    try { return this.storage?.getItem(key) ?? null; } catch { return null; }
  }

  #storageSet(key, value) {
    try {
      const previous = Number(this.storage?.getItem(key) ?? 0);
      if (value > previous) this.storage?.setItem(key, String(value));
    } catch { /* storage unavailable: rollback detection is best effort */ }
  }

  async #maintainPrekeys() {
    const me = await this.#request('/api/me');
    const needOpk = me.prekeys.opks < 10 ? 20 : 0;
    const needPq = me.prekeys.pqopks < 5 ? 10 : 0;
    const rotate = !me.prekeys.spkCreatedAt || Date.now() - me.prekeys.spkCreatedAt > SPK_ROTATION_MS;
    if (!needOpk && !needPq && !rotate) return;
    await this.#exclusive(async () => {
      const { vault, upload } = generatePrekeys(this.#vault, { opkCount: needOpk, pqopkCount: needPq, rotateSigned: rotate });
      this.#vault = vault;
      await this.#save(); // persist private halves before publishing public halves
      await this.#request('/api/prekeys', { method: 'POST', body: upload });
      this.#trace('Prekeys replenished', 'success', `${upload.opks.length} X25519 one-time, ${upload.pqopks.length} ML-KEM one-time${rotate ? ', signed prekeys rotated' : ''}.`);
    });
  }

  // ----- read-only views ----------------------------------------------------------------------
  get fingerprint() { return this.#vault?.identity.fp ?? null; }
  get identityBundle() { return this.#vault?.identity.bundle ?? null; }
  get vaultVersion() { return this.#version; }

  history(peer) {
    return [...(this.#vault?.history[peer] ?? [])].sort((a, b) => a.sentAt - b.sentAt);
  }

  contact(peer) {
    if (!this.#vault) return { state: 'unknown' };
    return contactStatus(this.#vault, peer);
  }

  quarantined(peer) {
    return (this.#vault?.quarantine ?? []).filter((entry) => entry.from === peer).length;
  }

  securityLog() {
    return [...(this.#vault?.securityLog ?? [])];
  }

  safetyNumber(peer) {
    const contact = this.#vault?.contacts[peer];
    if (!contact) return null;
    const bundle = contact.pendingChange?.bundle ?? contact.bundle;
    return computeSafetyNumber(this.#vault.identity.bundle, bundle);
  }

  async listUsers() {
    return (await this.#request('/api/users')).users;
  }

  // ----- identity management ------------------------------------------------------------------
  // Fetches the server's current identity for `peer` and compares it with the pinned key.
  async checkContactIdentity(peer) {
    this.#requireSession();
    let identity;
    try { ({ identity } = await this.#request(`/api/users/${encodeURIComponent(peer)}/identity`)); } catch (error) {
      if (error.status === 404) return this.contact(peer);
      throw error;
    }
    return this.#exclusive(async () => {
      const result = checkPeerIdentity(this.#vault, peer, identity);
      if (result.state === 'changed' && !this.#vault.contacts[peer].pendingChange) {
        this.#vault = recordIdentityChange(this.#vault, peer, identity);
        this.#logSecurity('identity_changed', peer, 'Directory identity differs from the pinned key.');
        await this.#save();
        this.#emit('identity-changed', { peer });
        this.#trace('Identity key change detected', 'failure', `The server now publishes a different identity for ${peer}. Sending is blocked until you verify and accept it.`);
      }
      return this.contact(peer);
    });
  }

  async acceptIdentityChange(peer) {
    return this.#exclusive(async () => {
      this.#vault = acceptIdentityChange(this.#vault, peer);
      const pending = this.#vault.quarantine.filter((entry) => entry.from === peer);
      this.#vault = { ...this.#vault, quarantine: this.#vault.quarantine.filter((entry) => entry.from !== peer) };
      await this.#save();
      this.#trace('New identity accepted', 'info', `${peer}'s new identity key was accepted by the user and is now pinned as UNVERIFIED.`);
      if (pending.length) await this.#processPackets(pending.map((entry) => ({ qid: null, packet: entry.packet })));
      return this.contact(peer);
    });
  }

  async setVerified(peer, verified = true) {
    return this.#exclusive(async () => {
      this.#vault = setVerified(this.#vault, peer, verified);
      await this.#save();
      return this.contact(peer);
    });
  }

  #logSecurity(code, claimedFrom, detail) {
    const entry = { at: Date.now(), code, claimedFrom, detail };
    this.#vault = { ...this.#vault, securityLog: [...this.#vault.securityLog, entry].slice(-MAX_SECURITY_LOG) };
    return entry;
  }

  // ----- messaging ----------------------------------------------------------------------------
  async sendText(peer, text) {
    this.#requireSession();
    return this.#exclusive(async () => {
      let prekeys = null;
      if (needsPrekeys(this.#vault, peer)) {
        prekeys = await this.#request(`/api/users/${encodeURIComponent(peer)}/prekeys`, { method: 'POST', body: {} });
        const check = checkPeerIdentity(this.#vault, peer, prekeys.identity);
        if (check.state === 'changed') {
          if (!this.#vault.contacts[peer].pendingChange) {
            this.#vault = recordIdentityChange(this.#vault, peer, prekeys.identity);
            this.#logSecurity('identity_changed', peer, 'Prekey bundle identity differs from the pinned key.');
            await this.#save();
            this.#emit('identity-changed', { peer });
          }
          throw new ProtocolError('identity_changed', `${peer}'s identity key changed. Compare safety numbers before accepting the new key.`);
        }
        if (check.state === 'new') {
          this.#trace('Identity pinned on first use', 'info', `${peer}'s identity was pinned (trust on first use). Compare safety numbers to mark it verified.`);
        }
      }
      const started = performance.now();
      const { vault, packet } = await encryptEnvelope(this.#vault, { peer, text, prekeys });
      const entry = { id: packet.h.id, from: this.username, to: peer, text, sentAt: packet.h.ts, status: 'sending', authenticated: true };
      this.#vault = this.#appendHistory({ ...vault, outbox: [...vault.outbox, { id: packet.h.id, packet }] }, peer, entry);
      if (prekeys) {
        this.#trace('PQXDH session started', 'success', `X25519 DH x${prekeys.opk ? 4 : 3} + ML-KEM-768 encapsulation (${prekeys.pq.kind === 'pqopk' ? 'one-time' : 'last-resort'} prekey); signatures on prekeys verified.`);
      }
      this.#trace('Message signed and encrypted', 'success', `Double Ratchet message key -> AES-256-GCM over ${Math.ceil(JSON.stringify({ text }).length / 256) * 256} padded bytes; header and ciphertext signed with Ed25519 + ML-DSA-65; packet ${JSON.stringify(packet).length} bytes; ${(performance.now() - started).toFixed(1)} ms.`);
      // Persist the advanced ratchet before the packet leaves this device.
      await this.#save();
      this.#transmit(packet);
      this.#emit('history', { peer });
      return entry;
    });
  }

  #appendHistory(vault, peer, entry) {
    const list = [...(vault.history[peer] ?? []).filter((item) => item.id !== entry.id), entry].slice(-MAX_HISTORY_PER_CONTACT);
    return { ...vault, history: { ...vault.history, [peer]: list } };
  }

  #transmit(packet) {
    if (this.#socket?.readyState === 1) this.#socket.send(JSON.stringify({ type: 'send', packet }));
  }

  // First contact is trust-on-first-use. The identity embedded in a session-establishment message
  // must at least match the directory entry; only safety-number comparison defeats a server that
  // lies consistently in both places.
  async #crossCheckFirstContact(packet) {
    const h = packet?.h;
    if (h?.t !== 'prekey' || typeof h.from !== 'string' || this.#vault.contacts[h.from]) return;
    let embeddedFp;
    try { embeddedFp = identityFingerprint(h.pre.identity); } catch { return; } // openEnvelope rejects it
    let identity;
    try { ({ identity } = await this.#request(`/api/users/${encodeURIComponent(h.from)}/identity`)); } catch (error) {
      if (error.status === 404) throw new ProtocolError('directory_mismatch', 'Sender has no published identity.');
      throw error; // transient: leave unacknowledged so it is redelivered
    }
    let directoryFp = null;
    try { directoryFp = identityFingerprint(identity); } catch { /* treated as mismatch */ }
    if (directoryFp !== embeddedFp) throw new ProtocolError('directory_mismatch', 'Sender identity does not match the published directory entry.');
  }

  async #processPackets(items) {
    const acks = [];
    let changed = false;
    for (const { qid, packet } of items) {
      const started = performance.now();
      try {
        await this.#crossCheckFirstContact(packet);
        const { vault, message } = await openEnvelope(this.#vault, packet);
        const contact = vault.contacts[message.from];
        this.#vault = this.#appendHistory(vault, message.from, { ...message, authenticated: true, verifiedContact: Boolean(contact?.verified), status: 'received' });
        changed = true;
        this.#trace('Message authenticated and decrypted', 'success', `From ${message.from}: hybrid signature verified, ${packet.h.t === 'prekey' ? 'PQXDH session accepted (ML-KEM decapsulation + X25519) and ' : ''}AES-256-GCM authentication succeeded; ${(performance.now() - started).toFixed(1)} ms.`);
        this.#emit('message', { peer: message.from, message });
      } catch (error) {
        // Transient network failure: leave the packet unacknowledged so the relay redelivers it.
        if (error instanceof ApiError) continue;
        const code = error instanceof ProtocolError ? error.code : 'error';
        const claimedFrom = typeof packet?.h?.from === 'string' ? packet.h.from.slice(0, 24) : 'unknown';
        if (code === 'identity_changed') {
          if (error.bundle) {
            try { this.#vault = recordIdentityChange(this.#vault, claimedFrom, error.bundle); } catch { /* invalid bundle: just quarantine */ }
          }
          this.#vault = { ...this.#vault, quarantine: [...this.#vault.quarantine, { from: claimedFrom, packet, at: Date.now() }].slice(-MAX_QUARANTINE) };
          this.#emit('identity-changed', { peer: claimedFrom });
        }
        this.#logSecurity(code, claimedFrom, error.message);
        changed = true;
        this.#trace('Incoming message rejected', 'failure', `Claimed sender ${claimedFrom}: ${code}. Nothing was displayed and no session state changed.`);
        this.#emit('rejected', { code, claimedFrom });
      }
      if (qid) acks.push(qid);
    }
    if (changed) await this.#save();
    if (acks.length && this.#socket?.readyState === 1) this.#socket.send(JSON.stringify({ type: 'ack', qids: acks }));
  }

  // ----- relay connection -----------------------------------------------------------------------
  connect() {
    this.#requireSession();
    this.#stopped = false;
    clearTimeout(this.#reconnectTimer);
    const previous = this.#socket;
    if (previous) { this.#socket = null; previous.close(1000, 'Reconnecting'); }
    const socket = this.createWebSocket(this.wsUrl);
    this.#socket = socket;
    socket.addEventListener('open', () => {
      if (this.#socket !== socket) return;
      this.#reconnectAttempts = 0;
      this.connected = true;
      this.#emit('status', { connected: true });
      // Retransmit packets the server has not acknowledged; the relay is idempotent per message ID.
      for (const { packet } of this.#vault?.outbox ?? []) this.#transmit(packet);
    });
    // Errors are always followed by 'close', which handles reconnection.
    socket.addEventListener('error', () => {});
    socket.addEventListener('close', (event) => {
      if (this.#socket !== socket) return;
      this.#socket = null;
      this.connected = false;
      if (event.code === 4001) {
        this.#stopped = true;
        this.#emit('displaced', { message: 'This account signed in on another device or tab.' });
        return;
      }
      this.#emit('status', { connected: false });
      if (!this.#stopped) {
        const delay = Math.min(1000 * 2 ** this.#reconnectAttempts, 15000);
        this.#reconnectAttempts += 1;
        this.#reconnectTimer = setTimeout(() => { if (!this.#stopped && this.#vault) this.connect(); }, delay);
      }
    });
    socket.addEventListener('message', (event) => {
      if (this.#socket !== socket) return;
      let frame;
      try { frame = JSON.parse(typeof event.data === 'string' ? event.data : event.data.toString()); } catch { return; }
      if (frame.type === 'deliver' && Array.isArray(frame.items)) {
        // Skip redeliveries of items still being processed (e.g. after a reconnect).
        const items = frame.items.filter((item) => typeof item?.qid === 'string' && !this.#inflight.has(item.qid));
        items.forEach((item) => this.#inflight.add(item.qid));
        this.#exclusive(() => this.#processPackets(items))
          .catch((error) => this.#emit('error', error))
          .finally(() => items.forEach((item) => this.#inflight.delete(item.qid)));
      } else if (frame.type === 'accepted') {
        this.#exclusive(async () => this.#markOutbox(frame.id, 'sent')).catch(() => {});
      } else if (frame.type === 'rejected') {
        this.#exclusive(async () => this.#markOutbox(frame.id, 'failed', frame.error)).catch(() => {});
      } else if (frame.type === 'users-changed') {
        this.#emit('users', {});
      } else if (frame.type === 'error') {
        this.#emit('server-error', { message: String(frame.error ?? 'Server error') });
      }
    });
  }

  // Asks the relay to redeliver everything still queued for this account.
  requestSync() {
    if (this.#socket?.readyState === 1) this.#socket.send(JSON.stringify({ type: 'sync' }));
  }

  // Stops the relay connection and reconnection attempts without ending the server session.
  disconnect() {
    this.#stopped = true;
    clearTimeout(this.#reconnectTimer);
    const socket = this.#socket;
    this.#socket = null;
    this.connected = false;
    socket?.close(1000, 'Disconnected');
  }

  async #markOutbox(id, status, error) {
    if (!this.#vault || !this.#vault.outbox.some((entry) => entry.id === id)) return;
    const outbox = this.#vault.outbox.filter((entry) => entry.id !== id);
    const history = { ...this.#vault.history };
    let peer = null;
    for (const [name, list] of Object.entries(history)) {
      if (list.some((item) => item.id === id)) {
        peer = name;
        history[name] = list.map((item) => (item.id === id ? { ...item, status, error } : item));
      }
    }
    this.#vault = { ...this.#vault, outbox, history };
    await this.#save();
    this.#emit(status === 'sent' ? 'sent' : 'send-failed', { peer, id, error });
  }

  // Waits until all queued vault operations have finished (used by tests and logout).
  async idle() {
    let current;
    do {
      current = this.#chain;
      await current;
    } while (current !== this.#chain);
  }

  // Test hook: a deep copy of the decrypted vault, used to model device compromise.
  snapshotForTesting() {
    return structuredClone(this.#vault);
  }
}
