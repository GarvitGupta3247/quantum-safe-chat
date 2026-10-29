# Upgrading from v0.5.x to v0.6.0

v0.6 replaces the authentication, key storage and message protocol. Old clients cannot talk to a
v0.6 server and vice versa.

## Operator steps
1. **Back up** `DATA_DIR/store.json`. (The server also writes `store.v2-backup-<timestamp>.json`
   before converting, but keep your own copy.)
2. Deploy v0.6 and set `OPAQUE_SERVER_SETUP` from a secret manager if possible (see SECURITY.md
   §6.4). If you do not, it is generated into `DATA_DIR` on first start — back it up: losing it
   locks every account out.
3. Start the server once. It converts the store in place:
   * scrypt hashes and PBKDF2 key bundles move under `users.<name>.legacy`;
   * old messages move to `legacyMessages` (still encrypted, still unauthenticated).
4. Tell users to upgrade (below). When everyone has, set `QSC_LEGACY_MIGRATION=0` and restart;
   that closes the only endpoint that still accepts a password.

Render settings are unchanged apart from the new variables: build `npm ci --include=dev && npm run build`, start
`npm start`, `NODE_ENV=production`, `ALLOWED_ORIGINS=https://YOUR-SERVICE.onrender.com`, optional
persistent disk with `DATA_DIR=/var/data`.

## User steps
1. On the login page choose **Upgrade legacy account**.
2. Enter the username, the **old** password, and a **new** password (≥12 characters, different
   from the old one — the old one was visible to the v0.5 server and must be retired).
3. The browser decrypts your old messages with your old key bundle, creates a brand-new identity,
   registers with OPAQUE, and stores everything in your encrypted vault.

What to expect:
* Old messages appear marked **legacy — sender not authenticated**; v0.5 could not prove who sent them.
* Your contacts see a new identity for you on first contact. Compare safety numbers.
* Accounts that never synced a key bundle to the server (pre-v0.4) can upgrade, but their old
  messages cannot be decrypted and are reported as unreadable.
* Users who have not upgraded are shown as *needs upgrade* and cannot receive new messages.
* An unencrypted private key left in the browser by a pre-v0.4 build is never used; the login page
  offers to delete it, and upgrading deletes it.
