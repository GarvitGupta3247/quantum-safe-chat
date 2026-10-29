# Upgrade to Research Lab build (v0.5.0)

This update adds Crypto Trace, a live benchmark comparison and focused security tests while keeping the existing chat UI, key bundle format and message protocol.

## Before updating

1. Back up any existing JSON store and keep the current Git repository history.
2. Do not overwrite the existing `.git` directory or force-push an unrelated commit history.
3. Keep `NODE_ENV=production` and set `ALLOWED_ORIGINS` to the exact hosted HTTPS origin.
4. If using a Render persistent disk, mount it at `/var/data` and set `DATA_DIR=/var/data`.

## Local test

After copying these files into an existing repository, run `npm install --include=dev` to reconcile `package-lock.json` with the bumped package version/dependencies, then commit the updated lockfile.

```powershell
npm install --include=dev
npm run build
npm run dev
```

Test registration/login, two-user messages, key-bundle unlock, Crypto Trace, the benchmark, the security tests and report exports before pushing.

## Render settings

- Build: `npm install --include=dev && npm run build`
- Start: `npm start`
- Environment: `NODE_ENV=production`
- Environment: `ALLOWED_ORIGINS=https://YOUR-SERVICE.onrender.com`
- Optional persistent disk: `DATA_DIR=/var/data`

The JSON store is still used in this phase; database migration is intentionally deferred.

## Known limits

The UI and research tools don't change the underlying security scope: no ML-DSA identity authentication, no reviewed Double Ratchet/forward-secrecy implementation, incomplete protocol-level replay protection, and no independent security audit. Benchmark timing is browser/device/API-specific and X25519 is reported unavailable when the browser does not support it.
