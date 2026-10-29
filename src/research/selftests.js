// In-browser security self-tests. They run the REAL protocol functions (encryptEnvelope /
// openEnvelope / vault sealing) on disposable identities, then attack the resulting envelopes.
// They do not touch the server; the full client-server attack suite runs under `npm test`.

import { fromBase64, toBase64 } from '../protocol/bytes.js';
import { createAccountVault, encryptEnvelope, openEnvelope, signPacket } from '../protocol/envelope.js';
import { deriveKek, generateDek, openVault, sealVault, unwrapDek, wrapDek } from '../protocol/vault.js';

function flip(b64) {
  const bytes = fromBase64(b64);
  bytes[bytes.length - 1] ^= 0x01;
  return toBase64(bytes);
}

async function expectRejection(promise, codes) {
  try {
    await promise;
    return { ok: false, detail: 'was ACCEPTED (unexpected)' };
  } catch (error) {
    const ok = !codes || codes.includes(error.code);
    return { ok, detail: `rejected with ${error.code ?? error.message}` };
  }
}

export async function runSelfTests(onResult = () => {}) {
  const results = [];
  const record = (name, ok, details, started) => {
    const entry = { name, status: ok ? 'PASS' : 'FAIL', details, durationMs: performance.now() - started, at: new Date().toISOString() };
    results.push(entry);
    onResult(entry);
  };
  const run = async (name, fn) => {
    const started = performance.now();
    try {
      const { ok, details } = await fn();
      record(name, ok, details, started);
    } catch (error) {
      record(name, false, `Test error: ${error?.message ?? error}`, started);
    }
  };

  const a = createAccountVault('selftest-alice', { opkCount: 2, pqopkCount: 2 });
  const b = createAccountVault('selftest-bob', { opkCount: 2, pqopkCount: 2 });
  const prekeys = { identity: b.upload.identity, spk: b.upload.spk, pq: b.upload.pqopks[0], opk: b.upload.opks[0] };
  const first = await encryptEnvelope(a.vault, { peer: 'selftest-bob', text: 'self-test message (not user data)', prekeys });
  const packet = first.packet;

  await run('Valid PQXDH + Double Ratchet envelope opens', async () => {
    const opened = await openEnvelope(b.vault, structuredClone(packet));
    return { ok: opened.message.text === 'self-test message (not user data)', details: `Signature verified and AES-256-GCM authenticated; ${JSON.stringify(packet).length}-byte envelope.` };
  });
  const tamper = async (name, mutate, codes) => run(name, async () => {
    const copy = structuredClone(packet);
    mutate(copy);
    const { ok, detail } = await expectRejection(openEnvelope(b.vault, copy), codes);
    return { ok, details: `Real envelope from encryptEnvelope, modified, then ${detail}.` };
  });
  await tamper('Modified ciphertext / GCM tag rejected', (p) => { p.ct = flip(p.ct); }, ['bad_signature']);
  await tamper('Modified KEM ciphertext rejected', (p) => { p.h.pre.kemCt = flip(p.h.pre.kemCt); }, ['bad_signature']);
  await tamper('Forged sender label rejected', (p) => { p.h.from = 'selftest-carol'; }, ['conversation_mismatch', 'bad_signature']);
  await tamper('Altered recipient rejected', (p) => { p.h.toFp = 'f'.repeat(64); }, ['wrong_recipient']);
  await tamper('Signature from a different identity rejected', (p) => {
    p.sig = signPacket(p, createAccountVault('selftest-alice', { opkCount: 0, pqopkCount: 0 }).vault.identity.private);
  }, ['bad_signature']);

  await run('Invalid ML-KEM ciphertext is caught by AEAD (no false "success")', async () => {
    const copy = structuredClone(packet);
    copy.h.pre.kemCt = flip(copy.h.pre.kemCt);
    copy.sig = signPacket(copy, a.vault.identity.private); // validly signed by the sender
    const { ok, detail } = await expectRejection(openEnvelope(b.vault, copy), ['decrypt_failed']);
    return { ok, details: `ML-KEM decapsulation returns an implicit-rejection secret rather than an error; the message ${detail}.` };
  });

  await run('Replayed envelope rejected', async () => {
    const opened = await openEnvelope(b.vault, structuredClone(packet));
    const { ok, detail } = await expectRejection(openEnvelope(opened.vault, structuredClone(packet)), ['replay']);
    return { ok, details: `Second delivery of the same envelope ${detail}.` };
  });

  await run('Substituted public key for a pinned contact blocked', async () => {
    const substituted = createAccountVault('selftest-bob', { opkCount: 1, pqopkCount: 1 }).upload;
    const fakePrekeys = { identity: substituted.identity, spk: substituted.spk, pq: substituted.pqopks[0], opk: substituted.opks[0] };
    const withoutSession = { ...first.vault, sessions: {} }; // alice has pinned bob but lost the session
    const { ok, detail } = await expectRejection(encryptEnvelope(withoutSession, { peer: 'selftest-bob', text: 'x', prekeys: fakePrekeys }), ['identity_changed']);
    return { ok, details: `Encrypting to a server-substituted identity ${detail}.` };
  });

  await run('Vault cannot be opened with a wrong password-derived key', async () => {
    const randomExportKey = () => toBase64(crypto.getRandomValues(new Uint8Array(64))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const dek = generateDek();
    const wrapped = await wrapDek(await deriveKek(randomExportKey(), 'selftest-alice'), dek, 'selftest-alice');
    const blob = await sealVault(dek, 'selftest-alice', 1, a.vault);
    const unwrap = await expectRejection(unwrapDek(await deriveKek(randomExportKey(), 'selftest-alice'), wrapped, 'selftest-alice'), ['vault_unwrap_failed']);
    const relabel = await expectRejection(openVault(dek, 'selftest-alice', 2, blob), ['vault_open_failed']);
    return { ok: unwrap.ok && relabel.ok, details: `Wrong key: ${unwrap.detail}; version relabel: ${relabel.detail}.` };
  });

  return results;
}
