// N1 / N2 / N4: research tooling must not leak secrets or misreport protocol outcomes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildResearchReport } from '../../src/research/report.js';
import { runSelfTests } from '../../src/research/selftests.js';

test('N4: the in-app security self-tests (real envelopes) all pass under Node as well', async () => {
  const results = await runSelfTests();
  assert.ok(results.length >= 10);
  for (const result of results) assert.equal(result.status, 'PASS', `${result.name}: ${result.details}`);
});

test('N1: the report builder uses an allow-list and redacts long key-like values', () => {
  const secret = 'Q'.repeat(44);
  const report = buildResearchReport({
    events: [{ at: 'now', title: 'x', outcome: 'success', details: `derived ${secret} value`, sharedSecretFingerprint: 'abc', key: secret }],
    securityTests: [{ name: 't', status: 'PASS', details: secret, durationMs: 1, at: 'now', privateKey: secret }],
    fingerprint: 'f'.repeat(64),
  });
  const text = JSON.stringify(report);
  assert.ok(!text.includes(secret));
  assert.ok(!text.includes('sharedSecretFingerprint') && !text.includes('privateKey'));
  assert.match(text, /\[redacted\]/);
});
