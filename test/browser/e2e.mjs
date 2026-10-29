// Real-browser end-to-end test: production build served by the real server, two isolated browser
// contexts, strict CSP enforced. Uses a locally installed Chrome/Edge via playwright-core
// (set CHROME_PATH to override). Run `npm run build` first.
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { createServer } from '../../server/app.js';

const candidates = [
  process.env.CHROME_PATH,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);
const executablePath = candidates.find((path) => existsSync(path));
if (!executablePath) {
  console.log('SKIPPED: no Chrome/Chromium/Edge found (set CHROME_PATH).');
  process.exit(0);
}
if (!existsSync('dist/index.html')) throw new Error('Run `npm run build` first.');

const PORT = Number(process.env.E2E_PORT || 3917);
const ORIGIN = `http://127.0.0.1:${PORT}`;
const dataDir = mkdtempSync(join(tmpdir(), 'qsc-e2e-'));
const server = await createServer({ dataDir, distDir: 'dist', allowedOrigins: [ORIGIN], log: { log() {}, error() {} } });
await server.listen(PORT);
const browser = await chromium.launch({ executablePath, headless: true });
const results = [];
const step = async (name, fn) => {
  const started = Date.now();
  try {
    await fn();
    results.push({ name, ok: true, ms: Date.now() - started });
    console.log(`  ✔ ${name} (${Date.now() - started} ms)`);
  } catch (error) {
    results.push({ name, ok: false, error: error.message });
    console.log(`  ✖ ${name}: ${error.message}`);
    throw error;
  }
};

const PW = { alice: 'violet-harbor-sunrise-71', bob: 'granite-meadow-lantern-38' };
const problems = [];
const outbound = [];

async function newUser(name) {
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (event) => console.error(`CSP violation: ${event.violatedDirective} ${event.blockedURI}`));
  });
  page.on('console', (message) => { if (message.type() === 'error') problems.push(`[${name}] ${message.text()}`); });
  page.on('pageerror', (error) => problems.push(`[${name}] pageerror ${error.message}`));
  page.on('request', (request) => outbound.push({ who: name, url: request.url(), body: request.postData() ?? '' }));
  await page.goto(ORIGIN);
  return { context, page };
}

async function authenticate(page, mode, username, password) {
  await page.click(`[data-mode="${mode}"]`);
  await page.fill('#username', username);
  await page.fill('#password', password);
  const started = Date.now();
  await page.click('#authSubmit');
  await page.waitForSelector('.app-shell', { timeout: 60000 });
  return Date.now() - started;
}

let exitCode = 0;
try {
  console.log(`E2E using ${executablePath}`);
  const alice = await newUser('alice');
  const bob = await newUser('bob');
  let timings = {};

  await step('register two accounts in separate browser contexts (OPAQUE + key generation in the browser)', async () => {
    timings.registerAlice = await authenticate(alice.page, 'register', 'alice', PW.alice);
    timings.registerBob = await authenticate(bob.page, 'register', 'bob', PW.bob);
  });

  await step('alice -> bob message is delivered and shown as signature-verified', async () => {
    await alice.page.reload();
    timings.loginAlice = await authenticate(alice.page, 'login', 'alice', PW.alice);
    await alice.page.click('[data-user="bob"]');
    await alice.page.fill('#messageInput', 'hello from a real browser');
    await alice.page.press('#messageInput', 'Enter');
    await bob.page.waitForSelector('[data-user="alice"]');
    await bob.page.click('[data-user="alice"]');
    await bob.page.waitForSelector('.message-row.theirs .bubble:has-text("hello from a real browser")', { timeout: 30000 });
    assert.ok(await bob.page.isVisible('.message-row.theirs .badge.verified'));
  });

  await step('bob replies; alice sees it', async () => {
    await bob.page.fill('#messageInput', 'reply from bob');
    await bob.page.press('#messageInput', 'Enter');
    await alice.page.waitForSelector('.bubble:has-text("reply from bob")', { timeout: 30000 });
  });

  await step('safety numbers match on both sides and can be marked verified', async () => {
    await alice.page.click('.conversation-header [data-action="toggle-safety"]');
    await bob.page.click('.conversation-header [data-action="toggle-safety"]');
    const a = await alice.page.textContent('.safety-number');
    const b = await bob.page.textContent('.safety-number');
    assert.equal(a, b);
    assert.match(a.replace(/\s/g, ''), /^\d{60}$/);
    await alice.page.click('[data-action="mark-verified"]');
    await alice.page.waitForSelector('.conversation-header .badge.verified');
  });

  await step('in-browser security self-tests all pass', async () => {
    await alice.page.click('[data-view="tests"]');
    await alice.page.click('#runSecurityTests');
    await alice.page.waitForFunction(() => document.querySelectorAll('.test-result').length >= 10 && !document.querySelector('#runSecurityTests')?.disabled, null, { timeout: 120000 });
    const statuses = await alice.page.$$eval('.test-result .event-status', (nodes) => nodes.map((node) => node.textContent));
    assert.ok(statuses.length >= 10 && statuses.every((status) => status === 'PASS'), `statuses: ${statuses.join(',')}`);
  });

  await step('benchmark runs and reports the pure-JS vs native methodology', async () => {
    await alice.page.click('[data-view="benchmark"]');
    await alice.page.fill('#benchmarkIterations', '20');
    await alice.page.click('#runBenchmarks');
    await alice.page.waitForSelector('.results-table', { timeout: 120000 });
    assert.ok((await alice.page.textContent('.tool-page')).includes('pure JavaScript'));
  });

  await step('exported research report contains no secrets or secret-derived digests (N1)', async () => {
    await alice.page.click('[data-view="trace"]');
    const [download] = await Promise.all([alice.page.waitForEvent('download'), alice.page.click('.heading-actions [data-action="export-report"]')]);
    const report = JSON.parse(readFileSync(await download.path(), 'utf8'));
    const text = JSON.stringify(report);
    assert.equal(report.schema, 'quantumsafe-chat-research-report-v2');
    assert.ok(report.cryptoEvents.length > 0);
    assert.ok(!/shared.?secret.{0,40}(fingerprint|digest)/i.test(text), 'no shared-secret digests');
    assert.ok(!text.includes('hello from a real browser') && !text.includes('reply from bob'), 'no plaintext');
    assert.ok(!text.includes(PW.alice), 'no password');
    // The public identity fingerprint is included deliberately; everything else must be free of
    // long key-like runs.
    assert.match(report.publicIdentityFingerprint, /^[0-9a-f]{64}$/);
    const longRun = JSON.stringify({ ...report, publicIdentityFingerprint: null }).match(/[A-Za-z0-9+/]{60,}/);
    assert.ok(!longRun, `no long key-like Base64 values (found: ${longRun?.[0]?.slice(0, 80)})`);
  });

  await step('history survives logout and login from a fresh browser context', async () => {
    await alice.page.click('#logoutButton');
    await alice.context.close();
    const again = await newUser('alice-2');
    await authenticate(again.page, 'login', 'alice', PW.alice);
    await again.page.click('[data-user="bob"]');
    await again.page.waitForSelector('.bubble:has-text("reply from bob")');
    assert.ok(await again.page.isVisible('.conversation-header .badge.verified'), 'verification state persists in vault');
    // Single active device: bob is unaffected, alice-2 is the only alice session.
    await again.context.close();
  });

  await step('no CSP violations, console errors, third-party requests or passwords on the wire', async () => {
    assert.deepEqual(problems, []);
    const foreign = outbound.filter((request) => !request.url.startsWith(ORIGIN) && !request.url.startsWith('data:') && !request.url.startsWith('blob:'));
    assert.deepEqual(foreign.map((request) => request.url), []);
    for (const request of outbound) {
      assert.ok(!request.body.includes(PW.alice) && !request.body.includes(PW.bob), `password in request to ${request.url}`);
      assert.ok(!/"password"/.test(request.body), `password field in request to ${request.url}`);
    }
  });
  console.log(`Browser timings (ms, includes Argon2id + key generation): ${JSON.stringify(timings)}`);
} catch (error) {
  exitCode = 1;
  if (problems.length) console.log('Browser problems:', problems);
} finally {
  await browser.close();
  await server.close();
  rmSync(dataDir, { recursive: true, force: true });
}
console.log(`${results.filter((r) => r.ok).length}/${results.length} browser steps passed`);
process.exit(exitCode);
