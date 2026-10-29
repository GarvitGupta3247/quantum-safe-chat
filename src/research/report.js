// Exported research report. It is built from an explicit allow-list of fields: operation titles,
// outcomes, sizes and timings, benchmark samples, self-test results and the PUBLIC identity
// fingerprint. It never includes keys, shared secrets, values derived from secrets (N1), passwords,
// plaintext, ciphertext previews, or contact names.

export const ALGORITHMS = Object.freeze({
  authentication: 'OPAQUE (RFC 9807, ristretto255) with Argon2id key stretching (64 MiB, t=3, p=1)',
  identity: 'Hybrid Ed25519 + ML-DSA-65 (FIPS 204) signatures; X25519 identity DH key',
  sessionSetup: 'PQXDH: X25519 + ML-KEM-768 (FIPS 203), HKDF-SHA-256',
  messaging: 'Double Ratchet (X25519, HKDF-SHA-256, HMAC-SHA-256), AES-256-GCM',
  keyStorage: 'Client-side vault: AES-256-GCM under a random data key wrapped by the OPAQUE export key',
});

const sanitizeDetails = (text) => String(text ?? '')
  // Defence in depth: redact any long Base64/hex run that might ever reach an event description.
  .replace(/[A-Za-z0-9+/_-]{40,}={0,2}/g, '[redacted]');

export function buildResearchReport({ events = [], benchmark = null, securityTests = [], fingerprint = null, environment = {} }) {
  return {
    schema: 'quantumsafe-chat-research-report-v2',
    generatedAt: new Date().toISOString(),
    project: 'QuantumSafe Chat',
    reportType: 'sanitized evaluation report',
    environment: {
      userAgent: environment.userAgent ?? null,
      secureContext: environment.secureContext ?? null,
      sourceRevision: environment.sourceRevision ?? 'not embedded in this build',
    },
    algorithms: ALGORITHMS,
    publicIdentityFingerprint: fingerprint,
    cryptoEvents: events.map(({ at, title, outcome, details }) => ({ at, title: sanitizeDetails(title), outcome, details: sanitizeDetails(details) })),
    benchmark,
    securityTests: securityTests.map(({ name, status, details, durationMs, at }) => ({ name, status, details: sanitizeDetails(details), durationMs, at })),
    privacyNotice: 'Excludes passwords, keys, shared secrets and anything derived from them, plaintext, ciphertext and contact names. Contains the public identity fingerprint of the exporting account.',
  };
}
