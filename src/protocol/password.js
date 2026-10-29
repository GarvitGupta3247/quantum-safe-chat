// Password policy and OPAQUE key-stretching parameters.
//
// The server never receives the password, so this policy can only be enforced by the client; a
// modified client weakens only its own account. Argon2id parameters are fixed client-side (not
// server-supplied) so a malicious server cannot request weaker stretching.

// RFC 9106 §4 second recommended option (64 MiB, t=3) with p=1 because the WASM build runs
// single-threaded. Measured ~160 ms per evaluation (steady state) in Node 25 / WASM on the
// development machine; the first evaluation in a process is slower while WASM memory grows.
// Each offline password guess by an attacker holding the database AND the OPAQUE server setup
// costs one such evaluation.
export const KEY_STRETCHING = Object.freeze({ 'argon2id-custom': { iterations: 3, memory: 65536, parallelism: 1 } });

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 256;

const COMMON_PASSWORDS = new Set([
  'password1234', '123456789012', 'qwertyuiop12', 'iloveyou1234', 'passwordpassword', 'letmein12345',
  'welcome12345', 'administrator', 'correcthorsebatterystaple', 'trustno112345', 'qwerty123456',
  'password123!', 'changeme1234', '1q2w3e4r5t6y', 'aaaaaaaaaaaa', 'abcdefghijkl', 'quantumsafechat',
]);

export function checkPassword(password, username = '') {
  if (typeof password !== 'string') return 'Enter a password.';
  if (password.length < PASSWORD_MIN_LENGTH) return `Use at least ${PASSWORD_MIN_LENGTH} characters (a passphrase of several words works well).`;
  if (password.length > PASSWORD_MAX_LENGTH) return `Use at most ${PASSWORD_MAX_LENGTH} characters.`;
  const lowered = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lowered.replace(/\s+/g, ''))) return 'That password is too common.';
  if (username && lowered.includes(username.toLowerCase())) return 'The password must not contain the username.';
  if (new Set(password).size < 5) return 'Use a password with more distinct characters.';
  return null;
}
