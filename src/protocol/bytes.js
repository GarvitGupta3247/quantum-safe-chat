// Byte helpers and the canonical encoding used for every signature and AEAD associated-data input.
// Runs unchanged in browsers and Node.js (>= 20), so the automated tests exercise the same code as the UI.

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder('utf-8', { fatal: true });

export function utf8(value) {
  return textEncoder.encode(value);
}

export function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

export function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i += 1) difference |= left[i] ^ right[i];
  return difference === 0;
}

export function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

export function toBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Strict decoder for untrusted input: rejects non-canonical encodings and unexpected lengths.
export function fromBase64(value, expectedLength) {
  if (typeof value !== 'string' || !BASE64_PATTERN.test(value)) throw new TypeError('Invalid Base64 value.');
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  if (expectedLength !== undefined) {
    const [min, max] = Array.isArray(expectedLength) ? expectedLength : [expectedLength, expectedLength];
    if (bytes.length < min || bytes.length > max) throw new TypeError('Unexpected Base64 value length.');
  }
  if (toBase64(bytes) !== value) throw new TypeError('Non-canonical Base64 value.');
  return bytes;
}

// The OPAQUE library returns base64url strings without padding.
export function fromBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError('Invalid base64url value.');
  const standard = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  return fromBase64(padded);
}

export function toHex(bytes) {
  return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
}

const TAG_NULL = 0x00;
const TAG_BYTES = 0x01;
const TAG_STRING = 0x02;
const TAG_UINT = 0x03;

function u32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

// Canonical, unambiguous encoding: a domain-separation label followed by a counted list of
// type-tagged, length-prefixed fields. Two different field lists can never encode to the same bytes,
// unlike delimiter-joined strings, so signatures and AEAD associated data cannot be reinterpreted.
export function encodeCanonical(label, fields) {
  if (typeof label !== 'string' || !label) throw new TypeError('A canonical encoding needs a label.');
  const parts = [utf8('QSC1'), u32(fields.length + 1)];
  const push = (tag, payload) => parts.push(Uint8Array.of(tag), u32(payload.length), payload);
  push(TAG_STRING, utf8(label));
  for (const field of fields) {
    if (field === null || field === undefined) {
      push(TAG_NULL, new Uint8Array(0));
    } else if (field instanceof Uint8Array) {
      push(TAG_BYTES, field);
    } else if (typeof field === 'string') {
      push(TAG_STRING, utf8(field));
    } else if (typeof field === 'number') {
      if (!Number.isSafeInteger(field) || field < 0) throw new TypeError('Canonical integers must be non-negative safe integers.');
      const payload = new Uint8Array(8);
      new DataView(payload.buffer).setBigUint64(0, BigInt(field), false);
      push(TAG_UINT, payload);
    } else {
      throw new TypeError(`Unsupported canonical field type: ${typeof field}`);
    }
  }
  return concatBytes(...parts);
}
