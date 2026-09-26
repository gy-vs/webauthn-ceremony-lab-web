/**
 * base64url (no padding) helpers used for every binary field on the wire.
 * Pure implementation with no platform-specific APIs; works in Node and
 * browsers. Readers tolerate the standard base64 alphabet and padding, but
 * writers always emit the URL-safe, unpadded form.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const INVALID = 255;
const LOOKUP = new Uint8Array(128).fill(INVALID);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;
// Also accept standard base64 alphabet characters on read.
LOOKUP['+'.charCodeAt(0)] = 62;
LOOKUP['/'.charCodeAt(0)] = 63;

export function bytesToBase64url(bytes: Uint8Array): string {
  let out = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += ALPHABET[(n >> 18) & 63];
    out += ALPHABET[(n >> 12) & 63];
    if (i + 1 < len) out += ALPHABET[(n >> 6) & 63];
    if (i + 2 < len) out += ALPHABET[n & 63];
  }
  return out;
}

export function base64urlToBytes(value: string): Uint8Array {
  if (typeof value !== 'string') throw new Error('base64url value must be a string');
  const clean = value.replace(/=+$/, '');
  if (clean.length % 4 === 1) throw new Error('invalid base64url length');
  const sextets = new Uint8Array(clean.length);
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    if (code >= 128 || LOOKUP[code] === INVALID) throw new Error(`invalid base64url character at ${i}`);
    sextets[i] = LOOKUP[code];
  }
  const full = Math.floor(clean.length / 4);
  const rem = clean.length % 4;
  let outLen = full * 3;
  if (rem === 2) outLen += 1;
  else if (rem === 3) outLen += 2;
  const out = new Uint8Array(outLen);
  let o = 0;
  let i = 0;
  for (; i + 3 < sextets.length; i += 4) {
    const n = (sextets[i] << 18) | (sextets[i + 1] << 12) | (sextets[i + 2] << 6) | sextets[i + 3];
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
    out[o++] = n & 255;
  }
  if (rem === 2) {
    out[o] = (sextets[i] << 2) | (sextets[i + 1] >> 4);
  } else if (rem === 3) {
    const n = (sextets[i] << 10) | (sextets[i + 1] << 4) | (sextets[i + 2] >> 2);
    out[o] = (n >> 8) & 255;
    out[o + 1] = n & 255;
  }
  return out;
}

/** Encode a JS string to UTF-8 bytes. */
export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Decode UTF-8 bytes to a JS string. */
export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}
