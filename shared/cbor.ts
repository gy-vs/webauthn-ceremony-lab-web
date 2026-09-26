/**
 * Minimal deterministic CBOR encoder/decoder (RFC 8949) — enough for
 * WebAuthn attestation/assertion client data and authData extensions.
 * Supports: uint (including 64-bit via BigInt), bytes, text, arrays, maps,
 * bool, null/undefined, negative ints in safe-integer range.
 * Keys in maps may be text or integer; map entries are encoded in insertion
 * order (records are produced here with canonical key order already).
 */

export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | CborValue[]
  | CborMap;

/**
 * A CBOR map with both integer and text keys. Use `setInt`/`getInt` for
 * integer-keyed labels (COSE keys) and plain string properties otherwise.
 * Entries are emitted in insertion order: integer keys first, then strings.
 */
export class CborMap {
  /** @internal */
  readonly intEntries: [number, CborValue][] = [];
  /** @internal */
  readonly strEntries: [string, CborValue][] = [];

  setInt(key: number, value: CborValue): this {
    const existing = this.intEntries.findIndex(([k]) => k === key);
    if (existing >= 0) this.intEntries[existing] = [key, value];
    else this.intEntries.push([key, value]);
    return this;
  }

  getInt(key: number): CborValue | undefined {
    return this.intEntries.find(([k]) => k === key)?.[1];
  }

  set(key: string, value: CborValue): this {
    const existing = this.strEntries.findIndex(([k]) => k === key);
    if (existing >= 0) this.strEntries[existing] = [key, value];
    else this.strEntries.push([key, value]);
    return this;
  }

  get(key: string): CborValue | undefined {
    return this.strEntries.find(([k]) => k === key)?.[1];
  }

  get size(): number {
    return this.intEntries.length + this.strEntries.length;
  }
}

const MAJOR = {
  UINT: 0,
  NINT: 1,
  BYTES: 2,
  TEXT: 3,
  ARRAY: 4,
  MAP: 5,
  SIMPLE: 7,
} as const;

class Writer {
  private chunks: number[] = [];

  private writeHead(major: number, value: number | bigint): void {
    const ai = major << 5;
    let v = typeof value === 'bigint' ? value : BigInt(value);
    if (v < 0n) throw new Error('use NINT for negative values');
    if (v < 24n) {
      this.chunks.push(ai | Number(v));
    } else if (v < 1n << 8n) {
      this.chunks.push(ai | 24, Number(v));
    } else if (v < 1n << 16n) {
      this.chunks.push(ai | 25, Number(v >> 8n) & 255, Number(v) & 255);
    } else if (v < 1n << 32n) {
      this.chunks.push(
        ai | 26,
        Number(v >> 24n) & 255,
        Number(v >> 16n) & 255,
        Number(v >> 8n) & 255,
        Number(v) & 255,
      );
    } else {
      this.chunks.push(ai | 27);
      for (let shift = 56n; shift >= 0n; shift -= 8n) {
        this.chunks.push(Number((v >> shift) & 255n));
      }
    }
  }

  private write(major: number, value: number | bigint): void {
    const v = typeof value === 'bigint' ? value : BigInt(value);
    if (major === MAJOR.NINT) this.writeHead(MAJOR.NINT, -1n - v);
    else this.writeHead(major, v);
  }

  encode(value: CborValue): Uint8Array {
    this.writeValue(value);
    return new Uint8Array(this.chunks);
  }

  private writeValue(value: CborValue): void {
    if (value === null) {
      this.chunks.push(0xf6);
      return;
    }
    if (value === undefined) {
      this.chunks.push(0xf7);
      return;
    }
    if (typeof value === 'boolean') {
      this.chunks.push(value ? 0xf5 : 0xf4);
      return;
    }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) throw new Error('only integers supported');
      if (value < 0) {
        this.writeHead(MAJOR.NINT, -1 - value);
      } else {
        this.writeHead(MAJOR.UINT, value);
      }
      return;
    }
    if (typeof value === 'bigint') {
      if (value < 0n) {
        this.writeHead(MAJOR.NINT, -1n - value);
      } else {
        this.writeHead(MAJOR.UINT, value);
      }
      return;
    }
    if (typeof value === 'string') {
      const bytes = new TextEncoder().encode(value);
      this.write(MAJOR.TEXT, bytes.length);
      for (const b of bytes) this.chunks.push(b);
      return;
    }
    if (value instanceof Uint8Array) {
      this.write(MAJOR.BYTES, value.length);
      for (const b of value) this.chunks.push(b);
      return;
    }
    if (Array.isArray(value)) {
      this.write(MAJOR.ARRAY, value.length);
      for (const item of value) this.writeValue(item);
      return;
    }
    if (value instanceof CborMap) {
      this.write(MAJOR.MAP, value.size);
      for (const [k, v] of value.intEntries) {
        this.writeValue(k);
        this.writeValue(v);
      }
      for (const [k, v] of value.strEntries) {
        this.writeValue(k);
        this.writeValue(v);
      }
      return;
    }
    throw new Error('unsupported CBOR value');
  }
}

export function encodeCbor(value: CborValue): Uint8Array {
  return new Writer().encode(value);
}

class Reader {
  private offset = 0;

  constructor(private bytes: Uint8Array) {}

  decode(): CborValue {
    return this.readValue();
  }

  done(): boolean {
    return this.offset === this.bytes.length;
  }

  consumedLength(): number {
    return this.offset;
  }

  private readByte(): number {
    if (this.offset >= this.bytes.length) throw new Error('unexpected end of CBOR');
    return this.bytes[this.offset++];
  }

  private readArg(ai: number): bigint {
    if (ai < 24) return BigInt(ai);
    const size = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : 0;
    if (size === 0) throw new Error('unsupported CBOR additional info');
    if (this.offset + size > this.bytes.length) throw new Error('truncated CBOR head');
    let v = 0n;
    for (let i = 0; i < size; i++) v = (v << 8n) | BigInt(this.bytes[this.offset + i]);
    this.offset += size;
    return v;
  }

  private readValue(): CborValue {
    const head = this.readByte();
    const major = head >> 5;
    const ai = head & 31;
    switch (major) {
      case MAJOR.UINT:
        return this.intArg(ai);
      case MAJOR.NINT: {
        const v = this.readArg(ai);
        const neg = -1n - v;
        // Return a number whenever it is a safe integer, so small labels like
        // COSE -1/-2/-3 compare cleanly with ===.
        return neg >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(neg) : neg;
      }
      case MAJOR.BYTES: {
        const len = Number(this.readArg(ai));
        const out = this.bytes.slice(this.offset, this.offset + len);
        if (out.length !== len) throw new Error('truncated CBOR bytes');
        this.offset += len;
        return out;
      }
      case MAJOR.TEXT: {
        const len = Number(this.readArg(ai));
        const slice = this.bytes.slice(this.offset, this.offset + len);
        if (slice.length !== len) throw new Error('truncated CBOR text');
        this.offset += len;
        return new TextDecoder().decode(slice);
      }
      case MAJOR.ARRAY: {
        const len = Number(this.readArg(ai));
        const arr: CborValue[] = [];
        for (let i = 0; i < len; i++) arr.push(this.readValue());
        return arr;
      }
      case MAJOR.MAP: {
        const len = Number(this.readArg(ai));
        const obj = new CborMap();
        for (let i = 0; i < len; i++) {
          const key = this.readValue();
          const val = this.readValue();
          // Integer keys come back as number (safe range) or bigint (64-bit).
          if (typeof key === 'number' || typeof key === 'bigint') {
            if (typeof key === 'bigint' && (key > BigInt(Number.MAX_SAFE_INTEGER) || key < BigInt(Number.MIN_SAFE_INTEGER))) {
              throw new Error('CBOR map integer key outside safe-integer range');
            }
            obj.setInt(Number(key), val);
          } else if (typeof key === 'string') {
            obj.set(key, val);
          } else {
            throw new Error('unsupported CBOR map key type');
          }
        }
        return obj;
      }
      case MAJOR.SIMPLE:
        if (ai === 20) return false;
        if (ai === 21) return true;
        if (ai === 22) return null;
        if (ai === 23) return undefined;
        throw new Error(`unsupported CBOR simple value ${ai}`);
      default:
        throw new Error(`unsupported CBOR major type ${major}`);
    }
  }

  private intArg(ai: number): number | bigint {
    const v = this.readArg(ai);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) return v;
    return Number(v);
  }
}

export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = reader.decode();
  if (!reader.done()) throw new Error('trailing bytes after CBOR value');
  return value;
}

/** Decode exactly one CBOR value and also return how many bytes it occupied. */
export function decodeCborOne(bytes: Uint8Array): { value: CborValue; length: number } {
  const reader = new Reader(bytes);
  const value = reader.decode();
  return { value, length: reader.consumedLength() };
}
