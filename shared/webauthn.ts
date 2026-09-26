import { base64urlToBytes, bytesEqual, bytesToBase64url, concatBytes, fromUtf8, utf8 } from './bytes';
import { CborMap, decodeCbor, decodeCborOne, encodeCbor, type CborValue } from './cbor';

/* ------------------------------------------------------------------ */
/*  Protocol constants                                                 */
/* ------------------------------------------------------------------ */

export const ES256 = -7;

/** COSE key type / EC2 / curve / algorithm labels (RFC 9053). */
const COSE_KTY = 1;
const COSE_ALG = 3;
const COSE_CRV = -1;
const COSE_X = -2;
const COSE_Y = -3;
const KTY_EC2 = 2;
const CRV_P256 = 1;

/** Authenticator data flags. */
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
/** Backup eligible (resident-capable credential may be backed up). */
export const FLAG_BE = 0x08;
/** Backup state: credential currently backed up. */
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

export type AttestationPreference = 'none' | 'indirect' | 'direct';

/* ------------------------------------------------------------------ */
/*  Client data (CollectedClientData)                                  */
/* ------------------------------------------------------------------ */

export interface ClientDataJSON {
  type: 'webauthn.create' | 'webauthn.get';
  challenge: string;
  origin: string;
  topOrigin?: string;
  crossOrigin?: boolean;
}

export function buildClientData(
  type: ClientDataJSON['type'],
  challengeB64Url: string,
  origin: string,
  crossOrigin = false,
): { text: string; json: ClientDataJSON } {
  const json: ClientDataJSON = { type, challenge: challengeB64Url, origin };
  if (crossOrigin) json.crossOrigin = true;
  // Key order is stable in JS objects; deterministic output matters for replay.
  return { text: JSON.stringify(json), json };
}

export function parseClientData(raw: Uint8Array): ClientDataJSON {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fromUtf8(raw));
  } catch {
    throw new CeremonyError('bad-client-data', 'clientDataJSON is not valid JSON');
  }
  const obj = parsed as Partial<ClientDataJSON>;
  if (obj.type !== 'webauthn.create' && obj.type !== 'webauthn.get') {
    throw new CeremonyError('bad-client-data', `unexpected clientData type: ${String(obj.type)}`);
  }
  if (typeof obj.challenge !== 'string' || !obj.challenge) {
    throw new CeremonyError('bad-client-data', 'clientDataJSON.challenge missing');
  }
  if (typeof obj.origin !== 'string' || !obj.origin) {
    throw new CeremonyError('bad-client-data', 'clientDataJSON.origin missing');
  }
  return obj as ClientDataJSON;
}

/* ------------------------------------------------------------------ */
/*  Authenticator data (§6.1)                                          */
/* ------------------------------------------------------------------ */

export interface ParsedAuthData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  attestedCredentialData?: AttestedCredentialData;
  extensions?: CborMap;
}

export interface AttestedCredentialData {
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  credentialPublicKey: Uint8Array; // COSE_Key bytes
}

export function parseAuthData(raw: Uint8Array): ParsedAuthData {
  if (raw.length < 37) throw new CeremonyError('bad-auth-data', 'authData shorter than 37 bytes');
  const rpIdHash = raw.slice(0, 32);
  const flags = raw[32];
  const signCount = new DataView(raw.buffer, raw.byteOffset + 33, 4).getUint32(0);
  let offset = 37;

  let attested: AttestedCredentialData | undefined;
  if (flags & FLAG_AT) {
    if (raw.length < offset + 18) throw new CeremonyError('bad-auth-data', 'truncated attested credential data');
    const aaguid = raw.slice(offset, offset + 16);
    offset += 16;
    const credIdLen = (raw[offset] << 8) | raw[offset + 1];
    offset += 2;
    if (raw.length < offset + credIdLen) throw new CeremonyError('bad-auth-data', 'truncated credential id');
    const credentialId = raw.slice(offset, offset + credIdLen);
    offset += credIdLen;
    // Rest must contain at least the COSE key map; find its end by decoding one value.
    const keyItem = consumeCbor(raw, offset, 'credential public key');
    offset += keyItem.length;
    attested = { aaguid, credentialId, credentialPublicKey: keyItem.bytes };
  }

  let extensions: CborMap | undefined;
  if (flags & FLAG_ED) {
    const extItem = consumeCbor(raw, offset, 'extensions');
    if (!(extItem.value instanceof CborMap)) {
      throw new CeremonyError('bad-auth-data', 'extensions must be a CBOR map');
    }
    extensions = extItem.value;
    offset += extItem.length;
  }

  if (offset !== raw.length) throw new CeremonyError('bad-auth-data', `trailing ${raw.length - offset} bytes in authData`);
  return { rpIdHash, flags, signCount, attestedCredentialData: attested, extensions };
}

function consumeCbor(raw: Uint8Array, offset: number, what: string): { bytes: Uint8Array; value: CborValue; length: number } {
  try {
    const { value, length } = decodeCborOne(raw.slice(offset));
    return { bytes: raw.slice(offset, offset + length), value, length };
  } catch (e) {
    throw new CeremonyError('bad-auth-data', `invalid CBOR in authData (${what}): ${(e as Error).message}`);
  }
}

/* ------------------------------------------------------------------ */
/*  COSE EC2 key handling                                              */
/* ------------------------------------------------------------------ */

export function coseEs256PublicJwk(publicKey: Uint8Array): JsonWebKey {
  const decoded = decodeCbor(publicKey);
  if (!(decoded instanceof CborMap)) {
    throw new CeremonyError('bad-public-key', 'COSE public key is not a map');
  }
  const kty = decoded.getInt(COSE_KTY);
  const alg = decoded.getInt(COSE_ALG);
  const crv = decoded.getInt(COSE_CRV);
  const x = decoded.getInt(COSE_X);
  const y = decoded.getInt(COSE_Y);
  if (kty !== KTY_EC2) throw new CeremonyError('bad-public-key', `unsupported kty ${String(kty)} (only EC2)`);
  if (alg !== ES256) throw new CeremonyError('bad-public-key', `unsupported alg ${String(alg)} (only ES256)`);
  if (crv !== CRV_P256) throw new CeremonyError('bad-public-key', `unsupported crv ${String(crv)} (only P-256)`);
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new CeremonyError('bad-public-key', 'x coordinate invalid');
  if (!(y instanceof Uint8Array) || y.length !== 32) throw new CeremonyError('bad-public-key', 'y coordinate invalid');
  return {
    kty: 'EC',
    crv: 'P-256',
    alg: 'ES256',
    x: bytesToBase64url(x),
    y: bytesToBase64url(y),
    ext: true,
  };
}

export function encodeEs256CoseKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  if (x.length !== 32 || y.length !== 32) throw new Error('P-256 coordinates must be 32 bytes');
  const map = new CborMap();
  map
    .setInt(COSE_KTY, KTY_EC2)
    .setInt(COSE_ALG, ES256)
    .setInt(COSE_CRV, CRV_P256)
    .setInt(COSE_X, x)
    .setInt(COSE_Y, y);
  return encodeCbor(map);
}

/* ------------------------------------------------------------------ */
/*  RP ID hash (SHA-256 of rpId)                                       */
/* ------------------------------------------------------------------ */

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

export async function rpIdHash(rpId: string): Promise<Uint8Array> {
  return sha256(utf8(rpId));
}

/**
 * Strict, deliberately non-wildcard RP ID / origin matching.
 * Real browsers implement a suffix rule (§7.1); this lab compares exact
 * registrable labels so that an "evil origin" test fails deterministically.
 * Scheme and port are compared as recorded in the origin string.
 */
export function originAllowed(origin: string, allowed: string[]): boolean {
  return allowed.includes(origin);
}

/* ------------------------------------------------------------------ */
/*  Signature verification (ES256 / ECDSA P-256 over SHA-256)          */
/* ------------------------------------------------------------------ */

/** Decode a DER ECDSA-Sig-Value into the fixed 64-byte R||S form WebCrypto wants. */
export function derEcdsaToRaw(der: Uint8Array): Uint8Array {
  let o = 0;
  const read = (): number => der[o++];
  if (read() !== 0x30) throw new CeremonyError('bad-signature', 'signature: missing SEQUENCE tag');
  const seqLen = read();
  if (seqLen !== der.length - 2) throw new CeremonyError('bad-signature', 'signature: bad SEQUENCE length');
  if (read() !== 0x02) throw new CeremonyError('bad-signature', 'signature: missing R INTEGER');
  const rLen = read();
  let r = der.slice(o, o + rLen);
  o += rLen;
  if (read() !== 0x02) throw new CeremonyError('bad-signature', 'signature: missing S INTEGER');
  const sLen = read();
  let s = der.slice(o, o + sLen);
  o += sLen;
  if (o !== der.length) throw new CeremonyError('bad-signature', 'signature: trailing bytes');
  r = trimPositiveInt(r);
  s = trimPositiveInt(s);
  if (r.length > 32 || s.length > 32) throw new CeremonyError('bad-signature', 'signature: integer exceeds 32 bytes');
  return concatBytes(pad32(r), pad32(s));
}

function trimPositiveInt(v: Uint8Array): Uint8Array {
  let start = 0;
  while (start < v.length - 1 && v[start] === 0) start++;
  // A leading 0x00 padding byte that disambiguates a positive integer is fine;
  // after trimming zeros, a remaining 0x00 means the integer itself was zero-ish.
  return v.slice(start);
}

function pad32(v: Uint8Array): Uint8Array {
  if (v.length === 32) return v;
  const out = new Uint8Array(32);
  out.set(v, 32 - v.length);
  return out;
}

export async function verifyEs256(
  publicKeyCose: Uint8Array,
  signedData: Uint8Array,
  signatureDer: Uint8Array,
): Promise<boolean> {
  const jwk = coseEs256PublicJwk(publicKeyCose);
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const rawSig = derEcdsaToRaw(signatureDer);
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rawSig, signedData);
}

/* ------------------------------------------------------------------ */
/*  Errors                                                             */
/* ------------------------------------------------------------------ */

export type CeremonyErrorCode =
  | 'bad-request'
  | 'challenge-expired'
  | 'challenge-consumed'
  | 'challenge-not-found'
  | 'bad-origin'
  | 'bad-rpid'
  | 'bad-type'
  | 'bad-client-data'
  | 'bad-auth-data'
  | 'bad-public-key'
  | 'bad-signature'
  | 'user-absent'
  | 'user-not-verified'
  | 'unsupported-algorithm'
  | 'duplicate-credential'
  | 'unknown-credential'
  | 'sign-count-clone'
  | 'credential-exists'
  | 'timeout'
  | 'cancelled'
  | 'invalid-record';

export class CeremonyError extends Error {
  constructor(
    public code: CeremonyErrorCode,
    message: string,
    public details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'CeremonyError';
  }
}

/* ------------------------------------------------------------------ */
/*  Small re-exports for authenticator/replay code                     */
/* ------------------------------------------------------------------ */

export { base64urlToBytes, bytesToBase64url, bytesEqual, concatBytes, utf8, encodeCbor, decodeCbor };
