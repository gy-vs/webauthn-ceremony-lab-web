/**
 * Software test authenticator (CTAP-authenticator-ish) that runs entirely in
 * the page using WebCrypto. It is NOT a platform authenticator and never talks
 * to real identity providers.
 *
 * Supported behavior:
 *  - ES256 (ECDSA P-256) credentials, non-extractable private keys kept only
 *    in page memory; exported ceremony records never contain private keys
 *  - injectable clock; the signature counter is derived from that clock, so
 *    rewinding the clock can produce a counter rollback (clone signal)
 *  - toggles for UP / UV / resident key (BE/BS flags)
 *  - attestation formats "none" and self "packed"
 *  - origin / rpId spoofing, corrupt signatures, duplicate credential ids,
 *    user absence, cancel and timeout simulations
 */

import { base64urlToBytes, bytesToBase64url, concatBytes, utf8 } from './bytes';
import { CborMap, encodeCbor } from './cbor';
import { encodeEs256CoseKey, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV, rpIdHash, sha256 } from './webauthn';
import type {
  AttestationStatementFormat,
  AuthenticatorAssertionResponsePayload,
  AuthenticatorAttestationResponsePayload,
  AuthenticationOptions,
  RegistrationOptions,
  Transport,
} from './protocol';

/** Fixed 16-byte AAGUID identifying this software test authenticator. */
export const TEST_AAGUID = utf8('webauthn-lab-v01'); // exactly 16 ASCII bytes
if (TEST_AAGUID.length !== 16) throw new Error('TEST_AAGUID must be 16 bytes');
const ALWAYS_TRANSPORTS: Transport[] = ['internal'];

export type LabDomError = 'NotAllowedError' | 'TimeoutError' | 'InvalidStateError';

export class AuthenticatorSimError extends Error {
  constructor(
    public domName: LabDomError,
    message: string,
  ) {
    super(message);
    this.name = domName;
  }
}

export interface StoredCredential {
  credentialId: Uint8Array;
  rpId: string;
  userHandle: Uint8Array;
  coseKey: Uint8Array;
  /** Non-extractable; never serialized out of the authenticator. */
  privateKey: CryptoKey;
  resident: boolean;
  createdAtMs: number;
  /** Authenticator-local monotonic tick added to clock-derived counter. */
  ticks: number;
}

export interface Clock {
  now(): number;
}

export const realClock: Clock = { now: () => Date.now() };

export interface MakeBehavior {
  /** Effective origin claimed in clientData (override to simulate bad origin). */
  origin: string;
  crossOrigin?: boolean;
  /** Effective RP ID the authenticator hashes (override to simulate rpId mismatch). */
  rpId: string;
  up: boolean;
  uv: boolean;
  residentKey: boolean;
  attestation: AttestationStatementFormat;
  /** Reuse an existing credential id (duplicate-credential scenario). */
  credentialIdOverride?: Uint8Array;
  failure?: 'cancel' | 'timeout' | 'user-absent';
  delayMs?: number;
  signal?: AbortSignal;
}

export interface GetBehavior {
  origin: string;
  crossOrigin?: boolean;
  rpId: string;
  up: boolean;
  uv: boolean;
  failure?: 'cancel' | 'timeout' | 'user-absent';
  delayMs?: number;
  signal?: AbortSignal;
  /**
   * Signature counter behavior:
   *  - 'auto' (default): clock-derived counter
   *  - number          : force an exact 32-bit value (use to replay/rewind)
   */
  signCount?: 'auto' | number;
  corruptSignature?: boolean;
  /** Credential to assert with; when omitted the authenticator picks from allowCredentials. */
  credentialIdOverride?: Uint8Array;
  /** Resident-key login: no allowCredentials, discover credential from store. */
  discoverable?: boolean;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (ms <= 0) {
      resolve();
      return;
    }
    if (signal?.aborted) {
      reject(new AuthenticatorSimError('NotAllowedError', 'ceremony aborted (cancelled)'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new AuthenticatorSimError('NotAllowedError', 'ceremony aborted (cancelled)'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** Convert WebCrypto's raw R||S (64 bytes) signature into DER ECDSA-Sig-Value. */
export function rawEcdsaToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) throw new Error('raw ECDSA signature must be 64 bytes');
  const r = derInteger(raw.slice(0, 32));
  const s = derInteger(raw.slice(32, 64));
  const body = concatBytes(new Uint8Array([0x02, r.length]), r, new Uint8Array([0x02, s.length]), s);
  return concatBytes(new Uint8Array([0x30, body.length]), body);
}

function derInteger(v: Uint8Array): Uint8Array {
  let start = 0;
  while (start < v.length - 1 && v[start] === 0) start++;
  const trimmed = v.slice(start);
  // High bit set needs a leading 0x00 so DER INTEGER stays positive.
  if (trimmed[0] & 0x80) return concatBytes(new Uint8Array([0x00]), trimmed);
  return trimmed;
}

export interface MakeResult {
  id: string;
  response: AuthenticatorAttestationResponsePayload;
  authData: Uint8Array;
  signCount: number;
}

export interface GetResult {
  id: string;
  response: AuthenticatorAssertionResponsePayload;
  signCount: number;
}

export class SoftwareAuthenticator {
  private credentials = new Map<string, StoredCredential>();
  /** Epoch from which clock-derived sign counts are measured. */
  private epochMs: number;

  constructor(private clock: Clock = realClock) {
    this.epochMs = clock.now();
  }

  setClock(clock: Clock): void {
    this.clock = clock;
  }

  getClock(): Clock {
    return this.clock;
  }

  reset(): void {
    this.credentials.clear();
  }

  listCredentials(): StoredCredential[] {
    return [...this.credentials.values()];
  }

  private storeKey(rpId: string, credentialId: Uint8Array): string {
    return `${rpId}:${bytesToBase64url(credentialId)}`;
  }

  private find(rpId: string, credentialId: Uint8Array): StoredCredential | null {
    return this.credentials.get(this.storeKey(rpId, credentialId)) ?? null;
  }

  private credentialsFor(rpId: string): StoredCredential[] {
    return [...this.credentials.values()].filter((c) => c.rpId === rpId);
  }

  private async generateKey(): Promise<{ pair: CryptoKeyPair; cose: Uint8Array }> {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
    const cose = encodeEs256CoseKey(base64urlToBytes(jwk.x!), base64urlToBytes(jwk.y!));
    return { pair, cose };
  }

  /**
   * Clock-derived sign count, wrapped to 32 bits.
   *
   * Rewinding the injected clock produces a value numerically below previously
   * observed counts (and wraps modulo 2^32 if driven below zero), which is
   * exactly the counter rollback / clone signal the RP must detect.
   */
  private currentCounterValue(): number {
    return Math.floor((this.clock.now() - this.epochMs) / 1000) >>> 0;
  }

  private nextCounter(stored: StoredCredential, mode: 'auto' | number | undefined): number {
    stored.ticks += 1;
    if (typeof mode === 'number') return mode >>> 0;
    return (this.currentCounterValue() + stored.ticks) >>> 0;
  }

  private async preFlight(
    failure: 'cancel' | 'timeout' | 'user-absent' | undefined,
    delayMs: number,
    signal: AbortSignal | undefined,
  ): Promise<void> {
    if (delayMs > 0) await sleep(delayMs, signal);
    if (failure === 'cancel') throw new AuthenticatorSimError('NotAllowedError', 'operation cancelled (test)');
    if (failure === 'timeout') throw new AuthenticatorSimError('TimeoutError', 'operation timed out (test)');
    if (signal?.aborted) throw new AuthenticatorSimError('NotAllowedError', 'operation cancelled (test)');
  }

  /** authenticatorMakeCredential. */
  async makeCredential(options: RegistrationOptions, behavior: MakeBehavior): Promise<MakeResult> {
    await this.preFlight(behavior.failure, behavior.delayMs ?? 0, behavior.signal);
    if (!behavior.up) {
      throw new AuthenticatorSimError('NotAllowedError', 'user presence not confirmed (test: user absent)');
    }
    const sel = options.authenticatorSelection;
    if (sel?.residentKey === 'required' && !behavior.residentKey) {
      throw new AuthenticatorSimError(
        'InvalidStateError',
        'authenticator cannot satisfy residentKey=required',
      );
    }

    const credentialId = behavior.credentialIdOverride ?? crypto.getRandomValues(new Uint8Array(16));
    if (this.find(behavior.rpId, credentialId)) {
      throw new AuthenticatorSimError(
        'InvalidStateError',
        'credential id already exists on this authenticator (test: duplicate credential id)',
      );
    }

    const { pair, cose } = await this.generateKey();
    const userHandle = base64urlToBytes(options.user.id);
    const signCount = this.currentCounterValue();

    let flags = FLAG_AT | FLAG_UP;
    if (behavior.uv) flags |= FLAG_UV;
    if (behavior.residentKey) flags |= FLAG_BE | FLAG_BS;

    const attested = concatBytes(
      TEST_AAGUID,
      new Uint8Array([(credentialId.length >> 8) & 255, credentialId.length & 255]),
      credentialId,
      cose,
    );
    const authData = concatBytes(await rpIdHash(behavior.rpId), packFlagsCount(flags, signCount), attested);

    const clientDataJSON = buildClientData('webauthn.create', options.challenge, behavior.origin, behavior.crossOrigin);

    let attestationObject: Uint8Array;
    if (behavior.attestation === 'none') {
      const obj = new CborMap();
      obj.set('fmt', 'none').set('attStmt', new CborMap()).set('authData', authData);
      attestationObject = encodeCbor(obj);
    } else {
      // Self attestation, packed format (§8.2.1): sig over authData || hash(clientDataJSON).
      const signed = concatBytes(authData, await sha256(clientDataJSON));
      const rawSig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, signed));
      const attStmt = new CborMap();
      attStmt.set('alg', -7).set('sig', rawEcdsaToDer(rawSig));
      const obj = new CborMap();
      obj.set('fmt', 'packed').set('attStmt', attStmt).set('authData', authData);
      attestationObject = encodeCbor(obj);
    }

    this.credentials.set(this.storeKey(behavior.rpId, credentialId), {
      credentialId,
      rpId: behavior.rpId,
      userHandle,
      coseKey: cose,
      privateKey: pair.privateKey,
      resident: behavior.residentKey,
      createdAtMs: this.clock.now(),
      ticks: 0,
    });

    return {
      id: bytesToBase64url(credentialId),
      response: {
        clientDataJSON: bytesToBase64url(clientDataJSON),
        attestationObject: bytesToBase64url(attestationObject),
        transports: ALWAYS_TRANSPORTS,
        authenticatorFlags: {
          up: behavior.up,
          uv: behavior.uv,
          be: behavior.residentKey,
          bs: behavior.residentKey,
        },
      },
      authData,
      signCount,
    };
  }

  /** authenticatorGetAssertion. */
  async getAssertion(options: AuthenticationOptions, behavior: GetBehavior): Promise<GetResult> {
    await this.preFlight(behavior.failure, behavior.delayMs ?? 0, behavior.signal);
    if (!behavior.up) {
      throw new AuthenticatorSimError('NotAllowedError', 'user presence not confirmed (test: user absent)');
    }

    // Credential discovery always uses the RP ID from the ceremony options:
    // a real authenticator resolves the credential before it would ever notice
    // a hash mismatch. behavior.rpId only controls which rpIdHash is written,
    // which lets the "wrong RP ID" scenario produce a signed-but-rejected
    // assertion instead of a device-side "no credential" error.
    let stored: StoredCredential | null = null;
    if (behavior.credentialIdOverride) {
      stored = this.find(options.rpId, behavior.credentialIdOverride);
    } else if (behavior.discoverable || options.allowCredentials.length === 0) {
      stored =
        this.credentialsFor(options.rpId).find((c) => c.resident) ??
        this.credentialsFor(options.rpId)[0] ??
        null;
    } else {
      for (const desc of options.allowCredentials) {
        stored = this.find(options.rpId, base64urlToBytes(desc.id));
        if (stored) break;
      }
    }
    if (!stored) {
      throw new AuthenticatorSimError(
        'NotAllowedError',
        'no matching credential on authenticator (test: unknown credential)',
      );
    }

    const signCount = this.nextCounter(stored, behavior.signCount);
    let flags = FLAG_UP;
    if (behavior.uv) flags |= FLAG_UV;
    if (stored.resident) flags |= FLAG_BE | FLAG_BS;
    const authData = concatBytes(await rpIdHash(behavior.rpId), packFlagsCount(flags, signCount));

    const clientDataJSON = buildClientData('webauthn.get', options.challenge, behavior.origin, behavior.crossOrigin);
    const signed = concatBytes(authData, await sha256(clientDataJSON));
    const rawSig = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, stored.privateKey, signed),
    );
    let signature = rawEcdsaToDer(rawSig);
    if (behavior.corruptSignature) {
      signature = signature.slice();
      signature[signature.length - 1] ^= 0xff;
    }

    // allowCredentials-based (non-discoverable) assertions carry no userHandle.
    const userHandle = behavior.discoverable || options.allowCredentials.length === 0
      ? bytesToBase64url(stored.userHandle)
      : null;

    return {
      id: bytesToBase64url(stored.credentialId),
      response: {
        clientDataJSON: bytesToBase64url(clientDataJSON),
        authenticatorData: bytesToBase64url(authData),
        signature: bytesToBase64url(signature),
        userHandle,
        authenticatorFlags: { up: behavior.up, uv: behavior.uv, be: stored.resident, bs: stored.resident },
      },
      signCount,
    };
  }
}

function buildClientData(
  type: 'webauthn.create' | 'webauthn.get',
  challenge: string,
  origin: string,
  crossOrigin: boolean | undefined,
): Uint8Array {
  const obj: Record<string, unknown> = { type, challenge, origin };
  if (crossOrigin) obj.crossOrigin = true;
  return utf8(JSON.stringify(obj));
}

function packFlagsCount(flags: number, signCount: number): Uint8Array {
  const out = new Uint8Array(5);
  out[0] = flags;
  new DataView(out.buffer).setUint32(1, signCount >>> 0);
  return out;
}
