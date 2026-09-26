/**
 * Server-side ceremony verification. These checks implement the RP algorithm
 * from WebAuthn §7.1 / §7.2 with strict, explicit distinctions between
 * origin, RP ID, UV, resident key and attestation preference.
 */

import { CborMap, decodeCbor } from '../shared/cbor';
import { base64urlToBytes, bytesEqual, bytesToBase64url, concatBytes, toHex } from '../shared/bytes';
import {
  CeremonyError,
  FLAG_AT,
  FLAG_BE,
  FLAG_BS,
  FLAG_UP,
  FLAG_UV,
  coseEs256PublicJwk,
  originAllowed,
  parseAuthData,
  parseClientData,
  rpIdHash,
  sha256,
  verifyEs256,
} from '../shared/webauthn';
import type {
  AuthenticationOptions,
  AuthenticatorAssertionResponsePayload,
  AuthenticatorAttestationResponsePayload,
  RegistrationOptions,
} from '../shared/protocol';
import type { PendingChallenge, ServerCredential } from './store';

export interface RpPolicy {
  rpId: string;
  rpName: string;
  /** Exact origin strings accepted by this RP (no wildcard suffix rule). */
  allowedOrigins: string[];
}

/* ------------------------------------------------------------------ */
/*  Registration                                                       */
/* ------------------------------------------------------------------ */

export interface VerifyRegistrationInput {
  policy: RpPolicy;
  challenge: PendingChallenge;
  credentialIdB64Url: string;
  response: AuthenticatorAttestationResponsePayload;
}

export interface VerifiedRegistration {
  credentialId: string;
  credentialIdBytes: Uint8Array;
  publicKeyCose: Uint8Array;
  publicKeyJwk: JsonWebKey;
  signCount: number;
  flags: { up: boolean; uv: boolean; be: boolean; bs: boolean };
  residentKey: boolean;
  userVerified: boolean;
  attestationFormat: 'none' | 'packed-self';
  authData: Uint8Array;
}

export async function verifyRegistration(input: VerifyRegistrationInput): Promise<VerifiedRegistration> {
  const { policy, challenge, response } = input;
  const options: RegistrationOptions = challenge.registration!.options;

  // 1. clientDataJSON
  const clientDataRaw = decodeB64(response.clientDataJSON, 'clientDataJSON');
  const client = parseClientData(clientDataRaw);
  if (client.type !== 'webauthn.create') {
    throw new CeremonyError('bad-type', `expected webauthn.create, got ${client.type}`);
  }
  if (client.challenge !== options.challenge) {
    throw new CeremonyError('challenge-not-found', 'clientData challenge does not match this ceremony', {
      expected: options.challenge,
      received: client.challenge,
    });
  }
  if (!originAllowed(client.origin, policy.allowedOrigins)) {
    throw new CeremonyError('bad-origin', `origin ${client.origin} is not in the RP allow-list`, {
      origin: client.origin,
      allowedOrigins: policy.allowedOrigins,
    });
  }
  if (client.crossOrigin) {
    throw new CeremonyError('bad-origin', 'crossOrigin=true is not allowed for this RP');
  }

  // 2. attestationObject CBOR
  const attObj = decodeCbor(decodeB64(response.attestationObject, 'attestationObject'));
  if (!(attObj instanceof CborMap)) {
    throw new CeremonyError('bad-auth-data', 'attestationObject must be a CBOR map');
  }
  const fmt = attObj.get('fmt');
  const attStmt = attObj.get('attStmt');
  const authDataBytes = attObj.get('authData');
  if (typeof fmt !== 'string') throw new CeremonyError('bad-auth-data', 'attestation fmt missing');
  if (!(authDataBytes instanceof Uint8Array)) {
    throw new CeremonyError('bad-auth-data', 'attestation authData missing');
  }
  if (!(attStmt instanceof CborMap)) {
    throw new CeremonyError('bad-auth-data', 'attestation attStmt must be a map');
  }

  const authData = parseAuthData(authDataBytes);
  const expectedHash = await rpIdHash(policy.rpId);
  if (!bytesEqual(authData.rpIdHash, expectedHash)) {
    throw new CeremonyError('bad-rpid', 'authData rpIdHash does not match rpId', {
      rpId: policy.rpId,
      expected: toHex(expectedHash),
      received: toHex(authData.rpIdHash),
    });
  }

  // 4. flags: UP required; UV must honor the selection; BE/BS compared to resident key
  if (!(authData.flags & FLAG_UP)) {
    throw new CeremonyError('user-absent', 'UP flag not set: user presence was not confirmed');
  }
  const wantUv = options.authenticatorSelection?.userVerification === 'required';
  const gotUv = (authData.flags & FLAG_UV) !== 0;
  if (wantUv && !gotUv) {
    throw new CeremonyError('user-not-verified', 'UV required by options but UV flag is not set');
  }
  const wantResident =
    options.authenticatorSelection?.residentKey === 'required' ||
    options.authenticatorSelection?.residentKey === 'preferred';
  const gotResident = (authData.flags & FLAG_BE) !== 0;
  if (wantResident && !gotResident) {
    throw new CeremonyError('bad-auth-data', 'resident key requested but BE flag is not set');
  }
  if (options.authenticatorSelection?.residentKey === 'discouraged' && gotResident) {
    throw new CeremonyError('bad-auth-data', 'residentKey discouraged but BE flag is set');
  }

  // 5. attested credential data
  if (!(authData.flags & FLAG_AT) || !authData.attestedCredentialData) {
    throw new CeremonyError('bad-auth-data', 'registration authData must carry attested credential data (AT flag)');
  }
  const acd = authData.attestedCredentialData;
  const credentialIdBytes = decodeB64(input.credentialIdB64Url, 'credential id');
  if (!bytesEqual(acd.credentialId, credentialIdBytes)) {
    throw new CeremonyError('bad-auth-data', 'response id does not match attested credential id');
  }

  // 6. public key: ES256 EC2 only
  const publicKeyJwk = coseEs256PublicJwk(acd.credentialPublicKey);

  // 7. attestation statement vs preference
  let attestationFormat: VerifiedRegistration['attestationFormat'];
  if (fmt === 'none') {
    attestationFormat = 'none';
    if (options.attestation === 'direct') {
      throw new CeremonyError(
        'bad-auth-data',
        'attestation preference "direct" but authenticator returned fmt "none"',
      );
    }
  } else if (fmt === 'packed') {
    const sig = attStmt.get('sig');
    const alg = attStmt.get('alg');
    if (!(sig instanceof Uint8Array)) throw new CeremonyError('bad-auth-data', 'packed attStmt.sig missing');
    if (alg !== -7) throw new CeremonyError('unsupported-algorithm', `packed attStmt.alg ${String(alg)} is not ES256`);
    // Self attestation: verify sig over authData || hash(clientDataJSON) with credential public key.
    const signed = concatBytes(authDataBytes, await sha256(clientDataRaw));
    const ok = await verifyEs256(acd.credentialPublicKey, signed, sig).catch(() => false);
    if (!ok) throw new CeremonyError('bad-signature', 'packed self-attestation signature failed verification');
    attestationFormat = 'packed-self';
  } else {
    throw new CeremonyError('bad-auth-data', `unsupported attestation format "${fmt}"`);
  }

  // 8. excludeCredentials: same credential id must not already exist for this RP
  if (options.excludeCredentials.some((d) => d.id === input.credentialIdB64Url)) {
    throw new CeremonyError('credential-exists', 'credential id already registered for this user (excludeCredentials)');
  }

  return {
    credentialId: input.credentialIdB64Url,
    credentialIdBytes,
    publicKeyCose: acd.credentialPublicKey,
    publicKeyJwk,
    signCount: authData.signCount,
    flags: {
      up: (authData.flags & FLAG_UP) !== 0,
      uv: gotUv,
      be: (authData.flags & FLAG_BE) !== 0,
      bs: (authData.flags & FLAG_BS) !== 0,
    },
    residentKey: gotResident,
    userVerified: gotUv,
    attestationFormat,
    authData: authDataBytes,
  };
}

/* ------------------------------------------------------------------ */
/*  Authentication                                                     */
/* ------------------------------------------------------------------ */

export interface VerifyAuthenticationInput {
  policy: RpPolicy;
  challenge: PendingChallenge;
  credentialIdB64Url: string;
  response: AuthenticatorAssertionResponsePayload;
  /** Server credential looked up by (rpId, credentialId). */
  credential: ServerCredential;
}

export interface VerifiedAuthentication {
  signCount: number;
  previousSignCount: number;
  cloneWarning: boolean;
  userVerified: boolean;
}

export async function verifyAuthentication(input: VerifyAuthenticationInput): Promise<VerifiedAuthentication> {
  const { policy, challenge, response, credential } = input;
  const options: AuthenticationOptions = challenge.authentication!.options;

  // 1. clientDataJSON
  const clientDataRaw = decodeB64(response.clientDataJSON, 'clientDataJSON');
  const client = parseClientData(clientDataRaw);
  if (client.type !== 'webauthn.get') {
    throw new CeremonyError('bad-type', `expected webauthn.get, got ${client.type}`);
  }
  if (client.challenge !== options.challenge) {
    throw new CeremonyError('challenge-not-found', 'clientData challenge does not match this ceremony');
  }
  if (!originAllowed(client.origin, policy.allowedOrigins)) {
    throw new CeremonyError('bad-origin', `origin ${client.origin} is not in the RP allow-list`, {
      origin: client.origin,
      allowedOrigins: policy.allowedOrigins,
    });
  }
  if (client.crossOrigin) {
    throw new CeremonyError('bad-origin', 'crossOrigin=true is not allowed for this RP');
  }

  // 2. authData
  const authDataRaw = decodeB64(response.authenticatorData, 'authenticatorData');
  const authData = parseAuthData(authDataRaw);
  const expectedHash = await rpIdHash(policy.rpId);
  if (!bytesEqual(authData.rpIdHash, expectedHash)) {
    throw new CeremonyError('bad-rpid', 'authData rpIdHash does not match rpId', {
      rpId: policy.rpId,
      expected: toHex(expectedHash),
      received: toHex(authData.rpIdHash),
    });
  }
  if (!(authData.flags & FLAG_UP)) {
    throw new CeremonyError('user-absent', 'UP flag not set: user presence was not confirmed');
  }
  const gotUv = (authData.flags & FLAG_UV) !== 0;
  if (options.userVerification === 'required' && !gotUv) {
    throw new CeremonyError('user-not-verified', 'UV required by options but UV flag is not set');
  }

  // 3. allowCredentials (empty list = discoverable / resident credential login)
  if (options.allowCredentials.length > 0 &&
      !options.allowCredentials.some((d) => d.id === input.credentialIdB64Url)) {
    throw new CeremonyError('unknown-credential', 'asserted credential id is not in allowCredentials');
  }

  // 4. userHandle: when present it must match the user bound to the credential
  if (response.userHandle !== null && response.userHandle !== credential.user.id) {
    throw new CeremonyError('bad-request', 'userHandle does not match the credential owner', {
      received: response.userHandle,
      expected: credential.user.id,
    });
  }

  // 5. signature over authData || hash(clientDataJSON)
  const signed = concatBytes(authDataRaw, await sha256(clientDataRaw));
  const signature = decodeB64(response.signature, 'signature');
  const ok = await verifyEs256(credential.publicKeyCose, signed, signature).catch(() => false);
  if (!ok) throw new CeremonyError('bad-signature', 'assertion signature failed ES256 verification');

  // 6. signature counter (WebAuthn §6.1.1 / §7.2 step 20).
  //    A cryptographic success with a suspicious counter is still cryptographi-
  //    cally "verified", but the RP must treat it as a cloned-device signal:
  //      a) signCount went down (or stayed equal once nonzero) — classic clone
  //      b) implausible jump near the uint32 ceiling — clock rewound on the
  //         device, so its counter wrapped modulo 2^32 to a huge value
  //    The server flags the credential and never moves the stored counter
  //    backwards or adopts a wrapped value.
  const previousSignCount = credential.signCount;
  const signCount = authData.signCount;
  let cloneWarning = false;
  if (signCount !== 0 || previousSignCount !== 0) {
    if (signCount <= previousSignCount) cloneWarning = true;
    // A normal authenticator cannot legitimately gain 2^31-1 counts in one use.
    if (signCount - previousSignCount > 0x7fffffff) cloneWarning = true;
  }

  return { signCount, previousSignCount, cloneWarning, userVerified: gotUv };
}

/* ------------------------------------------------------------------ */
/*  Stateless record re-check (export/import)                          */
/* ------------------------------------------------------------------ */

/**
 * Re-verify an exported record against the *current* server credential store.
 * Challenges are NOT consumed here: the record carries the full response and
 * is evaluated independently. Counter rollback is judged against the stored
 * credential's latest counter, which is why an old exported assertion may show
 * a clone warning after the credential kept being used.
 */
export async function recheckRecord(record: unknown, policy: RpPolicy, credentialLookup: {
  getCredential(rpId: string, id: string): ServerCredential | undefined;
}): Promise<{ ok: boolean; checks: { name: string; ok: boolean; detail: string }[]; error?: string }> {
  const checks: { name: string; ok: boolean; detail: string }[] = [];
  const fail = (name: string, detail: string) => {
    checks.push({ name, ok: false, detail });
    return { ok: false, checks, error: detail };
  };
  const rec = record as {
    format?: string;
    ceremony?: 'registration' | 'authentication';
    rp?: { id?: string };
    options?: RegistrationOptions | AuthenticationOptions;
    response?: AuthenticatorAttestationResponsePayload | AuthenticatorAssertionResponsePayload;
    verdict?: unknown;
    credentialId?: string;
  };
  if (rec?.format !== 'webauthn-ceremony-lab/record') {
    return fail('format', 'not a webauthn-ceremony-lab record');
  }
  if (rec.rp?.id !== policy.rpId) {
    return fail('rpId', `record rpId "${rec.rp?.id ?? '?'}" does not match policy "${policy.rpId}"`);
  }
  try {
    if (rec.ceremony === 'registration') {
      // Reconstruct a throwaway pending challenge so the same verifier runs.
      const challenge: PendingChallenge = {
        id: rec.options!.challenge!,
        kind: 'registration',
        createdAt: 0,
        expiresAt: Number.MAX_SAFE_INTEGER,
        status: 'pending',
        registration: { options: rec.options as RegistrationOptions },
      };
      const resp = rec.response as AuthenticatorAttestationResponsePayload;
      const credentialId = guessCredentialId(record, resp);
      const verified = await verifyRegistration({
        policy,
        challenge,
        credentialIdB64Url: credentialId,
        response: resp,
      });
      checks.push({ name: 'registration', ok: true, detail: `ES256 key accepted, signCount=${verified.signCount}` });
      const exists = credentialLookup.getCredential(policy.rpId, credentialId);
      checks.push({
        name: 'credential-store',
        ok: true,
        detail: exists ? 'credential currently exists on server' : 'not currently registered (record still valid)',
      });
      return { ok: true, checks };
    } else if (rec.ceremony === 'authentication') {
      const resp = rec.response as AuthenticatorAssertionResponsePayload;
      const credentialId = guessCredentialId(record, resp);
      const credential = credentialLookup.getCredential(policy.rpId, credentialId);
      if (!credential) {
        return fail('unknown-credential', `server has no credential ${credentialId} for rpId ${policy.rpId}`);
      }
      const challenge: PendingChallenge = {
        id: rec.options!.challenge!,
        kind: 'authentication',
        createdAt: 0,
        expiresAt: Number.MAX_SAFE_INTEGER,
        status: 'pending',
        authentication: {
          options: rec.options as AuthenticationOptions,
          userHandle: credential.user.id,
        },
      };
      const verified = await verifyAuthentication({
        policy,
        challenge,
        credentialIdB64Url: credentialId,
        response: resp,
        credential,
      });
      checks.push({
        name: 'signature',
        ok: true,
        detail: `ES256 signature verified, counter ${verified.previousSignCount} -> ${verified.signCount}`,
      });
      checks.push({
        name: 'counter',
        ok: !verified.cloneWarning,
        detail: verified.cloneWarning
          ? `CLONE WARNING: recorded counter ${verified.signCount} <= current server counter ${verified.previousSignCount}`
          : 'counter monotonic',
      });
      return { ok: !verified.cloneWarning, checks };
    }
    return fail('ceremony', 'unknown ceremony kind');
  } catch (e) {
    if (e instanceof CeremonyError) {
      return fail(e.code, e.message);
    }
    return fail('error', (e as Error).message);
  }
}

function guessCredentialId(
  record: unknown,
  response: AuthenticatorAttestationResponsePayload | AuthenticatorAssertionResponsePayload,
): string {
  const top = record as { credentialId?: string; result?: { credentialId?: string } };
  if (top.credentialId) return top.credentialId;
  const verdict = (record as { verdict?: { result?: { credentialId?: string } } }).verdict;
  if (verdict?.result?.credentialId) return verdict.result.credentialId;
  // Registration: parse it out of the attestation object.
  if ('attestationObject' in response) {
    const att = decodeCbor(base64urlToBytes(response.attestationObject));
    if (!(att instanceof CborMap) || !(att.get('authData') instanceof Uint8Array)) {
      throw new CeremonyError('invalid-record', 'attestationObject malformed');
    }
    const auth = parseAuthData(att.get('authData') as Uint8Array);
    if (auth.attestedCredentialData) {
      return bytesToBase64url(auth.attestedCredentialData.credentialId);
    }
  }
  throw new CeremonyError('invalid-record', 'record does not identify the credential');
}

function decodeB64(value: string, field: string): Uint8Array {
  try {
    return base64urlToBytes(value);
  } catch (e) {
    throw new CeremonyError('bad-request', `${field}: ${(e as Error).message}`);
  }
}
