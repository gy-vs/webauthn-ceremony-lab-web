/**
 * In-memory server state: no external database.
 *
 *  - challenges are single-use and expire (TTL tied to the requested timeout)
 *  - consumeChallenge() is atomic from the event loop's perspective: the first
 *    finisher wins and every later finisher (including a second tab that races
 *    the same challenge) is rejected with the winner recorded
 *  - credentials keyed by (rpId, credentialId) with a server-side sign counter
 */

import { bytesToBase64url } from '../shared/bytes';
import { CeremonyError } from '../shared/webauthn';
import type {
  AttestationPreference,
  RegistrationOptions,
  AuthenticationOptions,
  PublicKeyCredentialUserEntity,
  ResidentKeyRequirement,
  Transport,
  UserVerificationRequirement,
} from '../shared/protocol';

export interface ServerCredential {
  credentialId: string; // base64url
  rpId: string;
  user: PublicKeyCredentialUserEntity;
  publicKeyCose: Uint8Array;
  publicKeyJwk: JsonWebKey;
  signCount: number;
  residentKey: boolean;
  userVerified: boolean;
  createdAt: number;
  lastUsedAt: number | null;
  cloneDetected: boolean;
}

export interface ServerEvent {
  ts: number;
  level: 'info' | 'warn' | 'error';
  message: string;
  data?: Record<string, unknown>;
}

export interface PendingChallenge {
  id: string;
  kind: 'registration' | 'authentication';
  createdAt: number;
  expiresAt: number;
  status: 'pending' | 'consumed' | 'expired';
  consumedAt?: number;
  consumedBy?: string;
  /** Outcome snapshot so the state view can explain the terminal state. */
  outcome?:
    | { ok: true; label?: string }
    | { ok: false; label?: string; errorCode: string; message: string };
  registration?: {
    options: RegistrationOptions;
  };
  authentication?: {
    options: AuthenticationOptions;
    userHandle: string | null;
  };
}

const MAX_EVENTS = 200;

export class CeremonyStore {
  readonly challenges = new Map<string, PendingChallenge>();
  readonly credentials = new Map<string, ServerCredential>();
  readonly events: ServerEvent[] = [];

  log(level: ServerEvent['level'], message: string, data?: Record<string, unknown>): void {
    this.events.push({ ts: Date.now(), level, message, data });
    if (this.events.length > MAX_EVENTS) this.events.shift();
  }

  newChallengeId(): string {
    return bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)));
  }

  createRegistrationChallenge(params: {
    timeoutMs: number;
    rp: { id: string; name: string };
    user: PublicKeyCredentialUserEntity;
    attestation: AttestationPreference;
    residentKey: ResidentKeyRequirement;
    userVerification: UserVerificationRequirement;
    excludeCredentialsIds: string[];
    now?: number;
  }): PendingChallenge {
    const now = params.now ?? Date.now();
    const id = this.newChallengeId();
    const requireResidentKey = params.residentKey === 'required';
    const options: RegistrationOptions = {
      challenge: id,
      timeout: params.timeoutMs,
      rp: { id: params.rp.id, name: params.rp.name },
      user: params.user,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      attestation: params.attestation,
      authenticatorSelection: {
        residentKey: params.residentKey,
        requireResidentKey,
        userVerification: params.userVerification,
      },
      excludeCredentials: params.excludeCredentialsIds.map((cid) => ({
        id: cid,
        type: 'public-key' as const,
        transports: ['internal'] as Transport[],
      })),
      expectedOrigin: '', // filled by caller-independent policy layer below
      expectedRpId: params.rp.id,
      expiresAt: now + params.timeoutMs,
    };
    const challenge: PendingChallenge = {
      id,
      kind: 'registration',
      createdAt: now,
      expiresAt: now + params.timeoutMs,
      status: 'pending',
      registration: { options },
    };
    this.challenges.set(id, challenge);
    return challenge;
  }

  createAuthenticationChallenge(params: {
    timeoutMs: number;
    rpId: string;
    allowCredentialIds: string[];
    userVerification: UserVerificationRequirement;
    userHandle: string | null;
    now?: number;
  }): PendingChallenge {
    const now = params.now ?? Date.now();
    const id = this.newChallengeId();
    const options: AuthenticationOptions = {
      challenge: id,
      timeout: params.timeoutMs,
      rpId: params.rpId,
      allowCredentials: params.allowCredentialIds.map((cid) => ({
        id: cid,
        type: 'public-key' as const,
        transports: ['internal'] as Transport[],
      })),
      userVerification: params.userVerification,
      expectedOrigin: '',
      expectedRpId: params.rpId,
      expiresAt: now + params.timeoutMs,
    };
    const challenge: PendingChallenge = {
      id,
      kind: 'authentication',
      createdAt: now,
      expiresAt: now + params.timeoutMs,
      status: 'pending',
      authentication: { options, userHandle: params.userHandle },
    };
    this.challenges.set(id, challenge);
    return challenge;
  }

  /**
   * Atomically claim a challenge. Single-use: the first consumer wins.
   * Expired pending challenges are marked expired on sight.
   */
  consume(challengeId: string, label: string | undefined, now = Date.now()): PendingChallenge {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) throw new CeremonyError('challenge-not-found', 'challenge is unknown to the server');
    if (challenge.status === 'consumed') {
      throw new CeremonyError('challenge-consumed', 'challenge was already used (single-use)', {
        consumedBy: challenge.consumedBy ?? null,
        consumedAt: challenge.consumedAt ?? null,
        outcome: challenge.outcome ?? null,
      });
    }
    if (challenge.status === 'expired' || now >= challenge.expiresAt) {
      challenge.status = 'expired';
      throw new CeremonyError('challenge-expired', 'challenge has expired', {
        expiresAt: challenge.expiresAt,
        serverTime: now,
      });
    }
    challenge.status = 'consumed';
    challenge.consumedAt = now;
    challenge.consumedBy = label || 'unlabeled client';
    return challenge;
  }

  settle(challenge: PendingChallenge, outcome: NonNullable<PendingChallenge['outcome']>): void {
    challenge.outcome = outcome;
  }

  credentialKey(rpId: string, credentialId: string): string {
    return `${rpId}:${credentialId}`;
  }

  getCredential(rpId: string, credentialId: string): ServerCredential | undefined {
    return this.credentials.get(this.credentialKey(rpId, credentialId));
  }

  putCredential(credential: ServerCredential): void {
    this.credentials.set(this.credentialKey(credential.rpId, credential.credentialId), credential);
  }

  listCredentials(): ServerCredential[] {
    return [...this.credentials.values()];
  }

  /** Mark expired pending challenges; called periodically and before state reads. */
  sweepExpired(now = Date.now()): number {
    let n = 0;
    for (const challenge of this.challenges.values()) {
      if (challenge.status === 'pending' && now >= challenge.expiresAt) {
        challenge.status = 'expired';
        n++;
      }
    }
    return n;
  }

  reset(): void {
    this.challenges.clear();
    this.credentials.clear();
    this.events.length = 0;
    this.log('info', 'server state reset');
  }
}

export const store = new CeremonyStore();
