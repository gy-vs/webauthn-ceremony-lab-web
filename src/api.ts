import type {
  ApiError,
  AttestationPreference,
  AuthenticatorAssertionResponsePayload,
  AuthenticatorAttestationResponsePayload,
  AuthenticationOptions,
  CeremonyRecord,
  CredentialSummary,
  RegistrationOptions,
  ResidentKeyRequirement,
  UserVerificationRequirement,
} from '../shared/protocol';

export interface ServerConfig {
  rpId: string;
  rpName: string;
  allowedOrigins: string[];
  defaultTimeoutMs: number;
}

export interface ChallengeView {
  id: string;
  kind: 'registration' | 'authentication';
  status: 'pending' | 'consumed' | 'expired';
  createdAt: number;
  expiresAt: number;
  consumedAt: number | null;
  consumedBy: string | null;
  outcome:
    | { ok: true; label?: string }
    | { ok: false; label?: string; errorCode: string; message: string }
    | null;
  ttlMs: number;
}

export interface ServerState {
  credentials: CredentialSummary[];
  challenges: ChallengeView[];
  events: { ts: number; level: 'info' | 'warn' | 'error'; message: string; data?: Record<string, unknown> }[];
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
    body: init?.body,
  });
  const json = (await res.json().catch(() => ({}))) as T | ApiError;
  if (!res.ok || (json as ApiError).error) {
    const err = (json as ApiError).error;
    const error = new Error(err?.message ?? `HTTP ${res.status}`) as Error & {
      code?: string;
      details?: Record<string, unknown>;
    };
    error.code = err?.code;
    error.details = err?.details;
    throw error;
  }
  return json as T;
}

export interface BeginRegistrationRequest {
  timeoutMs: number;
  attestation: AttestationPreference;
  residentKey: ResidentKeyRequirement;
  userVerification: UserVerificationRequirement;
  userName?: string;
  displayName?: string;
  userId?: string;
  label?: string;
}

export interface BeginAuthenticationRequest {
  timeoutMs: number;
  userVerification: UserVerificationRequirement;
  credentialId?: string;
  userId?: string;
  discoverable?: boolean;
  label?: string;
}

export const api = {
  config: () => request<ServerConfig>('/api/config'),

  state: () => request<ServerState>('/api/state'),

  reset: () => request<{ ok: true }>('/api/reset', { method: 'POST', body: '{}' }),

  beginRegistration: (body: BeginRegistrationRequest) =>
    request<{ challengeId: string; options: RegistrationOptions; state: ChallengeView }>(
      '/api/register/begin',
      { method: 'POST', body: JSON.stringify(body) },
    ),

  finishRegistration: (body: {
    challengeId: string;
    credentialId: string;
    response: AuthenticatorAttestationResponsePayload;
    label?: string;
  }) =>
    request<{
      ok: true;
      result: import('../shared/protocol').RegistrationResult;
    }>('/api/register/finish', { method: 'POST', body: JSON.stringify(body) }),

  beginAuthentication: (body: BeginAuthenticationRequest) =>
    request<{ challengeId: string; options: AuthenticationOptions; state: ChallengeView }>(
      '/api/auth/begin',
      { method: 'POST', body: JSON.stringify(body) },
    ),

  finishAuthentication: (body: {
    challengeId: string;
    credentialId: string;
    response: AuthenticatorAssertionResponsePayload;
    label?: string;
  }) =>
    request<{
      ok: true;
      result: import('../shared/protocol').AuthenticationResult;
    }>('/api/auth/finish', { method: 'POST', body: JSON.stringify(body) }),

  checkRecord: (record: CeremonyRecord | unknown) =>
    request<{
      ok: boolean;
      checks: { name: string; ok: boolean; detail: string }[];
      error?: string;
    }>('/api/records/check', { method: 'POST', body: JSON.stringify({ record }) }),
};
