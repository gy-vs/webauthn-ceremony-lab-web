import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { base64urlToBytes, bytesToBase64url, toHex, utf8 } from '../shared/bytes';
import { CeremonyError } from '../shared/webauthn';
import { store, type PendingChallenge, type ServerCredential, type ServerEvent } from './store';
import { recheckRecord, verifyAuthentication, verifyRegistration, type RpPolicy } from './verify';
import type {
  AttestationPreference,
  AuthenticationOptions,
  AuthenticatorAssertionResponsePayload,
  AuthenticatorAttestationResponsePayload,
  RegistrationOptions,
  ResidentKeyRequirement,
  UserVerificationRequirement,
} from '../shared/protocol';

/* ------------------------------------------------------------------ */
/*  RP policy — the server trusts nothing from the client about these  */
/* ------------------------------------------------------------------ */

const DEFAULT_ORIGINS = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://[::1]:5173',
];

const policy: RpPolicy = {
  rpId: process.env.RP_ID || 'localhost',
  rpName: process.env.RP_NAME || 'WebAuthn Ceremony Lab',
  allowedOrigins: (process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : DEFAULT_ORIGINS).map((s) =>
    s.trim(),
  ),
};

const DEFAULT_TIMEOUT_MS = 60_000;
const MIN_TIMEOUT_MS = 5_000;
const MAX_TIMEOUT_MS = 300_000;

function clampTimeout(value: unknown): number {
  const n = typeof value === 'number' && Number.isFinite(value) ? value : DEFAULT_TIMEOUT_MS;
  return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, Math.floor(n)));
}

export function createApp(): express.Express {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  // Periodic expiry sweep.
  const sweeper = setInterval(() => {
    const n = store.sweepExpired();
    if (n > 0) store.log('info', `${n} challenge(s) expired`);
  }, 5_000);
  sweeper.unref();

  /* ---------------- meta / state ---------------- */

  app.get('/api/config', (_req, res) => {
    res.json({
      rpId: policy.rpId,
      rpName: policy.rpName,
      allowedOrigins: policy.allowedOrigins,
      defaultTimeoutMs: DEFAULT_TIMEOUT_MS,
    });
  });

  app.get('/api/state', (_req, res) => {
    store.sweepExpired();
    res.json({
      credentials: store.listCredentials().map(credentialView),
      challenges: [...store.challenges.values()].map(challengeView),
      events: store.events.slice(-100),
    });
  });

  app.post('/api/reset', (_req, res) => {
    store.reset();
    res.json({ ok: true });
  });

  /* ---------------- registration ---------------- */

  app.post('/api/register/begin', (req, res) => {
    try {
      const body = req.body ?? {};
      const timeoutMs = clampTimeout(body.timeoutMs);
      const attestation: AttestationPreference =
        body.attestation === 'indirect' || body.attestation === 'direct' ? body.attestation : 'none';
      const residentKey: ResidentKeyRequirement =
        body.residentKey === 'required' || body.residentKey === 'preferred' || body.residentKey === 'discouraged'
          ? body.residentKey
          : 'discouraged';
      const userVerification: UserVerificationRequirement =
        body.userVerification === 'required' ||
        body.userVerification === 'preferred' ||
        body.userVerification === 'discouraged'
          ? body.userVerification
          : 'preferred';

      // Stable demo user identity; caller may override name only.
      const userId = utf8(typeof body.userId === 'string' && body.userId ? body.userId : 'lab-user');
      const user = {
        id: bytesToBase64url(userId),
        name: typeof body.userName === 'string' && body.userName ? body.userName : 'lab@example.com',
        displayName: typeof body.displayName === 'string' && body.displayName ? body.displayName : 'Lab User',
      };

      // excludeCredentials: everything this user already has for this RP.
      const excludeIds = store
        .listCredentials()
        .filter((c) => c.rpId === policy.rpId && c.user.id === user.id)
        .map((c) => c.credentialId);

      const challenge = store.createRegistrationChallenge({
        timeoutMs,
        rp: { id: policy.rpId, name: policy.rpName },
        user,
        attestation,
        residentKey,
        userVerification,
        excludeCredentialsIds: excludeIds,
      });
      const options = challenge.registration!.options;
      options.expectedOrigin = policy.allowedOrigins[0];
      options.expectedRpId = policy.rpId;

      store.log('info', 'registration challenge issued', {
        challenge: challenge.id,
        attestation,
        residentKey,
        userVerification,
        expiresAt: challenge.expiresAt,
      });
      res.json({
        challengeId: challenge.id,
        options,
        state: challengeView(challenge),
      });
    } catch (e) {
      sendError(res, e);
    }
  });

  app.post('/api/register/finish', async (req, res) => {
    const label = clientLabel(req);
    let challengeId = '';
    try {
      const body = req.body ?? {};
      challengeId = String(body.challengeId ?? '');
      const credentialId = String(body.credentialId ?? '');
      const response = body.response as AuthenticatorAttestationResponsePayload | undefined;
      if (!challengeId || !credentialId || !response) {
        throw new CeremonyError('bad-request', 'challengeId, credentialId and response are required');
      }

      // Atomic single-use claim happens BEFORE verification: the first
      // finisher wins even if its verification later fails.
      const challenge = store.consume(challengeId, label);

      try {
        const verified = await verifyRegistration({
          policy,
          challenge,
          credentialIdB64Url: credentialId,
          response,
        });

        // Independent server-side duplicate guard for this RP.
        if (store.getCredential(policy.rpId, credentialId)) {
          throw new CeremonyError(
            'duplicate-credential',
            'a credential with this id is already stored for this rpId',
            { credentialId, rpId: policy.rpId },
          );
        }

        const options = challenge.registration!.options;
        const record: ServerCredential = {
          credentialId,
          rpId: policy.rpId,
          user: options.user,
          publicKeyCose: verified.publicKeyCose,
          publicKeyJwk: verified.publicKeyJwk,
          signCount: verified.signCount,
          residentKey: verified.residentKey,
          userVerified: verified.userVerified,
          createdAt: Date.now(),
          lastUsedAt: null,
          cloneDetected: false,
        };
        store.putCredential(record);

        store.settle(challenge, { ok: true, label: label || undefined });
        store.log('info', 'registration accepted', {
          challenge: challengeId,
          credentialId,
          attestation: verified.attestationFormat,
          residentKey: verified.residentKey,
          uv: verified.userVerified,
          signCount: verified.signCount,
          client: label,
        });
        res.json({
          ok: true,
          result: {
            credentialId,
            credentialIdHex: toHex(base64urlToBytes(credentialId)),
            publicKeyJwk: verified.publicKeyJwk,
            signCount: verified.signCount,
            flags: verified.flags,
            attestationFormat: verified.attestationFormat,
            residentKey: verified.residentKey,
            userVerified: verified.userVerified,
            createdAt: record.createdAt,
          },
        });
      } catch (verifyError) {
        store.settle(challenge, {
          ok: false,
          label,
          errorCode: (verifyError as CeremonyError).code || 'error',
          message: (verifyError as Error).message,
        });
        store.log('error', 'registration rejected', {
          challenge: challengeId,
          code: (verifyError as CeremonyError).code,
          message: (verifyError as Error).message,
          client: label,
        });
        sendError(res, verifyError);
      }
    } catch (e) {
      logConsumptionFailure(challengeId, e as Error, label);
      sendError(res, e);
    }
  });

  /* ---------------- authentication ---------------- */

  app.post('/api/auth/begin', (req, res) => {
    try {
      const body = req.body ?? {};
      const timeoutMs = clampTimeout(body.timeoutMs);
      const userVerification: UserVerificationRequirement =
        body.userVerification === 'required' ||
        body.userVerification === 'preferred' ||
        body.userVerification === 'discouraged'
          ? body.userVerification
          : 'preferred';

      const all = store.listCredentials().filter((c) => c.rpId === policy.rpId);
      let allowIds = all.map((c) => c.credentialId);
      let userHandle: string | null = null;

      if (body.credentialId) {
        const match = all.find((c) => c.credentialId === String(body.credentialId));
        allowIds = match ? [match.credentialId] : [String(body.credentialId)];
        userHandle = match?.user.id ?? null;
      } else if (body.userId) {
        const uid = bytesToBase64url(utf8(String(body.userId)));
        const mine = all.filter((c) => c.user.id === uid);
        allowIds = mine.map((c) => c.credentialId);
        userHandle = uid;
      }

      // Discoverable / resident login: empty allowCredentials.
      const discoverable = body.discoverable === true;
      if (discoverable) {
        allowIds = [];
        userHandle = null;
      }

      const challenge = store.createAuthenticationChallenge({
        timeoutMs,
        rpId: policy.rpId,
        allowCredentialIds: allowIds,
        userVerification,
        userHandle,
      });
      const options = challenge.authentication!.options;
      options.expectedOrigin = policy.allowedOrigins[0];
      options.expectedRpId = policy.rpId;

      store.log('info', 'authentication challenge issued', {
        challenge: challenge.id,
        allowCredentials: allowIds.length,
        discoverable,
        userVerification,
      });
      res.json({ challengeId: challenge.id, options, state: challengeView(challenge) });
    } catch (e) {
      sendError(res, e);
    }
  });

  app.post('/api/auth/finish', async (req, res) => {
    const label = clientLabel(req);
    let challengeId = '';
    try {
      const body = req.body ?? {};
      challengeId = String(body.challengeId ?? '');
      const credentialId = String(body.credentialId ?? '');
      const response = body.response as AuthenticatorAssertionResponsePayload | undefined;
      if (!challengeId || !credentialId || !response) {
        throw new CeremonyError('bad-request', 'challengeId, credentialId and response are required');
      }

      const credential = store.getCredential(policy.rpId, credentialId);
      if (!credential) {
        throw new CeremonyError('unknown-credential', 'no stored credential with that id for this rpId', {
          credentialId,
          rpId: policy.rpId,
        });
      }

      const challenge = store.consume(challengeId, label);

      try {
        const verified = await verifyAuthentication({
          policy,
          challenge,
          credentialIdB64Url: credentialId,
          response,
          credential,
        });

        let adopted = credential.signCount;
        if (verified.cloneWarning) {
          // Freeze the counter; never move it backwards. Mark credential as cloned.
          credential.cloneDetected = true;
          store.log('warn', 'SIGNATURE COUNTER CLONE WARNING', {
            challenge: challengeId,
            credentialId,
            previous: verified.previousSignCount,
            received: verified.signCount,
            client: label,
          });
        } else if (verified.signCount !== 0 && verified.signCount > credential.signCount) {
          adopted = verified.signCount;
        }
        credential.signCount = adopted;
        credential.lastUsedAt = Date.now();

        store.settle(challenge, {
          ok: true,
          label,
        });
        store.log(verified.cloneWarning ? 'warn' : 'info', 'authentication accepted', {
          challenge: challengeId,
          credentialId,
          signCount: adopted,
          cloneWarning: verified.cloneWarning,
          uv: verified.userVerified,
          client: label,
        });
        res.json({
          ok: true,
          result: {
            credentialId,
            userHandle: response.userHandle,
            signCount: adopted,
            previousSignCount: verified.previousSignCount,
            cloneWarning: verified.cloneWarning,
            userVerified: verified.userVerified,
            authenticatedAt: credential.lastUsedAt,
          },
        });
      } catch (verifyError) {
        store.settle(challenge, {
          ok: false,
          label,
          errorCode: (verifyError as CeremonyError).code || 'error',
          message: (verifyError as Error).message,
        });
        store.log('error', 'authentication rejected', {
          challenge: challengeId,
          code: (verifyError as CeremonyError).code,
          message: (verifyError as Error).message,
          client: label,
        });
        sendError(res, verifyError);
      }
    } catch (e) {
      logConsumptionFailure(challengeId, e as Error, label);
      sendError(res, e);
    }
  });

  /* ---------------- record re-check ---------------- */

  app.post('/api/records/check', async (req, res) => {
    try {
      let record = req.body?.record;
      if (typeof req.body?.record === 'string') {
        record = JSON.parse(req.body.record);
      }
      if (!record) record = req.body;
      const result = await recheckRecord(record, policy, store);
      res.json(result);
    } catch (e) {
      sendError(res, new CeremonyError('invalid-record', (e as Error).message));
    }
  });

  /* ---------------- static frontend (production) ---------------- */

  const here = path.dirname(fileURLToPath(import.meta.url));
  const distDir = path.resolve(here, '..', 'dist');
  if (fs.existsSync(distDir)) {
    app.use(express.static(distDir));
    app.get('*', (_req, res) => res.sendFile(path.join(distDir, 'index.html')));
  }

  return app;
}

/* ------------------------------------------------------------------ */
/*  View mappers / error handling                                      */
/* ------------------------------------------------------------------ */

function credentialView(c: ServerCredential) {
  return {
    credentialId: c.credentialId,
    credentialIdHex: toHex(base64urlToBytes(c.credentialId)),
    user: c.user,
    signCount: c.signCount,
    residentKey: c.residentKey,
    userVerified: c.userVerified,
    createdAt: c.createdAt,
    lastUsedAt: c.lastUsedAt,
    cloneDetected: c.cloneDetected,
    rpId: c.rpId,
    publicKeyJwk: c.publicKeyJwk,
  };
}

function challengeView(c: PendingChallenge) {
  return {
    id: c.id,
    kind: c.kind,
    status: c.status,
    createdAt: c.createdAt,
    expiresAt: c.expiresAt,
    consumedAt: c.consumedAt ?? null,
    consumedBy: c.consumedBy ?? null,
    outcome: c.outcome ?? null,
    ttlMs: Math.max(0, c.expiresAt - Date.now()),
  };
}

function clientLabel(req: express.Request): string | undefined {
  const label = req.body?.label ?? req.header('x-lab-client-label');
  return typeof label === 'string' && label ? label.slice(0, 60) : undefined;
}

function logConsumptionFailure(challengeId: string, error: Error, label: string | undefined): void {
  const code = (error as CeremonyError).code;
  if (code === 'challenge-consumed' || code === 'challenge-expired' || code === 'challenge-not-found') {
    store.log('warn', `challenge ${code}`, { challenge: challengeId, message: error.message, client: label });
  }
}

function sendError(res: express.Response, error: unknown): void {
  if (error instanceof CeremonyError) {
    res.status(error.code === 'bad-request' ? 400 : 409).json({
      error: { code: error.code, message: error.message, details: error.details },
    });
    return;
  }
  res.status(500).json({ error: { code: 'internal', message: (error as Error).message } });
}

// Keep type imports referenced for API consumers.
export type { RegistrationOptions, AuthenticationOptions, ServerEvent };
