import { api } from './api';
import { authenticator, type CeremonySettings } from './settings';
import { AuthenticatorSimError } from '../shared/authenticator';
import { base64urlToBytes, fromUtf8 } from '../shared/bytes';
import { decodeCbor, CborMap } from '../shared/cbor';
import { parseAuthData } from '../shared/webauthn';
import type {
  AuthenticationOptions,
  CeremonyRecord,
  RegistrationOptions,
} from '../shared/protocol';

export type StepPhase = 'rp' | 'device' | 'browser' | 'result';
export type StepStatus = 'ok' | 'warn' | 'error' | 'info' | 'pending';

export interface Step {
  id: number;
  ts: number;
  phase: StepPhase;
  title: string;
  detail?: string;
  status: StepStatus;
  /** Structured input/output shown in the JSON inspector. */
  payload?: unknown;
}

export class StepLog {
  private steps: Step[] = [];
  private counter = 0;

  constructor(private onChange: (steps: Step[]) => void) {}

  add(phase: StepPhase, title: string, status: StepStatus, detail?: string, payload?: unknown): Step {
    const step: Step = { id: ++this.counter, ts: Date.now(), phase, title, detail, status, payload };
    this.steps = [...this.steps, step];
    this.onChange(this.steps);
    return step;
  }

  list(): Step[] {
    return this.steps;
  }

  clear(): void {
    this.steps = [];
    this.onChange(this.steps);
  }
}

function behaviorForRegistration(settings: CeremonySettings, duplicateId?: Uint8Array) {
  return {
    origin: settings.effectiveOrigin,
    rpId: settings.effectiveRpId,
    crossOrigin: settings.crossOrigin,
    up: settings.up,
    uv: settings.uv,
    residentKey: settings.resident,
    attestation: settings.attestationFormat === 'direct' ? ('packed-self' as const) : ('none' as const),
    credentialIdOverride: settings.duplicateCredentialId ? duplicateId : undefined,
    delayMs: settings.delayMs,
    failure: settings.deviceFailure === 'none' ? undefined : settings.deviceFailure,
  };
}

function decodeClientData(b64: string) {
  try {
    return { decoded: JSON.parse(fromUtf8(base64urlToBytes(b64))) as unknown, rawBase64Url: b64 };
  } catch {
    return { rawBase64Url: b64 };
  }
}

function decodeAttestationObject(b64: string) {
  try {
    const obj = decodeCbor(base64urlToBytes(b64));
    const summary: Record<string, unknown> = {};
    if (obj instanceof CborMap) {
      summary.fmt = obj.get('fmt');
      const authData = obj.get('authData');
      if (authData instanceof Uint8Array) {
        const parsed = parseAuthData(authData);
        summary.authData = {
          rpIdHashHex: [...parsed.rpIdHash].map((b) => b.toString(16).padStart(2, '0')).join(''),
          flags: parsed.flags,
          signCount: parsed.signCount,
          credentialIdLength: parsed.attestedCredentialData?.credentialId.length ?? 0,
        };
      }
      summary.attStmtKeys = obj.get('attStmt') instanceof CborMap
        ? (obj.get('attStmt') as CborMap).strEntries.map(([k]) => k)
        : [];
    }
    return summary;
  } catch (e) {
    return { decodeError: (e as Error).message };
  }
}

function decodeAssertionAuthData(b64: string) {
  try {
    const parsed = parseAuthData(base64urlToBytes(b64));
    return {
      rpIdHashHex: [...parsed.rpIdHash].map((b) => b.toString(16).padStart(2, '0')).join(''),
      flags: parsed.flags,
      flagsText: [
        parsed.flags & 0x01 ? 'UP' : null,
        parsed.flags & 0x04 ? 'UV' : null,
        parsed.flags & 0x08 ? 'BE' : null,
        parsed.flags & 0x10 ? 'BS' : null,
        parsed.flags & 0x40 ? 'AT' : null,
        parsed.flags & 0x80 ? 'ED' : null,
      ]
        .filter(Boolean)
        .join('|') || '(none)',
      signCount: parsed.signCount,
    };
  } catch (e) {
    return { decodeError: (e as Error).message };
  }
}

/* ------------------------------------------------------------------ */
/*  Registration                                                       */
/* ------------------------------------------------------------------ */

export async function runRegistration(
  settings: CeremonySettings,
  log: StepLog,
): Promise<{ ok: boolean; record: CeremonyRecord | null }> {
  let record: CeremonyRecord | null = null;

  // Step 1 — RP issues options.
  log.add('rp', 'POST /api/register/begin（请求 RP 签发 challenge）', 'pending', undefined, {
    timeoutMs: settings.timeoutMs,
    attestation: settings.attestation,
    authenticatorSelection: {
      residentKey: settings.residentKey,
      userVerification: settings.userVerification,
    },
    label: settings.clientLabel,
  });
  const begin = await api.beginRegistration({
    timeoutMs: settings.timeoutMs,
    attestation: settings.attestation,
    residentKey: settings.residentKey,
    userVerification: settings.userVerification,
    label: settings.clientLabel,
  });
  const options = begin.options;
  log.add('rp', 'RP 返回 PublicKeyCredentialCreationOptions', 'ok', `challenge 一次性，TTL=${settings.timeoutMs}ms`, {
    challenge: options.challenge,
    rp: options.rp,
    user: options.user,
    pubKeyCredParams: options.pubKeyCredParams,
    attestation: options.attestation,
    authenticatorSelection: options.authenticatorSelection,
    excludeCredentials: options.excludeCredentials,
    expectedOrigin: options.expectedOrigin,
    expectedRpId: options.expectedRpId,
    expiresAt: new Date(options.expiresAt).toISOString(),
  });

  // Step 2 — software authenticator.
  let duplicateId: Uint8Array | undefined;
  if (settings.duplicateCredentialId) {
    const state = await api.state();
    const last = state.credentials[state.credentials.length - 1];
    if (last) duplicateId = base64urlToBytes(last.credentialId);
  }
  const deviceInput = {
    rpId: settings.effectiveRpId,
    origin: settings.effectiveOrigin,
    crossOrigin: settings.crossOrigin,
    up: settings.up,
    uv: settings.uv,
    residentKey: settings.resident,
    attestation: settings.attestationFormat,
    delayMs: settings.delayMs,
  };
  log.add('device', 'navigator.credentials.create() → 软件 authenticator 输入', 'pending', undefined, deviceInput);

  let device: Awaited<ReturnType<typeof authenticator.makeCredential>>;
  try {
    device = await authenticator.makeCredential(options, behaviorForRegistration(settings, duplicateId));
  } catch (e) {
    if (e instanceof AuthenticatorSimError) {
      log.add(
        'device',
        `authenticator 拒绝：${e.domName}`,
        'error',
        e.message,
        { name: e.name, message: e.message, deviceInput },
      );
      log.add('browser', '浏览器把 DOMException 返回给页面；challenge 未被消费，仍在服务端 pending', 'warn');
      record = buildRecord('registration', options.rp, options.expectedOrigin, options, null, {
        ok: false,
        errorCode: e.domName,
        message: e.message,
      }, [e.message]);
      return { ok: false, record };
    }
    throw e;
  }

  log.add('device', 'authenticator 产出 attestation response', 'ok', `credentialId=${device.id}`, {
    id: device.id,
    response: device.response,
    clientDataJSON: decodeClientData(device.response.clientDataJSON),
    attestationObject: decodeAttestationObject(device.response.attestationObject),
    deviceSignCount: device.signCount,
  });

  // Step 3 — RP verifies.
  log.add('rp', 'POST /api/register/finish（提交 attestation response）', 'pending', undefined, {
    challengeId: begin.challengeId,
    credentialId: device.id,
    label: settings.clientLabel,
  });
  try {
    const finish = await api.finishRegistration({
      challengeId: begin.challengeId,
      credentialId: device.id,
      response: device.response,
      label: settings.clientLabel,
    });
    log.add('result', '注册成功：凭据已保存', 'ok', `signCount=${finish.result.signCount}`, finish.result);
    record = buildRecord('registration', options.rp, options.expectedOrigin, options, device.response, {
      ok: true,
      result: finish.result,
    }, []);
    return { ok: true, record };
  } catch (e) {
    const err = e as Error & { code?: string; details?: unknown };
    log.add('result', `注册被拒绝：${err.code ?? 'error'}`, 'error', err.message, {
      code: err.code,
      message: err.message,
      details: err.details,
    });
    record = buildRecord('registration', options.rp, options.expectedOrigin, options, device.response, {
      ok: false,
      errorCode: err.code ?? 'error',
      message: err.message,
    }, [err.message]);
    return { ok: false, record };
  }
}

/* ------------------------------------------------------------------ */
/*  Authentication                                                     */
/* ------------------------------------------------------------------ */

export async function runAuthentication(
  settings: CeremonySettings,
  log: StepLog,
  selectedCredentialId: string | undefined,
): Promise<{ ok: boolean; record: CeremonyRecord | null }> {
  let record: CeremonyRecord | null = null;

  log.add('rp', 'POST /api/auth/begin（请求认证 challenge）', 'pending', undefined, {
    timeoutMs: settings.timeoutMs,
    userVerification: settings.userVerification,
    discoverable: settings.discoverable,
    label: settings.clientLabel,
  });
  const begin = await api.beginAuthentication({
    timeoutMs: settings.timeoutMs,
    userVerification: settings.userVerification,
    credentialId: settings.discoverable ? undefined : selectedCredentialId,
    discoverable: settings.discoverable,
    label: settings.clientLabel,
  });
  const options: AuthenticationOptions = begin.options;
  log.add('rp', 'RP 返回 PublicKeyCredentialRequestOptions', 'ok',
    `${options.allowCredentials.length} 个 allowCredentials${settings.discoverable ? '（空：discoverable）' : ''}`, {
      challenge: options.challenge,
      rpId: options.rpId,
      allowCredentials: options.allowCredentials,
      userVerification: options.userVerification,
      expectedOrigin: options.expectedOrigin,
      expectedRpId: options.expectedRpId,
      expiresAt: new Date(options.expiresAt).toISOString(),
    });

  const forcedCount = settings.forcedSignCount.trim();
  const deviceInput = {
    rpId: settings.effectiveRpId,
    origin: settings.effectiveOrigin,
    crossOrigin: settings.crossOrigin,
    up: settings.up,
    uv: settings.uv,
    corruptSignature: settings.corruptSignature,
    discoverable: settings.discoverable,
    signCount: forcedCount ? Number(forcedCount) : 'auto',
    delayMs: settings.delayMs,
    failure: settings.deviceFailure === 'none' ? undefined : settings.deviceFailure,
  };
  log.add('device', 'navigator.credentials.get() → 软件 authenticator 输入', 'pending', undefined, deviceInput);

  let device: Awaited<ReturnType<typeof authenticator.getAssertion>>;
  try {
    device = await authenticator.getAssertion(options, {
      origin: settings.effectiveOrigin,
      rpId: settings.effectiveRpId,
      crossOrigin: settings.crossOrigin,
      up: settings.up,
      uv: settings.uv,
      corruptSignature: settings.corruptSignature,
      discoverable: settings.discoverable,
      signCount: forcedCount ? Number(forcedCount) : 'auto',
      delayMs: settings.delayMs,
      failure: settings.deviceFailure === 'none' ? undefined : settings.deviceFailure,
    });
  } catch (e) {
    if (e instanceof AuthenticatorSimError) {
      log.add('device', `authenticator 拒绝：${e.domName}`, 'error', e.message, {
        name: e.name,
        message: e.message,
        deviceInput,
      });
      log.add('browser', 'DOMException 返回页面；服务端 challenge 保持 pending', 'warn');
      record = buildRecord('authentication', { id: options.rpId, name: '' }, options.expectedOrigin, options, null, {
        ok: false,
        errorCode: e.domName,
        message: e.message,
      }, [e.message]);
      return { ok: false, record };
    }
    throw e;
  }

  log.add('device', 'authenticator 产出 assertion response', 'ok', `credentialId=${device.id}`, {
    id: device.id,
    response: device.response,
    clientDataJSON: decodeClientData(device.response.clientDataJSON),
    authenticatorData: decodeAssertionAuthData(device.response.authenticatorData),
    deviceSignCount: device.signCount,
  });

  log.add('rp', 'POST /api/auth/finish（提交 assertion）', 'pending', undefined, {
    challengeId: begin.challengeId,
    credentialId: device.id,
    label: settings.clientLabel,
  });
  try {
    const finish = await api.finishAuthentication({
      challengeId: begin.challengeId,
      credentialId: device.id,
      response: device.response,
      label: settings.clientLabel,
    });
    if (finish.result.cloneWarning) {
      log.add('result', '签名验证通过，但检测到计数器克隆告警', 'warn',
        `${finish.result.previousSignCount} → ${finish.result.signCount}（未回写）`, finish.result);
    } else {
      log.add('result', '认证成功', 'ok', `signCount ${finish.result.previousSignCount} → ${finish.result.signCount}`, finish.result);
    }
    record = buildRecord('authentication', { id: options.rpId, name: '' }, options.expectedOrigin, options, device.response, {
      ok: true,
      result: finish.result,
    }, finish.result.cloneWarning ? ['签名计数器回退：克隆设备告警'] : []);
    return { ok: !finish.result.cloneWarning, record };
  } catch (e) {
    const err = e as Error & { code?: string; details?: unknown };
    log.add('result', `认证被拒绝：${err.code ?? 'error'}`, 'error', err.message, {
      code: err.code,
      message: err.message,
      details: err.details,
    });
    record = buildRecord('authentication', { id: options.rpId, name: '' }, options.expectedOrigin, options, device.response, {
      ok: false,
      errorCode: err.code ?? 'error',
      message: err.message,
    }, [err.message]);
    return { ok: false, record };
  }
}

/* ------------------------------------------------------------------ */
/*  Record builder (NO private key material)                           */
/* ------------------------------------------------------------------ */

function buildRecord(
  ceremony: CeremonyRecord['ceremony'],
  rp: CeremonyRecord['rp'],
  expectedOrigin: string,
  options: RegistrationOptions | AuthenticationOptions,
  response: CeremonyRecord['response'] | null,
  verdict: CeremonyRecord['verdict'],
  scenarioNotes: string[],
): CeremonyRecord {
  return {
    format: 'webauthn-ceremony-lab/record',
    formatVersion: 1,
    exportedAt: Date.now(),
    ceremony,
    rp,
    expectedOrigin,
    options,
    response: response ?? {
      clientDataJSON: '',
      ...(ceremony === 'registration'
        ? { attestationObject: '', transports: [], authenticatorFlags: { up: false, uv: false, be: false, bs: false } }
        : { authenticatorData: '', signature: '', userHandle: null, authenticatorFlags: { up: false, uv: false, be: false, bs: false } }),
    },
    verdict,
    scenarioNotes,
  };
}
