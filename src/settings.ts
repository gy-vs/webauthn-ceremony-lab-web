import { SoftwareAuthenticator, realClock, type Clock } from '../shared/authenticator';
import type {
  AttestationPreference,
  ResidentKeyRequirement,
  UserVerificationRequirement,
} from '../shared/protocol';

/** Page-wide test authenticator. Private keys live only in memory here. */
export const authenticator = new SoftwareAuthenticator(realClock);

/** Mutable virtual clock: 0 means "follow real time", otherwise an explicit value. */
class VirtualClock implements Clock {
  /** Offset added to Date.now(). */
  offsetMs = 0;

  now(): number {
    return Date.now() + this.offsetMs;
  }
}

export const virtualClock = new VirtualClock();
authenticator.setClock(virtualClock);

export interface CeremonySettings {
  // RP ceremony options
  timeoutMs: number;
  attestation: AttestationPreference;
  residentKey: ResidentKeyRequirement;
  userVerification: UserVerificationRequirement;
  // Behavior simulated by the software authenticator
  effectiveOrigin: string;
  effectiveRpId: string;
  up: boolean;
  uv: boolean;
  resident: boolean;
  crossOrigin: boolean;
  attestationFormat: AttestationPreference; // mapped to none/packed
  delayMs: number;
  corruptSignature: boolean;
  /** 'auto' or a forced 32-bit sign count for the next assertion. */
  forcedSignCount: string; // '' = auto
  duplicateCredentialId: boolean;
  clockOffsetSeconds: number;
  discoverable: boolean;
  clientLabel: string;
  /** Explicit device-side failure simulation. */
  deviceFailure: 'none' | 'cancel' | 'timeout';
}

export const DEFAULT_SETTINGS: CeremonySettings = {
  timeoutMs: 60_000,
  attestation: 'none',
  residentKey: 'discouraged',
  userVerification: 'preferred',
  effectiveOrigin: 'http://localhost:5173',
  effectiveRpId: 'localhost',
  up: true,
  uv: false,
  resident: false,
  crossOrigin: false,
  attestationFormat: 'none',
  delayMs: 0,
  corruptSignature: false,
  forcedSignCount: '',
  duplicateCredentialId: false,
  clockOffsetSeconds: 0,
  discoverable: false,
  clientLabel: '页面 A',
  deviceFailure: 'none',
};

export interface ScenarioPreset {
  id: string;
  title: string;
  description: string;
  apply: (base: CeremonySettings) => CeremonySettings;
}

export const SCENARIOS: ScenarioPreset[] = [
  {
    id: 'happy-register',
    title: '正常注册',
    description: '正确 origin/RP ID、UP 置位、attestation=none',
    apply: (s) => ({
      ...s,
      effectiveOrigin: 'http://localhost:5173',
      effectiveRpId: 'localhost',
      up: true,
      uv: false,
      attestation: 'none',
      attestationFormat: 'none',
      residentKey: 'discouraged',
      resident: false,
      userVerification: 'preferred',
      crossOrigin: false,
      corruptSignature: false,
      duplicateCredentialId: false,
      delayMs: 0,
      forcedSignCount: '',
      clockOffsetSeconds: 0,
      deviceFailure: 'none',
    }),
  },
  {
    id: 'resident-uv',
    title: 'resident key + UV',
    description: 'residentKey=required，BE/BS 与 UV 置位；认证走 discoverable 流程',
    apply: (s) => ({
      ...s,
      residentKey: 'required',
      resident: true,
      userVerification: 'required',
      uv: true,
      attestation: 'direct',
      attestationFormat: 'direct',
      discoverable: true,
    }),
  },
  {
    id: 'wrong-origin',
    title: '错误 origin',
    description: 'clientDataJSON 里的 origin 不在 RP 允许列表（evil.example）',
    apply: (s) => ({
      ...s,
      effectiveOrigin: 'https://evil.example',
      effectiveRpId: 'localhost',
      up: true,
      crossOrigin: false,
    }),
  },
  {
    id: 'cross-origin',
    title: 'crossOrigin iframe',
    description: 'clientDataJSON 标记 crossOrigin=true（跨站 iframe 重放）',
    apply: (s) => ({ ...s, effectiveOrigin: 'http://localhost:5173', crossOrigin: true }),
  },
  {
    id: 'bad-rpid',
    title: '错误 RP ID',
    description: 'authenticator 对 attacker.test 计算 rpIdHash，与服务端 localhost 不匹配',
    apply: (s) => ({ ...s, effectiveRpId: 'attacker.test', effectiveOrigin: 'http://localhost:5173' }),
  },
  {
    id: 'uv-required-missing',
    title: 'UV required 但未验证',
    description: '服务端要求 userVerification=required，设备未置 UV 标志',
    apply: (s) => ({ ...s, userVerification: 'required', uv: false }),
  },
  {
    id: 'user-absent',
    title: '用户缺席 (UP=0)',
    description: '模拟用户未触碰设备：authenticator 拒绝或 UP 标志缺失',
    apply: (s) => ({ ...s, up: false }),
  },
  {
    id: 'cancel',
    title: '取消',
    description: '浏览器侧 NotAllowedError：用户取消，challenge 保持 pending 直到过期',
    apply: (s) => ({ ...s, deviceFailure: 'cancel', delayMs: 0 }),
  },
  {
    id: 'timeout',
    title: '超时',
    description: '设备响应超过 timeout；也可把 timeout 调到 5s 并等待自然过期',
    apply: (s) => ({ ...s, deviceFailure: 'timeout', timeoutMs: 5_000, delayMs: 6_000 }),
  },
  {
    id: 'bad-signature',
    title: '签名损坏',
    description: '断言 DER 最后一字节被翻转，ES256 验证失败',
    apply: (s) => ({ ...s, corruptSignature: true }),
  },
  {
    id: 'duplicate-credid',
    title: '重复 credential id',
    description: '复用已有 credential id 再次注册（authenticator 与服务端双重拒绝）',
    apply: (s) => ({ ...s, duplicateCredentialId: true }),
  },
  {
    id: 'counter-rewind',
    title: '计数器回退（克隆告警）',
    description: '强制下一次断言 signCount=1，低于服务端已记录计数',
    apply: (s) => ({ ...s, forcedSignCount: '1' }),
  },
  {
    id: 'clock-rewind',
    title: '注入时钟回拨',
    description: '把设备虚拟时钟拨回 1 小时，时钟派生的 signCount 随之回退',
    apply: (s) => ({ ...s, clockOffsetSeconds: -3600, forcedSignCount: '' }),
  },
];
