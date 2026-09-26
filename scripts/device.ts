/**
 * Verifies the cancel/timeout/user-absent device-side paths and the
 * injectable clock rollback behavior, which the main e2e suite does not
 * exercise directly against an authenticator instance.
 */
import { SoftwareAuthenticator, AuthenticatorSimError } from '../shared/authenticator';

let passed = 0;
let failed = 0;
function check(name: string, cond: boolean, detail = '') {
  if (cond) { passed++; console.log(`  ✓ ${name}`); }
  else { failed++; console.log(`  ✗ ${name} ${detail}`); }
}

function makeOptions(kind: 'create' | 'get', rpId = 'localhost'): any {
  const base = {
    challenge: 'C' + Math.random().toString(36).slice(2, 12),
    timeout: 60000,
    rpId,
    expectedOrigin: 'http://localhost:5173',
    expectedRpId: rpId,
    expiresAt: Date.now() + 60000,
  };
  if (kind === 'create') {
    return {
      ...base,
      rp: { id: rpId, name: 'Lab' },
      user: { id: 'dXNlcg', name: 'a@b.c', displayName: 'A' },
      pubKeyCredParams: [{ type: 'public-key' as const, alg: -7 }],
      attestation: 'none' as const,
      authenticatorSelection: { residentKey: 'discouraged' as const, requireResidentKey: false, userVerification: 'preferred' as const },
      excludeCredentials: [],
    };
  }
  return base;
}

async function main() {
  console.log('\n[A] 设备行为：取消 / 超时 / 用户缺席');
  const auth = new SoftwareAuthenticator();

  // user absent on create
  try {
    await auth.makeCredential(makeOptions('create'), {
      origin: 'http://localhost:5173', rpId: 'localhost', up: false, uv: false,
      residentKey: false, attestation: 'none' as const,
    });
    check('UP=false 时 create 抛出', false);
  } catch (e) {
    check('UP=false 抛出 NotAllowedError', e instanceof AuthenticatorSimError && e.domName === 'NotAllowedError');
  }

  // cancel
  try {
    await auth.makeCredential(makeOptions('create'), {
      origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
      residentKey: false, attestation: 'none' as const, failure: 'cancel',
    });
    check('failure=cancel 抛出', false);
  } catch (e) {
    check('cancel → NotAllowedError', e instanceof AuthenticatorSimError && e.domName === 'NotAllowedError');
  }

  // timeout
  const t0 = Date.now();
  try {
    await auth.makeCredential(makeOptions('create'), {
      origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
      residentKey: false, attestation: 'none' as const, failure: 'timeout', delayMs: 50,
    });
    check('failure=timeout 抛出', false);
  } catch (e) {
    check('timeout → TimeoutError', e instanceof AuthenticatorSimError && e.domName === 'TimeoutError');
    check('延迟后才超时', Date.now() - t0 >= 45, `${Date.now() - t0}ms`);
  }

  // abort signal
  const ac = new AbortController();
  const pending = auth.makeCredential(makeOptions('create'), {
    origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
    residentKey: false, attestation: 'none' as const, delayMs: 2000, signal: ac.signal,
  });
  setTimeout(() => ac.abort(), 30);
  try {
    await pending;
    check('abort 中断仪式', false);
  } catch (e) {
    check('abort → NotAllowedError', e instanceof AuthenticatorSimError && e.domName === 'NotAllowedError');
  }

  // residentKey=required but device cannot satisfy
  try {
    const opts = makeOptions('create');
    opts.authenticatorSelection = { residentKey: 'required' as const, requireResidentKey: true, userVerification: 'required' as const };
    await auth.makeCredential(opts, {
      origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: true,
      residentKey: false, attestation: 'none' as const,
    });
    check('residentKey=required 且设备不支持 → 拒绝', false);
  } catch (e) {
    check('residentKey=required 不满足 → InvalidStateError', e instanceof AuthenticatorSimError && e.domName === 'InvalidStateError');
  }

  console.log('\n[B] 可注入时钟：计数器随时钟回退');
  class FixedClock {
    constructor(public t: number) {}
    now() { return this.t; }
  }
  const t = 1_000_000_000_000;
  const clockAuth = new SoftwareAuthenticator(new FixedClock(t));

  // register at clock t
  const regOpts = makeOptions('create');
  const made = await clockAuth.makeCredential(regOpts, {
    origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
    residentKey: false, attestation: 'none' as const,
  });
  check('注册时 signCount=0（时钟起点）', made.signCount === 0, `got ${made.signCount}`);

  // advance clock 100s -> sign count baseline ~100
  (clockAuth.getClock() as FixedClock).t = t + 100_000;
  const getOpts: any = { ...makeOptions('get'), allowCredentials: [{ id: made.id, type: 'public-key' }] };
  const got1 = await clockAuth.getAssertion(getOpts, {
    origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
  });
  check('时钟前进 100s → signCount≈101', got1.signCount >= 100, `got ${got1.signCount}`);

  // rewind clock 1 hour -> sign count wraps around uint32 (a real device
  // behavior); the value jumps away from the monotonic sequence.
  (clockAuth.getClock() as FixedClock).t = t - 3_600_000;
  const got2 = await clockAuth.getAssertion(getOpts, {
    origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
  });
  check('时钟回拨 → 计数器偏离单调序列（uint32 环绕，克隆信号）',
    got2.signCount !== got1.signCount && got2.signCount > 0xfffff000,
    `${got1.signCount} -> ${got2.signCount}`);

  // forced exact counter
  const got3 = await clockAuth.getAssertion(getOpts, {
    origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false, signCount: 1,
  });
  check('强制 signCount=1', got3.signCount === 1);

  // corrupt signature differs from a good one
  const good = await clockAuth.getAssertion(getOpts, {
    origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
  });
  const bad = await clockAuth.getAssertion(getOpts, {
    origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false, corruptSignature: true,
  });
  check('损坏签名字节与正常签名不同', good.response.signature !== bad.response.signature);

  console.log('\n[C] 重复 credential id（设备侧）');
  try {
    const { base64urlToBytes } = await import('../shared/bytes');
    await auth.makeCredential(makeOptions('create'), {
      origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
      residentKey: false, attestation: 'none' as const,
    });
    // a first valid credential on `auth` is required; register one
  } catch { /* ignore */ }
  // Register a real one then try to reuse its id.
  const first = await new SoftwareAuthenticator();
  const m1 = await first.makeCredential(makeOptions('create'), {
    origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
    residentKey: false, attestation: 'none' as const,
  });
  const { base64urlToBytes } = await import('../shared/bytes');
  try {
    await first.makeCredential(makeOptions('create'), {
      origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
      residentKey: false, attestation: 'none' as const,
      credentialIdOverride: base64urlToBytes(m1.id),
    });
    check('同 rpId 复用 credential id → 拒绝', false);
  } catch (e) {
    check('重复 credential id → InvalidStateError', e instanceof AuthenticatorSimError && e.domName === 'InvalidStateError');
  }

  console.log(`\n========================================\n通过 ${passed}，失败 ${failed}`);
  if (failed > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
