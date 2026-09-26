/**
 * End-to-end scenario test. Runs entirely against the HTTP API but uses the
 * SAME shared software authenticator to produce responses — exercising the
 * full wire path (JSON + base64url + CBOR + ES256).
 *
 * Run: npx tsx scripts/e2e.ts
 */
import { SoftwareAuthenticator } from '../shared/authenticator';
import type {
  AuthenticatorAssertionResponsePayload,
  AuthenticatorAttestationResponsePayload,
  CeremonyRecord,
} from '../shared/protocol';

const BASE = process.env.BASE || 'http://localhost:8787';

let passed = 0;
let failed = 0;

function check(name: string, cond: boolean, detail = '') {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.log(`  ✗ ${name} ${detail}`);
  }
}

async function call<T = unknown>(path: string, body?: unknown): Promise<{ status: number; json: T }> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = (await res.json()) as T;
  return { status: res.status, json };
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  return (await res.json()) as T;
}

interface ErrorBody {
  error: { code: string; message: string; details?: Record<string, unknown> };
}

async function main() {
  await call('/api/reset', {});
  const auth = new SoftwareAuthenticator();

  /* ---------------- 1. happy registration ---------------- */
  console.log('\n[1] 正常注册 (attestation=none)');
  {
    const begin = await call('/api/register/begin', {
      timeoutMs: 60000,
      attestation: 'none',
      residentKey: 'discouraged',
      userVerification: 'preferred',
      label: 'e2e',
    });
    const options = (begin.json as { options: any }).options;
    const made = await auth.makeCredential(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
      residentKey: false,
      attestation: 'none',
    });
    const finish = await call('/api/register/finish', {
      challengeId: options.challenge,
      credentialId: made.id,
      response: made.response,
      label: 'e2e',
    });
    check('注册返回 ok', finish.status === 200, JSON.stringify(finish.json));
    check('注册后存在 1 个凭据', (await getJson<{ credentials: unknown[] }>('/api/state')).credentials.length === 1);
    globalThis.__credId = made.id;
  }

  /* ---------------- 2. happy authentication ---------------- */
  console.log('\n[2] 正常认证');
  let firstCount = 0;
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred', label: 'e2e' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got.id,
      response: got.response,
      label: 'e2e',
    });
    check('认证返回 ok', finish.status === 200, JSON.stringify(finish.json));
    firstCount = (finish.json as { result: { signCount: number } }).result.signCount;
    check('计数器被服务端采纳', firstCount > 0, `count=${firstCount}`);
  }

  /* ---------------- 3. single-use challenge ---------------- */
  console.log('\n[3] challenge 一次性：重复 finish 被拒');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
    });
    const first = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got.id,
      response: got.response,
      label: 'first',
    });
    check('第一次 finish 成功', first.status === 200);
    // Second finish: must get a fresh authenticator response (different sig/counter)
    const got2 = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
    });
    const second = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got2.id,
      response: got2.response,
      label: 'second',
    });
    check('第二次 finish 被拒', second.status === 409);
    check('错误码 challenge-consumed', (second.json as ErrorBody).error.code === 'challenge-consumed');
  }

  /* ---------------- 4. concurrent consumption ---------------- */
  console.log('\n[4] 两个页面并发消费同一 challenge：恰有一个成功');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    const responses = await Promise.all([
      auth.getAssertion(options, { origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false }),
      auth.getAssertion(options, { origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false }),
    ]);
    const results = await Promise.all(
      responses.map((r, i) =>
        call('/api/auth/finish', {
          challengeId: options.challenge,
          credentialId: r.id,
          response: r.response,
          label: `页面 ${i === 0 ? 'A' : 'B'}`,
        }),
      ),
    );
    const oks = results.filter((r) => r.status === 200).length;
    const consumed = results.filter((r) => (r.json as ErrorBody).error?.code === 'challenge-consumed').length;
    check('恰好 1 个成功', oks === 1, `ok=${oks}`);
    check('恰好 1 个 challenge-consumed', consumed === 1, `consumed=${consumed}`);
  }

  /* ---------------- 5. challenge expiry ---------------- */
  console.log('\n[5] challenge 过期');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 5000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    // Backdate expiry isn't possible from the client; instead ask server for a
    // 5s challenge then wait. To keep e2e fast we issue a 5s one and sleep 5.1s.
    await new Promise((r) => setTimeout(r, 5200));
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got.id,
      response: got.response,
    });
    check('过期 challenge 被拒', (finish.json as ErrorBody).error?.code === 'challenge-expired', JSON.stringify(finish.json));
  }

  /* ---------------- 6. wrong origin ---------------- */
  console.log('\n[6] 错误 origin');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'https://evil.example',
      rpId: 'localhost',
      up: true,
      uv: false,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got.id,
      response: got.response,
    });
    check('错误 origin → bad-origin', (finish.json as ErrorBody).error?.code === 'bad-origin');
  }

  /* ---------------- 7. wrong rpId ---------------- */
  console.log('\n[7] 错误 RP ID');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'attacker.test',
      up: true,
      uv: false,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got.id,
      response: got.response,
    });
    check('错误 rpId → bad-rpid', (finish.json as ErrorBody).error?.code === 'bad-rpid');
  }

  /* ---------------- 8. corrupt signature ---------------- */
  console.log('\n[8] 签名损坏');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
      corruptSignature: true,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got.id,
      response: got.response,
    });
    check('损坏签名 → bad-signature', (finish.json as ErrorBody).error?.code === 'bad-signature');
  }

  /* ---------------- 9. counter rollback / clone ---------------- */
  console.log('\n[9] 计数器回退（克隆告警）');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
      signCount: 1,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got.id,
      response: got.response,
    });
    const result = (finish.json as { result?: { cloneWarning?: boolean; signCount?: number } }).result;
    check('返回 cloneWarning=true', result?.cloneWarning === true);
    check('服务端计数器没有回退', (result?.signCount ?? -1) >= firstCount, `stored=${result?.signCount}`);
    const state = await getJson<{ credentials: { cloneDetected: boolean }[] }>('/api/state');
    check('凭据被标记 cloneDetected', state.credentials.some((c) => c.cloneDetected));
  }

  /* ---------------- 9b. uint32 wrap from clock rewind ---------------- */
  console.log('\n[9b] 计数器 uint32 环绕（注入时钟回拨）');
  {
    // Establish a known nonzero counter first.
    const b0 = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const o0 = (b0.json as { options: any }).options;
    const g0 = await auth.getAssertion(o0, {
      origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false, signCount: 1000,
    });
    const f0 = await call('/api/auth/finish', { challengeId: o0.challenge, credentialId: g0.id, response: g0.response });
    check('基线 count=1000 被采纳', (f0.json as { result?: { signCount: number } }).result?.signCount === 1000);

    // A rewinded device clock wraps the counter to a value near 2^32.
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173', rpId: 'localhost', up: true, uv: false,
      signCount: 0xfffffff0,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge, credentialId: got.id, response: got.response,
    });
    const result = (finish.json as { result?: { cloneWarning?: boolean; signCount?: number } }).result;
    check('环绕突增 → cloneWarning=true', result?.cloneWarning === true);
    check('服务端不采纳环绕值，保持 1000', result?.signCount === 1000, `stored=${result?.signCount}`);
  }

  /* ---------------- 10. UV required but missing ---------------- */
  console.log('\n[10] UV required 但设备未置 UV');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'required' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got.id,
      response: got.response,
    });
    check('缺 UV → user-not-verified', (finish.json as ErrorBody).error?.code === 'user-not-verified');
  }

  /* ---------------- 11. user absent ---------------- */
  console.log('\n[11] 用户缺席（UP=0）');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    let deviceError: Error | null = null;
    try {
      await auth.getAssertion(options, {
        origin: 'http://localhost:5173',
        rpId: 'localhost',
        up: false,
        uv: false,
      });
    } catch (e) {
      deviceError = e as Error;
    }
    check('设备端抛出 NotAllowedError', deviceError?.name === 'NotAllowedError', deviceError?.message);
    const state = await getJson<{ challenges: { status: string }[] }>('/api/state');
    check('失败后 challenge 仍可被消费（设备拒绝不消费）', state.challenges.at(-1)?.status === 'pending');
  }

  /* ---------------- 12. resident + UV registration + packed ---------------- */
  console.log('\n[12] resident key + UV + packed 自证明注册');
  {
    const begin = await call('/api/register/begin', {
      timeoutMs: 60000,
      attestation: 'direct',
      residentKey: 'required',
      userVerification: 'required',
      userId: 'resident-user',
      userName: 'resident@example.com',
      displayName: 'Resident User',
    });
    const options = (begin.json as { options: any }).options;
    const made = await auth.makeCredential(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: true,
      residentKey: true,
      attestation: 'packed-self',
    });
    const finish = await call('/api/register/finish', {
      challengeId: options.challenge,
      credentialId: made.id,
      response: made.response,
    });
    const result = (finish.json as { result?: { residentKey?: boolean; attestationFormat?: string } }).result;
    check('packed self 注册成功', finish.status === 200, JSON.stringify(finish.json));
    check('residentKey=true', result?.residentKey === true);
    check('attestationFormat=packed-self', result?.attestationFormat === 'packed-self');

    // discoverable auth (empty allowCredentials)
    const abegin = await call('/api/auth/begin', {
      timeoutMs: 60000,
      userVerification: 'required',
      discoverable: true,
    });
    const aoptions = (abegin.json as { options: any }).options;
    check('discoverable allowCredentials 为空', aoptions.allowCredentials.length === 0);
    const agot = await auth.getAssertion(aoptions, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: true,
      discoverable: true,
    });
    const afinish = await call('/api/auth/finish', {
      challengeId: aoptions.challenge,
      credentialId: agot.id,
      response: agot.response,
    });
    check('discoverable 认证成功且返回 userHandle', afinish.status === 200 && !!agot.response.userHandle, JSON.stringify(afinish.json));
  }

  /* ---------------- 13. duplicate credential id ---------------- */
  console.log('\n[13] 重复 credential id');
  {
    // 13a. authenticator-side: reusing an id it already has -> InvalidStateError
    const state = await getJson<{ credentials: { credentialId: string }[] }>('/api/state');
    const existingB64 = state.credentials[0].credentialId;
    const begin = await call('/api/register/begin', {
      timeoutMs: 60000,
      attestation: 'none',
      residentKey: 'discouraged',
      userVerification: 'preferred',
      userId: 'another-user',
    });
    const options = (begin.json as { options: any }).options;
    // The device already stores a credential with this id for rpId=localhost
    const { base64urlToBytes } = await import('../shared/bytes');
    let deviceError: Error | null = null;
    try {
      await auth.makeCredential(options, {
        origin: 'http://localhost:5173',
        rpId: 'localhost',
        up: true,
        uv: false,
        residentKey: false,
        attestation: 'none',
        credentialIdOverride: base64urlToBytes(existingB64),
      });
    } catch (e) {
      deviceError = e as Error;
    }
    check('设备端拒绝重复 credential id', deviceError?.name === 'InvalidStateError', deviceError?.message);

    // 13b. server-side: a brand-new id at the device but posting an existing id
    // is caught by server duplicate-credential. Forge by making a valid
    // credential then claiming an existing id (id mismatch -> bad-auth-data),
    // so instead test excludeCredentials path: same user re-register returns
    // credential-exists only when device reuses; server duplicate guard is
    // reached when id matches. We directly re-POST the stored response shape
    // by creating a credential and then swapping id: expected bad-auth-data,
    // which is still an explainable terminal state.
    const begin2 = await call('/api/register/begin', {
      timeoutMs: 60000,
      attestation: 'none',
      residentKey: 'discouraged',
      userVerification: 'preferred',
      userId: 'dup-user',
    });
    const options2 = (begin2.json as { options: any }).options;
    const made2 = await auth.makeCredential(options2, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
      residentKey: false,
      attestation: 'none',
    });
    const forged = await call('/api/register/finish', {
      challengeId: options2.challenge,
      credentialId: existingB64, // claim a different id than attested
      response: made2.response,
    });
    check('id 与 attested 不一致 → bad-auth-data', (forged.json as ErrorBody).error?.code === 'bad-auth-data');
  }

  /* ---------------- 14. unknown credential ---------------- */
  console.log('\n[14] 未知 credential id');
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: 'AAAAAAAAAAAAAAAAAAAAAA', // random unknown id
      response: got.response,
    });
    check('未知 id → unknown-credential', (finish.json as ErrorBody).error?.code === 'unknown-credential');
  }

  /* ---------------- 15. record export / recheck ---------------- */
  console.log('\n[15] 仪式记录导出与重新导入检查');
  let goodRecord: CeremonyRecord | null = null;
  {
    const begin = await call('/api/auth/begin', { timeoutMs: 60000, userVerification: 'preferred' });
    const options = (begin.json as { options: any }).options;
    const got = await auth.getAssertion(options, {
      origin: 'http://localhost:5173',
      rpId: 'localhost',
      up: true,
      uv: false,
    });
    const finish = await call('/api/auth/finish', {
      challengeId: options.challenge,
      credentialId: got.id,
      response: got.response,
    });
    check('基线认证成功', finish.status === 200);
    goodRecord = {
      format: 'webauthn-ceremony-lab/record',
      formatVersion: 1,
      exportedAt: Date.now(),
      ceremony: 'authentication',
      rp: { id: 'localhost', name: 'Lab' },
      expectedOrigin: 'http://localhost:5173',
      options,
      response: got.response as AuthenticatorAssertionResponsePayload,
      verdict: { ok: true, result: (finish.json as { result: unknown }).result as never },
      scenarioNotes: [],
    };
  }
  // Re-check the record: the recorded counter is now <= latest stored counter
  // (stored kept advancing), so it should flag a clone warning — this proves
  // re-verification runs independently and does not consume challenges.
  {
    const recheck = await call('/api/records/check', { record: goodRecord });
    const body = recheck.json as {
      ok: boolean;
      checks: { name: string; ok: boolean }[];
    };
    check('复核包含 signature 项', body.checks?.some((c) => c.name === 'signature'));
    check('复核包含 counter 项', body.checks?.some((c) => c.name === 'counter'));
    const counterCheck = body.checks?.find((c) => c.name === 'counter');
    check('旧记录计数器检查触发克隆提示', counterCheck?.ok === false, JSON.stringify(counterCheck));
  }
  // Malformed record
  {
    const bad = await call('/api/records/check', { record: { format: 'nope' } });
    check('错误记录被拒绝', bad.status === 409 || (bad.json as { ok?: boolean }).ok === false);
  }

  /* ---------------- summary ---------------- */
  console.log(`\n========================================`);
  console.log(`通过 ${passed}，失败 ${failed}`);
  if (failed > 0) process.exit(1);
}

// globals for cross-test ids
declare global {
  // eslint-disable-next-line no-var
  var __credId: string;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
