import { useState } from 'react';
import { api } from '../api';
import { authenticator, type CeremonySettings } from '../settings';
import type {
  AuthenticatorAssertionResponsePayload,
  AuthenticatorAttestationResponsePayload,
} from '../../shared/protocol';

interface Props {
  settings: CeremonySettings;
  mode: 'registration' | 'authentication';
  onDone: () => void;
}

interface PageAttempt {
  label: string;
  ok: boolean;
  code?: string;
  message: string;
  detail?: string;
}

/**
 * Simulates two pages finishing the SAME challenge.
 *
 * The sequence is the important part:
 *   1. a single begin() produces one challenge shared by both pages
 *   2. each page drives the software authenticator independently against the
 *      same options (registration => two fresh ES256 keys; authentication =>
 *      the same stored credential signs twice)
 *   3. both finish() calls are fired with no await gap
 *
 * store.consume() claims the challenge atomically, so exactly one page
 * succeeds; the other gets challenge-consumed with the winner recorded.
 */
export function ConcurrencyPanel({ settings, mode, onDone }: Props) {
  const [results, setResults] = useState<PageAttempt[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState('');

  const race = async () => {
    setBusy(true);
    setResults(null);
    try {
      // 1. ONE begin — shared by both pages.
      setPhase('① 单个 begin() 签发一个共享 challenge');
      const begin =
        mode === 'registration'
          ? await api.beginRegistration({
              timeoutMs: settings.timeoutMs,
              attestation: settings.attestation,
              residentKey: settings.residentKey,
              userVerification: settings.userVerification,
              label: '共享 begin',
            })
          : await api.beginAuthentication({
              timeoutMs: settings.timeoutMs,
              userVerification: settings.userVerification,
              label: '共享 begin',
            });

      // 2. Each page produces its own authenticator response from the SAME options.
      setPhase('② 两个页面各自调用软件 authenticator');
      const deviceBehavior = {
        origin: settings.effectiveOrigin,
        rpId: settings.effectiveRpId,
        crossOrigin: settings.crossOrigin,
        up: settings.up,
        uv: settings.uv,
        residentKey: settings.resident,
        attestation: (settings.attestationFormat === 'direct' ? 'packed-self' : 'none') as 'none' | 'packed-self',
        delayMs: 0,
      };

      const [a, b] = await Promise.all(
        ['页面 A', '页面 B'].map(async (label) => {
          if (mode === 'registration') {
            const made = await authenticator.makeCredential(begin.options as never, deviceBehavior);
            return {
              label,
              id: made.id,
              response: made.response as AuthenticatorAttestationResponsePayload,
            };
          }
          const got = await authenticator.getAssertion(begin.options as never, {
            origin: settings.effectiveOrigin,
            rpId: settings.effectiveRpId,
            crossOrigin: settings.crossOrigin,
            up: settings.up,
            uv: settings.uv,
            signCount: 'auto',
          });
          return {
            label,
            id: got.id,
            response: got.response as AuthenticatorAssertionResponsePayload,
          };
        }),
      );

      // 3. Fire both finishes back-to-back; atomic consume decides the winner.
      setPhase('③ 两个 finish() 并发提交（零 await 间隙）');
      const finishOne = async (p: typeof a): Promise<PageAttempt> => {
        try {
          if (mode === 'registration') {
            await api.finishRegistration({
              challengeId: begin.challengeId,
              credentialId: p.id,
              response: p.response as AuthenticatorAttestationResponsePayload,
              label: p.label,
            });
          } else {
            await api.finishAuthentication({
              challengeId: begin.challengeId,
              credentialId: p.id,
              response: p.response as AuthenticatorAssertionResponsePayload,
              label: p.label,
            });
          }
          return { label: p.label, ok: true, message: '赢得 challenge，服务端已接受' };
        } catch (e) {
          const err = e as Error & { code?: string; details?: Record<string, unknown> };
          const winner = err.details?.consumedBy;
          return {
            label: p.label,
            ok: false,
            code: err.code,
            message: err.message,
            detail: winner ? `赢家：${String(winner)}` : undefined,
          };
        }
      };

      const [ra, rb] = await Promise.all([finishOne(a), finishOne(b)]);
      setResults([ra, rb]);
      onDone();
    } catch (e) {
      setResults([{ label: '设置失败', ok: false, message: (e as Error).message }]);
    } finally {
      setBusy(false);
      setPhase('');
    }
  };

  const needsCredential = mode === 'authentication' && authenticator.listCredentials().length === 0;

  return (
    <div className="panel">
      <h2>并发消费测试（两个页面完成同一 challenge）</h2>
      <div className="body">
        <div className="small muted" style={{ marginBottom: 8 }}>
          只调用一次 begin，然后“页面 A / 页面 B”同时提交 finish。服务端原子消费：
          第一个成功，另一个必定得到 <span className="mono">challenge-consumed</span>，
          右侧状态面板会记录赢家与失败原因。
        </div>
        <button className="primary" onClick={race} disabled={busy || needsCredential}>
          {busy ? phase : `模拟两页面同时完成${mode === 'registration' ? '注册' : '认证'}`}
        </button>
        {needsCredential && (
          <div className="small" style={{ color: 'var(--warn)', marginTop: 6 }}>
            认证模式需要设备里先有一个凭据。
          </div>
        )}

        {results && (
          <div style={{ marginTop: 10 }}>
            {results.map((r, i) => (
              <div key={i} className={`event-item ${r.ok ? 'info' : 'warn'}`}>
                <div className="msg">
                  {r.ok ? '✓' : '✗'} <b>{r.label}</b>：
                  {r.ok ? r.message : `${r.code} — ${r.message}`}
                  {r.detail && <div className="small muted">{r.detail}</div>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
