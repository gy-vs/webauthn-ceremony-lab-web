import type { ServerConfig } from '../api';
import type { ScenarioPreset, CeremonySettings } from '../settings';
import type { CredentialSummary } from '../../shared/protocol';

interface Props {
  config: ServerConfig | null;
  settings: CeremonySettings;
  mode: 'registration' | 'authentication';
  activeScenario: string;
  scenarios: ScenarioPreset[];
  originStatus: { allowed: boolean; rpMatch: boolean } | null;
  credentials: CredentialSummary[];
  selectedCredentialId: string;
  onPatch: (patch: Partial<CeremonySettings>) => void;
  onMode: (mode: 'registration' | 'authentication') => void;
  onScenario: (id: string) => void;
  onSelectCredential: (id: string) => void;
}

export function SettingsPanel(props: Props) {
  const { settings: s, onPatch: set, config, originStatus } = props;

  return (
    <>
      <div className="panel">
        <h2>场景预设</h2>
        <div className="body">
          <div className="preset-grid">
            {props.scenarios.map((sc) => (
              <button
                key={sc.id}
                className={props.activeScenario === sc.id ? 'active' : ''}
                title={sc.description}
                onClick={() => props.onScenario(sc.id)}
              >
                {sc.title}
              </button>
            ))}
          </div>
          {props.scenarios.find((x) => x.id === props.activeScenario)?.description && (
            <div className="small muted" style={{ marginTop: 8 }}>
              {props.scenarios.find((x) => x.id === props.activeScenario)?.description}
            </div>
          )}
        </div>
      </div>

      <div className="panel">
        <h2>RP / 浏览器参数</h2>
        <div className="body">
          <div className="field">
            <label>客户端标签（并发消费标识）</label>
            <input
              type="text"
              value={s.clientLabel}
              onChange={(e) => set({ clientLabel: e.target.value })}
            />
          </div>
          <div className="field">
            <label>timeout（毫秒，5000–300000）</label>
            <input
              type="number"
              min={5000}
              max={300000}
              step={1000}
              value={s.timeoutMs}
              onChange={(e) => set({ timeoutMs: Number(e.target.value) })}
            />
          </div>
          <div className="field">
            <label>有效 origin（clientDataJSON 中声明）</label>
            <input
              type="text"
              className={originStatus && !originStatus.allowed ? 'origin-bad' : ''}
              value={s.effectiveOrigin}
              onChange={(e) => set({ effectiveOrigin: e.target.value })}
            />
            <div className="small" style={{ color: originStatus?.allowed ? 'var(--ok)' : 'var(--error)' }}>
              {originStatus?.allowed ? '✓ 在 RP 允许列表' : '✗ 不在 RP 允许列表 → bad-origin'}
            </div>
          </div>
          <div className="field">
            <label>有效 RP ID（authenticator 哈希的对象）</label>
            <input
              type="text"
              className={originStatus && !originStatus.rpMatch ? 'origin-bad' : ''}
              value={s.effectiveRpId}
              onChange={(e) => set({ effectiveRpId: e.target.value })}
            />
            <div className="small" style={{ color: originStatus?.rpMatch ? 'var(--ok)' : 'var(--error)' }}>
              {originStatus?.rpMatch ? '✓ 与服务端 rpId 一致' : `✗ 与服务端 rpId(${config?.rpId}) 不一致 → bad-rpid`}
            </div>
          </div>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={s.crossOrigin}
              onChange={(e) => set({ crossOrigin: e.target.checked })}
            />
            crossOrigin=true（跨站 iframe）
          </label>
        </div>
      </div>

      <div className="panel">
        <h2>注册选项 (create)</h2>
        <div className="body">
          <div className="field">
            <label>attestation 偏好</label>
            <select value={s.attestation} onChange={(e) => set({ attestation: e.target.value as CeremonySettings['attestation'] })}>
              <option value="none">none</option>
              <option value="indirect">indirect</option>
              <option value="direct">direct（要求设备出具 packed 自证明）</option>
            </select>
          </div>
          <div className="field">
            <label>设备返回的 attestation 格式</label>
            <select
              value={s.attestationFormat}
              onChange={(e) => set({ attestationFormat: e.target.value as CeremonySettings['attestationFormat'] })}
            >
              <option value="none">fmt="none"</option>
              <option value="direct">fmt="packed"（自证明签名）</option>
            </select>
          </div>
          <div className="field">
            <label>residentKey 要求</label>
            <select
              value={s.residentKey}
              onChange={(e) => set({ residentKey: e.target.value as CeremonySettings['residentKey'] })}
            >
              <option value="discouraged">discouraged</option>
              <option value="preferred">preferred</option>
              <option value="required">required（discoverable credential）</option>
            </select>
          </div>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={s.resident}
              onChange={(e) => set({ resident: e.target.checked })}
            />
            设备实际创建 resident 凭据（BE/BS 标志）
          </label>
        </div>
      </div>

      <div className="panel">
        <h2>设备行为注入</h2>
        <div className="body">
          <div className="field">
            <label>设备失败模式（在返回 response 前抛出 DOMException）</label>
            <select
              value={s.deviceFailure}
              onChange={(e) => set({ deviceFailure: e.target.value as CeremonySettings['deviceFailure'] })}
            >
              <option value="none">无（正常返回）</option>
              <option value="cancel">cancel → NotAllowedError</option>
              <option value="timeout">timeout → TimeoutError</option>
            </select>
          </div>
          <div className="field">
            <label>userVerification 要求（注册 + 认证共用）</label>
            <select
              value={s.userVerification}
              onChange={(e) => set({ userVerification: e.target.value as CeremonySettings['userVerification'] })}
            >
              <option value="required">required</option>
              <option value="preferred">preferred</option>
              <option value="discouraged">discouraged</option>
            </select>
          </div>
          <label className="checkbox">
            <input type="checkbox" checked={s.up} onChange={(e) => set({ up: e.target.checked })} />
            用户在场（UP 标志）
          </label>
          <label className="checkbox">
            <input type="checkbox" checked={s.uv} onChange={(e) => set({ uv: e.target.checked })} />
            用户已验证（UV 标志）
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={s.discoverable}
              onChange={(e) => set({ discoverable: e.target.checked })}
            />
            认证走 discoverable 流程（空 allowCredentials）
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={s.corruptSignature}
              onChange={(e) => set({ corruptSignature: e.target.checked })}
            />
            翻转签名字节（签名失败）
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={s.duplicateCredentialId}
              onChange={(e) => set({ duplicateCredentialId: e.target.checked })}
              disabled={props.credentials.length === 0}
            />
            复用已有 credential id 注册
          </label>

          <div className="field" style={{ marginTop: 8 }}>
            <label>设备延迟（毫秒；大于 timeout 即超时）</label>
            <input
              type="number"
              min={0}
              value={s.delayMs}
              onChange={(e) => set({ delayMs: Number(e.target.value) })}
            />
          </div>
          <div className="field">
            <label>强制下一次断言 signCount（留空=时钟派生；填 1 可制造回退）</label>
            <input
              type="text"
              placeholder="例如 1"
              value={s.forcedSignCount}
              onChange={(e) => set({ forcedSignCount: e.target.value.replace(/[^0-9]/g, '') })}
            />
          </div>
          <div className="field">
            <label>注入时钟偏移（秒；负数=回拨，影响时钟派生计数器）</label>
            <input
              type="number"
              value={s.clockOffsetSeconds}
              onChange={(e) => set({ clockOffsetSeconds: Number(e.target.value) })}
            />
          </div>

          {props.mode === 'authentication' && (
            <div className="field">
              <label>认证使用的服务端凭据</label>
              <select
                value={props.selectedCredentialId}
                onChange={(e) => props.onSelectCredential(e.target.value)}
                disabled={s.discoverable}
              >
                <option value="">（自动：RP 返回的全部 allowCredentials）</option>
                {props.credentials.map((c) => (
                  <option key={c.credentialId} value={c.credentialId}>
                    {c.user.name} · {c.credentialIdHex.slice(0, 16)}… · count={c.signCount}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
