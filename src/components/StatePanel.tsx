import type { ServerState } from '../api';
import type { CredentialSummary } from '../../shared/protocol';
import type { CeremonySettings } from '../settings';

interface Props {
  state: ServerState;
  onRefresh: () => void;
  onSelectCredential: (id: string) => void;
  selectedCredentialId: string;
  settings: CeremonySettings;
  disabled: boolean;
}

export function StatePanel({ state, onRefresh, onSelectCredential, selectedCredentialId }: Props) {
  return (
    <>
      <div className="panel">
        <h2>
          服务端状态
          <button className="ghost" style={{ float: 'right', padding: '2px 8px', fontSize: 11 }} onClick={onRefresh}>
            刷新
          </button>
        </h2>
        <div className="body">
          <div className="summary-bar">
            <div className="stat">
              <span className="k">凭据</span>
              <span className="v">{state.credentials.length}</span>
            </div>
            <div className="stat">
              <span className="k">pending</span>
              <span className="v">{state.challenges.filter((c) => c.status === 'pending').length}</span>
            </div>
            <div className="stat">
              <span className="k">已消费</span>
              <span className="v">{state.challenges.filter((c) => c.status === 'consumed').length}</span>
            </div>
            <div className="stat">
              <span className="k">已过期</span>
              <span className="v">{state.challenges.filter((c) => c.status === 'expired').length}</span>
            </div>
          </div>

          <h3 style={sectionTitle}>凭据库（公钥 + 计数器）</h3>
          {state.credentials.length === 0 && <div className="small muted">暂无凭据。</div>}
          {state.credentials.map((c) => (
            <CredentialRow
              key={c.credentialId}
              credential={c}
              selected={c.credentialId === selectedCredentialId}
              onPick={() => onSelectCredential(c.credentialId)}
            />
          ))}

          <h3 style={sectionTitle}>Challenge 终态</h3>
          {state.challenges.length === 0 && <div className="small muted">暂无 challenge。</div>}
          {state.challenges.slice(-8).reverse().map((c) => (
            <div key={c.id} className="challenge-item">
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 6 }}>
                <span className="mono">{c.kind === 'registration' ? 'create' : 'get'}</span>
                <span className={`status-pill ${c.status}`}>{statusLabel(c.status)}</span>
              </div>
              <div className="mono small muted" style={{ wordBreak: 'break-all', margin: '3px 0' }}>
                {c.id.slice(0, 24)}…
              </div>
              <div className="small muted">
                TTL {c.status === 'pending' ? `${Math.ceil(c.ttlMs / 1000)}s` : '—'} · 消费者:{' '}
                {c.consumedBy ?? '—'}
              </div>
              {c.outcome && (
                <div className="small" style={{ color: c.outcome.ok ? 'var(--ok)' : 'var(--error)' }}>
                  {c.outcome.ok ? '✓ 接受' : `✗ ${c.outcome.errorCode}: ${c.outcome.message}`}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <h2>服务端事件日志</h2>
        <div className="body" style={{ maxHeight: 280, overflowY: 'auto' }}>
          {state.events.length === 0 && <div className="small muted">暂无事件。</div>}
          {state.events.slice(-30).reverse().map((e, i) => (
            <div key={i} className={`event-item ${e.level}`}>
              <div className="msg">
                <span className="ts">{new Date(e.ts).toLocaleTimeString('zh-CN', { hour12: false })} </span>
                {e.message}
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function CredentialRow({
  credential,
  selected,
  onPick,
}: {
  credential: CredentialSummary;
  selected: boolean;
  onPick: () => void;
}) {
  return (
    <div
      className="credential-item"
      style={{ cursor: 'pointer', borderColor: selected ? 'var(--accent)' : undefined }}
      onClick={onPick}
      title="点击用于认证"
    >
      <div>
        <span className="tag">{credential.user.name}</span>
        {credential.residentKey && <span className="tag rk">resident</span>}
        {credential.userVerified && <span className="tag uv">uv</span>}
        {credential.cloneDetected && <span className="tag clone">clone suspected</span>}
      </div>
      <div className="cid">{credential.credentialIdHex.slice(0, 32)}…</div>
      <div className="small muted">
        signCount=<b className={credential.cloneDetected ? 'tag clone' : ''}>{credential.signCount}</b> · rpId=
        {credential.rpId}
        {credential.lastUsedAt ? ` · 最近使用 ${new Date(credential.lastUsedAt).toLocaleTimeString('zh-CN', { hour12: false })}` : ''}
      </div>
    </div>
  );
}

function statusLabel(status: ServerState['challenges'][number]['status']): string {
  switch (status) {
    case 'pending':
      return 'pending';
    case 'consumed':
      return '已消费';
    case 'expired':
      return '已过期';
  }
}

const sectionTitle: React.CSSProperties = {
  fontSize: 12,
  color: 'var(--muted)',
  margin: '12px 0 6px',
};
