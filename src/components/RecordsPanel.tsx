import { useRef, useState } from 'react';
import { api } from '../api';
import type { CeremonyRecord } from '../../shared/protocol';

interface Props {
  lastRecord: CeremonyRecord | null;
  onExport: () => void;
  onRechecked: () => void;
}

interface CheckResult {
  ok: boolean;
  checks: { name: string; ok: boolean; detail: string }[];
  error?: string;
}

export function RecordsPanel({ lastRecord, onExport, onRechecked }: Props) {
  const [imported, setImported] = useState<{ name: string; record: CeremonyRecord } | null>(null);
  const [check, setCheck] = useState<CheckResult | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const readFile = async (file: File) => {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as CeremonyRecord;
      if (parsed.format !== 'webauthn-ceremony-lab/record') {
        throw new Error('缺少 format 标识，不是本工作台的仪式记录');
      }
      setImported({ name: file.name, record: parsed });
      setCheck(null);
      setImportError(null);
    } catch (e) {
      setImportError((e as Error).message);
      setImported(null);
      setCheck(null);
    }
  };

  const runRecheck = async () => {
    const record = imported?.record ?? lastRecord;
    if (!record) return;
    setCheck(await api.checkRecord(record));
    onRechecked();
  };

  const record = imported?.record ?? lastRecord;

  return (
    <div className="panel">
      <h2>仪式记录（不含私钥）</h2>
      <div className="body">
        <div className="small muted" style={{ marginBottom: 8 }}>
          记录只包含 challenge、clientDataJSON、attestationObject / authenticatorData、签名与服务端裁决；
          设备私钥（non-extractable CryptoKey）永远不会出现在导出内容中。
        </div>

        <div className="btn-row" style={{ marginBottom: 8 }}>
          <button onClick={onExport} disabled={!lastRecord}>
            导出最近一次记录
          </button>
          <label className="file-label" style={{ flex: 1 }}>
            导入记录文件
            <input
              ref={fileRef}
              type="file"
              accept="application/json,.json"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void readFile(f);
                e.target.value = '';
              }}
            />
          </label>
        </div>
        <button style={{ width: '100%' }} onClick={runRecheck} disabled={!record}>
          重新导入检查（服务端独立复核）
        </button>

        {importError && (
          <div className="callout error" style={{ marginTop: 8 }}>
            导入失败：{importError}
          </div>
        )}

        {record && (
          <div className="small muted" style={{ marginTop: 8 }}>
            {imported ? `已导入：${imported.name}` : '使用当前会话最近一次记录'} · {record.ceremony} ·
            裁决：{record.verdict.ok ? '成功' : record.verdict.errorCode}
            {record.scenarioNotes.length > 0 && (
              <div>备注：{record.scenarioNotes.join('；')}</div>
            )}
          </div>
        )}

        {check && (
          <div style={{ marginTop: 10 }}>
            <div className={`callout ${check.ok ? 'ok' : 'warn'}`}>
              {check.ok ? '复核通过：所有检查项成立' : '复核未通过（详见检查项）'}
            </div>
            {check.checks.map((c, i) => (
              <div key={i} className="event-item" style={{ borderLeftColor: c.ok ? 'var(--ok)' : 'var(--error)' }}>
                <div className="msg">
                  {c.ok ? '✓' : '✗'} <b>{c.name}</b>
                  <div className="small muted">{c.detail}</div>
                </div>
              </div>
            ))}
            {check.error && <div className="small" style={{ color: 'var(--error)' }}>{check.error}</div>}
          </div>
        )}
      </div>
    </div>
  );
}
