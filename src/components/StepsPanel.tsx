import { useState } from 'react';
import type { Step } from '../runner';

const STATUS_GLYPH: Record<Step['status'], string> = {
  ok: '✓',
  warn: '⚠',
  error: '✗',
  info: 'ℹ',
  pending: '→',
};

interface Props {
  steps: Step[];
}

export function StepsPanel({ steps }: Props) {
  if (steps.length === 0) {
    return (
      <div className="panel">
        <h2>每一步输入 / 输出</h2>
        <div className="body muted small">
          选择左侧场景后点击“开始仪式”。这里将依次展示 RP 签发 challenge、浏览器调用软件 authenticator、
          设备产出 response、服务端逐条校验的完整输入输出（二进制字段为 base64url 无填充编码）。
        </div>
      </div>
    );
  }
  return (
    <div className="panel">
      <h2>每一步输入 / 输出（{steps.length}）</h2>
      <div className="body">
        {steps.map((step) => (
          <StepItem key={step.id} step={step} />
        ))}
      </div>
    </div>
  );
}

function StepItem({ step }: { step: Step }) {
  const [open, setOpen] = useState(step.status === 'error' || step.status === 'warn');
  const time = new Date(step.ts).toLocaleTimeString('zh-CN', { hour12: false }) +
    '.' + String(step.ts % 1000).padStart(3, '0');
  return (
    <div className={`step ${step.status}`}>
      <div className="head" onClick={() => setOpen((o) => !o)}>
        <span className={`badge ${step.phase}`}>{phaseLabel(step.phase)}</span>
        <span className="title">
          {STATUS_GLYPH[step.status]} {step.title}
        </span>
        <span className="time">{time}</span>
      </div>
      {step.detail && <div className="detail">{step.detail}</div>}
      {open && step.payload !== undefined && (
        <pre>{JSON.stringify(step.payload, jsonReplacer, 2)}</pre>
      )}
    </div>
  );
}

function phaseLabel(phase: Step['phase']): string {
  switch (phase) {
    case 'rp':
      return 'RP/服务端';
    case 'device':
      return 'Authenticator';
    case 'browser':
      return '浏览器';
    case 'result':
      return '终态';
  }
}

/** Render Uint8Array as hex inside JSON dumps. */
function jsonReplacer(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return { __bytesHex: [...value].map((b) => b.toString(16).padStart(2, '0')).join('') };
  }
  return value;
}
