import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, type ServerConfig, type ServerState } from './api';
import {
  DEFAULT_SETTINGS,
  SCENARIOS,
  authenticator,
  virtualClock,
  type CeremonySettings,
} from './settings';
import { runAuthentication, runRegistration, StepLog, type Step } from './runner';
import type { CeremonyRecord } from '../shared/protocol';
import { SettingsPanel } from './components/SettingsPanel';
import { StepsPanel } from './components/StepsPanel';
import { StatePanel } from './components/StatePanel';
import { RecordsPanel } from './components/RecordsPanel';
import { ConcurrencyPanel } from './components/ConcurrencyPanel';

type Mode = 'registration' | 'authentication';

export function App() {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [state, setState] = useState<ServerState>({ credentials: [], challenges: [], events: [] });
  const [settings, setSettings] = useState<CeremonySettings>(DEFAULT_SETTINGS);
  const [mode, setMode] = useState<Mode>('registration');
  const [activeScenario, setActiveScenario] = useState<string>('happy-register');
  const [steps, setSteps] = useState<Step[]>([]);
  const [running, setRunning] = useState(false);
  const [lastRecord, setLastRecord] = useState<CeremonyRecord | null>(null);
  const [selectedCredentialId, setSelectedCredentialId] = useState<string>('');
  const [verdict, setVerdict] = useState<{ kind: 'idle' | 'ok' | 'warn' | 'error'; text: string }>({
    kind: 'idle',
    text: '尚未运行仪式',
  });
  const logRef = useRef<StepLog | null>(null);
  if (!logRef.current) logRef.current = new StepLog(setSteps);

  const refreshState = useCallback(async () => {
    try {
      setState(await api.state());
    } catch {
      // server briefly unavailable during dev restart
    }
  }, []);

  useEffect(() => {
    void api.config().then((cfg) => {
      setConfig(cfg);
      setSettings((s) => ({
        ...s,
        effectiveOrigin: cfg.allowedOrigins[0],
        effectiveRpId: cfg.rpId,
        timeoutMs: cfg.defaultTimeoutMs,
      }));
    });
    void refreshState();
    const timer = setInterval(refreshState, 2000);
    return () => clearInterval(timer);
  }, [refreshState]);

  // Push clock offset into the authenticator's virtual clock.
  useEffect(() => {
    virtualClock.offsetMs = settings.clockOffsetSeconds * 1000;
  }, [settings.clockOffsetSeconds]);

  const updateSettings = useCallback((patch: Partial<CeremonySettings>) => {
    setSettings((s) => ({ ...s, ...patch }));
    setActiveScenario('');
  }, []);

  const applyScenario = useCallback(
    (id: string) => {
      const scenario = SCENARIOS.find((s) => s.id === id);
      if (!scenario) return;
      setSettings((s) => scenario.apply(s));
      setActiveScenario(id);
      if (id === 'resident-uv') setMode('registration');
    },
    [],
  );

  const clearSteps = useCallback(() => {
    logRef.current?.clear();
    setLastRecord(null);
    setVerdict({ kind: 'idle', text: '尚未运行仪式' });
  }, []);

  const run = useCallback(async () => {
    if (running || !config) return;
    setRunning(true);
    logRef.current?.clear();
    setLastRecord(null);
    setVerdict({ kind: 'idle', text: '仪式进行中…' });
    try {
      const result =
        mode === 'registration'
          ? await runRegistration(settings, logRef.current!)
          : await runAuthentication(
              settings,
              logRef.current!,
              selectedCredentialId || undefined,
            );
      setLastRecord(result.record);
      if (result.ok) {
        setVerdict({ kind: 'ok', text: '终态：仪式成功，服务端已接受' });
      } else {
        const v = result.record?.verdict;
        if (v && !v.ok && v.errorCode === 'sign-count-clone') {
          setVerdict({ kind: 'warn', text: `终态：可解释的克隆告警 — ${v.message}` });
        } else if (result.record?.ceremony === 'authentication' && v && v.ok) {
          setVerdict({ kind: 'warn', text: '终态：签名通过但计数器回退，凭据已被标记为疑似克隆' });
        } else {
          setVerdict({
            kind: 'error',
            text: v && !v.ok ? `终态：${v.errorCode} — ${v.message}` : '终态：仪式失败',
          });
        }
      }
    } catch (e) {
      logRef.current?.add('result', '运行异常', 'error', (e as Error).message);
      setVerdict({ kind: 'error', text: `终态：${(e as Error).message}` });
    } finally {
      setRunning(false);
      void refreshState();
    }
  }, [running, config, mode, settings, selectedCredentialId, refreshState]);

  const resetServer = useCallback(async () => {
    await api.reset();
    authenticator.reset();
    clearSteps();
    setSelectedCredentialId('');
    await refreshState();
  }, [clearSteps, refreshState]);

  const exportRecord = useCallback(() => {
    if (!lastRecord) return;
    const blob = new Blob([JSON.stringify(lastRecord, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ceremony-${lastRecord.ceremony}-${lastRecord.exportedAt}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [lastRecord]);

  const hasCredentials = state.credentials.length > 0;

  const originStatus = useMemo(() => {
    if (!config) return null;
    const allowed = config.allowedOrigins.includes(settings.effectiveOrigin);
    return { allowed, rpMatch: settings.effectiveRpId === config.rpId };
  }, [config, settings.effectiveOrigin, settings.effectiveRpId]);

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <h1>WebAuthn 注册 / 认证仪式模拟工作台</h1>
          <div className="meta">
            软件测试 authenticator · ES256 · challenge 一次性 + TTL · 不连接任何真实身份平台或外部数据库
          </div>
        </div>
        <div className="meta">
          {config && (
            <>
              RP ID: <span className="mono">{config.rpId}</span> · 允许 origin:{' '}
              <span className="mono">{config.allowedOrigins.join(', ')}</span>
            </>
          )}
        </div>
      </header>

      <div className="layout">
        <div>
          <SettingsPanel
            config={config}
            settings={settings}
            mode={mode}
            activeScenario={activeScenario}
            scenarios={SCENARIOS}
            originStatus={originStatus}
            credentials={state.credentials}
            selectedCredentialId={selectedCredentialId}
            onPatch={updateSettings}
            onMode={setMode}
            onScenario={applyScenario}
            onSelectCredential={setSelectedCredentialId}
          />
        </div>

        <div>
          <div className="panel">
            <h2>仪式控制台</h2>
            <div className="body">
              <div className="tabs">
                <button
                  className={mode === 'registration' ? 'active' : ''}
                  onClick={() => setMode('registration')}
                >
                  注册 (webauthn.create)
                </button>
                <button
                  className={mode === 'authentication' ? 'active' : ''}
                  onClick={() => setMode('authentication')}
                  disabled={!hasCredentials}
                  title={hasCredentials ? '' : '先注册一个凭据'}
                >
                  认证 (webauthn.get)
                </button>
              </div>

              <div className={`final-verdict ${verdict.kind}`}>{verdict.text}</div>

              <div className="btn-row">
                <button className="primary" onClick={run} disabled={running || (mode === 'authentication' && !hasCredentials)}>
                  {running ? '仪式进行中…' : mode === 'registration' ? '开始注册仪式' : '开始认证仪式'}
                </button>
                <button onClick={clearSteps} disabled={running}>
                  清空日志
                </button>
                <button className="danger" onClick={resetServer} disabled={running}>
                  重置服务端与设备
                </button>
              </div>
              <div className="small muted" style={{ marginTop: 8 }}>
                客户端标签用于演示两个页面并发消费同一 challenge：把“页面 B”标签页里 begin 得到的 challenge 复制到
                <span className="mono"> 并发测试 </span>面板。
              </div>
            </div>
          </div>

          <StepsPanel steps={steps} />
          <ConcurrencyPanel settings={settings} mode={mode} onDone={refreshState} />
        </div>

        <div>
          <StatePanel
            state={state}
            onRefresh={refreshState}
            onSelectCredential={(id) => {
              setMode('authentication');
              setSelectedCredentialId(id);
            }}
            selectedCredentialId={selectedCredentialId}
            settings={settings}
            disabled={running}
          />
          <RecordsPanel lastRecord={lastRecord} onExport={exportRecord} onRechecked={refreshState} />
        </div>
      </div>
    </div>
  );
}
