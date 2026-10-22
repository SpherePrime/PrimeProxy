import { useCallback, useEffect, useState } from "react";
import {
  analyzeLogFile,
  analyzeLogText,
  LogAnalyzeResponse,
} from "../api";

// Топ соединений — как в ответе бэкенда (см. log_analyzer_api).
interface ConnectionRow {
  proto: string;
  remote_ip: string;
  remote_port: number;
  hostname: string;
  l7proto: string;
  profiles: string[];
  packets_total: number;
  packets_out: number;
  packets_in: number;
  verdicts: { kind: string; count: number }[];
  positive_lists: string[];
}

interface AnalyzeState {
  summary: {
    lines: number;
    profiles: { id: number; name: string }[];
    hostlists: { path: string; hosts: number }[];
    ipsets: { path: string; subnets: number }[];
    packets_total: number;
    connections_total: number;
    positive_checks_total: number;
    unparsed_blocks: number;
    unrecognized_packet_lines: number;
  };
  connections: ConnectionRow[];
  file_path?: string;
  file_bytes?: number;
}

export function LogAnalyzerPage() {
  const [path, setPath] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeState | null>(null);

  const run = useCallback(async (action: () => Promise<LogAnalyzeResponse>) => {
    setBusy(true);
    setError(null);
    try {
      const data = await action();
      setResult(data as AnalyzeState);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (result && result.connections.length === 0) return;
  }, [result]);

  return (
    <div className="page">
      <div className="page-header">
        <h1>Анализ лога</h1>
        <p className="subtitle">
          Разбор debug-лога winws2: соединения, профили, вердикты DESYNC.
        </p>
      </div>

      {error && <div className="infobar error">{error}</div>}

      <div className="card">
        <h2>Файл лога</h2>
        <div className="launch-row">
          <div className="field" style={{ flex: 1 }}>
            <span className="field-label">Путь к файлу</span>
            <input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="путь к debug-логу winws2"
              style={{ width: "100%" }}
            />
          </div>
          <button
            className="btn accent"
            disabled={busy || path.trim() === ""}
            onClick={() => void run(() => analyzeLogFile(path.trim()))}
          >
            {busy ? "Разбираю…" : "Анализировать"}
          </button>
        </div>
      </div>

      <div className="card">
        <h2>Или вставить текст</h2>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={6}
          placeholder="Вставь кусок лога winws2…"
          style={{
            width: "100%",
            background: "var(--panel-2)",
            color: "var(--text)",
            border: "1px solid #334155",
            borderRadius: 8,
            padding: "10px 12px",
            fontFamily: "var(--mono)",
            fontSize: 13,
          }}
        />
        <div className="launch-row" style={{ marginTop: 10 }}>
          <button
            className="btn secondary"
            disabled={busy || text.trim() === ""}
            onClick={() => void run(() => analyzeLogText(text))}
          >
            {busy ? "Разбираю…" : "Анализировать текст"}
          </button>
        </div>
      </div>

      {result && (
        <>
          <div className="card">
            <h2>Сводка{result.file_path ? ` — ${result.file_path}` : ""}</h2>
            <div className="stats-row">
              <span className="chip">Строк: {result.summary.lines}</span>
              <span className="chip">Соединений: {result.summary.connections_total}</span>
              <span className="chip">Пакетов: {result.summary.packets_total}</span>
              <span className="chip">Позитивных проверок: {result.summary.positive_checks_total}</span>
              <span className="chip">Нераспознанных блоков: {result.summary.unparsed_blocks}</span>
            </div>
            {result.summary.profiles.length > 0 && (
              <div className="stats-row">
                {result.summary.profiles.map((profile) => (
                  <span className="chip" key={profile.id}>
                    Профиль {profile.id}: {profile.name}
                  </span>
                ))}
              </div>
            )}
            {(result.summary.hostlists.length > 0 || result.summary.ipsets.length > 0) && (
              <div className="stats-row">
                {result.summary.hostlists.map((entry) => (
                  <span className="chip" key={`h-${entry.path}`}>
                    {entry.path}: {entry.hosts} хостов
                  </span>
                ))}
                {result.summary.ipsets.map((entry) => (
                  <span className="chip" key={`i-${entry.path}`}>
                    {entry.path}: {entry.subnets} подсетей
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="card">
            <h2>Соединения (топ-{result.connections.length})</h2>
            {result.connections.length === 0 ? (
              <div className="preset-empty">Лог не содержит соединений.</div>
            ) : (
              <div className="log-table">
                {result.connections.map((row, index) => (
                  <div className="log-row" key={`${row.remote_ip}-${row.remote_port}-${index}`}>
                    <span className="log-cell key">
                      {row.hostname || row.remote_ip}:{row.remote_port}
                    </span>
                    <span className="log-cell">
                      {row.l7proto || row.proto}
                    </span>
                    <span className="log-cell">
                      {row.packets_total} пак. ({row.packets_out}↑ {row.packets_in}↓)
                    </span>
                    <span className="log-cell">
                      {row.verdicts.map((v) => `${v.kind}×${v.count}`).join(", ") || "—"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
