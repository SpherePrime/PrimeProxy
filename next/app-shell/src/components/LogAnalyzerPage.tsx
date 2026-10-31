import { useCallback, useState } from "react";
import {
  analyzeLogFile,
  analyzeLogText,
  LogAnalyzeResponse,
} from "../api";
import { IconChart, IconClose, IconFile, IconTerminal } from "./Icons";
import { PageHeader } from "./PageHeader";

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

function sizeLabel(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
  return `${bytes} Б`;
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

  return (
    <div className="page">
      <PageHeader
        index="04"
        group="Диагностика"
        title="Анализ лога"
        description="Разбор debug-лога winws2: соединения, профили и вердикты DESYNC."
        actions={
          result ? (
            <span className="chip tone-accent">
              {result.connections.length} соединений
            </span>
          ) : undefined
        }
      />

      {error && (
        <div className="infobar error with-icon" role="alert">
          <IconClose />
          <span>{error}</span>
        </div>
      )}

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>01</b> Источник
            </span>
            <h2 className="card-title">Лог winws2</h2>
            <p className="card-note">
              Укажите путь к файлу на машине ядра или вставьте фрагмент текста.
            </p>
          </div>
        </div>

        <div className="launch-row">
          <label className="field grow">
            <span className="field-label">Путь к файлу</span>
            <input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="путь к debug-логу winws2"
              spellCheck={false}
            />
          </label>
          <button
            type="button"
            className="btn accent"
            disabled={busy || path.trim() === ""}
            onClick={() => void run(() => analyzeLogFile(path.trim()))}
          >
            {busy ? <span className="spinner" /> : <IconFile />}
            {busy ? "Разбираю…" : "Анализировать файл"}
          </button>
        </div>

        <div className="source-or" aria-hidden="true">
          или текст
        </div>

        <label className="field">
          <span className="field-label">Фрагмент лога</span>
          <textarea
            className="textarea"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={6}
            placeholder="Вставь кусок лога winws2…"
            spellCheck={false}
          />
        </label>
        <div className="launch-row spaced">
          <button
            type="button"
            className="btn secondary"
            disabled={busy || text.trim() === ""}
            onClick={() => void run(() => analyzeLogText(text))}
          >
            {busy ? <span className="spinner" /> : <IconTerminal />}
            {busy ? "Разбираю…" : "Анализировать текст"}
          </button>
        </div>
      </section>

      {result && (
        <>
          <section className="card">
            <div className="card-head">
              <div>
                <span className="section-kicker">
                  <b>02</b> Итог
                </span>
                <h2 className="card-title">Сводка</h2>
                <p className="card-note">
                  {result.file_path
                    ? `Файл: ${result.file_path}`
                    : "Источник: вставленный текст"}
                  {typeof result.file_bytes === "number"
                    ? ` · ${sizeLabel(result.file_bytes)}`
                    : ""}
                </p>
              </div>
              <IconChart />
            </div>

            <div className="metric-grid">
              <div className="metric">
                <span className="metric-value">{result.summary.lines}</span>
                <span className="metric-label">строк</span>
              </div>
              <div className="metric">
                <span className="metric-value">{result.summary.connections_total}</span>
                <span className="metric-label">соединений</span>
              </div>
              <div className="metric">
                <span className="metric-value">{result.summary.packets_total}</span>
                <span className="metric-label">пакетов</span>
              </div>
              <div className="metric">
                <span className="metric-value">{result.summary.positive_checks_total}</span>
                <span className="metric-label">позитивных проверок</span>
              </div>
              <div className="metric">
                <span className="metric-value">{result.summary.unparsed_blocks}</span>
                <span className="metric-label">нераспознанных блоков</span>
              </div>
            </div>

            {result.summary.profiles.length > 0 && (
              <div className="stats-row">
                {result.summary.profiles.map((profile) => (
                  <span className="chip" key={profile.id}>
                    профиль {profile.id}: {profile.name}
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
          </section>

          <section className="card">
            <div className="card-head">
              <div>
                <span className="section-kicker">
                  <b>03</b> Соединения
                </span>
                <h2 className="card-title">
                  Топ соединений
                </h2>
                <p className="card-note">
                  Отсортировано по объёму пакетов; вердикты — сработавшие
                  DESYNC-профили.
                </p>
              </div>
              <span className="chip tone-neutral">{result.connections.length}</span>
            </div>

            {result.connections.length === 0 ? (
              <div className="empty-state">
                <strong>Лог не содержит соединений</strong>
                <span>Проверьте, что выбран debug-лог winws2.</span>
              </div>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Узел</th>
                      <th>Протокол</th>
                      <th>Пакеты</th>
                      <th>Вердикты</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.connections.map((row, index) => (
                      <tr key={`${row.remote_ip}-${row.remote_port}-${index}`}>
                        <td className="mono cell-strong">
                          {row.hostname || row.remote_ip}:{row.remote_port}
                        </td>
                        <td>{row.l7proto || row.proto}</td>
                        <td className="mono cell-nowrap">
                          {row.packets_total} ({row.packets_out}↑ {row.packets_in}↓)
                        </td>
                        <td className="mono">
                          {row.verdicts.map((v) => `${v.kind}×${v.count}`).join(", ") || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
