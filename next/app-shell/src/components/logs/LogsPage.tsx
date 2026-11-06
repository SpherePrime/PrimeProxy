import { useCallback, useState } from "react";
import { analyzeLogFile, analyzeLogText, LogAnalyzeResponse } from "../../api";
import { Notice } from "../ui/Notice";
import { PageHead } from "../ui/PageHead";
import { ConnectionsTable } from "./ConnectionsTable";
import { LogSource } from "./LogSource";
import { LogSummary } from "./LogSummary";
import { AnalyzeState } from "./types";
import "../../styles/pages/logs.css";

export function LogsPage() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeState | null>(null);

  const run = useCallback(async (action: () => Promise<LogAnalyzeResponse>) => {
    setBusy(true);
    setError(null);
    try {
      setResult((await action()) as AnalyzeState);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }, []);

  return (
    <div className="page">
      <PageHead
        eyebrow="Диагностика"
        title={
          <>
            Анализ <em>лога</em>
          </>
        }
        lead="Разбор debug-лога winws2: какие соединения шли, какие профили сработали и где DESYNC."
      />

      <div className="notices">{error && <Notice tone="error">{error}</Notice>}</div>

      <div className="layout layout--even">
        <LogSource
          busy={busy}
          onFile={(path) => void run(() => analyzeLogFile(path))}
          onText={(text) => void run(() => analyzeLogText(text))}
        />
        <LogSummary result={result} />
      </div>

      {result && (
        <div className="logs-table">
          <ConnectionsTable rows={result.connections} />
        </div>
      )}
    </div>
  );
}
