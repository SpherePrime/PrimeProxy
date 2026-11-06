import { STATUS_LABELS, STATUS_TONE } from "../../data/checkDomains";
import { IconArrowRight, IconSearch } from "../Icons";
import { EmptyState } from "../ui/EmptyState";
import { Panel } from "../ui/Panel";
import { Stat } from "../ui/Stat";
import type { SiteCheckModel } from "./useSiteCheck";

interface ResultsPanelProps {
  model: SiteCheckModel;
  fixableCount: number;
  onFix: () => void;
}

export function ResultsPanel({ model, fixableCount, onFix }: ResultsPanelProps) {
  const progress = model.total ? Math.round((model.results.length / model.total) * 100) : 0;

  return (
    <Panel title="Результат" meta={<span className="chip">выбрано {model.selectedCount}</span>}>
      <button
        type="button"
        className="btn btn--accent btn--lg btn--block"
        onClick={() => void model.run()}
        disabled={model.running || model.selectedCount === 0}
      >
        {model.running ? <span className="spinner" /> : <IconSearch size={16} />}
        {model.running ? `Проверяю… ${model.results.length} из ${model.total}` : "Проверить доступность"}
      </button>
      {model.running && (
        <div className="progress check-progress" aria-hidden="true">
          <span style={{ width: `${progress}%` }} />
        </div>
      )}

      {model.results.length > 0 ? (
        <>
          <div className="stats check-stats">
            <Stat value={model.okCount} label="доступно" tone="ok" />
            <Stat value={model.blocked.length} label="блок" tone={model.blocked.length ? "fail" : undefined} />
            <Stat value={model.slowCount} label="медленно" tone={model.slowCount ? "warn" : undefined} />
          </div>

          {model.finished && fixableCount > 0 && (
            <button type="button" className="btn btn--light btn--block fix-btn" onClick={onFix}>
              Включить профили для заблокированных · {fixableCount}
              <IconArrowRight size={14} />
            </button>
          )}

          <ul className="results">
            {model.results.map((result) => (
              <li className={`result is-${result.status}`} key={result.domain}>
                <span className="result__domain">{result.domain}</span>
                {typeof result.ms === "number" && <span className="result__ms">{result.ms} мс</span>}
                <span className={`chip ${STATUS_TONE[result.status] ?? ""}`}>
                  {STATUS_LABELS[result.status] ?? result.status}
                </span>
              </li>
            ))}
          </ul>
        </>
      ) : model.running ? (
        <EmptyState title="Проверяю домены" loading>
          Результаты появляются по мере готовности.
        </EmptyState>
      ) : model.finished ? (
        <EmptyState title="Ответов нет">Выберите другие домены и запустите ещё раз.</EmptyState>
      ) : (
        <EmptyState title="Ещё не проверялось">Совет: проверьте с выключенным и включённым обходом.</EmptyState>
      )}
    </Panel>
  );
}
