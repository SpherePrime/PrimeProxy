import { useState } from "react";
import { fetchServerCheck, ServerCheckResponse } from "../../api";
import { IconCheck } from "../Icons";
import { EmptyState } from "../ui/EmptyState";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";

const VERDICT_TONE: Record<string, "ok" | "warn" | "error"> = {
  ok: "ok",
  warn: "warn",
  fail: "error",
};

const CARD_TONE: Record<string, string> = {
  ok: "chip--ok",
  silent: "",
  network: "chip--fail",
};

export function ServerCheck() {
  const [domain, setDomain] = useState("example.com");
  const [checking, setChecking] = useState(false);
  const [check, setCheck] = useState<ServerCheckResponse | null>(null);
  const [error, setError] = useState("");

  async function run() {
    setChecking(true);
    setError("");
    try {
      setCheck(await fetchServerCheck(domain.trim()));
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setChecking(false);
    }
  }

  return (
    <Panel title="Сверка серверов" note="Один домен — все известные серверы: кто ответил и насколько быстро.">
      <div className="toolbar">
        <input
          className="input input--mono server-check__input"
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
          onKeyDown={(event) => event.key === "Enter" && void run()}
          placeholder="домен для пробы"
          aria-label="Домен для сверки"
          spellCheck={false}
        />
        <button type="button" className="btn btn--accent" onClick={() => void run()} disabled={checking}>
          {checking ? <span className="spinner" /> : <IconCheck size={16} />}
          {checking ? "Сверяю…" : "Сверить серверы"}
        </button>
      </div>

      {error && <Notice tone="error">{error}</Notice>}

      {check ? (
        <div className="stack">
          <Notice tone={VERDICT_TONE[check.verdict.kind] ?? "hint"}>{check.verdict.detail}</Notice>
          <div className="server-cards">
            {check.cards.map((card) => (
              <div className="server-card" key={card.server}>
                <span className={`chip ${CARD_TONE[card.status] ?? ""}`}>{card.status}</span>
                <b className="mono">{card.server}</b>
                {card.note && <span className="muted">{card.note}</span>}
                {card.best && <span className="server-card__best">{card.best}</span>}
              </div>
            ))}
          </div>
          <details className="details">
            <summary>Полный отчёт</summary>
            <div className="details__body">
              <pre className="codeline">{check.text}</pre>
            </div>
          </details>
        </div>
      ) : (
        !checking && <EmptyState title="Сверка не запускалась">Введите домен и нажмите «Сверить серверы».</EmptyState>
      )}
    </Panel>
  );
}
