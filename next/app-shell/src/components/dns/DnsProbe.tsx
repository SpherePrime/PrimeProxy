import { useState } from "react";
import { DnsQueryResult, queryDns } from "../../api";
import { IconGlobe } from "../Icons";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";

export function DnsProbe({ servers }: { servers: string[] }) {
  const [domain, setDomain] = useState("example.com");
  const [server, setServer] = useState("");
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<DnsQueryResult | null>(null);
  const [error, setError] = useState("");

  const chosen = server || servers[0] || "";

  async function run() {
    const value = domain.trim();
    if (!value) {
      setError("Укажите домен");
      return;
    }
    setChecking(true);
    setError("");
    setResult(null);
    try {
      setResult(await queryDns(value, chosen));
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setChecking(false);
    }
  }

  return (
    <Panel title="Проба запроса" note="Один домен через выбранный сервер: ответ и задержка.">
      <div className="dns-form">
        <label className="field">
          <span className="field__label">Домен</span>
          <input
            className="input input--mono"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            onKeyDown={(event) => event.key === "Enter" && void run()}
            disabled={checking}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span className="field__label">Сервер</span>
          <select className="select" value={chosen} onChange={(event) => setServer(event.target.value)} disabled={checking}>
            {servers.map((item) => (
              <option value={item} key={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="btn btn--accent" onClick={() => void run()} disabled={checking}>
          {checking ? <span className="spinner" /> : <IconGlobe size={16} />}
          {checking ? "Запрос…" : "Запросить"}
        </button>
      </div>

      {error && <Notice tone="error">{error}</Notice>}
      {result && !result.ok && <Notice tone="error">{result.error ?? "Запрос не удался"}</Notice>}
      {result?.ok && (
        <div className="answer">
          <div className="answer__head">
            <span className="field__label">Ответ</span>
            {typeof result.ms === "number" && <span className="chip chip--ok">{result.ms} мс</span>}
          </div>
          <div className="chips">
            {(result.addresses ?? []).length > 0 ? (
              (result.addresses ?? []).map((address) => (
                <span className="chip" key={address}>
                  {address}
                </span>
              ))
            ) : (
              <span className="hint">Адресов в ответе нет</span>
            )}
          </div>
        </div>
      )}
    </Panel>
  );
}
