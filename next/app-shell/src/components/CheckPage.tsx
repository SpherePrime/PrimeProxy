import { useEffect, useState } from "react";
import { fetchCheckSites, fetchCheckStatus, SiteCheckResult } from "../api";

// Домены по умолчанию — типичные маркеры блокировок (видео, мессенджеры, ИИ, игры).
const DEFAULT_DOMAINS = [
  "www.youtube.com",
  "discord.com",
  "gateway.discord.gg",
  "chatgpt.com",
  "www.google.com",
  "www.twitch.tv",
  "instagram.com",
  "store.steampowered.com",
];

// Подписи и CSS-классы статусов из контракта /api/check/sites/status.
const STATUS_LABELS: Record<string, string> = {
  ok: "Доступен",
  blocked: "Заблокирован",
  slow: "Медленно",
};

const STATUS_CHIP_CLASS: Record<string, string> = {
  ok: "chip-ok",
  blocked: "chip-fail",
  slow: "chip-slow",
};

// Сколько секунд ждём завершения фонового опроса на сервере.
const MAX_POLLS = 120;

// Страница «Проверка» — доступность сервисов с включённым и выключенным
// обходом. Сервер проверяет домены в фоне: POST запускает задачу, дальше
// поллим статус раз в секунду, пока не придёт done.
export function CheckPage() {
  const [checked, setChecked] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(DEFAULT_DOMAINS.map((domain) => [domain, true])),
  );
  const [running, setRunning] = useState(false);
  const [finished, setFinished] = useState(false);
  const [results, setResults] = useState<SiteCheckResult[]>([]);
  const [error, setError] = useState("");

  // Поллинг статуса раз в секунду, пока идёт фоновая проверка.
  useEffect(() => {
    if (!running) return;
    let alive = true;
    let attempts = 0;
    const tick = async () => {
      attempts += 1;
      try {
        const status = await fetchCheckStatus();
        if (!alive) return;
        setResults(status.results ?? []);
        if (status.done) {
          setFinished(true);
          setRunning(false);
          return;
        }
        if (attempts >= MAX_POLLS) {
          setError(`Проверка не завершилась за ${MAX_POLLS} с`);
          setRunning(false);
        }
      } catch (e) {
        if (!alive) return;
        setError(String((e as Error).message));
        setRunning(false);
      }
    };
    void tick();
    const timer = window.setInterval(() => void tick(), 1000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [running]);

  function toggle(domain: string) {
    setChecked((prev) => ({ ...prev, [domain]: !prev[domain] }));
  }

  async function runCheck() {
    const domains = DEFAULT_DOMAINS.filter((domain) => checked[domain]);
    if (domains.length === 0) {
      setError("Отметьте хотя бы один домен");
      return;
    }
    setError("");
    // Повторная проверка заменяет предыдущие результаты.
    setResults([]);
    setFinished(false);
    try {
      await fetchCheckSites(domains);
      // Задача принята — начинаем поллинг статуса.
      setRunning(true);
    } catch (e) {
      setError(String((e as Error).message));
    }
  }

  const okCount = results.filter((r) => r.status === "ok").length;

  return (
    <div className="page">
      <header className="page-header">
        <h1>Проверка</h1>
        <p className="subtitle">
          Доступность популярных сервисов: какие домены проходят, а какие
          блокируются.
        </p>
      </header>

      <div className="infobar hint">
        💡 Сравни результаты с включённым и выключенным обходом
      </div>
      {error && <div className="infobar error">✗ {error}</div>}

      <section className="card">
        <h2>Сайты</h2>
        <div className="site-checks">
          {DEFAULT_DOMAINS.map((domain) => (
            <label className="site-check" key={domain}>
              <input
                type="checkbox"
                checked={Boolean(checked[domain])}
                onChange={() => toggle(domain)}
                disabled={running}
              />
              <span>{domain}</span>
            </label>
          ))}
        </div>
        <div className="actions-row">
          <button className="btn accent" onClick={runCheck} disabled={running}>
            {running ? "Проверяю…" : "Проверить доступность"}
          </button>
          {running && (
            <span className="site-ms">
              Опрос каждую секунду — результаты появляются по мере готовности.
            </span>
          )}
        </div>

        {results.length > 0 && (
          <>
            <p className="summary-line">
              {okCount} из {results.length} доступны
            </p>
            <div className="site-results">
              {results.map((r) => (
                <article className="site-result" key={r.domain}>
                  <span className="site-result-domain">{r.domain}</span>
                  <div className="site-result-meta">
                    <span className={`chip site-chip ${STATUS_CHIP_CLASS[r.status] ?? ""}`}>
                      {STATUS_LABELS[r.status] ?? r.status}
                    </span>
                    {typeof r.ms === "number" && (
                      <span className="site-ms">{r.ms} мс</span>
                    )}
                  </div>
                </article>
              ))}
            </div>
          </>
        )}

        {!running && results.length === 0 && (
          <p className="preset-empty">
            Ещё не проверялось — отметьте домены и запустите проверку.
          </p>
        )}
      </section>
    </div>
  );
}
