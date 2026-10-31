import { useEffect, useState } from "react";
import { fetchCheckSites, fetchCheckStatus, SiteCheckResult } from "../api";
import { IconClose, IconInfo, IconSearch } from "./Icons";
import { PageHeader } from "./PageHeader";

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

// Подписи и тона статусов из контракта /api/check/sites/status.
const STATUS_LABELS: Record<string, string> = {
  ok: "Доступен",
  blocked: "Заблокирован",
  slow: "Медленно",
};

const STATUS_TONE: Record<string, string> = {
  ok: "tone-ok",
  blocked: "tone-fail",
  slow: "tone-warn",
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

  const selectedCount = DEFAULT_DOMAINS.filter((domain) => checked[domain]).length;
  const okCount = results.filter((r) => r.status === "ok").length;
  const blockedCount = results.filter((r) => r.status === "blocked").length;
  const slowCount = results.filter((r) => r.status === "slow").length;

  return (
    <div className="page">
      <PageHeader
        index="03"
        group="Диагностика"
        title="Проверка"
        description="Доступность популярных сервисов: какие домены проходят, а какие блокируются."
        actions={
          <span className="chip tone-neutral">
            выбрано {selectedCount} из {DEFAULT_DOMAINS.length}
          </span>
        }
      />

      <div className="infobar hint with-icon">
        <IconInfo />
        <span>
          Сравните результаты с включённым и выключенным обходом — так видно,
          что именно меняет движок.
        </span>
      </div>
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
              <b>01</b> Домены
            </span>
            <h2 className="card-title">Что проверяем</h2>
            <p className="card-note">
              Отметьте сервисы — запрос уйдёт через локальную сеть и вернёт
              время ответа.
            </p>
          </div>
          <button
            type="button"
            className="btn ghost"
            onClick={() =>
              setChecked((prev) => {
                const allOn = DEFAULT_DOMAINS.every((domain) => prev[domain]);
                return Object.fromEntries(
                  DEFAULT_DOMAINS.map((domain) => [domain, !allOn]),
                );
              })
            }
            disabled={running}
          >
            {selectedCount === DEFAULT_DOMAINS.length ? "Снять все" : "Выбрать все"}
          </button>
        </div>

        <div className="site-checks">
          {DEFAULT_DOMAINS.map((domain) => (
            <label className="site-check" key={domain}>
              <input
                type="checkbox"
                checked={Boolean(checked[domain])}
                onChange={() => toggle(domain)}
                disabled={running}
              />
              <span className="mono">{domain}</span>
            </label>
          ))}
        </div>

        <div className="actions-row">
          <button
            type="button"
            className="btn accent"
            onClick={runCheck}
            disabled={running || selectedCount === 0}
          >
            {running ? <span className="spinner" /> : <IconSearch />}
            {running ? "Проверяю…" : "Проверить доступность"}
          </button>
          <span className="site-ms">
            {running
              ? "Опрос идёт раз в секунду — результаты появляются по мере готовности."
              : "Проверка занимает до двух минут."}
          </span>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>02</b> Результат
            </span>
            <h2 className="card-title">Доступность доменов</h2>
          </div>
          {results.length > 0 && (
            <span className="chip tone-neutral">готово {results.length}</span>
          )}
        </div>

        {results.length > 0 ? (
          <>
            <div className="metric-grid">
              <div className="metric">
                <span className="metric-value">{okCount}</span>
                <span className="metric-label">доступно</span>
              </div>
              <div className="metric">
                <span className="metric-value">{blockedCount}</span>
                <span className="metric-label">заблокировано</span>
              </div>
              <div className="metric">
                <span className="metric-value">{slowCount}</span>
                <span className="metric-label">медленно</span>
              </div>
            </div>

            <div className="site-results">
              {results.map((r) => (
                <article
                  className={`site-result is-${r.status}`}
                  key={r.domain}
                >
                  <span className="site-result-domain">{r.domain}</span>
                  <div className="site-result-meta">
                    <span
                      className={`chip site-chip ${
                        STATUS_TONE[r.status] ?? "tone-neutral"
                      }`}
                    >
                      {STATUS_LABELS[r.status] ?? r.status}
                    </span>
                  </div>
                  {typeof r.ms === "number" && (
                    <span className="site-ms">{r.ms} мс</span>
                  )}
                </article>
              ))}
            </div>
          </>
        ) : running ? (
          <div className="empty-state" role="status">
            <span className="spinner" />
            <strong>Проверяю домены</strong>
            <span>Результаты появятся здесь по мере готовности.</span>
          </div>
        ) : finished ? (
          <div className="empty-state">
            <strong>Проверка завершилась без ответов</strong>
            <span>Попробуйте выбрать другие домены и запустить ещё раз.</span>
          </div>
        ) : (
          <div className="empty-state">
            <strong>Ещё не проверялось</strong>
            <span>Отметьте домены выше и запустите проверку.</span>
          </div>
        )}
      </section>
    </div>
  );
}
