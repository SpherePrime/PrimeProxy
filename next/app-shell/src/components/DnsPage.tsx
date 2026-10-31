import { useEffect, useMemo, useState } from "react";
import {
  fetchProviders,
  fetchServerCheck,
  FILTERS,
  GROUP_ORDER,
  Providers,
  ServerCheckResponse,
} from "../api";
import { IconCheck, IconClose, IconWarning } from "./Icons";

// Каталог DNS-провайдеров — перенос python dns/ui/page.py на React.
// Это только справочная часть страницы «DNS»: фильтры по статусу и плитки
// провайдеров. Инструменты (текущие серверы, проба, установка) — выше,
// в DnsToolsPage.

// Статус провайдера: подпись и тон плитки.
const STATUS_LABEL: Record<string, string> = {
  blocked: "блокируется",
  at_risk: "в зоне риска",
};

export function DnsPage() {
  const [providers, setProviders] = useState<Providers>({});
  const [filter, setFilter] = useState<string>("all");
  const [error, setError] = useState<string>("");
  const [domain, setDomain] = useState("example.com");
  const [checking, setChecking] = useState(false);
  const [check, setCheck] = useState<ServerCheckResponse | null>(null);

  useEffect(() => {
    fetchProviders().then(setProviders).catch((e) => setError(String(e.message)));
  }, []);

  // Фильтр: «Блокируются» — плитки со статусом blocked, «В зоне риска» — at_risk.
  const visibleGroups = useMemo(() => {
    const result: Array<{ group: string; tiles: Array<[string, Providers[string][string]]> }> = [];
    for (const group of GROUP_ORDER) {
      const tiles = Object.entries(providers[group] || {}).filter(([, data]) => {
        if (filter === "all") return true;
        return data.status === filter;
      });
      if (tiles.length > 0) result.push({ group, tiles });
    }
    return result;
  }, [providers, filter]);

  const totalProviders = useMemo(
    () =>
      Object.values(providers).reduce(
        (sum, group) => sum + Object.keys(group).length,
        0,
      ),
    [providers],
  );

  const visibleCount = visibleGroups.reduce(
    (sum, group) => sum + group.tiles.length,
    0,
  );

  async function runCheck() {
    setChecking(true);
    setError("");
    try {
      setCheck(await fetchServerCheck(domain));
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setChecking(false);
    }
  }

  return (
    <>
      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>04</b> Каталог
            </span>
            <h2 className="card-title">DNS-провайдеры</h2>
            <p className="card-note">
              Статус в вашем регионе и поддержка DoH. Установка сервера — в
              карточке «Установить DNS» выше.
            </p>
          </div>
          <span className="chip tone-neutral">
            {visibleCount} из {totalProviders}
          </span>
        </div>

        {error && (
          <div className="infobar error with-icon" role="alert">
            <IconClose />
            <span>{error}</span>
          </div>
        )}

        <nav className="filter-bar" aria-label="Фильтр провайдеров">
          {FILTERS.map((item) => (
            <button
              key={item.key}
              type="button"
              className={filter === item.key ? "chip active" : "chip"}
              onClick={() => setFilter(item.key)}
              aria-pressed={filter === item.key}
            >
              {item.title}
            </button>
          ))}
        </nav>

        {totalProviders === 0 && !error ? (
          <div className="empty-state" role="status">
            <span className="spinner" />
            <span>Загружаю каталог провайдеров…</span>
          </div>
        ) : visibleGroups.length === 0 ? (
          <div className="empty-state">
            <strong>Под фильтр ничего не подходит</strong>
            <span>Выберите другой статус или покажите все серверы.</span>
          </div>
        ) : (
          <div className="provider-groups">
            {visibleGroups.map(({ group, tiles }) => (
              <section key={group} className="group">
                <h2>
                  {group} · {tiles.length}
                </h2>
                <div className="tiles">
                  {tiles.map(([name, data]) => (
                    <article
                      className={`tile ${data.status ? `is-${data.status}` : ""}`}
                      key={name}
                      title={data.desc || ""}
                    >
                      <div className="tile-head">
                        <span className="tile-icon" aria-hidden="true">
                          {name.slice(0, 1)}
                        </span>
                        <span className="tile-name">{name}</span>
                        {data.status && (
                          <span className={`badge ${data.status}`}>
                            {STATUS_LABEL[data.status] ?? data.status}
                          </span>
                        )}
                      </div>
                      <p className="tile-desc">{data.desc}</p>
                      {data.doh && (
                        <p className="tile-doh">
                          <IconCheck size={11} /> DoH
                        </p>
                      )}
                    </article>
                  ))}
                </div>
              </section>
            ))}
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>05</b> Сверка
            </span>
            <h2 className="card-title">Проверка DNS-серверов</h2>
            <p className="card-note">
              Один домен — все известные серверы: кто ответил и насколько быстро.
            </p>
          </div>
        </div>

        <div className="check-row">
          <input
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            placeholder="домен для пробы"
            aria-label="Домен для проверки DNS-серверов"
            spellCheck={false}
          />
          <button
            type="button"
            className="btn accent"
            onClick={runCheck}
            disabled={checking}
          >
            {checking ? <span className="spinner" /> : <IconCheck />}
            {checking ? "Проверяю…" : "Проверить серверы"}
          </button>
        </div>

        {check && (
          <>
            <div className={`verdict ${check.verdict.kind}`} role="status">
              <b className="verdict-icon">
                {check.verdict.kind === "ok" ? (
                  <IconCheck />
                ) : check.verdict.kind === "warn" ? (
                  <IconWarning />
                ) : (
                  <IconClose />
                )}
              </b>
              {check.verdict.detail}
            </div>
            <ul className="cards">
              {check.cards.map((card) => (
                <li key={card.server}>
                  <span className={`card-status ${card.status}`}>{card.status}</span>
                  <b className="mono">{card.server}</b>
                  {card.note && <span>— {card.note}</span>}
                  {card.best && <span className="best">({card.best})</span>}
                </li>
              ))}
            </ul>
            <pre className="report">{check.text}</pre>
          </>
        )}
      </section>
    </>
  );
}
