import { useEffect, useMemo, useState } from "react";
import {
  fetchProviders,
  fetchServerCheck,
  FILTERS,
  GROUP_ORDER,
  Providers,
  ServerCheckResponse,
} from "../api";

// Страница «Настройка DNS» — перенос python dns/ui/page.py на React.
// Структура та же: строка состояния, сетка плиток провайдеров по группам,
// фильтры и панель проверки серверов. Windows-часть (адаптеры) появится,
// когда на Linux подключится платформенный слой.
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
    <div className="page">
      <header className="page-header">
        <h1>Настройка DNS</h1>
        <p className="subtitle">
          Выберите DNS-сервер — он сразу встанет на отмеченные сетевые адаптеры.
        </p>
      </header>

      {error && <div className="infobar error">{error}</div>}

      <section className="status-line">
        <span className="eyebrow">Сейчас на отмеченных адаптерах</span>
        <span className="status-chip">Автоматически (DHCP)</span>
      </section>

      <nav className="filter-bar">
        {FILTERS.map((item) => (
          <button
            key={item.key}
            className={filter === item.key ? "chip active" : "chip"}
            onClick={() => setFilter(item.key)}
          >
            {item.title}
          </button>
        ))}
      </nav>

      <main className="grid-area">
        {visibleGroups.map(({ group, tiles }) => (
          <section key={group} className="group">
            <h2>{group}</h2>
            <div className="tiles">
              {tiles.map(([name, data]) => (
                <article className="tile" key={name} title={data.desc || ""}>
                  <div className="tile-head">
                    <span className="tile-icon" style={{ background: data.color || "#334155" }}>
                      {name.slice(0, 1)}
                    </span>
                    <span className="tile-name">{name}</span>
                    {data.status && (
                      <span className={`badge ${data.status}`}>
                        {data.status === "blocked" ? "блокируется" : "в зоне риска"}
                      </span>
                    )}
                  </div>
                  <p className="tile-desc">{data.desc}</p>
                  {data.doh && <p className="tile-doh">DoH ✓</p>}
                </article>
              ))}
            </div>
          </section>
        ))}
      </main>

      <section className="check-panel">
        <h2>Проверка DNS-серверов</h2>
        <div className="check-row">
          <input
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            placeholder="домен для пробы"
          />
          <button onClick={runCheck} disabled={checking}>
            {checking ? "Проверяю…" : "Проверить серверы"}
          </button>
        </div>
        {check && (
          <>
            <div className={`verdict ${check.verdict.kind}`}>
              <b>{check.verdict.kind === "ok" ? "✅" : check.verdict.kind === "warn" ? "⚠" : "✗"}</b>{" "}
              {check.verdict.detail}
            </div>
            <ul className="cards">
              {check.cards.map((card) => (
                <li key={card.server}>
                  <span className={`card-status ${card.status}`}>{card.status}</span>
                  <b>{card.server}</b>
                  {card.note && <span> — {card.note}</span>}
                  {card.best && <span className="best"> ({card.best})</span>}
                </li>
              ))}
            </ul>
            <pre className="report">{check.text}</pre>
          </>
        )}
      </section>
    </div>
  );
}
