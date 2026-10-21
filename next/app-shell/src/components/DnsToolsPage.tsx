import { useEffect, useState } from "react";
import {
  DnsCurrent,
  DnsQueryResult,
  DnsSetError,
  fetchDnsCurrent,
  queryDns,
  setDns,
} from "../api";
import { DnsPage } from "./DnsPage";

// Фиксированные серверы для пробы — всегда доступны в списке выбора
// наряду с системными из /api/dns/current.
const FALLBACK_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

// Страница «DNS»: инструменты поверх каталога провайдеров — текущие серверы,
// проба запроса и установка на интерфейс. Сам каталог (DnsPage) рендерится
// ниже без изменений.
export function DnsToolsPage() {
  return (
    <div className="page">
      <header className="page-header">
        <h1>DNS</h1>
        <p className="subtitle">
          Инструменты DNS и каталог провайдеров: текущие серверы, проба
          запроса, установка на интерфейс.
        </p>
      </header>

      <CurrentDnsCard />
      <DnsQueryCard />
      <DnsSetCard />

      <DnsPage />
    </div>
  );
}

// Карточка «Текущие DNS»: системные серверы чипами с подписью источника
// (kind) и отдельной строкой DoH-адреса.
function CurrentDnsCard() {
  const [current, setCurrent] = useState<DnsCurrent | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchDnsCurrent()
      .then(setCurrent)
      .catch((e) => setError(String((e as Error).message)));
  }, []);

  return (
    <section className="card">
      <h2>Текущие DNS</h2>
      {error && <div className="infobar error">✗ {error}</div>}
      {current && (
        <>
          {current.system.length > 0 ? (
            <div className="chip-row">
              {current.system.map((entry) => (
                <span className="chip static" key={entry.server}>
                  {entry.server}
                  <span className="chip-note">{entry.kind}</span>
                </span>
              ))}
            </div>
          ) : (
            <p className="preset-empty">Системные серверы не найдены.</p>
          )}
          <div className="chip-row">
            {current.doh.length > 0 ? (
              current.doh.map((url) => (
                <span className="chip static chip-ok" key={url}>
                  {url}
                </span>
              ))
            ) : (
              <span className="site-ms">DoH не используется</span>
            )}
          </div>
        </>
      )}
      {!current && !error && <p className="preset-empty">Загрузка…</p>}
    </section>
  );
}

// Карточка «Проверка DNS-сервера»: пробный запрос домена через выбранный
// сервер, результат — адреса и время ответа.
function DnsQueryCard() {
  const [domain, setDomain] = useState("example.com");
  const [servers, setServers] = useState<string[]>(FALLBACK_SERVERS);
  const [server, setServer] = useState(FALLBACK_SERVERS[0]);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<DnsQueryResult | null>(null);
  const [error, setError] = useState("");

  // Системные серверы подтягиваются из /api/dns/current и добавляются
  // к фиксированному списку (без дублей).
  useEffect(() => {
    let alive = true;
    fetchDnsCurrent()
      .then((data) => {
        if (!alive) return;
        const system = data.system.map((entry) => entry.server);
        setServers([...system, ...FALLBACK_SERVERS.filter((s) => !system.includes(s))]);
      })
      .catch(() => {
        // список системных серверов не критичен — останутся фиксированные
      });
    return () => {
      alive = false;
    };
  }, []);

  async function run() {
    const domainValue = domain.trim();
    if (!domainValue) {
      setError("Укажите домен для проверки");
      return;
    }
    setChecking(true);
    setError("");
    setResult(null);
    try {
      const answer = await queryDns(domainValue, server);
      setResult(answer);
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setChecking(false);
    }
  }

  return (
    <section className="card">
      <h2>Проверка DNS-сервера</h2>
      {error && <div className="infobar error">✗ {error}</div>}
      <div className="form-grid">
        <label className="field">
          <span className="field-label">Домен</span>
          <input
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            placeholder="example.com"
            disabled={checking}
          />
        </label>
        <label className="field">
          <span className="field-label">DNS-сервер</span>
          <select
            value={server}
            onChange={(event) => setServer(event.target.value)}
            disabled={checking}
          >
            {servers.map((item) => (
              <option value={item} key={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <button className="btn accent" onClick={run} disabled={checking}>
          {checking ? "Проверяю…" : "Проверить"}
        </button>
      </div>

      {result && !result.ok && (
        <div className="infobar error">✗ {result.error ?? "Запрос не удался"}</div>
      )}
      {result?.ok && (
        <div className="status-line">
          <span className="eyebrow">Ответ</span>
          <div className="chip-row">
            {(result.addresses ?? []).map((address) => (
              <span className="chip static" key={address}>
                {address}
              </span>
            ))}
          </div>
          {typeof result.ms === "number" && (
            <span className="site-ms">{result.ms} мс</span>
          )}
        </div>
      )}
    </section>
  );
}

// Карточка «Установить DNS»: два сервера на указанный интерфейс.
// 409 — нет прав (нужен polkit), 500 — ошибка применения.
function DnsSetCard() {
  const [ifname, setIfname] = useState("");
  const [server1, setServer1] = useState("");
  const [server2, setServer2] = useState("");
  const [saving, setSaving] = useState(false);
  const [done, setDone] = useState(false);
  const [noRights, setNoRights] = useState(false);
  const [error, setError] = useState("");

  async function apply() {
    const iface = ifname.trim();
    const servers = [server1.trim(), server2.trim()].filter(Boolean);
    if (!iface) {
      setError("Укажите имя интерфейса, например eth0");
      return;
    }
    if (servers.length === 0) {
      setError("Укажите хотя бы один DNS-сервер");
      return;
    }
    setSaving(true);
    setError("");
    setNoRights(false);
    setDone(false);
    try {
      await setDns(servers, iface);
      setDone(true);
    } catch (e) {
      if (e instanceof DnsSetError && e.status === 409) {
        setNoRights(true);
      } else {
        setError(String((e as Error).message));
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="card">
      <h2>Установить DNS</h2>
      {done && <div className="infobar ok">✓ DNS установлен</div>}
      {noRights && (
        <div className="infobar warn">
          Нет прав: на вкладке Обход нажми Разрешить
        </div>
      )}
      {error && <div className="infobar error">✗ {error}</div>}
      <div className="form-grid">
        <label className="field">
          <span className="field-label">Интерфейс</span>
          <input
            value={ifname}
            onChange={(event) => setIfname(event.target.value)}
            placeholder="eth0"
            disabled={saving}
          />
        </label>
        <label className="field">
          <span className="field-label">Сервер 1</span>
          <input
            value={server1}
            onChange={(event) => setServer1(event.target.value)}
            placeholder="1.1.1.1"
            disabled={saving}
          />
        </label>
        <label className="field">
          <span className="field-label">Сервер 2</span>
          <input
            value={server2}
            onChange={(event) => setServer2(event.target.value)}
            placeholder="8.8.8.8"
            disabled={saving}
          />
        </label>
        <button className="btn accent" onClick={apply} disabled={saving}>
          {saving ? "Применяю…" : "Установить"}
        </button>
      </div>
    </section>
  );
}
