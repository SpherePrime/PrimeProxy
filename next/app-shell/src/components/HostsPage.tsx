import { useCallback, useEffect, useState } from "react";
import {
  applyHosts,
  fetchHostsFile,
  HostsFileResponse,
  HostsApplyResponse,
} from "../api";

// Сервисы страницы: домены 127.0.0.2-блока (как у семейства zapret —
// запись на зарезервированный локальный адрес уходит мимо DPI).
interface ServiceGroup {
  title: string;
  domains: string[];
}

const SERVICES: ServiceGroup[] = [
  { title: "YouTube", domains: ["youtube.com", "www.youtube.com", "ytimg.com", "googlevideo.com"] },
  { title: "Discord", domains: ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"] },
  { title: "ChatGPT", domains: ["chatgpt.com", "openai.com", "oaistatic.com"] },
  { title: "Instagram", domains: ["instagram.com", "cdninstagram.com"] },
  { title: "Facebook", domains: ["facebook.com", "fbcdn.net"] },
  { title: "Twitter/X", domains: ["x.com", "twitter.com", "twimg.com"] },
];

export function HostsPage() {
  const [file, setFile] = useState<HostsFileResponse | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [applied, setApplied] = useState<HostsApplyResponse | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await fetchHostsFile();
      setFile(data);
      setError(null);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const toggleDomain = (domain: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(domain)) next.delete(domain);
      else next.add(domain);
      return next;
    });
  };

  const apply = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const rows = Array.from(selected).map((domain): [string, string] => [domain, "127.0.0.2"]);
      const result = await applyHosts(rows, true);
      setApplied(result);
      setConfirmOpen(false);
      setNotice("Блок записан в hosts (бэкап .primebak создан).");
      await load();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      setConfirmOpen(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1>Разблокировка</h1>
        <p className="subtitle">
          Запись сервисов в файл hosts на зарезервированный адрес 127.0.0.2 —
          стандартный приём этого семейства программ (обход по подмене адреса).
        </p>
      </div>

      {error && <div className="infobar error">{error}</div>}
      {notice && <div className="infobar warn">{notice}</div>}

      <div className="card">
        <div className="card-head">
          <h2>Файл hosts</h2>
          {file && (
            <span className="chip">
              {file.blocked_count} записей в блоке PrimeProxy
            </span>
          )}
        </div>
        {file ? (
          <>
            <p className="plan-line">
              <code>{file.path}</code>
            </p>
            {file.error ? (
              <div className="infobar warn">{file.error}</div>
            ) : (
              <div className="stats-row">
                {file.managed_rows.slice(0, 24).map((row) => (
                  <span className="chip" key={row[0]}>
                    {row[0]} → {row[1]}
                  </span>
                ))}
                {file.managed_rows.length > 24 && (
                  <span className="preset-count">
                    … и ещё {file.managed_rows.length - 24}
                  </span>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="preset-empty">Загружаю…</div>
        )}
      </div>

      <div className="card">
        <h2>Сервисы</h2>
        {SERVICES.map((service) => (
          <div className="host-group" key={service.title}>
            <h3>{service.title}</h3>
            <div className="host-domains">
              {service.domains.map((domain) => (
                <label className="host-row" key={domain}>
                  <input
                    type="checkbox"
                    checked={selected.has(domain)}
                    onChange={() => toggleDomain(domain)}
                  />
                  <span>{domain}</span>
                </label>
              ))}
            </div>
          </div>
        ))}
        <div className="launch-row">
          <button
            className="btn accent"
            disabled={busy || selected.size === 0}
            onClick={() => setConfirmOpen(true)}
          >
            Применить в hosts ({selected.size})
          </button>
        </div>
        {confirmOpen && (
          <div className="infobar warn">
            Изменить hosts? Будет создан бэкап <code>.primebak</code>.
            <div className="launch-row" style={{ marginTop: 8 }}>
              <button className="btn accent" disabled={busy} onClick={() => void apply()}>
                {busy ? "Записываю…" : "Применить"}
              </button>
              <button className="btn ghost" onClick={() => setConfirmOpen(false)}>
                Отмена
              </button>
            </div>
          </div>
        )}
        {applied && (
          <div className="stats-row">
            {applied.managed_rows.map((row) => (
              <span className="chip chip-ok" key={row[0]}>
                {row[0]} → {row[1]}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
