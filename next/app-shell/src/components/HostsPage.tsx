import { useCallback, useEffect, useState } from "react";
import {
  applyHosts,
  fetchHostsFile,
  HostsFileResponse,
  HostsApplyResponse,
} from "../api";
import { IconCheck, IconClose, IconRefresh, IconWarning } from "./Icons";
import { PageHeader } from "./PageHeader";

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

const BLOCK_ADDRESS = "127.0.0.2";

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
      const rows = Array.from(selected).map((domain): [string, string] => [domain, BLOCK_ADDRESS]);
      const result = await applyHosts(rows, true);
      setApplied(result);
      setConfirmOpen(false);
      setNotice("Блок записан в hosts — бэкап .primebak создан.");
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
      <PageHeader
        index="02"
        group="Управление"
        title="Разблокировка"
        description="Запись сервисов в файл hosts на зарезервированный адрес 127.0.0.2 — обход по подмене адреса."
        actions={
          <span className="chip tone-neutral">
            выбрано {selected.size} доменов
          </span>
        }
      />

      {error && (
        <div className="infobar error with-icon" role="alert">
          <IconClose />
          <span>{error}</span>
        </div>
      )}
      {notice && (
        <div className="infobar ok with-icon" role="status">
          <IconCheck />
          <span>{notice}</span>
        </div>
      )}

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>01</b> Система
            </span>
            <h2 className="card-title">Файл hosts</h2>
            <p className="card-note">
              Управляемый блок PrimeProxy: строки вне его не изменяются.
            </p>
          </div>
          <div className="page-actions">
            {file && (
              <span className="chip tone-accent">
                {file.blocked_count} записей в блоке
              </span>
            )}
            <button
              type="button"
              className="btn ghost icon"
              onClick={() => void load()}
              aria-label="Перечитать файл hosts"
              title="Перечитать файл hosts"
            >
              <IconRefresh />
            </button>
          </div>
        </div>

        {file ? (
          <>
            <p className="plan-line">
              <span className="field-label">Путь</span>
              <code>{file.path}</code>
            </p>

            {file.error ? (
              <div className="infobar warn with-icon">
                <IconWarning />
                <span>{file.error}</span>
              </div>
            ) : file.managed_rows.length > 0 ? (
              <div className="kv-list" aria-label="Записи PrimeProxy в hosts">
                {file.managed_rows.map((row) => (
                  <div className="kv-row" key={row[0]}>
                    <span className="kv-key">{row[0]}</span>
                    <span className="kv-arrow" aria-hidden="true">
                      →
                    </span>
                    <span className="kv-value">{row[1]}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <strong>Блок пуст</strong>
                <span>В hosts пока нет записей PrimeProxy.</span>
              </div>
            )}
          </>
        ) : (
          <div className="empty-state" role="status">
            <span className="spinner" />
            <span>Читаю файл hosts…</span>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>02</b> Сервисы
            </span>
            <h2 className="card-title">Что разблокировать</h2>
            <p className="card-note">
              Отмеченные домены будут направлены на {BLOCK_ADDRESS} — трафик
              пойдёт мимо DPI.
            </p>
          </div>
          <span className="chip tone-neutral">{selected.size} отмечено</span>
        </div>

        {SERVICES.map((service) => {
          const allOn = service.domains.every((domain) => selected.has(domain));
          return (
            <div className="host-group" key={service.title}>
              <h3>
                {service.title}
                <span>{service.domains.length} доменов</span>
                <button
                  type="button"
                  className="btn ghost sm"
                  aria-label={
                    allOn
                      ? `Снять все домены ${service.title}`
                      : `Выбрать все домены ${service.title}`
                  }
                  onClick={() =>
                    setSelected((prev) => {
                      const next = new Set(prev);
                      for (const domain of service.domains) {
                        if (allOn) next.delete(domain);
                        else next.add(domain);
                      }
                      return next;
                    })
                  }
                >
                  {allOn ? "Снять" : "Выбрать"}
                </button>
              </h3>
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
          );
        })}

        <div className="launch-row">
          <button
            type="button"
            className="btn accent"
            disabled={busy || selected.size === 0}
            onClick={() => setConfirmOpen(true)}
          >
            {busy ? <span className="spinner" /> : <IconCheck />}
            Применить в hosts ({selected.size})
          </button>
          {selected.size > 0 && (
            <button
              type="button"
              className="btn ghost"
              onClick={() => setSelected(new Set())}
              disabled={busy}
            >
              Сбросить выбор
            </button>
          )}
        </div>

        {confirmOpen && (
          <div className="infobar warn with-icon">
            <IconWarning />
            <span>
              Изменить hosts? Будет создан бэкап <code>.primebak</code>, старые
              записи PrimeProxy заменятся.
            </span>
            <div className="actions-row">
              <button
                type="button"
                className="btn accent"
                disabled={busy}
                onClick={() => void apply()}
              >
                {busy ? <span className="spinner" /> : <IconCheck />}
                {busy ? "Записываю…" : "Применить"}
              </button>
              <button
                type="button"
                className="btn ghost"
                onClick={() => setConfirmOpen(false)}
                disabled={busy}
              >
                Отмена
              </button>
            </div>
          </div>
        )}

        {applied && applied.managed_rows.length > 0 && (
          <div className="stats-row" aria-label="Записанные строки">
            {applied.managed_rows.map((row) => (
              <span className="chip tone-ok" key={row[0]}>
                {row[0]} → {row[1]}
              </span>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
