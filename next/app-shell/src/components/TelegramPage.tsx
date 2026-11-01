import { useCallback, useEffect, useState } from "react";
import {
  fetchTgProxy,
  fetchTgWorker,
  startTgProxy,
  stopTgProxy,
  TgProxyStatus,
  TgWorkerData,
} from "../api";
import {
  IconCheck,
  IconClose,
  IconCopy,
  IconExternal,
  IconPlay,
  IconPower,
  IconStop,
  IconWarning,
} from "./Icons";
import { HelpTip } from "./HelpTip";
import { PageHeader } from "./PageHeader";
import "../styles/telegram.css";

// Страница «Telegram» — живой локальный прокси.
//
// Принцип tg-ws-proxy: Telegram Desktop подключается к локальному SOCKS5,
// а поток уходит в WebSocket к фронту Cloudflare, который дотягивает его до
// дата-центра Telegram. Для провайдера это обычный HTTPS к чужому домену.

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 1353;
const POLL_MS = 2000;

/** Байты в человекочитаемый вид. */
function bytesLabel(value: number): string {
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} МБ`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} КБ`;
  return `${value} Б`;
}

export function TelegramPage() {
  const [status, setStatus] = useState<TgProxyStatus | null>(null);
  const [host, setHost] = useState(DEFAULT_HOST);
  const [port, setPort] = useState(String(DEFAULT_PORT));
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [worker, setWorker] = useState<TgWorkerData | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await fetchTgProxy();
      setStatus(data);
      setError("");
      return data;
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      return null;
    }
  }, []);

  // Первая загрузка: состояние и настройки из сохранённого конфига.
  useEffect(() => {
    let alive = true;
    void load().then((data) => {
      if (!alive || !data) return;
      if (data.host) setHost(data.host);
      if (data.port) setPort(String(data.port));
      if (data.front && data.front.includes(".")) setDomain(data.front);
    });
    return () => {
      alive = false;
    };
  }, [load]);

  // Пока страница открыта — обновляем счётчики соединений.
  useEffect(() => {
    const timer = window.setInterval(() => void load(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [load]);

  const running = status?.running ?? false;
  const link = status?.link ?? `tg://socks?server=${host}&port=${port}`;

  async function connect() {
    setBusy(true);
    setError("");
    setNotice("");
    const value = Math.floor(Number(port));
    if (!Number.isFinite(value) || value < 0 || value > 65535) {
      setError("Порт должен быть числом от 1 до 65535");
      setBusy(false);
      return;
    }
    try {
      await startTgProxy(host.trim() || DEFAULT_HOST, value, domain.trim());
      setNotice("Прокси поднят — добавьте ссылку в Telegram.");
      await load();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await stopTgProxy();
      setNotice("Прокси остановлен.");
      await load();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      setNotice(`${what} скопирован в буфер обмена.`);
      setError("");
    } catch (e) {
      setError(`Не удалось скопировать: ${String((e as Error).message)}`);
    }
  }

  async function loadWorker() {
    setError("");
    try {
      const data = await fetchTgWorker();
      setWorker(data);
      setNotice("Код воркера готов — скопируйте его в Cloudflare.");
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  }

  return (
    <div className="page">
      <PageHeader
        index="06"
        group="Сеть"
        title="Telegram"
        description="Локальный прокси: Telegram подключается к SOCKS5 на этом компьютере, а поток уходит в WebSocket к фронту Cloudflare — провайдер видит обычный HTTPS."
        actions={
          <span className={`chip ${running ? "tone-ok" : "tone-neutral"}`}>
            {running ? "подключено" : "отключено"}
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

      <section className="card engine-card" data-state={running ? "running" : "idle"}>
        <div className="engine-top">
          <span className="engine-label">
            <IconPower size={14} /> Прокси Telegram
          </span>
          <span className={`chip ${running ? "tone-ok" : "tone-neutral"}`}>
            <span className={`status-dot ${running ? "is-ok" : "is-idle"}`} />
            {running ? "работает" : "остановлен"}
          </span>
        </div>

        <div className="engine-body">
          <div className="engine-state">
            <h2 className="engine-state-word" aria-live="polite">
              {running ? "Подключено" : "Отключено"}
            </h2>
            <p className="engine-state-note">
              {running
                ? "Добавьте ссылку ниже в Telegram — дальше он ходит через этот компьютер."
                : "Нажмите «Подключить», затем добавьте ссылку в Telegram: одно нажатие — и трафик идёт через туннель."}
            </p>
          </div>
          <div className="engine-actions">
            <button
              type="button"
              className="btn accent lg"
              onClick={() => void connect()}
              disabled={busy || running}
            >
              {busy && !running ? <span className="spinner" /> : <IconPlay />}
              Подключить
            </button>
            <button
              type="button"
              className="btn danger lg"
              onClick={() => void disconnect()}
              disabled={busy || !running}
            >
              {busy && running ? <span className="spinner" /> : <IconStop />}
              Отключить
            </button>
          </div>
        </div>

        <dl className="engine-meta">
          <div>
            <dt>Адрес</dt>
            <dd>
              {status?.host ?? host}:{status?.port ?? port}
            </dd>
          </div>
          <div>
            <dt>Фронт</dt>
            <dd>{status?.last_front || status?.front || "не выбран"}</dd>
          </div>
          <div>
            <dt>Соединения</dt>
            <dd>
              {status?.active ?? 0} активных · {status?.connections ?? 0} всего
            </dd>
          </div>
          <div>
            <dt>Трафик</dt>
            <dd>
              ↑ {bytesLabel(status?.bytes_up ?? 0)} · ↓ {bytesLabel(status?.bytes_down ?? 0)}
            </dd>
          </div>
        </dl>

        <div className="signal" aria-hidden="true" />
      </section>

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>01</b> Подключение
            </span>
            <h2 className="card-title">
              Ссылка для Telegram{" "}
              <HelpTip label="как подключить Telegram">
                Скопируйте ссылку и откройте её на устройстве — Telegram
                предложит добавить прокси. Либо впишите адрес вручную:
                «Настройки → Продвинутые → Тип соединения → Прокси → SOCKS5».
              </HelpTip>
            </h2>
            <p className="card-note">
              Прокси работает, пока открыто это приложение: движок обхода для
              Telegram не нужен.
            </p>
          </div>
          <span className={`chip ${running ? "tone-accent" : "tone-neutral"}`}>
            {running ? "ссылка готова" : "сначала подключите"}
          </span>
        </div>

        <p className="plan-line">
          <span className="field-label">Ссылка</span>
          <code>{link}</code>
        </p>

        <div className="actions-row">
          <button
            type="button"
            className="btn accent"
            onClick={() => void copy(link, "Ссылка")}
            disabled={!running}
          >
            <IconCopy />
            Скопировать ссылку
          </button>
          <a
            className="btn secondary"
            href={link}
            onClick={(event) => {
              // В Electron переход по tg:// может быть заблокирован —
              // тогда остаётся скопированная ссылка.
              event.preventDefault();
              window.location.href = link;
            }}
          >
            <IconExternal />
            Открыть в Telegram
          </a>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>02</b> Настройки
            </span>
            <h2 className="card-title">
              Порт и фронт{" "}
              <HelpTip label="зачем свой домен">
                По умолчанию берутся встроенные фронты Cloudflare. Если они
                перестали отвечать, поднимите свой воркер: скопируйте код и
                DNS-записи, заведите домен в Cloudflare и впишите его сюда.
              </HelpTip>
            </h2>
            <p className="card-note">
              Меняются только при следующем подключении — текущий туннель они
              не трогают.
            </p>
          </div>
          {status?.configured && (
            <span className="chip tone-neutral">конфиг сохранён</span>
          )}
        </div>

        <div className="launch-row">
          <label className="field">
            <span className="field-label">Адрес</span>
            <input
              value={host}
              onChange={(event) => setHost(event.target.value)}
              disabled={busy || running}
              placeholder={DEFAULT_HOST}
            />
          </label>
          <label className="field">
            <span className="field-label">Порт</span>
            <input
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(event) => setPort(event.target.value)}
              disabled={busy || running}
            />
          </label>
          <label className="field grow">
            <span className="field-label">Свой домен воркера (необязательно)</span>
            <input
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              disabled={busy || running}
              placeholder="например, my-proxy.example.com"
            />
          </label>
        </div>

        <div className="actions-row">
          <button type="button" className="btn ghost" onClick={() => void loadWorker()}>
            Код воркера и DNS
          </button>
          {worker && (
            <>
              <button
                type="button"
                className="btn ghost"
                onClick={() => void copy(worker.code, "Код воркера")}
              >
                <IconCopy />
                Скопировать код
              </button>
              <button
                type="button"
                className="btn ghost"
                onClick={() => void copy(worker.dns, "DNS-записи")}
              >
                <IconCopy />
                Скопировать DNS
              </button>
            </>
          )}
        </div>

        {worker && (
          <details className="tg-details">
            <summary>Показать код воркера</summary>
            <pre className="log-view tg-code">{worker.code}</pre>
            <p className="card-note">
              Путь WebSocket: <code>{worker.path}</code> — воркер отвечает на
              него и туннелирует поток к дата-центру Telegram.
            </p>
          </details>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>03</b> Как это работает
            </span>
            <h2 className="card-title">Схема туннеля</h2>
          </div>
        </div>
        <ol className="tg-steps">
          <li>
            Telegram Desktop подключается к локальному SOCKS5 на{" "}
            <code>
              {status?.host ?? host}:{status?.port ?? port}
            </code>
            .
          </li>
          <li>
            Каждое соединение к дата-центру Telegram уходит в WebSocket
            (wss://) к фронту Cloudflare по пути <code>/apiws</code>.
          </li>
          <li>
            Воркер фронта дотягивает поток до адреса дата-центра и обратно —
            трафик идёт как обычный HTTPS к чужому домену.
          </li>
          <li>
            Для провайдера это не MTProto: блокировать нечего, а сам Telegram
            видит обычный прокси.
          </li>
        </ol>
        {status?.last_error && (
          <div className="infobar warn with-icon">
            <IconWarning />
            <span>Последняя ошибка туннеля: {status.last_error}</span>
          </div>
        )}
      </section>
    </div>
  );
}
