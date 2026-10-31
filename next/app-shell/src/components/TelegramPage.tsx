import { useEffect, useState } from "react";
import { fetchTgProxy, saveTgProxy, TgProxyConfig } from "../api";
import {
  IconCheck,
  IconClose,
  IconCopy,
  IconSend,
  IconWarning,
} from "./Icons";
import { PageHeader } from "./PageHeader";

// Страница «Telegram» — конфиг MTProto-прокси и готовая ссылка подключения
// tg://proxy. Пока заготовка: эндпоинт /api/tg/proxy/start сохраняет конфиг,
// реальный запуск прокси появится позже.
export function TelegramPage() {
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [secret, setSecret] = useState("");
  const [config, setConfig] = useState<TgProxyConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [okNote, setOkNote] = useState("");
  const [copied, setCopied] = useState(false);

  // Текущий конфиг: если прокси уже настроен — подставляем значения в поля.
  useEffect(() => {
    fetchTgProxy()
      .then((data) => {
        setConfig(data);
        if (data.configured && data.host) {
          setHost(data.host);
          if (data.port) setPort(String(data.port));
        }
      })
      .catch((e) => setError(String(e.message)));
  }, []);

  // Конфиг считается сохранённым, если сервер вернул configured
  // либо сохранение в этой сессии прошло успешно.
  const saved = Boolean(config?.configured) || okNote !== "";
  const linkReady = saved && host.trim() && port.trim() && secret.trim();
  const proxyLink = linkReady
    ? `tg://proxy?server=${encodeURIComponent(host.trim())}&port=${port.trim()}&secret=${encodeURIComponent(secret.trim())}`
    : "";

  async function save() {
    const hostValue = host.trim();
    const portValue = Math.floor(Number(port));
    const secretValue = secret.trim();
    if (!hostValue) {
      setError("Укажите host прокси");
      return;
    }
    if (!Number.isFinite(portValue) || portValue <= 0 || portValue > 65535) {
      setError("Порт должен быть числом от 1 до 65535");
      return;
    }
    if (!secretValue) {
      setError("Укажите secret прокси");
      return;
    }
    setSaving(true);
    setError("");
    setOkNote("");
    try {
      const result = await saveTgProxy(hostValue, portValue, secretValue);
      setOkNote(result.note ? `Конфиг сохранён: ${result.note}` : "Конфиг сохранён");
      // Обновим карточку текущего состояния — best effort.
      fetchTgProxy()
        .then(setConfig)
        .catch(() => {
          // статус конфига не критичен
        });
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setSaving(false);
    }
  }

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(proxyLink);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Не удалось скопировать — выделите ссылку вручную");
    }
  }

  return (
    <div className="page">
      <PageHeader
        index="06"
        group="Сеть"
        title="Telegram"
        description="MTProto-прокси для Telegram: конфигурация и готовая ссылка подключения."
        actions={
          <span className={`chip ${saved ? "tone-ok" : "tone-neutral"}`}>
            {saved ? "конфиг сохранён" : "не настроен"}
          </span>
        }
      />

      <div className="infobar warn with-icon">
        <IconWarning />
        <span>
          Заготовка: запуск локального прокси появится позже, конфиг уже можно
          сохранить.
        </span>
      </div>
      {error && (
        <div className="infobar error with-icon" role="alert">
          <IconClose />
          <span>{error}</span>
        </div>
      )}
      {okNote && (
        <div className="infobar ok with-icon" role="status">
          <IconCheck />
          <span>{okNote}</span>
        </div>
      )}

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>01</b> Конфигурация
            </span>
            <h2 className="card-title">MTProto-прокси</h2>
            <p className="card-note">
              Параметры сервера, к которому Telegram будет подключаться.
            </p>
          </div>
        </div>

        {config && (
          <div className="status-line config-line">
            <span className="eyebrow">Текущий конфиг</span>
            <span className={`status-chip ${config.configured ? "chip-run" : ""}`}>
              {config.configured ? "Настроен" : "Не настроен"}
            </span>
            {config.configured && config.host && (
              <span className="status-chip">
                {config.host}
                {config.port ? `:${config.port}` : ""}
              </span>
            )}
          </div>
        )}

        <div className="form-grid">
          <label className="field grow">
            <span className="field-label">Host</span>
            <input
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="например, proxy.example.com"
              disabled={saving}
              spellCheck={false}
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
              placeholder="443"
              disabled={saving}
            />
          </label>
          <label className="field grow">
            <span className="field-label">Secret</span>
            <input
              type="password"
              value={secret}
              onChange={(event) => setSecret(event.target.value)}
              placeholder="hex-строка или ee…"
              disabled={saving}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <button
            type="button"
            className="btn accent"
            onClick={save}
            disabled={saving}
          >
            {saving ? <span className="spinner" /> : <IconCheck />}
            {saving ? "Сохраняю…" : "Сохранить конфиг"}
          </button>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>02</b> Подключение
            </span>
            <h2 className="card-title">Ссылка для Telegram</h2>
            <p className="card-note">
              Откройте ссылку на устройстве — Telegram предложит добавить прокси.
            </p>
          </div>
        </div>

        {!saved ? (
          <div className="empty-state">
            <IconSend />
            <strong>Сначала сохраните конфиг</strong>
            <span>Ссылка появится после сохранения host, порта и secret.</span>
          </div>
        ) : !linkReady ? (
          <div className="empty-state">
            <strong>Не хватает secret</strong>
            <span>
              Конфиг сохранён, но secret не известен странице — заполните поле
              Secret выше.
            </span>
          </div>
        ) : (
          <div className="code-row">
            <code>{proxyLink}</code>
            <button type="button" className="btn secondary" onClick={copyLink}>
              {copied ? <IconCheck /> : <IconCopy />}
              {copied ? "Скопировано" : "Скопировать"}
            </button>
          </div>
        )}
      </section>
    </div>
  );
}
