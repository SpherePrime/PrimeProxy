import { IconChevronDown, IconCopy, IconServer } from "../Icons";
import { HelpTip } from "../HelpTip";
import { Panel } from "../ui/Panel";
import { DEFAULT_HOST, TgModel } from "./useTgProxy";

export function TgSettings({ model }: { model: TgModel }) {
  const locked = model.busy || model.running;

  return (
    <Panel
      title={
        <>
          Порт и фронт
          <HelpTip label="зачем свой домен">
            По умолчанию берутся встроенные фронты Cloudflare. Если они перестали
            отвечать, поднимите свой воркер: скопируйте код и DNS-записи, заведите
            домен в Cloudflare и впишите его сюда.
          </HelpTip>
        </>
      }
      note={model.running ? "Отключите прокси, чтобы поменять настройки." : "Применятся при следующем подключении."}
      meta={model.status?.configured ? <span className="chip">конфиг сохранён</span> : undefined}
    >
      <div className="tg-fields">
        <label className="field">
          <span className="field__label">Адрес</span>
          <input
            className="input input--mono"
            value={model.host}
            onChange={(event) => model.setHost(event.target.value)}
            disabled={locked}
            placeholder={DEFAULT_HOST}
          />
        </label>
        <label className="field">
          <span className="field__label">Порт</span>
          <input
            className="input input--mono"
            type="number"
            min={1}
            max={65535}
            value={model.port}
            onChange={(event) => model.setPort(event.target.value)}
            disabled={locked}
          />
        </label>
        <label className="field tg-fields__wide">
          <span className="field__label">Свой домен воркера</span>
          <input
            className="input input--mono"
            value={model.domain}
            onChange={(event) => model.setDomain(event.target.value)}
            disabled={locked}
            placeholder="необязательно: my-proxy.example.com"
          />
        </label>
      </div>

      <div className="panel__section">
        <div className="row row--center">
          <button type="button" className="btn btn--outline btn--sm" onClick={() => void model.loadWorker()}>
            <IconServer size={14} />
            Код воркера и DNS
          </button>
          {model.worker && (
            <>
              <button
                type="button"
                className="btn btn--ghost btn--sm"
                onClick={() => void model.copy(model.worker!.code, "Код воркера")}
              >
                <IconCopy size={14} />
                Код
              </button>
              <button
                type="button"
                className="btn btn--ghost btn--sm"
                onClick={() => void model.copy(model.worker!.dns, "DNS-записи")}
              >
                <IconCopy size={14} />
                DNS
              </button>
            </>
          )}
        </div>

        {model.worker && (
          <details className="details tg-worker">
            <summary>
              <IconChevronDown size={13} />
              Показать код воркера
            </summary>
            <div className="details__body">
              <pre className="term__body tg-code">{model.worker.code}</pre>
              <p className="hint">
                Путь WebSocket: <code>{model.worker.path}</code>
              </p>
            </div>
          </details>
        )}
      </div>
    </Panel>
  );
}
