import { IconCheck, IconChevronDown, IconRefresh } from "../Icons";
import { HelpTip } from "../HelpTip";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";
import { Stat } from "../ui/Stat";
import type { HostsModel } from "./useHosts";

export function ChangesPanel({ model }: { model: HostsModel }) {
  const file = model.file;

  return (
    <Panel
      className={model.dirty ? "changes is-dirty" : "changes"}
      title={
        <>
          Файл hosts
          <HelpTip label="что такое блок в hosts">
            Мы пишем в hosts только свой блок: домены сервисов указывают на
            127.0.0.2. Остальные строки не трогаем, перед первой записью рядом
            появляется копия .primebak.
          </HelpTip>
        </>
      }
      meta={
        <button
          type="button"
          className="btn btn--ghost btn--icon"
          onClick={() => void model.reload()}
          aria-label="Перечитать файл hosts"
          title="Перечитать файл"
        >
          <IconRefresh size={15} />
        </button>
      }
    >
      <code className="codeline changes__path">{file ? file.path : "читаю файл…"}</code>

      {file?.error && <Notice tone="warn">{file.error}</Notice>}

      <div className="stats changes__stats">
        <Stat value={model.current.size} label="в блоке" />
        <Stat value={`+${model.added.length}`} label="добавится" tone={model.added.length ? "ok" : undefined} />
        <Stat value={`−${model.removed.length}`} label="уйдёт" tone={model.removed.length ? "fail" : undefined} />
      </div>

      <p className="changes__summary">
        {!model.loaded
          ? "Сверяю выбор с текущим файлом…"
          : model.dirty
            ? `Итог: ${model.desired.size} строк в блоке (сейчас ${model.current.size}).`
            : "Файл уже совпадает с выбором — записывать нечего."}
      </p>

      {model.confirmOpen ? (
        <div className="confirm">
          <p>
            Перезаписать блок PrimeProxy в hosts ({model.desired.size} строк)? Будет создан бэкап{" "}
            <code>.primebak</code>.
          </p>
          <div className="row row--center">
            <button
              type="button"
              className="btn btn--accent"
              disabled={model.busy}
              onClick={() => void model.apply()}
            >
              {model.busy ? <span className="spinner" /> : <IconCheck size={16} />}
              {model.busy ? "Записываю…" : "Да, записать"}
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => model.setConfirmOpen(false)} disabled={model.busy}>
              Отмена
            </button>
          </div>
        </div>
      ) : (
        <div className="row row--center">
          <button
            type="button"
            className="btn btn--accent btn--lg changes__apply"
            disabled={model.busy || !model.loaded || !model.dirty}
            onClick={() => model.setConfirmOpen(true)}
          >
            <IconCheck size={16} />
            Применить в hosts
          </button>
          {model.dirty && (
            <button type="button" className="btn btn--ghost" onClick={model.reset} disabled={model.busy}>
              Сбросить
            </button>
          )}
        </div>
      )}

      {model.applied && model.applied.dropped.length > 0 && (
        <p className="hint">Снято конфликтующих строк: {model.applied.dropped.length}</p>
      )}

      {file && file.managed_rows.length > 0 && (
        <details className="details changes__rows">
          <summary>
            <IconChevronDown size={13} />
            Строки блока ({file.managed_rows.length})
          </summary>
          <div className="details__body">
            <pre className="term__body changes__list">
              {file.managed_rows.map((row) => `${row[1]}  ${row[0]}`).join("\n")}
            </pre>
          </div>
        </details>
      )}
    </Panel>
  );
}
