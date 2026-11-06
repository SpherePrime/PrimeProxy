import { filesBridge } from "../../electronBridge";
import { IconCheck, IconExternal, IconRefresh } from "../Icons";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";
import { Stat } from "../ui/Stat";
import type { HostsModel } from "./useHosts";

export function ChangesPanel({ model }: { model: HostsModel }) {
  const file = model.file;
  const files = filesBridge();

  return (
    <Panel
      className={model.dirty ? "changes is-dirty" : "changes"}
      title="Изменения"
      meta={
        <>
          {files && file && (
            <button
              type="button"
              className="btn btn--ghost btn--icon"
              onClick={() => void files.open(file.path)}
              aria-label="Открыть файл hosts"
              title="Открыть файл hosts"
            >
              <IconExternal size={15} />
            </button>
          )}
          <button
            type="button"
            className="btn btn--ghost btn--icon"
            onClick={() => void model.reload()}
            aria-label="Перечитать файл hosts"
            title="Перечитать"
          >
            <IconRefresh size={15} />
          </button>
        </>
      }
    >
      {file?.error && <Notice tone="warn">{file.error}</Notice>}

      <div className="stats changes__stats">
        <Stat value={model.unlockedCount} label="работает" tone={model.unlockedCount ? "accent" : undefined} />
        <Stat value={`+${model.added.length}`} label="добавится" tone={model.added.length ? "ok" : undefined} />
        <Stat value={`−${model.removed.length}`} label="уберётся" tone={model.removed.length ? "fail" : undefined} />
      </div>

      <p className="changes__summary">
        {!model.loaded
          ? "Читаю текущее состояние…"
          : model.dirty
            ? "Выбор изменился — примените, чтобы сервисы заработали."
            : "Всё применено, изменений нет."}
      </p>

      {model.confirmOpen ? (
        <div className="confirm">
          <p>Записать изменения? Прежнее состояние сохранится в резервной копии.</p>
          <div className="row row--center">
            <button type="button" className="btn btn--accent" disabled={model.busy} onClick={() => void model.apply()}>
              {model.busy ? <span className="spinner" /> : <IconCheck size={16} />}
              {model.busy ? "Записываю…" : "Да, применить"}
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
            Применить
          </button>
          {model.dirty && (
            <button type="button" className="btn btn--ghost" onClick={model.reset} disabled={model.busy}>
              Сбросить
            </button>
          )}
        </div>
      )}
    </Panel>
  );
}
