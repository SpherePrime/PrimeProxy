import { HostlistMode } from "../../api";
import { Dropdown, DropdownOption } from "../ui/Dropdown";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";
import type { BypassModel } from "./useBypass";

const HOSTLIST_MODES: DropdownOption<HostlistMode>[] = [
  { value: "none", label: "Без списков", hint: "Стратегии применяются ко всему подходящему трафику" },
  { value: "hostlist", label: "По спискам", hint: "Только домены из готовых списков сервисов" },
  { value: "autohostlist", label: "Автосписок", hint: "Движок сам добавляет домены, которые блокируются" },
];

export function LaunchPanel({ model }: { model: BypassModel }) {
  return (
    <Panel title="Параметры запуска" note="Применяются к следующему запуску.">
      {model.needsPrompt && (
        <Notice
          tone="warn"
          actions={
            model.platformKnown && !model.isWindows ? (
              <button
                type="button"
                className="btn btn--accent btn--sm"
                onClick={() => void model.runGrant()}
                disabled={model.granting}
              >
                {model.granting ? "Жду…" : "Разрешить"}
              </button>
            ) : undefined
          }
        >
          {model.isWindows
            ? "Нужны права администратора: перезапустите приложение — оно само их запросит."
            : "Нужны права администратора. Пароль спросят один раз."}
        </Notice>
      )}

      <div className="launch-fields">
        <div className="field field--grow">
          <span className="field__label">Списки доменов</span>
          <Dropdown<HostlistMode>
            label="Списки доменов"
            value={model.mode}
            options={HOSTLIST_MODES}
            onChange={model.setMode}
            disabled={model.busy}
          />
        </div>
        {model.platformKnown && !model.isWindows && (
          <label className="field">
            <span className="field__label">qnum</span>
            <input
              className="input input--mono launch-fields__qnum"
              type="number"
              min={1}
              max={65535}
              value={model.qnum}
              onChange={(event) => model.setQnum(event.target.value)}
              disabled={model.busy}
            />
          </label>
        )}
      </div>
      <p className="hint">
        {model.isWindows ? "WinDivert фильтрует трафик автоматически." : "NFQUEUE использует указанный номер очереди."}
      </p>
    </Panel>
  );
}
