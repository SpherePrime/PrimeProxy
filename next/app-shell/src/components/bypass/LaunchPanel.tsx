import { HostlistMode } from "../../api";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";
import type { BypassModel } from "./useBypass";

const HOSTLIST_MODES: Array<{ key: HostlistMode; title: string }> = [
  { key: "none", title: "Без списков" },
  { key: "hostlist", title: "По спискам" },
  { key: "autohostlist", title: "Автосписок" },
];

export function LaunchPanel({ model }: { model: BypassModel }) {
  return (
    <Panel
      title="Параметры запуска"
      note="Применяются к следующему запуску."
      meta={model.detail ? <span className="chip chip--accent">план готов</span> : undefined}
    >
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

      <div className="row">
        <label className="field field--grow">
          <span className="field__label">Списки доменов</span>
          <select
            className="select"
            value={model.mode}
            onChange={(event) => model.setMode(event.target.value as HostlistMode)}
            disabled={model.busy}
          >
            {HOSTLIST_MODES.map((item) => (
              <option key={item.key} value={item.key}>
                {item.title}
              </option>
            ))}
          </select>
        </label>
        {model.platformKnown && !model.isWindows && (
          <label className="field">
            <span className="field__label">qnum</span>
            <input
              className="input input--mono"
              type="number"
              min={1}
              max={65535}
              value={model.qnum}
              onChange={(event) => model.setQnum(event.target.value)}
              disabled={model.busy}
              style={{ width: 110 }}
            />
          </label>
        )}
      </div>
      <p className="hint">
        {model.isWindows ? "WinDivert фильтрует трафик автоматически." : "NFQUEUE использует указанный номер очереди."}
      </p>

      {model.detail && (
        <div className="plan">
          <span className="field__label">Команда · {model.detailName}</span>
          <code className="codeline">
            {model.detail.plan.exe} {model.detail.plan.args.join(" ")}
          </code>
        </div>
      )}
    </Panel>
  );
}
