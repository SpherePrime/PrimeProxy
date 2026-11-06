import { useEffect, useRef } from "react";
import { IconTrash } from "../Icons";
import { Panel } from "../ui/Panel";
import type { BypassModel } from "./useBypass";

export function EngineLog({ model }: { model: BypassModel }) {
  const logRef = useRef<HTMLPreElement>(null);
  const stickRef = useRef(true);

  useEffect(() => {
    const el = logRef.current;
    if (el && stickRef.current) el.scrollTop = el.scrollHeight;
  }, [model.logLines]);

  const state = model.running ? "идёт запись" : model.offline ? "нет связи" : "ожидание";

  return (
    <Panel
      title="Журнал движка"
      meta={
        <>
          <span className="chip">{model.logLines.length} строк</span>
          <button
            type="button"
            className="btn btn--ghost btn--icon"
            onClick={model.clearLog}
            aria-label="Очистить вид журнала"
            title="Очистить вид"
          >
            <IconTrash size={15} />
          </button>
        </>
      }
    >
      <div className="term">
        <div className="term__bar">
          <span className="term__lights" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          {model.status?.engine ?? "engine"}
          <span className={`term__state ${model.running ? "tone-ok" : ""}`}>{state}</span>
        </div>
        <pre
          className="term__body engine-log"
          ref={logRef}
          onScroll={(event) => {
            const el = event.currentTarget;
            stickRef.current = el.scrollTop + el.clientHeight >= el.scrollHeight - 24;
          }}
        >
          {model.logLines.length > 0 ? model.logLines.join("\n") : "Журнал пуст — включите обход, чтобы увидеть вывод."}
        </pre>
      </div>
      {model.dropped !== null && <p className="hint">Пропущено старых строк: {model.dropped}</p>}
    </Panel>
  );
}
