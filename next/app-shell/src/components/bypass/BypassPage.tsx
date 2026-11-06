import { Notice } from "../ui/Notice";
import { BypassHero } from "./BypassHero";
import { EngineLog } from "./EngineLog";
import { LaunchPanel } from "./LaunchPanel";
import { ProfilesPanel } from "./ProfilesPanel";
import { useBypass } from "./useBypass";
import "../../styles/pages/bypass.css";

export function BypassPage() {
  const model = useBypass();

  return (
    <div className="page">
      <div className="notices">
        {model.error && <Notice tone="error">{model.error}</Notice>}
        {model.pollError && <Notice tone="error">Ядро не отвечает: {model.pollError}</Notice>}
        {model.status && !model.status.root && (
          <Notice tone="warn">
            {model.isWindows
              ? "Нет прав администратора: движку нужен доступ к WinDivert. Перезапустите приложение — оно само запросит права."
              : "Нет root-прав: при запуске понадобится подтверждение через polkit."}
          </Notice>
        )}
      </div>

      <BypassHero model={model} />

      <div className="layout">
        <div className="layout__main">
          <ProfilesPanel model={model} />
        </div>
        <aside className="layout__side layout__side--sticky">
          <EngineLog model={model} />
          <LaunchPanel model={model} />
        </aside>
      </div>
    </div>
  );
}
