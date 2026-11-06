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
        {model.status && !model.status.root && !model.running && (
          <Notice tone="hint">
            {model.isWindows
              ? "При включении Windows спросит права администратора — они нужны драйверу WinDivert."
              : "При включении система спросит пароль администратора (polkit)."}
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
