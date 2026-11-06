import { Notice } from "../ui/Notice";
import { TelegramHero } from "./TelegramHero";
import { TgSettings } from "./TgSettings";
import { TunnelSteps } from "./TunnelSteps";
import { useTgProxy } from "./useTgProxy";
import "../../styles/pages/telegram.css";

export function TelegramPage() {
  const model = useTgProxy();

  return (
    <div className="page">
      <div className="notices">
        {model.error && <Notice tone="error">{model.error}</Notice>}
        {model.notice && <Notice tone="ok">{model.notice}</Notice>}
      </div>

      <TelegramHero model={model} />

      <div className="layout layout--even">
        <TgSettings model={model} />
        <TunnelSteps model={model} />
      </div>
    </div>
  );
}
