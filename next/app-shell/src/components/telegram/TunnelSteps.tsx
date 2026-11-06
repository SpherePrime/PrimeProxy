import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";
import type { TgModel } from "./useTgProxy";

export function TunnelSteps({ model }: { model: TgModel }) {
  const address = `${model.status?.host ?? model.host}:${model.status?.port ?? model.port}`;
  const steps = [
    <>
      Telegram подключается к локальному SOCKS5 на <code>{address}</code>.
    </>,
    <>
      Каждое соединение уходит в WebSocket к фронту Cloudflare по пути <code>/apiws</code>.
    </>,
    <>Воркер фронта дотягивает поток до дата-центра Telegram и обратно.</>,
    <>Провайдер видит обычный HTTPS к чужому домену — блокировать нечего.</>,
  ];

  return (
    <Panel title="Как это работает">
      <ol className="steps">
        {steps.map((step, index) => (
          <li className="step" key={index}>
            <span className="step__num">{String(index + 1).padStart(2, "0")}</span>
            <span className="step__text">{step}</span>
          </li>
        ))}
      </ol>
      {model.status?.last_error && <Notice tone="warn">Последняя ошибка туннеля: {model.status.last_error}</Notice>}
    </Panel>
  );
}
