import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";
import type { TgModel } from "./useTgProxy";

export function TunnelSteps({ model }: { model: TgModel }) {
  const address = `${model.status?.host ?? model.host}:${model.status?.port ?? model.port}`;
  const steps = [
    <>
      Telegram подключается к MTProto-прокси на <code>{address}</code> по ссылке с секретом.
    </>,
    <>
      Прокси расшифровывает поток и отправляет его в WebSocket к <code>kws.web.telegram.org</code>.
    </>,
    <>Если прямой путь закрыт — через воркер или CF-прокси, в крайнем случае напрямую по TCP.</>,
    <>Провайдер видит обычный HTTPS — блокировать нечего.</>,
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
      {model.status?.last_front && (
        <Notice tone="ok">Последний маршрут: {model.status.last_front}</Notice>
      )}
      {model.status?.last_error && <Notice tone="warn">Последняя ошибка: {model.status.last_error}</Notice>}
    </Panel>
  );
}
