import type { EngineSnapshot } from "../../hooks/useEngineStatus";

interface EngineIndicatorProps {
  engine: EngineSnapshot;
  onOpen: () => void;
}

export function EngineIndicator({ engine, onOpen }: EngineIndicatorProps) {
  const engineOn = Boolean(engine.status?.running);
  const running = engineOn || engine.tgRunning;
  const offline = engine.link === "offline";
  const checking = engine.link === "checking";
  const label = offline
    ? "Ядро недоступно"
    : checking
      ? "Подключаюсь к ядру"
      : engineOn && engine.tgRunning
        ? "Обход и Telegram включены"
        : engineOn
          ? "Обход включён"
          : engine.tgRunning
            ? "Telegram на связи"
            : "Всё выключено";
  const dotClass = offline ? "dot--fail" : checking ? "dot--warn" : running ? "" : "dot--ok";

  return (
    <button
      type="button"
      className={`indicator ${running ? "is-on" : ""} ${offline ? "is-off-core" : ""}`}
      onClick={onOpen}
      title={offline ? "primecore-server не отвечает" : "Открыть управление обходом"}
    >
      <span className={`dot ${dotClass}`} aria-hidden="true" />
      <span className="indicator__label">{label}</span>
    </button>
  );
}
