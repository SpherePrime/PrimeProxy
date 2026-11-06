import { HelpTip } from "../HelpTip";
import { MetaGrid } from "../ui/MetaGrid";
import { PowerButton } from "../ui/PowerButton";
import { AutoPanel } from "./AutoPanel";
import type { BypassModel } from "./useBypass";

function stateCopy(model: BypassModel) {
  if (model.offline) {
    return { word: <>Нет связи</>, note: "Ядро не отвечает. Проверьте, запущен ли primecore-server." };
  }
  if (model.autoRunning) {
    return {
      word: <>Ищу блокировки…</>,
      note: `Проверяю сервисы напрямую: ${model.autoProgress.done} из ${model.autoProgress.total}. Потом всё включится само.`,
    };
  }
  if (model.powerBusy) {
    return {
      word: <>{model.stopping ? "Выключаю" : model.granting || model.awaitingGrant ? "Подтверждение" : "Запускаю"}…</>,
      note: "Пара секунд — собираю план запуска и поднимаю туннели.",
    };
  }
  if (model.running) {
    return {
      word: (
        <>
          Всё <em>работает</em>
        </>
      ),
      note: model.autoNote || "Трафик идёт через подобранные стратегии. Журнал справа обновляется сам.",
    };
  }
  if (model.tgRunning) {
    return {
      word: (
        <>
          Telegram <em>на связи</em>
        </>
      ),
      note: model.autoNote || "Прокси Telegram работает, движок обхода выключен.",
    };
  }
  return {
    word: <>Обход выключен</>,
    note: model.autoMode
      ? "Нажмите кнопку — программа сама найдёт, что заблокировано, и всё включит."
      : "Ручной режим: запустится то, что выбрано ниже.",
  };
}

export function BypassHero({ model }: { model: BypassModel }) {
  const copy = stateCopy(model);
  const profileLabel = model.running
    ? model.status?.preset || model.status?.names?.join(" · ") || "—"
    : model.effectiveMode === "all"
      ? model.universalChosen || "—"
      : `${model.activeProfileCount} профилей`;
  const rightsLabel = !model.rightsKnown ? "неизвестно" : model.rightsGranted ? "есть" : "нужен запрос";
  const rightsTone = !model.rightsKnown ? "tone-mute" : model.rightsGranted ? "tone-ok" : "tone-warn";
  const powerLabel = model.powerBusy ? "подождите" : model.active ? "выключить" : "включить всё";

  return (
    <section className={`hero ${model.active ? "is-on" : ""}`} aria-busy={model.powerBusy}>
      <PowerButton
        on={model.active}
        busy={model.powerBusy}
        disabled={model.offline}
        label={powerLabel}
        onClick={() => void (model.active ? model.powerOff() : model.powerOn())}
      />

      <div className="hero__state">
        <span className="eyebrow">
          {model.autoMode ? "Автоматический режим" : "Ручной режим"} · {model.status?.engine ?? "движок"}
          <HelpTip label="что делает кнопка">
            В автоматическом режиме кнопка проверяет сервисы, включает профили
            только для заблокированных, запускает движок и поднимает прокси
            Telegram. Повторное нажатие всё выключает.
          </HelpTip>
        </span>
        <h1 className="hero__word" aria-live="polite">
          {copy.word}
        </h1>
        <p className="hero__note">{copy.note}</p>
        {model.autoRunning && (
          <div className="progress hero__progress" aria-hidden="true">
            <span
              style={{
                width: `${model.autoProgress.total ? (model.autoProgress.done / model.autoProgress.total) * 100 : 0}%`,
              }}
            />
          </div>
        )}
        <MetaGrid
          className="hero__meta"
          items={[
            { label: "Профиль", value: profileLabel },
            { label: "Движок", value: model.running ? `PID ${model.status?.pid ?? "—"}` : "выключен", tone: model.running ? "tone-ok" : "tone-mute" },
            { label: "Telegram", value: model.tgRunning ? "прокси работает" : "выключен", tone: model.tgRunning ? "tone-ok" : "tone-mute" },
            { label: "Права", value: rightsLabel, tone: rightsTone },
          ]}
        />
      </div>

      <div className="hero__side">
        <AutoPanel model={model} />
      </div>
    </section>
  );
}
