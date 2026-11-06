import { MetaGrid } from "../ui/MetaGrid";
import { PowerButton } from "../ui/PowerButton";
import type { BypassModel } from "./useBypass";

function targetSummary(model: BypassModel): string {
  if (model.effectiveMode === "all") return "все сайты";
  const count = model.enabledTargets.length;
  if (count === 0) return "ничего не выбрано";
  if (count <= 3) return model.enabledTargets.join(", ");
  return `${model.enabledTargets.slice(0, 2).join(", ")} и ещё ${count - 2}`;
}

function stateCopy(model: BypassModel) {
  if (model.offline) {
    return { word: <>Нет связи</>, note: "Ядро не отвечает. Проверьте, запущен ли primecore-server." };
  }
  if (model.elevating) {
    return {
      word: <>Подтвердите права…</>,
      note: "Windows спрашивает разрешение. После «Да» приложение перезапустится и сразу включит обход.",
    };
  }
  if (model.busy) {
    return {
      word: <>{model.stopping ? "Выключаю" : model.granting || model.awaitingGrant ? "Подтверждение" : "Запускаю"}…</>,
      note: "Пара секунд — собираю план запуска.",
    };
  }
  if (model.running) {
    return {
      word: (
        <>
          Обход <em>включён</em>
        </>
      ),
      note: `Работает: ${targetSummary(model)}.`,
    };
  }
  return {
    word: <>Обход выключен</>,
    note:
      model.effectiveMode === "all"
        ? "Нажмите кнопку — обход включится для всех заблокированных сайтов."
        : `Нажмите кнопку — обход включится только для выбранного: ${targetSummary(model)}.`,
  };
}

export function BypassHero({ model }: { model: BypassModel }) {
  const copy = stateCopy(model);
  const rightsLabel = !model.rightsKnown ? "неизвестно" : model.rightsGranted ? "есть" : "нужен запрос";
  const rightsTone = !model.rightsKnown ? "tone-mute" : model.rightsGranted ? "tone-ok" : "tone-warn";

  return (
    <section className={`hero hero--compact ${model.running ? "is-on" : ""}`} aria-busy={model.busy}>
      <PowerButton
        on={model.running}
        busy={model.busy}
        disabled={model.offline}
        label={model.busy ? "подождите" : model.running ? "выключить" : "включить"}
        onClick={() => void (model.running ? model.stop() : model.start())}
      />

      <div className="hero__state">
        <span className="eyebrow">Движок {model.status?.engine ?? "обхода"}</span>
        <h1 className="hero__word" aria-live="polite">
          {copy.word}
        </h1>
        <p className="hero__note">{copy.note}</p>
        <MetaGrid
          className="hero__meta"
          items={[
            { label: "Режим", value: model.effectiveMode === "all" ? "все сайты" : "точечно" },
            {
              label: "Сервисы",
              value: model.effectiveMode === "all" ? "все" : `${model.enabledTargets.length} выбрано`,
            },
            {
              label: "Движок",
              value: model.running ? `PID ${model.status?.pid ?? "—"}` : "выключен",
              tone: model.running ? "tone-ok" : "tone-mute",
            },
            { label: "Права", value: rightsLabel, tone: rightsTone },
          ]}
        />
      </div>
    </section>
  );
}
