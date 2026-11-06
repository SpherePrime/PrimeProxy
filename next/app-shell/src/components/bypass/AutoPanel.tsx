import { IconBolt, IconSend } from "../Icons";
import { Segmented } from "../ui/Segmented";
import { Switch } from "../ui/Switch";
import type { BypassModel } from "./useBypass";

type LaunchKind = "auto" | "manual";

export function AutoPanel({ model }: { model: BypassModel }) {
  const locked = model.powerBusy;

  return (
    <div className="autopick">
      <Segmented<LaunchKind>
        label="Режим запуска"
        value={model.autoMode ? "auto" : "manual"}
        onChange={(value) => model.setAutoMode(value === "auto")}
        options={[
          { value: "auto", label: "Авто", disabled: locked },
          { value: "manual", label: "Вручную", disabled: locked },
        ]}
      />

      <p className="autopick__note">
        {model.autoMode
          ? "Кнопка сама проверит сервисы, включит нужные профили и запустит обход."
          : "Кнопка запускает режим и профили, выбранные ниже."}
      </p>

      <div className="autopick__option">
        <span className="autopick__option-text">
          <IconSend size={15} />
          <span>
            <b>Прокси Telegram</b>
            <small>{model.tgRunning ? "работает" : "поднимется вместе с обходом"}</small>
          </span>
        </span>
        <Switch
          on={model.withTelegram}
          label="Поднимать прокси Telegram вместе с обходом"
          onToggle={() => model.setWithTelegram(!model.withTelegram)}
          disabled={locked}
        />
      </div>

      {!model.autoMode && (
        <button
          type="button"
          className="btn btn--outline btn--block"
          onClick={() => void model.runAutoPick(false)}
          disabled={locked || model.offline}
        >
          {model.autoRunning ? <span className="spinner" /> : <IconBolt size={16} />}
          {model.autoRunning ? "Проверяю…" : "Подобрать профили сейчас"}
        </button>
      )}
    </div>
  );
}
