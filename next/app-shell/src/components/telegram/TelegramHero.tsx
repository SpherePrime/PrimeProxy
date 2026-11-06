import { IconCopy, IconExternal } from "../Icons";
import { MetaGrid } from "../ui/MetaGrid";
import { PowerButton } from "../ui/PowerButton";
import { bytesLabel, TgModel } from "./useTgProxy";

export function TelegramHero({ model }: { model: TgModel }) {
  const status = model.status;
  const address = `${status?.host ?? model.host}:${status?.port ?? model.port}`;

  return (
    <section className={`hero ${model.running ? "is-on" : ""}`} aria-busy={model.busy}>
      <PowerButton
        on={model.running}
        busy={model.busy}
        label={model.busy ? "подождите" : model.running ? "отключить" : "подключить"}
        onClick={() => void (model.running ? model.disconnect() : model.connect())}
      />

      <div className="hero__state">
        <span className="eyebrow">Прокси Telegram · MTProto</span>
        <h1 className="hero__word" aria-live="polite">
          {model.running ? (
            <>
              Telegram <em>на связи</em>
            </>
          ) : (
            "Прокси выключен"
          )}
        </h1>
        <p className="hero__note">
          {model.running
            ? "Добавьте ссылку в Telegram — дальше он ходит через этот компьютер. Провайдер видит обычный HTTPS."
            : "Нажмите кнопку, затем добавьте ссылку в Telegram. Движок обхода для этого не нужен."}
        </p>
        <MetaGrid
          className="hero__meta"
          items={[
            { label: "Адрес", value: address },
            { label: "Фронт", value: status?.last_front || status?.front || "авто" },
            { label: "Соединения", value: `${status?.active ?? 0} / ${status?.connections ?? 0}` },
            {
              label: "Трафик",
              value: `↑ ${bytesLabel(status?.bytes_up ?? 0)} ↓ ${bytesLabel(status?.bytes_down ?? 0)}`,
            },
          ]}
        />
      </div>

      <div className="hero__side">
        <div className="tg-link">
          <span className="field__label">Ссылка для Telegram</span>
          <code className="codeline tg-link__code">{model.link}</code>
          <button
            type="button"
            className="btn btn--accent btn--block"
            onClick={() => void model.copy(model.link, "Ссылка")}
            disabled={!model.running}
          >
            <IconCopy size={16} />
            Скопировать
          </button>
          <a
            className="btn btn--outline btn--block"
            href={model.link}
            onClick={(event) => {
              event.preventDefault();
              window.location.href = model.link;
            }}
          >
            <IconExternal size={16} />
            Открыть в Telegram
          </a>
        </div>
      </div>
    </section>
  );
}
