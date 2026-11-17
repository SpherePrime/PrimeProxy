import { IconBolt, IconShieldCheck } from "../Icons";
import { EmptyState } from "../ui/EmptyState";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";
import { SearchBox } from "../ui/SearchBox";
import { Segmented } from "../ui/Segmented";
import { categorizeProfiles, isEnabled, ProfileMode } from "./presetCatalog";
import { ProfileTile } from "./ProfileTile";
import type { BypassModel } from "./useBypass";

function AllSitesCard({ model }: { model: BypassModel }) {
  return (
    <div className="all-sites">
      <span className="all-sites__icon" aria-hidden="true">
        <IconShieldCheck size={24} />
      </span>
      <div>
        <h3 className="all-sites__title">Обход для всех сайтов</h3>
        <p className="all-sites__note">
          Флагманский универсальный набор стратегий на весь трафик (YouTube, Discord, Telegram, торренты, соцсети).
          Для точечного подбора лучшего конфига под каждое приложение или минимального пинга в играх переключитесь на «Точечно».
        </p>
        <div style={{ marginTop: "10px", display: "flex", gap: "8px", alignItems: "center" }}>
          <button
            type="button"
            className="btn btn--outline btn--xs"
            onClick={() => {
              model.chooseProfileMode("profiles");
              void model.runAutoPick();
            }}
            disabled={model.running || model.busy || model.autoRunning}
            title="Автоматически проверить сайты и подобрать наилучший конфиг под каждое приложение"
          >
            <IconBolt size={12} />
            <span>Автоподбор под каждый сервис</span>
          </button>
        </div>
      </div>
      {model.universalChosen && (
        <span className="chip chip--accent" title={`Активный профиль: ${model.universalChosen}`}>
          {model.universalChosen}
        </span>
      )}
    </div>
  );
}

function ProfileGrid({ model }: { model: BypassModel }) {
  const locked = model.running || model.busy || model.autoRunning;

  return (
    <>
      <div className="toolbar">
        <SearchBox value={model.search} onChange={model.setSearch} placeholder="Найти сервис…" />
        <button
          type="button"
          className="btn btn--outline btn--sm"
          onClick={() => void model.runAutoPick()}
          disabled={locked || model.offline}
          title="Автоматически определить заблокированные сайты, подобрать лучшие конфиги и пустить остальное напрямую"
        >
          {model.autoRunning ? <span className="spinner" /> : <IconBolt size={14} />}
          {model.autoRunning
            ? `Проверяю ${model.autoProgress.done}/${model.autoProgress.total}`
            : "Автоопределение блокировок"}
        </button>
        <button type="button" className="btn btn--ghost btn--sm" onClick={() => model.setAllProfiles(false)} disabled={locked}>
          Снять всё
        </button>
      </div>

      {model.running && <Notice tone="hint">Чтобы поменять список, выключите обход.</Notice>}
      {model.autoNote && !model.running && <Notice tone="ok">{model.autoNote}</Notice>}

      {model.visibleProfiles.length === 0 ? (
        <EmptyState title="Ничего не найдено">Измените запрос или очистите поиск.</EmptyState>
      ) : (
        <div className="categories">
          {categorizeProfiles(model.visibleProfiles).map((category) => (
            <div className="category" key={category.title}>
              <h3 className="category__title">
                {category.title}
                <span>{category.groups.length}</span>
              </h3>
              <div className="tiles">
                {category.groups.map((group) => (
                  <ProfileTile
                    key={group.target}
                    group={group}
                    enabled={isEnabled(group.target, model.enabledMap)}
                    disabled={locked}
                    onToggle={model.toggleGroup}
                    top5={model.getTop5(group.target, group.presets)}
                    activePreset={model.chosenFor(group)}
                    onSelectPreset={model.selectPreset}
                    onFailover={model.triggerFailover}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

export function ProfilesPanel({ model }: { model: BypassModel }) {
  return (
    <Panel
      title="Что обходить"
      note={
        model.effectiveMode === "all"
          ? "Обход работает для всего трафика."
          : "Обход работает только для выбранных сервисов, остальной трафик идёт напрямую."
      }
      meta={
        <Segmented<ProfileMode>
          label="Режим обхода"
          value={model.effectiveMode}
          onChange={model.chooseProfileMode}
          options={[
            { value: "all", label: "Все сайты", disabled: (!model.hasUniversal && model.universalKnown) || model.running },
            { value: "profiles", label: "Точечно", count: model.enabledTargets.length, disabled: model.running },
          ]}
        />
      }
    >
      {model.universalKnown && !model.hasUniversal && (
        <Notice tone="warn">Ядро не сообщило универсальный набор — доступен только точечный режим.</Notice>
      )}

      {model.presets.length === 0 ? (
        <EmptyState title="Каталог не загружен" loading={!model.pollError}>
          {model.pollError ? "Ядро недоступно — проверьте локальный API." : "Загружаю каталог ядра…"}
        </EmptyState>
      ) : model.effectiveMode === "all" ? (
        <AllSitesCard model={model} />
      ) : (
        <ProfileGrid model={model} />
      )}
    </Panel>
  );
}
