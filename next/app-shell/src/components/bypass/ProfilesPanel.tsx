import { useState } from "react";
import { IconChevronDown } from "../Icons";
import { EmptyState } from "../ui/EmptyState";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";
import { SearchBox } from "../ui/SearchBox";
import { Segmented } from "../ui/Segmented";
import { categorizeProfiles, isEnabled, presetsLabel, ProfileMode, visiblePresets } from "./presetCatalog";
import { PresetList } from "./PresetList";
import { ProfileTile } from "./ProfileTile";
import type { BypassModel } from "./useBypass";

function UniversalList({ model }: { model: BypassModel }) {
  const [openTarget, setOpenTarget] = useState<string | null>(model.universalGroups[0]?.target ?? null);

  return (
    <div className="universal">
      {model.universalGroups.map((group) => {
        const visible = visiblePresets(group, model.search);
        const isOpen = openTarget === group.target;
        return (
          <div className={`universal__group ${isOpen ? "is-open" : ""}`} key={group.target}>
            <button
              type="button"
              className="universal__toggle"
              aria-expanded={isOpen}
              onClick={() => setOpenTarget(isOpen ? null : group.target)}
            >
              <span className="universal__name">{group.target}</span>
              <span className="universal__chosen">{model.effectiveDefaults[group.target]}</span>
              <span className="chip">{presetsLabel(group.presets.length)}</span>
              <span className="tile__chevron" aria-hidden="true">
                <IconChevronDown size={14} />
              </span>
            </button>
            {isOpen &&
              (visible.length > 0 ? (
                <PresetList
                  target={group.target}
                  presets={visible}
                  chosen={model.effectiveDefaults[group.target]}
                  onChoose={model.choosePreset}
                />
              ) : (
                <p className="tile__empty">По запросу «{model.search.trim()}» ничего не найдено.</p>
              ))}
          </div>
        );
      })}
    </div>
  );
}

function ProfileGrid({ model }: { model: BypassModel }) {
  if (model.visibleProfiles.length === 0) {
    return <EmptyState title="Ничего не найдено">Измените запрос или очистите поиск.</EmptyState>;
  }
  return (
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
                chosen={model.effectiveDefaults[group.target]}
                search={model.search}
                open={model.openGroup === group.target}
                onToggle={model.toggleGroup}
                onChoose={model.choosePreset}
                onOpen={model.setOpenGroup}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export function ProfilesPanel({ model }: { model: BypassModel }) {
  const universalCount = model.universalGroups.reduce((total, group) => total + group.presets.length, 0);

  return (
    <Panel
      title="Что обходить"
      note={
        model.effectiveMode === "all"
          ? "Один универсальный пресет на весь трафик — подходит большинству сайтов."
          : "Работают только включённые сервисы, остальной трафик движок не трогает."
      }
      meta={<span className="chip">{model.presets.length} пресетов</span>}
    >
      <div className="toolbar">
        <Segmented<ProfileMode>
          label="Режим профилей"
          value={model.effectiveMode}
          onChange={model.chooseProfileMode}
          options={[
            {
              value: "all",
              label: "Все сайты",
              count: universalCount,
              disabled: !model.hasUniversal && model.universalKnown,
            },
            { value: "profiles", label: "Точечно", count: model.activeProfileCount },
          ]}
        />
        <SearchBox
          value={model.search}
          onChange={model.setSearch}
          placeholder={model.effectiveMode === "all" ? "Найти пресет…" : "Найти сервис или пресет…"}
        />
      </div>

      {model.universalKnown && !model.hasUniversal && (
        <Notice tone="warn">Ядро не сообщило универсальных пресетов — доступны только точечные профили.</Notice>
      )}

      {model.presets.length === 0 ? (
        <EmptyState title="Пресеты не загружены" loading={!model.pollError}>
          {model.pollError ? "Ядро недоступно — проверьте локальный API." : "Загружаю каталог ядра…"}
        </EmptyState>
      ) : model.effectiveMode === "all" ? (
        <UniversalList model={model} />
      ) : (
        <ProfileGrid model={model} />
      )}
    </Panel>
  );
}
