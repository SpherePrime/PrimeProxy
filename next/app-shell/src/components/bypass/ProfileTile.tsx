import { useState } from "react";
import { IconBolt, IconChevronDown, IconWarning } from "../Icons";
import { ServiceBadge } from "../ServiceBadge";
import { Switch } from "../ui/Switch";
import { PresetGroup, targetDescription } from "./presetCatalog";
import { ProfileScore } from "./profileRanking";

interface ProfileTileProps {
  group: PresetGroup;
  enabled: boolean;
  disabled: boolean;
  onToggle: (target: string) => void;
  top5: ProfileScore[];
  activePreset: string;
  onSelectPreset: (target: string, presetName: string) => void;
  onFailover: (target: string) => void;
}

export function ProfileTile({
  group,
  enabled,
  disabled,
  onToggle,
  top5,
  activePreset,
  onSelectPreset,
  onFailover,
}: ProfileTileProps) {
  const [isOpen, setIsOpen] = useState(false);

  const activeItem = top5.find((p) => p.name === activePreset) || top5[0];
  const latency = activeItem?.latencyMs ?? 35;
  const rank = activeItem?.rank ?? 1;

  const latencyTone =
    activeItem?.status === "failed"
      ? "tone-fail"
      : latency <= 45
        ? "tone-ok"
        : latency <= 85
          ? "tone-warn"
          : "tone-fail";

  return (
    <article className={`tile ${enabled ? "is-on" : ""} ${isOpen ? "is-open" : ""}`}>
      <div className="tile__row">
        <button
          type="button"
          className="tile__main"
          onClick={() => onToggle(group.target)}
          disabled={disabled}
          aria-pressed={enabled}
        >
          <ServiceBadge name={group.target} size={36} />
          <span className="tile__text">
            <span className="tile__name">{group.target}</span>
            <span className="tile__desc">
              {enabled && activeItem ? (
                <>
                  <span className={`tile__top5-latency ${latencyTone}`}>⚡ {latency} мс</span> ·{" "}
                  <span title={activeItem.name}>№{rank} {activeItem.name}</span>
                </>
              ) : (
                targetDescription(group.target)
              )}
            </span>
          </span>
        </button>

        <button
          type="button"
          className={`tile__top-toggle ${isOpen ? "is-active" : ""}`}
          onClick={() => setIsOpen((prev) => !prev)}
          title={`Показать топ-5 профилей для ${group.target}`}
          aria-expanded={isOpen}
        >
          <span>Топ-5</span>
          <IconChevronDown size={14} className={isOpen ? "icon-rotated" : ""} />
        </button>

        <Switch
          on={enabled}
          label={`Обходить ${group.target}`}
          onToggle={() => onToggle(group.target)}
          disabled={disabled}
        />
      </div>

      {isOpen && (
        <div className="tile__top5-body">
          <div className="tile__top5-head">
            <span>Топ-5 лучших профилей под {group.target}</span>
            <span className="chip chip--sm">фолбэк: авто</span>
          </div>

          <ul className="tile__top5-list">
            {top5.map((profile) => {
              const isActive = profile.name === activePreset;
              const pTone =
                profile.status === "failed"
                  ? "tone-fail"
                  : profile.latencyMs <= 45
                    ? "tone-ok"
                    : profile.latencyMs <= 85
                      ? "tone-warn"
                      : "tone-fail";

              return (
                <li
                  key={profile.name}
                  className={`tile__top5-item ${isActive ? "is-active" : ""}`}
                >
                  <div className="tile__top5-info">
                    <span className={`tile__top5-rank ${profile.rank === 1 ? "is-first" : ""}`}>
                      {profile.rank === 1 ? "★ 1" : profile.rank}
                    </span>
                    <span className="tile__top5-name" title={profile.name}>
                      {profile.name}
                    </span>
                    {profile.tag && <span className="chip chip--mute chip--sm">{profile.tag}</span>}
                  </div>

                  <div className="tile__top5-meta">
                    <span className={`tile__top5-latency ${pTone}`} title="Задержка">
                      ⚡ {profile.latencyMs} мс
                    </span>
                    {profile.failCount > 0 && (
                      <span className="chip chip--fail chip--sm" title="Число зафиксированных сбоев">
                        сбоев: {profile.failCount}
                      </span>
                    )}
                    {isActive ? (
                      <span className="chip chip--accent chip--sm">Активен</span>
                    ) : (
                      <button
                        type="button"
                        className="btn btn--outline btn--xs"
                        onClick={() => onSelectPreset(group.target, profile.name)}
                        disabled={disabled}
                      >
                        Выбрать
                      </button>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>

          <div className="tile__top5-actions">
            <button
              type="button"
              className="btn btn--ghost btn--xs"
              onClick={() => onFailover(group.target)}
              disabled={disabled || top5.length < 2}
              title="Имитировать сбой профиля №1 и автоматически переключиться на 2-й лучший"
            >
              <IconWarning size={13} />
              <span>Сбой? Переключить на №2</span>
            </button>
          </div>
        </div>
      )}
    </article>
  );
}
