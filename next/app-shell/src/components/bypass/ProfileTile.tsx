import { IconChevronDown } from "../Icons";
import { ServiceBadge } from "../ServiceBadge";
import { Switch } from "../ui/Switch";
import { PresetGroup, presetsLabel, targetDescription, visiblePresets } from "./presetCatalog";
import { PresetList } from "./PresetList";

interface ProfileTileProps {
  group: PresetGroup;
  enabled: boolean;
  chosen: string | undefined;
  search: string;
  open: boolean;
  onToggle: (target: string) => void;
  onChoose: (target: string, name: string) => void;
  onOpen: (target: string | null) => void;
}

export function ProfileTile({ group, enabled, chosen, search, open, onToggle, onChoose, onOpen }: ProfileTileProps) {
  const visible = visiblePresets(group, search);
  return (
    <article className={`tile ${enabled ? "is-on" : ""} ${open ? "is-open" : ""}`}>
      <div className="tile__row">
        <button
          type="button"
          className="tile__main"
          aria-expanded={open}
          onClick={() => onOpen(open ? null : group.target)}
        >
          <ServiceBadge name={group.target} size={36} />
          <span className="tile__text">
            <span className="tile__name">{group.target}</span>
            <span className="tile__desc">
              {enabled && chosen ? chosen : targetDescription(group.target) || presetsLabel(group.presets.length)}
            </span>
          </span>
          <span className="tile__chevron" aria-hidden="true">
            <IconChevronDown size={14} />
          </span>
        </button>
        <Switch on={enabled} label={`Профиль ${group.target}`} onToggle={() => onToggle(group.target)} />
      </div>
      {open && (
        <div className="tile__body">
          <div className="tile__caption">
            {presetsLabel(group.presets.length)} · выбранный уйдёт в запуск
          </div>
          {visible.length > 0 ? (
            <PresetList target={group.target} presets={visible} chosen={chosen} onChoose={onChoose} />
          ) : (
            <p className="tile__empty">По запросу «{search.trim()}» здесь ничего нет.</p>
          )}
        </div>
      )}
    </article>
  );
}
