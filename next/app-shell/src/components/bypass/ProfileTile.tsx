import { ServiceBadge } from "../ServiceBadge";
import { Switch } from "../ui/Switch";
import { PresetGroup, targetDescription } from "./presetCatalog";

interface ProfileTileProps {
  group: PresetGroup;
  enabled: boolean;
  disabled: boolean;
  onToggle: (target: string) => void;
}

export function ProfileTile({ group, enabled, disabled, onToggle }: ProfileTileProps) {
  return (
    <article className={`tile ${enabled ? "is-on" : ""}`}>
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
            <span className="tile__desc">{targetDescription(group.target)}</span>
          </span>
        </button>
        <Switch
          on={enabled}
          label={`Обходить ${group.target}`}
          onToggle={() => onToggle(group.target)}
          disabled={disabled}
        />
      </div>
    </article>
  );
}
