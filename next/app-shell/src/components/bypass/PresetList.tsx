import { useEffect, useRef } from "react";
import { PresetInfo } from "../../api";
import { IconCheck } from "../Icons";

interface PresetListProps {
  target: string;
  presets: PresetInfo[];
  chosen: string | undefined;
  onChoose: (target: string, name: string) => void;
}

export function PresetList({ target, presets, chosen, onChoose }: PresetListProps) {
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const list = listRef.current;
    const item = list?.querySelector<HTMLElement>(".preset.is-selected");
    if (!list || !item) return;
    list.scrollTop = Math.max(0, item.offsetTop - list.clientHeight / 2 + item.clientHeight / 2);
  }, [target]);

  return (
    <div className="preset-list" ref={listRef} role="radiogroup" aria-label={`Пресеты: ${target}`}>
      {presets.map((preset) => {
        const selected = chosen === preset.name;
        return (
          <button
            key={preset.name}
            type="button"
            role="radio"
            aria-checked={selected}
            className={`preset ${selected ? "is-selected" : ""}`}
            onClick={() => onChoose(target, preset.name)}
            title={preset.description}
          >
            <span className="preset__pick" aria-hidden="true">
              {selected && <IconCheck size={11} />}
            </span>
            <span className="preset__body">
              <span className="preset__name">{preset.name}</span>
              {preset.description.trim() !== "" && <span className="preset__desc">{preset.description}</span>}
            </span>
          </button>
        );
      })}
    </div>
  );
}
