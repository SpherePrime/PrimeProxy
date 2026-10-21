import { useMemo, useState } from "react";
import { PresetInfo } from "../api";

// Группировка пресетов по целевым сервисам (targets из /api/ws/presets):
// одна секция — один сервис, пресет может входить в несколько секций.
// Порядок секций фиксированный, неизвестные цели уходят в конец по алфавиту.
export const GROUP_ORDER = [
  "YouTube",
  "Discord",
  "ChatGPT",
  "Google",
  "Соцсети Meta",
  "Twitch",
  "Игры",
  "Все сайты",
  "Общий",
] as const;

// Секции, включённые по умолчанию при первом запуске.
const DEFAULT_ON = new Set<string>(["Все сайты", "Discord", "YouTube"]);

export interface PresetGroup {
  target: string;
  presets: PresetInfo[];
}

function sortPresets(list: PresetInfo[]): PresetInfo[] {
  return [...list].sort((a, b) =>
    a.name.localeCompare(b.name, "ru", { sensitivity: "base" }),
  );
}

export function buildGroups(presets: PresetInfo[]): PresetGroup[] {
  const map = new Map<string, PresetInfo[]>();
  for (const preset of presets) {
    // Без targets (старый бэкенд) пресет попадает в «Общий».
    const targets =
      preset.targets && preset.targets.length > 0 ? preset.targets : ["Общий"];
    for (const target of targets) {
      const bucket = map.get(target);
      if (bucket) bucket.push(preset);
      else map.set(target, [preset]);
    }
  }
  const ordered: PresetGroup[] = [];
  const seen = new Set<string>();
  for (const target of GROUP_ORDER) {
    const bucket = map.get(target);
    if (bucket) {
      ordered.push({ target, presets: sortPresets(bucket) });
      seen.add(target);
    }
  }
  const rest = [...map.keys()]
    .filter((target) => !seen.has(target))
    .sort((a, b) => a.localeCompare(b, "ru"));
  for (const target of rest) {
    ordered.push({ target, presets: sortPresets(map.get(target)!) });
  }
  return ordered;
}

// Включена ли секция: сохранённый выбор или правило по умолчанию.
export function isEnabled(target: string, saved: Record<string, boolean>): boolean {
  const stored = saved[target];
  if (stored === undefined) return DEFAULT_ON.has(target);
  return stored;
}

export function saveEnabled(target: string, value: boolean): void {
  try {
    localStorage.setItem(`pp.grp.${target}`, value ? "1" : "0");
  } catch (_) {
    // localStorage недоступен — состояние живёт до перезагрузки
  }
}

export function saveDefault(target: string, name: string): void {
  try {
    localStorage.setItem(`pp.def.${target}`, name);
  } catch (_) {
    // localStorage недоступен — состояние живёт до перезагрузки
  }
}

// «1 пресет / 2 пресета / 5 пресетов» — русские формы множественного числа.
function presetsLabel(count: number): string {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return `${count} пресет`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) {
    return `${count} пресета`;
  }
  return `${count} пресетов`;
}

interface PresetGroupsProps {
  groups: PresetGroup[];
  search: string;
  totalPresets: number;
  enabled: Record<string, boolean>;
  defaults: Record<string, string | undefined>;
  onToggle: (target: string) => void;
  onChoose: (target: string, name: string) => void;
  openTarget: string | null;
  onOpen: (target: string | null) => void;
}

export function PresetGroups({
  groups,
  search,
  totalPresets,
  enabled,
  defaults,
  onToggle,
  onChoose,
  openTarget,
  onOpen,
}: PresetGroupsProps) {
  const [localOpen, setLocalOpen] = useState<string | null>(null);
  const open = openTarget ?? localOpen;
  const setOpen = onOpen ?? setLocalOpen;
  const query = search.trim().toLowerCase();

  const visible = useMemo(
    () =>
      query
        ? groups
            .map((group) => ({
              ...group,
              presets: group.presets.filter(
                (preset) =>
                  preset.name.toLowerCase().includes(query) ||
                  preset.description.toLowerCase().includes(query),
              ),
            }))
            .filter((group) => group.presets.length > 0)
        : groups,
    [groups, query],
  );

  if (totalPresets === 0) {
    return (
      <div className="preset-empty">Пресеты не найдены — сервер недоступен?</div>
    );
  }

  if (visible.length === 0) {
    return <div className="preset-empty">Ничего не найдено по запросу.</div>;
  }

  return (
    <>
      <div className="pgroup-grid">
        {visible.map((group) => {
          const on = isEnabled(group.target, enabled);
          return (
            <section
              className={`pgroup ${open === group.target ? "open" : ""}`}
              key={group.target}
            >
              <button
                type="button"
                className="pgroup-head"
                onClick={() => setOpen(open === group.target ? null : group.target)}
                aria-expanded={open === group.target}
              >
                <span className="pgroup-arrow">▶</span>
                <h3>{group.target}</h3>
                <span className="preset-count">{presetsLabel(group.presets.length)}</span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={on}
                  aria-label={`Группа ${group.target}`}
                  className={`switch ${on ? "on" : ""}`}
                  onClick={(event) => {
                    event.stopPropagation();
                    onToggle(group.target);
                  }}
                />
              </button>
              {open === group.target && (
                <div className="pgroup-list">
                  {group.presets.map((preset) => {
                    const isDefault = defaults[group.target] === preset.name;
                    return (
                      <button
                        key={preset.name}
                        className={`pgroup-item ${isDefault ? "selected" : ""}`}
                        onClick={() => onChoose(group.target, preset.name)}
                        title={preset.description}
                      >
                        <span className="pgroup-item-main">
                          <span className="preset-name">{preset.name}</span>
                          {isDefault && <span className="badge def">по умолчанию</span>}
                        </span>
                        {preset.description.trim() !== "" && (
                          <span className="preset-desc">{preset.description}</span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </section>
          );
        })}
      </div>
    </>
  );
}
