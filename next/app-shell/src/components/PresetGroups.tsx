import { useEffect, useRef, useState } from "react";
import { PresetInfo } from "../api";
import { IconCheck, IconChevron } from "./Icons";

// Группировка пресетов по целевым сервисам (targets из /api/ws/presets):
// одна секция — один сервис, пресет может входить в несколько секций.
// Порядок секций фиксированный, неизвестные цели уходят в конец по алфавиту.
// Первые две цели — универсальные: они работают для всего трафика и живут
// в отдельном режиме, а не среди точечных профилей.
export const GROUP_ORDER = [
  "Все сайты",
  "Общий",
  "YouTube",
  "Discord",
  "Telegram",
  "Instagram",
  "Facebook",
  "Twitter/X",
  "TikTok",
  "WhatsApp",
  "ChatGPT",
  "Anthropic",
  "Google",
  "Twitch",
  "Игры",
  "Торренты",
] as const;

// Секции, включённые по умолчанию при первом запуске.
const DEFAULT_ON = new Set<string>(["Все сайты"]);

// Подписи профилей: что покрывает сервис. Нужны, чтобы профиль выбирали по
// смыслу, а не по имени цели в каталоге ядра.
const TARGET_DESCRIPTIONS: Record<string, string> = {
  "Все сайты": "универсальные пресеты: подходят большинству заблокированных сайтов",
  Общий: "пресеты без привязки к конкретному сервису",
  YouTube: "видео, трансляции и превью",
  Discord: "чат, голос, обновления и медиа",
  Telegram: "мессенджер, веб-клиент и дата-центры",
  Instagram: "лента, сторис и CDN картинок",
  Facebook: "лента, видео и CDN",
  "Twitter/X": "лента, картинки и короткие ссылки",
  TikTok: "лента, видео и CDN",
  WhatsApp: "веб-клиент и медиа",
  ChatGPT: "чат, API и статика OpenAI",
  Anthropic: "Claude и API Anthropic",
  Google: "поиск, бэкенд и сервисы Google",
  Twitch: "стримы, чат и превью",
  Игры: "Steam, Roblox, Epic Games и Fortnite",
  Торренты: "rutracker и rutor",
};

/** Человеческое описание профиля; пустая строка — если сервис неизвестен. */
export function targetDescription(target: string): string {
  return TARGET_DESCRIPTIONS[target] ?? "";
}

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

export function isUniversal(target: string): boolean {
  return target === "Все сайты" || target === "Общий";
}

export function saveEnabled(target: string, value: boolean): void {
  try {
    localStorage.setItem(`pp.grp.${target}`, value ? "1" : "0");
  } catch (_) {
    // localStorage недоступен — состояние живёт до перезагрузки
  }
}

/**
 * Сохранённые переключатели групп. Без чтения при старте выбор терялся бы
 * после перезапуска: запись была, а восстановления — нет.
 */
export function loadEnabled(): Record<string, boolean> {
  const map: Record<string, boolean> = {};
  try {
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (!key || !key.startsWith("pp.grp.")) continue;
      map[key.slice("pp.grp.".length)] = localStorage.getItem(key) === "1";
    }
  } catch (_) {
    // localStorage недоступен — работаем с правилами по умолчанию
  }
  return map;
}

export function saveDefault(target: string, name: string): void {
  try {
    localStorage.setItem(`pp.def.${target}`, name);
  } catch (_) {
    // localStorage недоступен — состояние живёт до перезагрузки
  }
}

/** Сохранённые пресеты групп — та же причина, что и у [`loadEnabled`]. */
export function loadDefaults(): Record<string, string> {
  const map: Record<string, string> = {};
  try {
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (!key || !key.startsWith("pp.def.")) continue;
      const value = localStorage.getItem(key);
      if (value) map[key.slice("pp.def.".length)] = value;
    }
  } catch (_) {
    // localStorage недоступен — работаем без сохранённых пресетов
  }
  return map;
}

// «1 пресет / 2 пресета / 5 пресетов» — русские формы множественного числа.
export function presetsLabel(count: number): string {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return `${count} пресет`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) {
    return `${count} пресета`;
  }
  return `${count} пресетов`;
}

/** Фильтр списка пресетов по запросу: имя и описание. */
function filterPresets(presets: PresetInfo[], query: string): PresetInfo[] {
  if (query === "") return presets;
  return presets.filter(
    (preset) =>
      preset.name.toLowerCase().includes(query) ||
      preset.description.toLowerCase().includes(query),
  );
}

/** Есть ли в группе пресеты под запрос — чтобы не показывать пустые карточки. */
export function groupMatches(group: PresetGroup, search: string): boolean {
  return filterPresets(group.presets, search.trim().toLowerCase()).length > 0;
}

interface PresetListProps {
  target: string;
  presets: PresetInfo[];
  chosen: string | undefined;
  onChoose: (target: string, name: string) => void;
}

/**
 * Список пресетов одной группы: выбор одного пресета (радио-поведение).
 * Живёт и внутри универсального блока, и внутри карточки профиля.
 */
export function PresetList({ target, presets, chosen, onChoose }: PresetListProps) {
  const listRef = useRef<HTMLDivElement>(null);

  // В группе «Все сайты» больше сотни пресетов: без прокрутки к выбранному
  // непонятно, что именно уйдёт в запуск. Скроллим только сам список.
  useEffect(() => {
    const list = listRef.current;
    const item = list?.querySelector<HTMLElement>(".pgroup-item.selected");
    if (!list || !item) return;
    list.scrollTop = Math.max(
      0,
      item.offsetTop - list.clientHeight / 2 + item.clientHeight / 2,
    );
  }, [target]);

  return (
    <div
      className="pgroup-list"
      ref={listRef}
      role="radiogroup"
      aria-label={`Пресеты: ${target}`}
    >
      {presets.map((preset) => {
        const isDefault = chosen === preset.name;
        return (
          <button
            key={preset.name}
            type="button"
            role="radio"
            aria-checked={isDefault}
            className={`pgroup-item ${isDefault ? "selected" : ""}`}
            onClick={() => onChoose(target, preset.name)}
            title={preset.description}
          >
            <span className="pgroup-pick" aria-hidden="true">
              {isDefault && <IconCheck size={10} />}
            </span>
            <span className="pgroup-item-body">
              <span className="preset-name">{preset.name}</span>
              {preset.description.trim() !== "" && (
                <span className="preset-desc">{preset.description}</span>
              )}
            </span>
          </button>
        );
      })}
    </div>
  );
}

interface ProfileCardProps {
  group: PresetGroup;
  enabled: boolean;
  chosen: string | undefined;
  search: string;
  open: boolean;
  onToggle: (target: string) => void;
  onChoose: (target: string, name: string) => void;
  onOpen: (target: string | null) => void;
}

/**
 * Крупная карточка сервиса: имя, покрытие, число пресетов, выбранный пресет
 * и переключатель. Список пресетов раскрывается внутри карточки.
 */
export function ProfileCard({
  group,
  enabled,
  chosen,
  search,
  open,
  onToggle,
  onChoose,
  onOpen,
}: ProfileCardProps) {
  const query = search.trim().toLowerCase();
  const visible = filterPresets(group.presets, query);
  const description = targetDescription(group.target);
  return (
    <article className={`pcard ${enabled ? "on" : ""} ${open ? "open" : ""}`}>
      <div className="pcard-top">
        <button
          type="button"
          className="pcard-open"
          aria-expanded={open}
          onClick={() => onOpen(open ? null : group.target)}
        >
          <span className="pcard-name">{group.target}</span>
          {description !== "" && <span className="pcard-desc">{description}</span>}
        </button>
        <button
          type="button"
          role="switch"
          aria-checked={enabled}
          aria-label={`Профиль ${group.target}`}
          className={`switch ${enabled ? "on" : ""}`}
          onClick={() => onToggle(group.target)}
        />
      </div>

      <div className="pcard-meta">
        <span className="preset-count">{presetsLabel(group.presets.length)}</span>
        <span className={`pcard-current ${enabled ? "" : "mute"}`}>
          {enabled
            ? chosen
              ? `пресет: ${chosen}`
              : "пресет не выбран"
            : "выключен"}
        </span>
        <span className="pcard-arrow" aria-hidden="true">
          <IconChevron />
        </span>
      </div>

      {open && (
        <div className="pcard-body">
          {visible.length > 0 ? (
            <PresetList
              target={group.target}
              presets={visible}
              chosen={chosen}
              onChoose={onChoose}
            />
          ) : (
            <p className="pcard-empty">
              По запросу «{search.trim()}» в этом профиле ничего нет.
            </p>
          )}
        </div>
      )}
    </article>
  );
}

interface UniversalBlockProps {
  groups: PresetGroup[];
  search: string;
  active: boolean;
  chosen: (target: string) => string | undefined;
  onChoose: (target: string, name: string) => void;
  onSwitchMode: () => void;
}

/**
 * Универсальный профиль: отдельный крупный блок, а не карточка среди сервисов.
 * В режиме «Все сайты» он включён по определению, в режиме профилей — только
 * показывает, что произойдёт после переключения.
 */
export function UniversalBlock({
  groups,
  search,
  active,
  chosen,
  onChoose,
  onSwitchMode,
}: UniversalBlockProps) {
  const [openTarget, setOpenTarget] = useState<string | null>(
    groups[0]?.target ?? null,
  );
  const query = search.trim().toLowerCase();

  if (groups.length === 0) return null;

  return (
    <div className={`universal-card ${active ? "on" : "off"}`}>
      <div className="universal-head">
        <div className="universal-title">
          <span className="universal-kicker">Универсальный профиль</span>
          <h3>Один пресет для всего трафика</h3>
          <p>
            Работает для большинства заблокированных сайтов и приложений: движок
            сам решает, к какому трафику применить десинк.
          </p>
        </div>
        <span className={`chip ${active ? "tone-accent" : "tone-neutral"}`}>
          {active ? "включён" : "выключен"}
        </span>
      </div>

      {!active && (
        <div className="universal-off">
          <span>
            Сейчас работает режим точечных профилей. Универсальный пресет
            включится, если выбрать режим «Все сайты».
          </span>
          <button type="button" className="btn ghost sm" onClick={onSwitchMode}>
            Переключить на «Все сайты»
          </button>
        </div>
      )}

      {active &&
        groups.map((group) => {
          const visible = filterPresets(group.presets, query);
          const isOpen = openTarget === group.target;
          return (
            <div className="universal-group" key={group.target}>
              <button
                type="button"
                className="universal-toggle"
                aria-expanded={isOpen}
                onClick={() => setOpenTarget(isOpen ? null : group.target)}
              >
                <span className="pcard-arrow" aria-hidden="true">
                  <IconChevron />
                </span>
                <span className="universal-group-name">{group.target}</span>
                <span className="preset-count">
                  {presetsLabel(group.presets.length)}
                </span>
              </button>
              {isOpen &&
                (visible.length > 0 ? (
                  <PresetList
                    target={group.target}
                    presets={visible}
                    chosen={chosen(group.target)}
                    onChoose={onChoose}
                  />
                ) : (
                  <p className="pcard-empty">
                    По запросу «{search.trim()}» ничего не найдено.
                  </p>
                ))}
            </div>
          );
        })}
    </div>
  );
}
