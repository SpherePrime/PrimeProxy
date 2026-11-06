import { PresetInfo } from "../../api";

export const GROUP_ORDER = [
  "Все сайты",
  "Общий",
  "YouTube",
  "Twitch",
  "Instagram",
  "Facebook",
  "Twitter/X",
  "TikTok",
  "LinkedIn",
  "Discord",
  "Telegram",
  "WhatsApp",
  "ChatGPT",
  "Anthropic",
  "Gemini",
  "DeepSeek",
  "Steam",
  "Roblox",
  "Epic Games",
  "Riot/Valorant",
  "Ubisoft",
  "itch.io",
  "Microsoft Store",
  "SoundCloud",
  "Google",
  "Google бэкенд",
  "Cloudflare",
  "Amazon",
  "Apple",
  "GitHub",
  "Speedtest",
  "Торренты",
  "Obsidian",
  "Notion",
  "Fandom",
  "Vencord",
  "Мои сайты",
] as const;

const PROFILE_CATEGORIES: Array<{ title: string; targets: string[] }> = [
  { title: "Видео и стримы", targets: ["YouTube", "Twitch"] },
  { title: "Соцсети", targets: ["Instagram", "Facebook", "Twitter/X", "TikTok", "LinkedIn"] },
  { title: "Мессенджеры", targets: ["Discord", "Telegram", "WhatsApp"] },
  { title: "ИИ-сервисы", targets: ["ChatGPT", "Anthropic", "Gemini", "DeepSeek"] },
  {
    title: "Игры",
    targets: ["Steam", "Roblox", "Epic Games", "Riot/Valorant", "Ubisoft", "itch.io", "Microsoft Store"],
  },
  { title: "Медиа", targets: ["SoundCloud"] },
  {
    title: "Инфраструктура",
    targets: ["Google", "Google бэкенд", "Cloudflare", "Amazon", "Apple", "GitHub", "Speedtest"],
  },
  { title: "Разное", targets: ["Торренты", "Obsidian", "Notion", "Fandom", "Vencord", "Мои сайты"] },
];

const DEFAULT_ON = new Set<string>(["Все сайты"]);

const TARGET_DESCRIPTIONS: Record<string, string> = {
  "Все сайты": "универсальные пресеты для большинства заблокированных сайтов",
  Общий: "пресеты без привязки к конкретному сервису",
  YouTube: "видео, трансляции и превью",
  Twitch: "стримы, чат и превью",
  Instagram: "лента, сторис и CDN картинок",
  Facebook: "лента, видео и CDN",
  "Twitter/X": "лента, картинки и короткие ссылки",
  TikTok: "лента, видео и CDN",
  LinkedIn: "лента, профили и картинки",
  Discord: "чат, голос, обновления и медиа",
  Telegram: "мессенджер, веб-клиент и дата-центры",
  WhatsApp: "веб-клиент и медиа",
  ChatGPT: "чат, API и статика OpenAI",
  Anthropic: "Claude и API Anthropic",
  Gemini: "Gemini и сервисы Google AI",
  DeepSeek: "чат и API DeepSeek",
  Steam: "магазин, сообщество и загрузки",
  Roblox: "игра, сайт и CDN",
  "Epic Games": "магазин Epic и Fortnite",
  "Riot/Valorant": "League of Legends и Valorant",
  Ubisoft: "магазин и лаунчер",
  "itch.io": "магазин инди-игр",
  "Microsoft Store": "магазин и загрузки Microsoft",
  SoundCloud: "музыка и CDN",
  Google: "поиск и сайты Google",
  "Google бэкенд": "служебные домены Google для чужих сайтов",
  Cloudflare: "инфраструктура Cloudflare и CloudFront",
  Amazon: "магазин и облако AWS",
  Apple: "сервисы Apple",
  GitHub: "репозитории, файлы и статика",
  Speedtest: "замеры скорости",
  Торренты: "rutracker и rutor",
  Obsidian: "заметки и синхронизация",
  Notion: "заметки и рабочие пространства",
  Fandom: "вики и фан-порталы",
  Vencord: "модификация клиента Discord",
  "Мои сайты": "ваши собственные списки доменов",
};

const TARGET_PROBES: Record<string, string> = {
  YouTube: "www.youtube.com",
  Twitch: "www.twitch.tv",
  Instagram: "www.instagram.com",
  Facebook: "www.facebook.com",
  "Twitter/X": "x.com",
  TikTok: "www.tiktok.com",
  LinkedIn: "www.linkedin.com",
  Discord: "discord.com",
  Telegram: "telegram.org",
  WhatsApp: "web.whatsapp.com",
  ChatGPT: "chatgpt.com",
  Anthropic: "claude.ai",
  Gemini: "gemini.google.com",
  DeepSeek: "chat.deepseek.com",
  Steam: "store.steampowered.com",
  Roblox: "www.roblox.com",
  "Epic Games": "www.epicgames.com",
  "Riot/Valorant": "www.riotgames.com",
  Ubisoft: "www.ubisoft.com",
  "itch.io": "itch.io",
  "Microsoft Store": "apps.microsoft.com",
  SoundCloud: "soundcloud.com",
  Google: "www.google.com",
  Cloudflare: "www.cloudflare.com",
  Amazon: "www.amazon.com",
  Apple: "www.apple.com",
  GitHub: "github.com",
  Speedtest: "www.speedtest.net",
  Торренты: "rutracker.org",
  Obsidian: "obsidian.md",
  Notion: "www.notion.so",
  Fandom: "www.fandom.com",
};

const EXTRA_DOMAIN_TARGETS: Record<string, string> = {
  "youtu.be": "YouTube",
  "instagram.com": "Instagram",
  "gateway.discord.gg": "Discord",
};

const PROFILE_MODE_KEY = "pp.mode";

export type ProfileMode = "all" | "profiles";

export interface PresetGroup {
  target: string;
  presets: PresetInfo[];
}

export interface ProfileCategory {
  title: string;
  groups: PresetGroup[];
}

export function targetDescription(target: string): string {
  return TARGET_DESCRIPTIONS[target] ?? "";
}

export function targetProbe(target: string): string {
  return TARGET_PROBES[target] ?? "";
}

export function targetForDomain(domain: string): string | null {
  const direct = Object.entries(TARGET_PROBES).find(([, probe]) => probe === domain);
  if (direct) return direct[0];
  return EXTRA_DOMAIN_TARGETS[domain] ?? null;
}

function sortPresets(list: PresetInfo[]): PresetInfo[] {
  return [...list].sort((a, b) => a.name.localeCompare(b.name, "ru", { sensitivity: "base" }));
}

export function buildGroups(presets: PresetInfo[]): PresetGroup[] {
  const map = new Map<string, PresetInfo[]>();
  for (const preset of presets) {
    const targets = preset.targets && preset.targets.length > 0 ? preset.targets : ["Общий"];
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
  const rest = [...map.keys()].filter((target) => !seen.has(target)).sort((a, b) => a.localeCompare(b, "ru"));
  for (const target of rest) ordered.push({ target, presets: sortPresets(map.get(target)!) });
  return ordered;
}

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
  } catch {
    return;
  }
}

export function loadEnabled(): Record<string, boolean> {
  const map: Record<string, boolean> = {};
  try {
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (!key || !key.startsWith("pp.grp.")) continue;
      map[key.slice("pp.grp.".length)] = localStorage.getItem(key) === "1";
    }
  } catch {
    return map;
  }
  return map;
}

export function saveDefault(target: string, name: string): void {
  try {
    localStorage.setItem(`pp.def.${target}`, name);
  } catch {
    return;
  }
}

export function loadDefaults(): Record<string, string> {
  const map: Record<string, string> = {};
  try {
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (!key || !key.startsWith("pp.def.")) continue;
      const value = localStorage.getItem(key);
      if (value) map[key.slice("pp.def.".length)] = value;
    }
  } catch {
    return map;
  }
  return map;
}

export function readProfileMode(): ProfileMode {
  try {
    return localStorage.getItem(PROFILE_MODE_KEY) === "profiles" ? "profiles" : "all";
  } catch {
    return "all";
  }
}

export function saveProfileMode(mode: ProfileMode): void {
  try {
    localStorage.setItem(PROFILE_MODE_KEY, mode);
  } catch {
    return;
  }
}

export function enableOnlyTargets(targets: string[], allTargets: string[]): void {
  const wanted = new Set(targets);
  for (const target of allTargets) saveEnabled(target, wanted.has(target));
  saveProfileMode("profiles");
}

export function presetsLabel(count: number): string {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return `${count} пресет`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${count} пресета`;
  return `${count} пресетов`;
}

export function visiblePresets(group: PresetGroup, search: string): PresetInfo[] {
  const query = search.trim().toLowerCase();
  if (query === "") return group.presets;
  const byTarget =
    group.target.toLowerCase().includes(query) || targetDescription(group.target).toLowerCase().includes(query);
  if (byTarget) return group.presets;
  return group.presets.filter(
    (preset) => preset.name.toLowerCase().includes(query) || preset.description.toLowerCase().includes(query),
  );
}

export function groupMatches(group: PresetGroup, search: string): boolean {
  return visiblePresets(group, search).length > 0;
}

export function categorizeProfiles(groups: PresetGroup[]): ProfileCategory[] {
  const result: ProfileCategory[] = [];
  const used = new Set<string>();
  for (const category of PROFILE_CATEGORIES) {
    const items = groups.filter((group) => category.targets.includes(group.target));
    if (items.length === 0) continue;
    for (const item of items) used.add(item.target);
    result.push({ title: category.title, groups: items });
  }
  const rest = groups.filter((group) => !used.has(group.target));
  if (rest.length > 0) result.push({ title: "Другие профили", groups: rest });
  return result;
}
