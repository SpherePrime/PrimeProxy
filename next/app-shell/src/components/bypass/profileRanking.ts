import { PresetInfo, SiteCheckResult } from "../../api";
import { isUniversal, targetProbe } from "./presetCatalog";

export interface ProfileScore {
  name: string;
  target: string;
  latencyMs: number;
  status: "ok" | "slow" | "failed";
  failCount: number;
  lastTested: number;
  rank: number;
  isDefault: boolean;
  tag?: string;
  score: number;
}

const TOP_LIMIT = 5;

// Специализация пресетов под категории приложений:
// возвращает базовую оценку задержки (мс), бонус приоритета и текстовый тег.
function evaluatePresetSuitability(
  target: string,
  preset: PresetInfo,
): { baseLatency: number; bonus: number; tag: string } {
  const name = preset.name.toLowerCase();
  const desc = (preset.description || "").toLowerCase();
  const targetLower = target.toLowerCase();

  // 1. ИГРОВЫЕ СЕРВИСЫ: критичен ультранизкий пинг и корректная работа UDP
  const isGame = [
    "steam",
    "roblox",
    "epic games",
    "riot/valorant",
    "ubisoft",
    "itch.io",
    "microsoft store",
  ].some((g) => targetLower.includes(g));

  if (isGame) {
    if (name.includes("epicgames") || (name.includes("epic") && !name.includes("dead by daylight"))) {
      return { baseLatency: 28, bonus: -350, tag: "⚡ Epic Games" };
    }
    if (name.includes("gaming") || (name.includes("game filter") && !name.includes("dead by daylight"))) {
      return { baseLatency: 28, bonus: -300, tag: "⚡ Игровой (низкий пинг)" };
    }
    if (name.includes("riot") || name.includes("valorant")) {
      return { baseLatency: 30, bonus: -280, tag: "⚡ Riot / Valorant" };
    }
    if (name.includes("send + syndata") || name.includes("syndata")) {
      return { baseLatency: 35, bonus: -220, tag: "⚡ Fast UDP" };
    }
    if (name.includes("universal v5") || (name.includes("universal") && name.includes("v5"))) {
      return { baseLatency: 36, bonus: -200, tag: "Универсальный" };
    }
    if (name.includes("dead by daylight")) {
      return { baseLatency: 45, bonus: -50, tag: "Игровой" };
    }
    if (name.includes("multisplit")) {
      return { baseLatency: 48, bonus: -100, tag: "Низкая задержка" };
    }
    if (name.includes("circular")) {
      return { baseLatency: 95, bonus: 200, tag: "Тяжёлый десинк" };
    }
    return { baseLatency: 55, bonus: 0, tag: "Стандартный" };
  }

  // 2. DISCORD (голос, видео, STUN)
  if (targetLower.includes("discord")) {
    if (name.includes("discord_urgent_sni") || name.includes("urgent")) {
      return { baseLatency: 32, bonus: -400, tag: "⚡ Быстрый голосовой" };
    }
    if (name.includes("stun") || name.includes("multisplit_stun")) {
      return { baseLatency: 36, bonus: -350, tag: "⚡ STUN / Voice" };
    }
    if (name.includes("media") || name.includes("discord_media")) {
      return { baseLatency: 40, bonus: -250, tag: "Медиа / Стримы" };
    }
    if (name.includes("multisplit")) {
      return { baseLatency: 45, bonus: -150, tag: "Низкая задержка" };
    }
    return { baseLatency: 55, bonus: 0, tag: "Стандартный" };
  }

  // 3. TELEGRAM И WHATSAPP
  if (targetLower.includes("telegram") || targetLower.includes("whatsapp")) {
    if (name === "default multisplit_sni" || (name.includes("multisplit_sni") && !name.includes("game filter"))) {
      return { baseLatency: 32, bonus: -420, tag: "⚡ TLS Multisplit SNI" };
    }
    if (name === "universal v5" || (name.includes("universal") && name.includes("v5"))) {
      return { baseLatency: 34, bonus: -360, tag: "Универсальный" };
    }
    if (name.includes("fake_tls_auto") || name.includes("faketls")) {
      return { baseLatency: 38, bonus: -250, tag: "Fake TLS Auto" };
    }
    return { baseLatency: 50, bonus: 0, tag: "Стандартный" };
  }

  // 4. СОЦСЕТИ META (Facebook, Instagram)
  if (targetLower.includes("facebook") || targetLower.includes("instagram")) {
    if (name === "default multisplit_sni" || (name.includes("multisplit_sni") && !name.includes("game filter"))) {
      return { baseLatency: 32, bonus: -450, tag: "⚡ Проверенный TLS SNI (Meta)" };
    }
    if (name === "universal v5" || (name.includes("universal") && name.includes("v5"))) {
      return { baseLatency: 34, bonus: -380, tag: "Универсальный" };
    }
    if (name.includes("fake_tls_auto") || name.includes("faketls")) {
      return { baseLatency: 40, bonus: -250, tag: "Fake TLS Auto" };
    }
    return { baseLatency: 55, bonus: 0, tag: "Стандартный" };
  }

  // 3. ВИДЕО И СТРИМИНГ: YouTube, Twitch — важен высокий битрейт и CDN
  if (targetLower.includes("youtube") || targetLower.includes("twitch")) {
    if (name.includes("ytdisbystro") || name.includes("bystro")) {
      return { baseLatency: 34, bonus: -300, tag: "⚡ Быстрый поток" };
    }
    if (name.includes("multisplit_sni") || name.includes("hostfakesplit")) {
      return { baseLatency: 40, bonus: -220, tag: "⚡ Оптимальный RTT" };
    }
    if (name.includes("fake_tls_auto")) {
      return { baseLatency: 48, bonus: -150, tag: "Стабильный" };
    }
    if (name.includes("v3") || name.includes("v2") || name.includes("v1")) {
      return { baseLatency: 55, bonus: -80, tag: "Проверенный" };
    }
    return { baseLatency: 65, bonus: 0, tag: "Стандартный" };
  }

  // 4. ИИ-СЕРВИСЫ И ОБЛАКА: ChatGPT, Anthropic, Gemini, DeepSeek, Cloudflare, GitHub
  if (
    targetLower.includes("chatgpt") ||
    targetLower.includes("anthropic") ||
    targetLower.includes("gemini") ||
    targetLower.includes("deepseek") ||
    targetLower.includes("github") ||
    targetLower.includes("cloudflare")
  ) {
    if (name.includes("multisplit") || name.includes("hostfakesplit")) {
      return { baseLatency: 38, bonus: -250, tag: "⚡ Быстрый API" };
    }
    if (name.includes("fake_tls") || name.includes("faketls")) {
      return { baseLatency: 46, bonus: -180, tag: "Стабильный" };
    }
    return { baseLatency: 55, bonus: 0, tag: "Стандартный" };
  }

  // 5. ТОРРЕНТЫ И МУЗЫКА (SoundCloud, Rutracker, Rutor):
  if (targetLower.includes("soundcloud") || targetLower.includes("торренты")) {
    if (name.includes("default multisplit_sni") && !name.includes("game filter")) {
      return { baseLatency: 30, bonus: -500, tag: "⚡ Проверенный TLS SNI" };
    }
    if (name.includes("multisplit_sni")) {
      return { baseLatency: 34, bonus: -400, tag: "⚡ Быстрый TLS SNI" };
    }
    if ((name.includes("universal") && name.includes("v5")) || name === "universal v5") {
      return { baseLatency: 35, bonus: -350, tag: "Универсальный" };
    }
    if (name.includes("fake_tls_auto") || name.includes("faketls")) {
      return { baseLatency: 42, bonus: -250, tag: "Стабильный Fake TLS" };
    }
    if (name.includes("game filter")) {
      return { baseLatency: 75, bonus: 400, tag: "Не для веб-трекеров" };
    }
    return { baseLatency: 50, bonus: 0, tag: "Стандартный" };
  }

  // 6. ДЛЯ ВСЕХ ОСТАЛЬНЫХ / УНИВЕРСАЛЬНЫХ («Все сайты», «Общий»)
  if (targetLower === "все сайты" || targetLower === "общий") {
    if (name === "universal v5" || (name.includes("universal") && name.includes("v5"))) {
      return { baseLatency: 32, bonus: -600, tag: "★ Флагманский универсальный (все сайты)" };
    }
    if (
      name === "default multisplit_sni" ||
      (name.includes("default multisplit_sni") && !name.includes("game filter"))
    ) {
      return { baseLatency: 34, bonus: -500, tag: "★ Полное покрытие (SoundCloud, Rutracker, Discord)" };
    }
    if (name.includes("circular") && name.includes("v2")) {
      return { baseLatency: 38, bonus: -400, tag: "Адаптивный circular v2" };
    }
    if (name.includes("circular")) {
      return { baseLatency: 42, bonus: -300, tag: "Адаптивный circular" };
    }
    if (name.includes("fake_tls_auto_11") || name.includes("fake_tls_auto")) {
      return { baseLatency: 44, bonus: -250, tag: "Fake TLS Auto" };
    }
    if (name.includes("game filter")) {
      return { baseLatency: 80, bonus: 500, tag: "Только для игр" };
    }
    return { baseLatency: 55, bonus: 0, tag: "Базовый" };
  }

  if (name.includes("universal") || name.includes("v5")) {
    return { baseLatency: 50, bonus: -200, tag: "Универсальный" };
  }
  if (name.includes("game filter")) {
    return { baseLatency: 40, bonus: -100, tag: "Фильтр трафика" };
  }
  if (name.includes("default") || name.includes("general")) {
    return { baseLatency: 55, bonus: -50, tag: "Базовый" };
  }

  return { baseLatency: 70, bonus: 0, tag: "Запасной" };
}

// Ключ в localStorage для сохранения топ-5 конкретного таргета
function storageKeyForTarget(target: string): string {
  return `pp.top5.${target}`;
}

// Расчёт общего балла качества (чем меньше, тем лучше)
function calculateScore(item: {
  latencyMs: number;
  status: "ok" | "slow" | "failed";
  failCount: number;
  bonus: number;
}): number {
  let score = item.latencyMs + item.bonus;
  if (item.status === "failed") score += 10000;
  if (item.status === "slow") score += 300;
  score += item.failCount * 2500;
  return Math.round(score);
}

export function loadStoredTop5(target: string): ProfileScore[] | null {
  try {
    const raw = localStorage.getItem(storageKeyForTarget(target));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed as ProfileScore[];
    }
  } catch {
    return null;
  }
  return null;
}

export function saveStoredTop5(target: string, top5: ProfileScore[]): void {
  try {
    localStorage.setItem(storageKeyForTarget(target), JSON.stringify(top5));
  } catch {
    // игнорируем квоты хранилища
  }
}

/**
 * Строит или возвращает сохранённый Топ-5 профилей для конкретного приложения.
 * Профили сортируются по качеству (задержка + пригодность для приложения + отсутствие сбоев).
 * Профиль с рангом 1 является наилучшим (№1) для этого приложения.
 */
export function getTop5Profiles(target: string, availablePresets: PresetInfo[]): ProfileScore[] {
  if (availablePresets.length === 0) return [];

  // Проверяем, есть ли уже сохранённый топ в localStorage
  const stored = loadStoredTop5(target);
  const availableNames = new Set(availablePresets.map((p) => p.name));

  // Получаем текущий выбранный пресет из дефолтов
  let savedDefault = "";
  try {
    savedDefault = localStorage.getItem(`pp.def.${target}`) || "";
  } catch {
    savedDefault = "";
  }

  if (stored && stored.length > 0) {
    // Оставляем только те, что реально присутствуют в доступных пресетах
    const valid = stored.filter((item) => availableNames.has(item.name));
    if (valid.length >= Math.min(TOP_LIMIT, availablePresets.length)) {
      // Актуализируем флаг isDefault
      const currentDefault = savedDefault || valid[0]?.name;
      const refreshed = valid.map((item, idx) => ({
        ...item,
        rank: idx + 1,
        isDefault: item.name === currentDefault,
      }));
      return refreshed.slice(0, TOP_LIMIT);
    }
  }

  // Строим рейтинг с нуля
  const candidates: Array<{
    preset: PresetInfo;
    baseLatency: number;
    bonus: number;
    tag: string;
    failCount: number;
    status: "ok" | "slow" | "failed";
  }> = [];

  for (const preset of availablePresets) {
    const evalResult = evaluatePresetSuitability(target, preset);
    candidates.push({
      preset,
      baseLatency: evalResult.baseLatency,
      bonus: evalResult.bonus,
      tag: evalResult.tag,
      failCount: 0,
      status: "ok",
    });
  }

  // Сортируем по вычисленному баллу
  candidates.sort((a, b) => {
    const scoreA = calculateScore({
      latencyMs: a.baseLatency,
      status: a.status,
      failCount: a.failCount,
      bonus: a.bonus,
    });
    const scoreB = calculateScore({
      latencyMs: b.baseLatency,
      status: b.status,
      failCount: b.failCount,
      bonus: b.bonus,
    });
    return scoreA - scoreB;
  });

  const activeName = savedDefault || candidates[0]?.preset.name || "";
  const topList: ProfileScore[] = candidates.slice(0, TOP_LIMIT).map((c, idx) => {
    const score = calculateScore({
      latencyMs: c.baseLatency,
      status: c.status,
      failCount: c.failCount,
      bonus: c.bonus,
    });
    return {
      name: c.preset.name,
      target,
      latencyMs: c.baseLatency,
      status: c.status,
      failCount: c.failCount,
      lastTested: Date.now(),
      rank: idx + 1,
      isDefault: c.preset.name === activeName,
      tag: c.tag,
      score,
    };
  });

  // Если выбранный пользователем профиль не попал в топ-5 (например, редкий ручной выбор),
  // ставим первый как default
  if (!topList.some((t) => t.isDefault) && topList.length > 0) {
    topList[0].isDefault = true;
  }

  saveStoredTop5(target, topList);
  return topList;
}

/**
 * Возвращает имя наилучшего профиля (№1) для приложения.
 */
export function getBestProfileForTarget(target: string, presets: PresetInfo[]): string {
  const top5 = getTop5Profiles(target, presets);
  const defaultItem = top5.find((p) => p.isDefault);
  if (defaultItem) return defaultItem.name;
  return top5[0]?.name || presets[0]?.name || "";
}

/**
 * Смена активного профиля внутри Топ-5 (по клику пользователя или при переключении).
 */
export function setActiveProfileInTop5(
  target: string,
  presetName: string,
  presets: PresetInfo[],
): ProfileScore[] {
  const current = getTop5Profiles(target, presets);
  const updated = current.map((p) => ({
    ...p,
    isDefault: p.name === presetName,
  }));
  try {
    localStorage.setItem(`pp.def.${target}`, presetName);
  } catch {
    // ignore
  }
  saveStoredTop5(target, updated);
  return updated;
}

export interface FailoverResult {
  target: string;
  failedProfile: string;
  nextBestProfile: string;
  newRank: number;
  latencyMs: number;
  top5: ProfileScore[];
}

/**
 * Обработка сбоя профиля:
 * Фиксирует сбой текущего профиля (№1), увеличивает failCount, пересчитывает рейтинг,
 * и автоматически переключается на 2-й самый лучший профиль из сохранённого Топ-5!
 */
export function reportProfileFailure(
  target: string,
  failedPresetName: string,
  availablePresets: PresetInfo[],
): FailoverResult | null {
  const currentTop5 = getTop5Profiles(target, availablePresets);
  if (currentTop5.length <= 1) return null;

  // Находим сбойный профиль
  const failedItem = currentTop5.find((p) => p.name === failedPresetName);
  if (!failedItem) {
    // Если его нет в топ-5, берём первый активный
    return null;
  }

  // Обновляем параметры сбойного профиля
  failedItem.failCount += 1;
  failedItem.status = "failed";
  failedItem.latencyMs += 150; // штраф за сбой
  failedItem.score = calculateScore({
    latencyMs: failedItem.latencyMs,
    status: failedItem.status,
    failCount: failedItem.failCount,
    bonus: 500,
  });

  // Пересортировываем список: профили со сбоем уходят вниз,
  // следующий лучший профиль (прежний №2) поднимается наверх!
  const sorted = [...currentTop5].sort((a, b) => a.score - b.score);

  // Переназначаем ранги 1..5
  const newBest = sorted[0];
  const reindexed = sorted.map((item, idx) => ({
    ...item,
    rank: idx + 1,
    isDefault: item.name === newBest.name,
  }));

  // Сохраняем новый выбор как дефолт
  try {
    localStorage.setItem(`pp.def.${target}`, newBest.name);
  } catch {
    // ignore
  }
  saveStoredTop5(target, reindexed);

  return {
    target,
    failedProfile: failedPresetName,
    nextBestProfile: newBest.name,
    newRank: 1,
    latencyMs: newBest.latencyMs,
    top5: reindexed,
  };
}

/**
 * Обновление замеренной задержки для профилей на основе результатов реальных сетевых проб (/api/check/sites).
 * При получении низкого пинга (например, 28 мс для игры) профиль поднимается в топе!
 */
export function applyMeasuredLatency(
  target: string,
  presetName: string,
  realLatencyMs: number,
  status: "ok" | "slow" | "failed",
  availablePresets: PresetInfo[],
): ProfileScore[] {
  const currentTop5 = getTop5Profiles(target, availablePresets);
  const found = currentTop5.find((p) => p.name === presetName);

  if (found) {
    found.latencyMs = realLatencyMs;
    found.status = status;
    found.lastTested = Date.now();
    if (status === "ok") {
      found.failCount = Math.max(0, found.failCount - 1);
    } else if (status === "failed") {
      found.failCount += 1;
    }
    const evalData = evaluatePresetSuitability(target, { name: found.name, description: "" });
    found.score = calculateScore({
      latencyMs: found.latencyMs,
      status: found.status,
      failCount: found.failCount,
      bonus: evalData.bonus,
    });
  }

  // Пересортировываем
  const sorted = [...currentTop5].sort((a, b) => a.score - b.score);
  const defaultName = sorted.find((p) => p.isDefault)?.name || sorted[0].name;

  const refreshed = sorted.map((item, idx) => ({
    ...item,
    rank: idx + 1,
    isDefault: item.name === defaultName,
  }));

  saveStoredTop5(target, refreshed);
  return refreshed;
}

/**
 * Пакетное обновление Топ-5 для всех приложений по результатам проверки сайтов.
 */
export function updateAllRankingsFromCheckResults(
  results: SiteCheckResult[],
  targets: string[],
  presets: PresetInfo[],
): Record<string, ProfileScore[]> {
  const resultMap = new Map<string, SiteCheckResult>();
  for (const r of results) {
    resultMap.set(r.domain, r);
  }

  const updatedMap: Record<string, ProfileScore[]> = {};

  for (const target of targets) {
    const probe = targetProbe(target);
    const check = probe ? resultMap.get(probe) : undefined;
    const targetPresets = presets.filter(
      (p) => (p.targets && p.targets.includes(target)) || isUniversal(p.name),
    );
    if (targetPresets.length === 0) continue;

    const currentTop = getTop5Profiles(target, targetPresets);
    const active = currentTop.find((p) => p.isDefault) || currentTop[0];

    if (check && active) {
      const ms = typeof check.ms === "number" && check.ms > 0 ? check.ms : check.status === "ok" ? 35 : 180;
      const updated = applyMeasuredLatency(target, active.name, ms, check.status, targetPresets);
      updatedMap[target] = updated;
    } else {
      updatedMap[target] = currentTop;
    }
  }

  return updatedMap;
}
