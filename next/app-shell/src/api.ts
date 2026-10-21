// Адрес Rust-ядра (sidecar primecore-server).
const BASE = import.meta.env.VITE_API || "http://127.0.0.1:7290";

export const API = BASE;

export interface ProviderData {
  desc?: string;
  icon?: string;
  color?: string;
  dnssec?: boolean;
  status?: string;
  doh?: string;
  dot?: string;
  local_proxy?: string;
  ipv4?: string[];
  ipv6?: string[];
}

export interface Providers {
  [group: string]: { [name: string]: ProviderData };
}

export interface ServerCard {
  server: string;
  status: string;
  note: string;
  best: string;
}

export interface Verdict {
  kind: string;
  detail: string;
}

export interface ServerCheckResponse {
  text: string;
  verdict: Verdict;
  cards: ServerCard[];
}

// Порядок и подписи групп — как в python-странице (provider_grid).
export const GROUP_ORDER = ["Шифрованные", "Популярные", "Безопасные", "Малоизвестные", "Для ИИ"] as const;

export const GROUP_TITLES: Record<string, string> = {
  Шифрованные: "Шифрованные",
  Популярные: "Популярные",
  Безопасные: "Безопасные",
  Малоизвестные: "Малоизвестные",
  "Для ИИ": "Для ИИ",
};

// Фильтры страницы — как в python (_filter_title).
export const FILTERS = [
  { key: "all", title: "Все" },
  { key: "blocked", title: "Блокируются" },
  { key: "at_risk", title: "В зоне риска" },
] as const;

export async function fetchProviders(): Promise<Providers> {
  const response = await fetch(`${BASE}/api/dns/providers`);
  if (!response.ok) throw new Error(`сервер ответил ${response.status}`);
  const body = await response.json();
  return body.providers;
}

export async function fetchServerCheck(domain: string): Promise<ServerCheckResponse> {
  const response = await fetch(`${BASE}/api/dns/server_check?domain=${encodeURIComponent(domain)}`);
  if (!response.ok) throw new Error(`сервер ответил ${response.status}`);
  return response.json();
}

// ---------------------------------------------------------------------------
// Обход (nfqws2/zapret2) — контракт /api/ws/*.
// ---------------------------------------------------------------------------

export interface PresetInfo {
  name: string;
  description: string;
}

export interface WsPresetPlan {
  exe: string;
  args: string[];
  cwd: string;
  pidfile: string;
}

export interface WsPresetDetail {
  text: string;
  stripped: string;
  plan: WsPresetPlan;
}

export type HostlistMode = "none" | "hostlist" | "autohostlist";

export interface WsStatus {
  running: boolean;
  pid: number | null;
  preset: string | null;
  qnum: number | null;
  root: boolean;
}

export interface WsLogs {
  lines: string[];
  total: number;
  dropped: number;
}

export interface WsStartResult {
  ok: boolean;
  pid?: number;
}

// Читает {"error":"..."} из тела ошибки, иначе — статус ответа.
async function errorFrom(response: Response): Promise<Error> {
  try {
    const body = await response.json();
    if (body && typeof body.error === "string") return new Error(body.error);
  } catch (_) {
    // тело не json — покажем просто статус
  }
  return new Error(`сервер ответил ${response.status}`);
}

export async function fetchPresets(): Promise<PresetInfo[]> {
  const response = await fetch(`${BASE}/api/ws/presets`);
  if (!response.ok) throw await errorFrom(response);
  const body = await response.json();
  return body.presets ?? [];
}

export async function fetchPreset(name: string): Promise<WsPresetDetail> {
  const response = await fetch(`${BASE}/api/ws/preset?name=${encodeURIComponent(name)}`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export async function startWs(
  name: string,
  qnum: number,
  hostlistMode: HostlistMode,
): Promise<WsStartResult> {
  const response = await fetch(`${BASE}/api/ws/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, qnum, hostlist_mode: hostlistMode }),
  });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export async function stopWs(): Promise<{ ok: boolean }> {
  const response = await fetch(`${BASE}/api/ws/stop`, { method: "POST" });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export async function fetchWsStatus(): Promise<WsStatus> {
  const response = await fetch(`${BASE}/api/ws/status`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export async function fetchWsLogs(since: number): Promise<WsLogs> {
  const response = await fetch(`${BASE}/api/ws/logs?since=${since}`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}
