// Адрес Rust-ядра (sidecar primecore-server).
const BASE = import.meta.env.VITE_API || "http://127.0.0.1:7290";

export const API = BASE;

/**
 * Живо ли ядро: `GET /health`.
 *
 * Ответ нужен панели, чтобы показывать настоящее состояние связи, а не
 * декоративную точку. Таймаут короткий — проверка идёт в фоне по таймеру.
 */
export async function fetchHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${BASE}/health`, {
      signal: AbortSignal.timeout(2500),
    });
    return response.ok;
  } catch (_) {
    return false;
  }
}

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
  // Целевые сервисы пресета (["YouTube"], ["Discord"], ["Общий"]…); бэкенд
  // пишет их в параллельной ветке, пока поле может отсутствовать.
  targets?: string[];
}

// `GET /api/ws/privilege` — состояние прав администратора на стороне ядра.
export interface PrivilegeInfo {
  granted: boolean;
  needs_prompt: boolean;
  helper: string[];
  sock?: string;
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
  names?: string[] | null;
  qnum: number | null;
  root: boolean;
  /** Платформа ядра: `windows`, `linux`, … — от неё зависит текст и поля. */
  platform?: string;
  /** Движок обхода: `winws2` на Windows, `nfqws2` на unix. */
  engine?: string;
}

export interface WsLogs {
  lines: string[];
  total: number;
  dropped: number;
}

export interface WsStartResult {
  ok: boolean;
  pid?: number;
  names?: string[];
}

// Ошибка старта: помимо сообщения может нести «хвост» вывода dry-run.
export class WsStartError extends Error {
  tail?: string;
  constructor(message: string, tail?: string) {
    super(message);
    this.name = "WsStartError";
    this.tail = tail;
  }
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

// Состояние прав: запрашивается один раз при монтировании страницы.
export async function fetchPrivilege(): Promise<PrivilegeInfo> {
  const response = await fetch(`${BASE}/api/ws/privilege`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

// Выдача прав через pkexec — на экране появляется системный диалог пароля.
// Диалог может висеть долго, поэтому таймаут щедрый (90 с).
export async function grantPrivilege(): Promise<{ ok: boolean; helper?: string[] }> {
  const response = await fetch(`${BASE}/api/ws/privilege/grant`, {
    method: "POST",
    signal: AbortSignal.timeout(90_000),
  });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export async function fetchPreset(name: string): Promise<WsPresetDetail> {
  const response = await fetch(`${BASE}/api/ws/preset?name=${encodeURIComponent(name)}`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

// Старт: names — по одному выбранному пресету от каждой включённой группы.
// 400 может нести tail (вывод dry-run), 409 — «нет прав» либо «уже запущено».
export async function startWs(
  names: string[],
  qnum: number,
  hostlistMode: HostlistMode,
): Promise<WsStartResult> {
  const response = await fetch(`${BASE}/api/ws/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ names, qnum, hostlist_mode: hostlistMode }),
  });
  if (!response.ok) {
    let message = `сервер ответил ${response.status}`;
    let tail: string | undefined;
    try {
      const body = await response.json();
      if (typeof body.error === "string") message = body.error;
      if (typeof body.tail === "string") tail = body.tail;
    } catch (_) {
      // тело не json — покажем просто статус
    }
    throw new WsStartError(message, tail);
  }
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

// ---------------------------------------------------------------------------
// Проверка доступности сайтов (/api/check/*).
// ---------------------------------------------------------------------------

export type SiteStatus = "ok" | "blocked" | "slow";

export interface SiteCheckResult {
  domain: string;
  status: SiteStatus;
  ms: number;
}

export interface CheckSitesStatus {
  done: boolean;
  results: SiteCheckResult[];
}

// Запуск фоновой проверки: сервер сам опрашивает домены, статус — по /status.
export async function fetchCheckSites(
  domains: string[],
): Promise<{ ok: boolean; total: number }> {
  const response = await fetch(`${BASE}/api/check/sites`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domains }),
  });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export async function fetchCheckStatus(): Promise<CheckSitesStatus> {
  const response = await fetch(`${BASE}/api/check/sites/status`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

// ---------------------------------------------------------------------------
// DNS: текущие серверы, проба запроса, установка на интерфейс.
// ---------------------------------------------------------------------------

export interface DohEntry {
  server: string;
  url: string;
}

export interface DnsCurrent {
  system: Array<{ server: string; kind: string }>;
  /** Известные DoH-серверы: пара «адрес + шаблон запроса». */
  doh: DohEntry[];
}

export async function fetchDnsCurrent(): Promise<DnsCurrent> {
  const response = await fetch(`${BASE}/api/dns/current`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export interface DnsQueryResult {
  ok: boolean;
  addresses?: string[];
  ms?: number;
  error?: string;
}

export async function queryDns(domain: string, server: string): Promise<DnsQueryResult> {
  const response = await fetch(`${BASE}/api/dns/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, server }),
  });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

// 409 — нет прав (нужен polkit), 500 — ошибка применения на интерфейсе.
export class DnsSetError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "DnsSetError";
    this.status = status;
  }
}

export async function setDns(servers: string[], ifname: string): Promise<{ ok: boolean }> {
  const response = await fetch(`${BASE}/api/dns/set`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ servers, ifname }),
  });
  if (!response.ok) {
    const cause = await errorFrom(response);
    throw new DnsSetError(cause.message, response.status);
  }
  return response.json();
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Telegram: локальный прокси (SOCKS5 → WSS к фронту Cloudflare).
// ---------------------------------------------------------------------------

export interface TgProxyStatus {
  configured: boolean;
  host: string;
  port: number;
  running: boolean;
  /** Свой домен воркера или пометка про встроенные фронты. */
  front: string | null;
  started_at: number | null;
  connections: number;
  active: number;
  bytes_up: number;
  bytes_down: number;
  last_front: string;
  last_error: string;
  /** Готовая ссылка tg://socks — по ней Telegram подключается в один клик. */
  link: string;
  saved_at: number | null;
}

export async function fetchTgProxy(): Promise<TgProxyStatus> {
  const response = await fetch(`${BASE}/api/tg/proxy`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export async function startTgProxy(
  host: string,
  port: number,
  domain: string,
): Promise<TgProxyStatus & { ok: boolean }> {
  const response = await fetch(`${BASE}/api/tg/proxy/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host, port, domain }),
  });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export async function stopTgProxy(): Promise<{ ok: boolean; stopped: boolean }> {
  const response = await fetch(`${BASE}/api/tg/proxy/stop`, { method: "POST" });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export interface TgWorkerData {
  code: string;
  dns: string;
  path: string;
}

/** Код воркера и DNS-записи для своего домена Cloudflare. */
export async function fetchTgWorker(): Promise<TgWorkerData> {
  const response = await fetch(`${BASE}/api/tg/proxy/worker`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

// Разблокировка (файл hosts), анализ лога, каталог фейков.
// ---------------------------------------------------------------------------

export interface HostsFileResponse {
  path: string;
  content: string | null;
  managed_rows: [string, string][];
  blocked_count: number;
  error?: string;
}

export async function fetchHostsFile(): Promise<HostsFileResponse> {
  const response = await fetch(`${BASE}/api/hosts/file`);
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export interface HostsApplyResponse {
  ok: boolean;
  path: string;
  managed_rows: [string, string][];
  dropped: string[];
  blocked_count: number;
}

export async function applyHosts(
  rows: [string, string][],
  allowIpv6: boolean,
): Promise<HostsApplyResponse> {
  const response = await fetch(`${BASE}/api/hosts/apply`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rows, allow_ipv6: allowIpv6 }),
  });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export interface LogAnalyzeResponse {
  summary: {
    lines: number;
    profiles: { id: number; name: string }[];
    hostlists: { path: string; hosts: number }[];
    ipsets: { path: string; subnets: number }[];
    packets_total: number;
    connections_total: number;
    positive_checks_total: number;
    unparsed_blocks: number;
    unrecognized_packet_lines: number;
  };
  connections: Array<{
    proto: string;
    remote_ip: string;
    remote_port: number;
    hostname: string;
    l7proto: string;
    profiles: string[];
    packets_total: number;
    packets_out: number;
    packets_in: number;
    verdicts: { kind: string; count: number }[];
    positive_lists: string[];
  }>;
  file_path?: string;
  file_bytes?: number;
}

export async function analyzeLogText(content: string): Promise<LogAnalyzeResponse> {
  const response = await fetch(`${BASE}/api/logs/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content }),
  });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}

export async function analyzeLogFile(path: string): Promise<LogAnalyzeResponse> {
  const response = await fetch(`${BASE}/api/logs/analyze_file`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path }),
  });
  if (!response.ok) throw await errorFrom(response);
  return response.json();
}
