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
