export interface CheckService {
  name: string;
  domain: string;
}

export interface CheckGroup {
  title: string;
  services: CheckService[];
}

export const CHECK_GROUPS: CheckGroup[] = [
  {
    title: "Видео и стримы",
    services: [
      { name: "YouTube", domain: "www.youtube.com" },
      { name: "Twitch", domain: "www.twitch.tv" },
      { name: "Netflix", domain: "www.netflix.com" },
    ],
  },
  {
    title: "Соцсети",
    services: [
      { name: "Instagram", domain: "www.instagram.com" },
      { name: "Facebook", domain: "www.facebook.com" },
      { name: "Twitter/X", domain: "x.com" },
      { name: "TikTok", domain: "www.tiktok.com" },
      { name: "LinkedIn", domain: "www.linkedin.com" },
      { name: "Reddit", domain: "www.reddit.com" },
    ],
  },
  {
    title: "ИИ-сервисы",
    services: [
      { name: "ChatGPT", domain: "chatgpt.com" },
      { name: "Claude", domain: "claude.ai" },
      { name: "Gemini", domain: "gemini.google.com" },
      { name: "DeepSeek", domain: "chat.deepseek.com" },
      { name: "Perplexity", domain: "www.perplexity.ai" },
    ],
  },
  {
    title: "Мессенджеры",
    services: [
      { name: "Discord", domain: "discord.com" },
      { name: "Telegram", domain: "telegram.org" },
      { name: "WhatsApp", domain: "web.whatsapp.com" },
      { name: "Signal", domain: "signal.org" },
    ],
  },
  {
    title: "Игры",
    services: [
      { name: "Steam", domain: "store.steampowered.com" },
      { name: "Roblox", domain: "www.roblox.com" },
      { name: "Epic Games", domain: "www.epicgames.com" },
      { name: "Riot Games", domain: "www.riotgames.com" },
    ],
  },
  {
    title: "Инфраструктура",
    services: [
      { name: "Google", domain: "www.google.com" },
      { name: "Cloudflare", domain: "www.cloudflare.com" },
      { name: "GitHub", domain: "github.com" },
      { name: "Speedtest", domain: "www.speedtest.net" },
      { name: "Apple", domain: "www.apple.com" },
    ],
  },
  {
    title: "Разное",
    services: [
      { name: "SoundCloud", domain: "soundcloud.com" },
      { name: "Rutracker", domain: "rutracker.org" },
      { name: "Notion", domain: "www.notion.so" },
      { name: "Spotify", domain: "open.spotify.com" },
    ],
  },
];

export const ALL_SERVICES = CHECK_GROUPS.flatMap((group) => group.services);
export const ALL_DOMAINS = ALL_SERVICES.map((service) => service.domain);

const NAME_BY_DOMAIN = new Map(ALL_SERVICES.map((service) => [service.domain, service.name]));

export function serviceName(domain: string): string {
  return NAME_BY_DOMAIN.get(domain) ?? domain;
}

export const STATUS_LABELS: Record<string, string> = {
  ok: "работает",
  blocked: "заблокирован",
  slow: "медленно",
};

export const STATUS_TONE: Record<string, string> = {
  ok: "chip--ok",
  blocked: "chip--fail",
  slow: "chip--warn",
};
