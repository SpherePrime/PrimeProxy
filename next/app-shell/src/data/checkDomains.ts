export interface CheckGroup {
  title: string;
  domains: string[];
}

export const CHECK_GROUPS: CheckGroup[] = [
  { title: "Видео и стримы", domains: ["www.youtube.com", "youtu.be", "www.twitch.tv", "www.netflix.com"] },
  {
    title: "Соцсети",
    domains: ["instagram.com", "www.facebook.com", "x.com", "www.tiktok.com", "www.linkedin.com", "www.reddit.com"],
  },
  {
    title: "ИИ-сервисы",
    domains: ["chatgpt.com", "claude.ai", "gemini.google.com", "chat.deepseek.com", "www.perplexity.ai"],
  },
  {
    title: "Мессенджеры",
    domains: ["discord.com", "gateway.discord.gg", "telegram.org", "web.whatsapp.com", "signal.org"],
  },
  { title: "Игры", domains: ["store.steampowered.com", "www.roblox.com", "www.epicgames.com", "www.riotgames.com"] },
  {
    title: "Инфраструктура",
    domains: ["www.google.com", "www.cloudflare.com", "github.com", "www.speedtest.net", "www.apple.com"],
  },
  { title: "Разное", domains: ["soundcloud.com", "rutracker.org", "www.notion.so", "open.spotify.com"] },
];

export const ALL_DOMAINS = CHECK_GROUPS.flatMap((group) => group.domains);

export const STATUS_LABELS: Record<string, string> = {
  ok: "доступен",
  blocked: "блок",
  slow: "медленно",
};

export const STATUS_TONE: Record<string, string> = {
  ok: "chip--ok",
  blocked: "chip--fail",
  slow: "chip--warn",
};
