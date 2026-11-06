export interface Service {
  id: string;
  title: string;
  note: string;
  domains: string[];
}

export interface ServiceCategory {
  title: string;
  services: Service[];
}

export const CATEGORIES: ServiceCategory[] = [
  {
    title: "Видео",
    services: [
      {
        id: "youtube",
        title: "YouTube",
        note: "сайт, приложение, превью и видео",
        domains: [
          "youtube.com",
          "www.youtube.com",
          "m.youtube.com",
          "youtu.be",
          "ytimg.com",
          "i.ytimg.com",
          "googlevideo.com",
        ],
      },
      {
        id: "twitch",
        title: "Twitch",
        note: "стримы, чат и превью",
        domains: ["twitch.tv", "www.twitch.tv"],
      },
      {
        id: "netflix",
        title: "Netflix",
        note: "каталог и видео",
        domains: ["netflix.com", "www.netflix.com", "nflxvideo.net", "nflximg.net"],
      },
      {
        id: "vimeo",
        title: "Vimeo",
        note: "видео и плеер",
        domains: ["vimeo.com", "player.vimeo.com", "vimeocdn.com"],
      },
    ],
  },
  {
    title: "Соцсети",
    services: [
      {
        id: "instagram",
        title: "Instagram",
        note: "лента, сторис и картинки",
        domains: ["instagram.com", "www.instagram.com", "cdninstagram.com"],
      },
      {
        id: "facebook",
        title: "Facebook",
        note: "лента, видео и CDN",
        domains: ["facebook.com", "www.facebook.com", "m.facebook.com", "fbcdn.net"],
      },
      {
        id: "twitter",
        title: "Twitter/X",
        note: "лента, картинки и короткие ссылки",
        domains: ["x.com", "twitter.com", "t.co", "twimg.com"],
      },
      {
        id: "tiktok",
        title: "TikTok",
        note: "лента, видео и CDN",
        domains: ["tiktok.com", "www.tiktok.com", "tiktokcdn.com"],
      },
      {
        id: "linkedin",
        title: "LinkedIn",
        note: "лента, профили и картинки",
        domains: ["linkedin.com", "www.linkedin.com", "licdn.com"],
      },
      {
        id: "reddit",
        title: "Reddit",
        note: "лента, обсуждения и медиа",
        domains: ["reddit.com", "www.reddit.com", "redd.it", "redditstatic.com"],
      },
      {
        id: "pinterest",
        title: "Pinterest",
        note: "лента идей и картинки",
        domains: ["pinterest.com", "www.pinterest.com", "pinimg.com"],
      },
      {
        id: "snapchat",
        title: "Snapchat",
        note: "сообщения и истории",
        domains: ["snapchat.com", "www.snapchat.com", "sc-cdn.net"],
      },
    ],
  },
  {
    title: "ИИ-сервисы",
    services: [
      {
        id: "chatgpt",
        title: "ChatGPT",
        note: "чат, API и статика OpenAI",
        domains: ["chatgpt.com", "openai.com", "platform.openai.com", "oaistatic.com"],
      },
      {
        id: "anthropic",
        title: "Anthropic (Claude)",
        note: "Claude и API Anthropic",
        domains: ["claude.ai", "claude.com", "anthropic.com", "www.anthropic.com"],
      },
      {
        id: "deepseek",
        title: "DeepSeek",
        note: "чат и API",
        domains: ["deepseek.com", "chat.deepseek.com", "www.deepseek.com"],
      },
      {
        id: "gemini",
        title: "Gemini",
        note: "чат Google и DeepMind",
        domains: ["gemini.google.com", "bard.google.com", "deepmind.google"],
      },
      {
        id: "perplexity",
        title: "Perplexity",
        note: "поиск с ИИ",
        domains: ["perplexity.ai", "www.perplexity.ai"],
      },
      {
        id: "grok",
        title: "Grok",
        note: "чат xAI",
        domains: ["grok.com", "x.ai", "www.x.ai"],
      },
    ],
  },
  {
    title: "Мессенджеры",
    services: [
      {
        id: "discord",
        title: "Discord",
        note: "чат, голос и медиа",
        domains: [
          "discord.com",
          "discord.gg",
          "discordapp.com",
          "discordapp.net",
          "discord.media",
        ],
      },
      {
        id: "telegram",
        title: "Telegram",
        note: "мессенджер и веб-клиент",
        domains: ["telegram.org", "t.me", "web.telegram.org", "telegram.me"],
      },
      {
        id: "whatsapp",
        title: "WhatsApp",
        note: "веб-клиент и медиа",
        domains: ["whatsapp.com", "web.whatsapp.com", "whatsapp.net"],
      },
      {
        id: "signal",
        title: "Signal",
        note: "мессенджер и сайт",
        domains: ["signal.org", "www.signal.org"],
      },
      {
        id: "viber",
        title: "Viber",
        note: "звонки и сообщения",
        domains: ["viber.com", "www.viber.com", "cdn.viber.com"],
      },
      {
        id: "slack",
        title: "Slack",
        note: "рабочие чаты и файлы",
        domains: ["slack.com", "app.slack.com", "slack-edge.com"],
      },
      {
        id: "zoom",
        title: "Zoom",
        note: "встречи и вебинары",
        domains: ["zoom.us", "www.zoom.us", "zoomgov.com"],
      },
    ],
  },
  {
    title: "Игры",
    services: [
      {
        id: "steam",
        title: "Steam",
        note: "магазин, сообщество и загрузки",
        domains: [
          "store.steampowered.com",
          "steampowered.com",
          "steamcommunity.com",
          "steamstatic.com",
        ],
      },
      {
        id: "roblox",
        title: "Roblox",
        note: "игра, сайт и CDN",
        domains: ["roblox.com", "www.roblox.com", "rbxcdn.com"],
      },
      {
        id: "epic",
        title: "Epic Games",
        note: "магазин и Fortnite",
        domains: ["epicgames.com", "www.epicgames.com", "fortnite.com"],
      },
      {
        id: "riot",
        title: "Riot / Valorant",
        note: "League of Legends и Valorant",
        domains: [
          "riotgames.com",
          "www.riotgames.com",
          "leagueoflegends.com",
          "valorant.com",
        ],
      },
      {
        id: "ubisoft",
        title: "Ubisoft",
        note: "магазин и лаунчер",
        domains: ["ubisoft.com", "www.ubisoft.com", "ubisoftconnect.com"],
      },
      {
        id: "itch",
        title: "itch.io",
        note: "магазин инди-игр",
        domains: ["itch.io", "itch.zone"],
      },
    ],
  },
  {
    title: "Разное",
    services: [
      {
        id: "spotify",
        title: "Spotify",
        note: "музыка, подкасты и CDN",
        domains: ["spotify.com", "open.spotify.com", "scdn.co"],
      },
      {
        id: "soundcloud",
        title: "SoundCloud",
        note: "музыка и CDN",
        domains: ["soundcloud.com", "sndcdn.com"],
      },
      {
        id: "rutracker",
        title: "Rutracker",
        note: "торрент-трекер",
        domains: ["rutracker.org", "rutracker.net"],
      },
      {
        id: "notion",
        title: "Notion",
        note: "заметки и рабочие пространства",
        domains: ["notion.so", "notion.com"],
      },
      {
        id: "github",
        title: "GitHub",
        note: "репозитории, файлы и статика",
        domains: ["github.com", "githubusercontent.com", "githubassets.com"],
      },
      {
        id: "proton",
        title: "Proton Mail",
        note: "почта и вход",
        domains: ["proton.me", "mail.proton.me", "protonmail.com"],
      },
      {
        id: "amazon",
        title: "Amazon",
        note: "магазин и медиа",
        domains: ["amazon.com", "www.amazon.com", "media-amazon.com"],
      },
      {
        id: "ebay",
        title: "eBay",
        note: "магазин и статика",
        domains: ["ebay.com", "www.ebay.com", "ebaystatic.com"],
      },
      {
        id: "medium",
        title: "Medium",
        note: "статьи и картинки",
        domains: ["medium.com", "cdn.medium.com"],
      },
      {
        id: "patreon",
        title: "Patreon",
        note: "подписки авторов",
        domains: ["patreon.com", "www.patreon.com", "patreonusercontent.com"],
      },
      {
        id: "speedtest",
        title: "Speedtest",
        note: "замеры скорости",
        domains: ["speedtest.net", "www.speedtest.net"],
      },
      {
        id: "coursera",
        title: "Coursera",
        note: "курсы и лекции",
        domains: ["coursera.org", "www.coursera.org"],
      },
      {
        id: "duolingo",
        title: "Duolingo",
        note: "языки и упражнения",
        domains: ["duolingo.com", "www.duolingo.com"],
      },
      {
        id: "bbc",
        title: "BBC",
        note: "новости и видео",
        domains: ["bbc.com", "www.bbc.com", "bbci.co.uk"],
      },
      {
        id: "tor",
        title: "Tor Project",
        note: "сайт проекта и загрузки",
        domains: ["torproject.org", "www.torproject.org"],
      },
      {
        id: "mullvad",
        title: "Mullvad",
        note: "VPN-сервис и сайт",
        domains: ["mullvad.net", "www.mullvad.net"],
      },
    ],
  },
];

export const SERVICES: Service[] = CATEGORIES.flatMap((category) => category.services);
export const BLOCK_ADDRESS = "127.0.0.2";

export function countIn(set: Set<string>, domains: string[]): number {
  return domains.reduce((total, domain) => total + (set.has(domain) ? 1 : 0), 0);
}
