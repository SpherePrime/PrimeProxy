// Мок ядра PrimeProxy для визуальной проверки страницы «Обход».
import http from "node:http";

const targets = {
  "Все сайты": 6,
  "Общий": 3,
  "YouTube": 4,
  "Twitch": 2,
  "Instagram": 3,
  "Facebook": 2,
  "Twitter/X": 2,
  "TikTok": 2,
  "LinkedIn": 2,
  "Discord": 3,
  "Telegram": 3,
  "WhatsApp": 2,
  "ChatGPT": 3,
  "Anthropic": 2,
  "Gemini": 2,
  "DeepSeek": 2,
  "Steam": 3,
  "Roblox": 2,
  "Epic Games": 2,
  "Riot/Valorant": 2,
  "SoundCloud": 2,
  "Google": 3,
  "Cloudflare": 2,
  "GitHub": 3,
  "Торренты": 2,
  "Notion": 2,
};

const presets = [];
for (const [target, count] of Object.entries(targets)) {
  for (let i = 1; i <= count; i += 1) {
    presets.push({
      name: `${target.toLowerCase().replace(/[^a-zа-я]/g, "")}-${i}`,
      description: i === 1 ? `основной пресет для ${target}` : `альтернатива ${i} для ${target}`,
      targets: [target],
    });
  }
}

const lines = [
  "[core] primecore-server 0.1.0",
  "[ws] движок winws2 найден: resources/bin/winws2.exe",
  "[ws] профили: 12, универсальных пресетов: 9",
  "[ws] hostlist: lists/russia-blacklist.txt (18422 домена)",
  "[ws] старт: qnum=300 hostlist_mode=none",
  "[ws] pid=21844, WinDivert загружен",
  "[ws] трафик проходит через выбранные стратегии",
];

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Content-Type", "application/json");
  if (url.pathname === "/api/ws/presets") {
    res.end(JSON.stringify({ presets }));
  } else if (url.pathname === "/api/ws/status") {
    res.end(
      JSON.stringify({
        running: true,
        pid: 21844,
        preset: "youtube-1",
        names: ["youtube-1", "anthropic-1"],
        qnum: 300,
        root: true,
        platform: "windows",
        engine: "winws2",
      }),
    );
  } else if (url.pathname === "/api/ws/privilege") {
    res.end(JSON.stringify({ granted: true, needs_prompt: false, helper: [] }));
  } else if (url.pathname === "/api/ws/logs") {
    const since = Number(url.searchParams.get("since") ?? 0);
    res.end(JSON.stringify({ lines: lines.slice(since), total: lines.length, dropped: 0 }));
  } else if (url.pathname === "/api/ws/preset") {
    res.end(
      JSON.stringify({
        text: "",
        stripped: "",
        plan: { exe: "winws2.exe", args: ["--wf-tcp=80,443", "--filter-tcp=443"], cwd: ".", pidfile: "ws.pid" },
      }),
    );
  } else {
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "нет такого эндпоинта" }));
  }
});

server.listen(7391, "127.0.0.1", () => console.log("mock core on 7391"));
