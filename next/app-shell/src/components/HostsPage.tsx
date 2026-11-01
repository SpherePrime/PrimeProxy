import { useCallback, useEffect, useMemo, useState } from "react";
import {
  applyHosts,
  fetchHostsFile,
  HostsFileResponse,
  HostsApplyResponse,
} from "../api";
import {
  IconCheck,
  IconChevron,
  IconClose,
  IconFile,
  IconLock,
  IconRefresh,
  IconUnlock,
  IconWarning,
} from "./Icons";
import { ServiceBadge } from "./ServiceBadge";
import { HelpTip } from "./HelpTip";
import { PageHeader } from "./PageHeader";
import "../styles/hosts.css";

// Страница «Разблокировка»: домены сервисов пишутся в файл hosts на
// зарезервированный локальный адрес 127.0.0.2 (приём семейства zapret:
// трафик к такому адресу уходит мимо DPI). Пользователь работает целыми
// сервисами — одна кнопка на сервис, без галок по каждому домену.

interface Service {
  id: string;
  title: string;
  note: string;
  domains: string[];
}

interface ServiceCategory {
  title: string;
  services: Service[];
}

const CATEGORIES: ServiceCategory[] = [
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

const SERVICES: Service[] = CATEGORIES.flatMap((category) => category.services);
const BLOCK_ADDRESS = "127.0.0.2";

/** Сколько доменов сервиса уже стоит в блоке (для подписи «частично»). */
function countIn(set: Set<string>, domains: string[]): number {
  return domains.reduce((total, domain) => total + (set.has(domain) ? 1 : 0), 0);
}

export function HostsPage() {
  const [file, setFile] = useState<HostsFileResponse | null>(null);
  // Желаемое содержимое блока: стартует из файла и меняется переключателями.
  // Иначе «Применить» стирало бы строки, которые пользователь уже добавил.
  const [desired, setDesired] = useState<Set<string>>(new Set());
  const [loaded, setLoaded] = useState(false);
  const [search, setSearch] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [applied, setApplied] = useState<HostsApplyResponse | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await fetchHostsFile();
      setFile(data);
      setDesired(new Set(data.managed_rows.map((row) => row[0])));
      setLoaded(true);
      setError(null);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Текущее содержимое файла: с ним сравниваем желаемое, чтобы показать
  // честную сводку «что изменится».
  const current = useMemo(
    () => new Set((file?.managed_rows ?? []).map((row) => row[0])),
    [file],
  );

  const added = useMemo(
    () => [...desired].filter((domain) => !current.has(domain)),
    [desired, current],
  );
  const removed = useMemo(
    () => [...current].filter((domain) => !desired.has(domain)),
    [desired, current],
  );
  const dirty = added.length > 0 || removed.length > 0;

  // Сервисы, которые уже целиком стоят в блоке hosts: их названия идут
  // в бегущую строку, а количество — в шапку и в полосу счётчиков.
  const unlockedNames = SERVICES.filter(
    (service) => countIn(current, service.domains) === service.domains.length,
  ).map((service) => service.title);
  const unlockedCount = unlockedNames.length;

  const query = search.trim().toLowerCase();
  const visibleCategories = useMemo(
    () =>
      CATEGORIES.map((category) => ({
        ...category,
        services: category.services.filter(
          (service) =>
            query === "" ||
            service.title.toLowerCase().includes(query) ||
            service.note.toLowerCase().includes(query) ||
            service.domains.some((domain) => domain.includes(query)),
        ),
      })).filter((category) => category.services.length > 0),
    [query],
  );

  // Сквозная нумерация карточек каталога: моно-номер в углу карточки,
  // как нумерация карточек в языке SpherePrime.
  const serviceIndex = useMemo(() => {
    const map = new Map<string, number>();
    let n = 0;
    for (const category of visibleCategories) {
      for (const service of category.services) {
        n += 1;
        map.set(service.id, n);
      }
    }
    return map;
  }, [visibleCategories]);

  const toggleService = (service: Service) => {
    setDesired((prev) => {
      const next = new Set(prev);
      const allIn = service.domains.every((domain) => next.has(domain));
      for (const domain of service.domains) {
        if (allIn) next.delete(domain);
        else next.add(domain);
      }
      return next;
    });
    setNotice(null);
  };

  const fillAll = () => {
    setDesired(new Set(SERVICES.flatMap((service) => service.domains)));
    setNotice(null);
  };

  const clearAll = () => {
    setDesired(new Set());
    setNotice(null);
  };

  const apply = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const rows = [...desired].map((domain): [string, string] => [domain, BLOCK_ADDRESS]);
      const result = await applyHosts(rows, true);
      setApplied(result);
      setConfirmOpen(false);
      setNotice(
        `Блок записан: ${result.blocked_count} строк, бэкап .primebak создан.`,
      );
      await load();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      setConfirmOpen(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <PageHeader
        index="02"
        group="Управление"
        title="Разблокировка"
        description="Сервисы открываются через файл hosts: их домены уходят на зарезервированный адрес 127.0.0.2 и обходят DPI."
        actions={
          <span className="chip tone-neutral">
            разблокировано {unlockedCount} из {SERVICES.length}
          </span>
        }
      />

      {error && (
        <div className="infobar error with-icon" role="alert">
          <IconClose />
          <span>{error}</span>
        </div>
      )}
      {notice && (
        <div className="infobar ok with-icon" role="status">
          <IconCheck />
          <span>{notice}</span>
        </div>
      )}

      {/* Бегущая строка с сервисами, которые уже стоят в блоке файла.
          Содержимое — реальное состояние hosts, ничего выдуманного. */}
      {unlockedNames.length > 0 && (
        <div className="marquee hosts-ticker" aria-hidden="true">
          <div className="marquee__track">
            {[0, 1].map((pass) =>
              unlockedNames.map((name) => (
                <span className="marquee__item" key={`${pass}-${name}`}>
                  {name}
                  <i>разблокирован</i>
                </span>
              )),
            )}
          </div>
        </div>
      )}

      <section className="card card--paper">
        <div className="card-head">
          <div>
            <span className="section-tag">
              <b>01 /</b> Файл hosts
            </span>
            <h2 className="card-title">
              Блок PrimeProxy в файле <em>hosts</em>
              <HelpTip label="что такое блок в hosts">
                hosts — системный файл, который сопоставляет домены и адреса.
                Мы пишем туда свой блок: домены сервисов указывают на
                127.0.0.2 — служебный локальный адрес. Остальные строки файла
                не трогаем, а перед первой записью рядом появляется копия
                .primebak.
              </HelpTip>
            </h2>
            <p className="card-note">
              Мы меняем только свой блок в файле — остальные строки hosts
              остаются нетронутыми. При первой записи рядом появляется копия
              <code> .primebak</code>.
            </p>
          </div>
          <div className="actions-row">
            {file && (
              <span className="chip tone-accent">
                {file.blocked_count} строк в блоке
              </span>
            )}
            <button
              type="button"
              className="btn ghost icon"
              onClick={() => void load()}
              aria-label="Перечитать файл hosts"
              title="Перечитать файл hosts и синхронизировать выбор"
            >
              <IconRefresh />
            </button>
          </div>
        </div>

        {file ? (
          <>
            <p className="plan-line">
              <span className="field-label">Путь</span>
              <code>{file.path}</code>
            </p>

            {file.error ? (
              <div className="infobar warn with-icon">
                <IconWarning />
                <span>{file.error}</span>
              </div>
            ) : file.managed_rows.length > 0 ? (
              <details className="hosts-details">
                <summary>
                  <span className="hosts-details-arrow" aria-hidden="true">
                    <IconChevron />
                  </span>
                  Показать строки блока ({file.managed_rows.length})
                </summary>
                <div className="term hosts-term">
                  <span className="term__bar">
                    <IconFile size={12} /> блок PrimeProxy ·{" "}
                    {file.managed_rows.length} строк
                  </span>
                  <pre
                    className="term__body"
                    aria-label="Записи PrimeProxy в файле hosts"
                  >
                    {file.managed_rows.map((row) => (
                      <span className="hosts-term__line" key={row[0]}>
                        <span className="hosts-term__key">{row[0]}</span>
                        <span className="hosts-term__arrow">{"  →  "}</span>
                        <span className="hosts-term__value">{row[1]}</span>
                      </span>
                    ))}
                  </pre>
                </div>
              </details>
            ) : (
              <div className="empty-state">
                <strong>Блок пуст</strong>
                <span>
                  В hosts пока нет записей PrimeProxy — выберите сервисы ниже.
                </span>
              </div>
            )}
          </>
        ) : (
          <div className="empty-state" role="status">
            <span className="spinner" />
            <span>Читаю файл hosts…</span>
          </div>
        )}
      </section>

      {/* Полоса счётчиков: все числа — реальное состояние страницы. */}
      <div className="stats-band">
        <div className="stats-band__grid">
          <div className="stat">
            <b>{unlockedCount}</b>
            <span>сервисов разблокировано</span>
          </div>
          <div className="stat">
            <b>{current.size}</b>
            <span>строк в блоке hosts</span>
          </div>
          <div className="stat">
            <b>{added.length}</b>
            <span>доменов добавится</span>
          </div>
          <div className="stat">
            <b>{removed.length}</b>
            <span>доменов уйдёт</span>
          </div>
        </div>
      </div>

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-tag">
              <b>02 /</b> Сервисы
            </span>
            <h2 className="card-title">
              Что <em>разблокировать</em>
              <HelpTip label="как работает разблокировка">
                Одна кнопка включает сервис целиком — все его домены сразу.
                Выбор подтягивается из текущего файла, поэтому «Применить»
                заменяет только блок PrimeProxy и не теряет то, что уже
                добавлено. Изменения вступят в силу сразу после записи.
              </HelpTip>
            </h2>
            <p className="card-note">
              Одна кнопка включает сервис целиком — все его домены сразу. Ниже
              видно, какие именно адреса уйдут в hosts.
            </p>
          </div>
          <span className="chip tone-neutral">
            выбрано {SERVICES.filter((s) => countIn(desired, s.domains) > 0).length} из{" "}
            {SERVICES.length}
          </span>
        </div>

        <div className="hosts-toolbar">
          <label className="search-box">
            <span className="sr-only">Поиск сервиса</span>
            <input
              className="input"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Найти сервис или домен…"
              aria-label="Поиск сервиса"
            />
            {search && (
              <button
                type="button"
                className="btn icon sm ghost"
                onClick={() => setSearch("")}
                aria-label="Очистить поиск"
              >
                <IconClose size={14} />
              </button>
            )}
          </label>
          <div className="hosts-toolbar-actions">
            <button
              type="button"
              className="btn ghost sm"
              onClick={fillAll}
              disabled={busy}
            >
              <IconUnlock size={14} />
              Разблокировать всё
            </button>
            <button
              type="button"
              className="btn ghost sm"
              onClick={clearAll}
              disabled={busy}
            >
              <IconLock size={14} />
              Очистить блок
            </button>
          </div>
        </div>

        {visibleCategories.length === 0 ? (
          <div className="empty-state">
            <strong>Ничего не найдено</strong>
            <span>Измените запрос или очистите поиск.</span>
          </div>
        ) : (
          visibleCategories.map((category) => (
            <div className="hosts-category" key={category.title}>
              <h3 className="hosts-category-title">{category.title}</h3>
              <div className="hosts-grid">
                {category.services.map((service) => {
                  const inDesired = countIn(desired, service.domains);
                  const total = service.domains.length;
                  const allOn = inDesired === total;
                  const partial = inDesired > 0 && !allOn;
                  const inFile = countIn(current, service.domains);
                  return (
                    <article
                      className={`svc ${allOn ? "on" : ""} ${partial ? "partial" : ""}`}
                      key={service.id}
                    >
                      <div className="svc-head">
                        <ServiceBadge name={service.title} size={32} />
                        <div className="svc-head-text">
                          <span className="card-index">
                            {String(serviceIndex.get(service.id) ?? 0).padStart(2, "0")}
                          </span>
                          <h4 className="svc-title">{service.title}</h4>
                          <p className="svc-note">{service.note}</p>
                        </div>
                        <span
                          className={`chip ${
                            allOn ? "tone-ok" : partial ? "tone-warn" : "tone-neutral"
                          }`}
                        >
                          {allOn
                            ? "разблокирован"
                            : partial
                              ? `частично ${inDesired} из ${total}`
                              : "выключен"}
                        </span>
                      </div>
                      <div className="svc-foot">
                        <button
                          type="button"
                          className={`btn ${allOn ? "ghost" : "accent"} sm`}
                          aria-pressed={allOn}
                          onClick={() => toggleService(service)}
                          disabled={busy}
                        >
                          {allOn ? <IconLock size={14} /> : <IconUnlock size={14} />}
                          {allOn
                            ? "Вернуть как было"
                            : partial
                              ? "Разблокировать полностью"
                              : "Разблокировать"}
                        </button>
                        <span className="svc-count">
                          {total} домен{total === 1 ? "" : total < 5 ? "а" : "ов"}
                          {inFile > 0 && inFile !== inDesired
                            ? ` · в файле ${inFile}`
                            : ""}
                        </span>
                      </div>
                      <details className="svc-domains">
                        <summary>
                          <span className="hosts-details-arrow" aria-hidden="true">
                            <IconChevron />
                          </span>
                          домены
                        </summary>
                        <div className="svc-domain-list">
                          {service.domains.map((domain) => (
                            <span
                              className={`svc-domain ${
                                desired.has(domain) ? "on" : ""
                              }`}
                              key={domain}
                            >
                              {domain}
                            </span>
                          ))}
                        </div>
                      </details>
                    </article>
                  );
                })}
              </div>
            </div>
          ))
        )}

        <div className="cta-block hosts-apply">
          <span className="cta-block__glyph cta-block__glyph--1" aria-hidden="true">
            ↗
          </span>
          {!loaded ? (
            <>
              <h2>Читаю файл hosts</h2>
              <p>Секунду — сверяю выбор с текущим содержимым блока.</p>
            </>
          ) : dirty ? (
            <>
              <h2>
                Применить <em>изменения</em> в hosts
              </h2>
              <p>
                {added.length > 0 ? `+${added.length} доменов` : "без добавлений"}
                {" · "}
                {removed.length > 0 ? `−${removed.length} доменов` : "без удалений"}
                {` · итог: ${desired.size} строк в блоке (сейчас ${current.size})`}
              </p>
            </>
          ) : (
            <>
              <h2>Изменений нет</h2>
              <p>Файл hosts уже соответствует выбору — записывать нечего.</p>
            </>
          )}
          <div className="cta-block__actions">
            {dirty && (
              <button
                type="button"
                className="btn ghost"
                onClick={() => void load()}
                disabled={busy}
              >
                Отменить изменения
              </button>
            )}
            <button
              type="button"
              className="btn accent"
              disabled={busy || !loaded || !dirty}
              onClick={() => setConfirmOpen(true)}
            >
              {busy ? <span className="spinner" /> : <IconCheck />}
              Применить в hosts
            </button>
          </div>
        </div>

        {confirmOpen && (
          <div className="infobar warn with-icon" role="alert">
            <IconWarning />
            <span>
              Изменить файл hosts? Будет создан бэкап <code>.primebak</code>,
              старые записи PrimeProxy заменятся новым набором ({desired.size}{" "}
              строк).
            </span>
            <div className="actions-row">
              <button
                type="button"
                className="btn accent"
                disabled={busy}
                onClick={() => void apply()}
              >
                {busy ? <span className="spinner" /> : <IconCheck />}
                {busy ? "Записываю…" : "Применить"}
              </button>
              <button
                type="button"
                className="btn ghost"
                onClick={() => setConfirmOpen(false)}
                disabled={busy}
              >
                Отмена
              </button>
            </div>
          </div>
        )}

        {applied && applied.managed_rows.length > 0 && (
          <div className="stats-row" aria-label="Записанные строки">
            <span className="chip tone-ok">
              записано {applied.blocked_count} строк
            </span>
            {applied.dropped.length > 0 && (
              <span className="chip tone-warn">
                конфликтов снято: {applied.dropped.length}
              </span>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
