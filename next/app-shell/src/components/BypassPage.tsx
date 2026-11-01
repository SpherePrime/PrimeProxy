import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  fetchPresets,
  fetchPreset,
  fetchPrivilege,
  fetchWsLogs,
  fetchWsStatus,
  grantPrivilege,
  startWs,
  stopWs,
  HostlistMode,
  PresetInfo,
  PrivilegeInfo,
  WsPresetDetail,
  WsStartError,
  WsStatus,
} from "../api";
import {
  PresetGroup,
  ProfileCard,
  UniversalBlock,
  buildGroups,
  categorizeProfiles,
  groupMatches,
  isEnabled,
  isUniversal,
  loadDefaults,
  loadEnabled,
  saveDefault,
  saveEnabled,
} from "./PresetGroups";
import {
  IconClose,
  IconInfo,
  IconPlay,
  IconPower,
  IconSearch,
  IconShieldCheck,
  IconStop,
  IconUnlock,
  IconWarning,
} from "./Icons";
import { PageHeader } from "./PageHeader";
import "../styles/bypass.css";

// Страница «Обход» — управление движком обхода: группы пресетов по сервисам,
// права администратора (на unix — polkit один раз при старте, на Windows —
// запуск от имени администратора), запуск/останов, журнал.

// Режимы списков — подписи как в python-эталоне запуска.
const HOSTLIST_MODES: Array<{ key: HostlistMode; title: string }> = [
  { key: "none", title: "Без списков" },
  { key: "hostlist", title: "По спискам" },
  { key: "autohostlist", title: "Автосписок" },
];

// Режим профилей: «all» — один универсальный пресет на весь трафик,
// «profiles» — только выбранные сервисы. Режимы не смешиваются, поэтому в
// запуск уходит ровно то, что видно включённым на экране.
type ProfileMode = "all" | "profiles";

const PROFILE_MODE_KEY = "pp.mode";

function readProfileMode(): ProfileMode {
  try {
    return localStorage.getItem(PROFILE_MODE_KEY) === "profiles"
      ? "profiles"
      : "all";
  } catch (_) {
    // localStorage недоступен — работаем с режимом по умолчанию
    return "all";
  }
}

const LOG_KEEP = 500; // сколько строк журнала держим в памяти вида

export function BypassPage() {
  const [presets, setPresets] = useState<PresetInfo[]>([]);
  const [search, setSearch] = useState("");
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const [profileMode, setProfileMode] = useState<ProfileMode>(readProfileMode);
  const [qnum, setQnum] = useState("300");
  const [mode, setMode] = useState<HostlistMode>("none");
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState("");
  const [pollError, setPollError] = useState("");
  const [logLines, setLogLines] = useState<string[]>([]);
  const [dropped, setDropped] = useState<number | null>(null);

  // Состояние движка: обновляется поллингом /api/ws/status.
  const [status, setStatus] = useState<WsStatus | null>(null);

  // Права администратора: состояние с /api/ws/privilege + процесс выдачи.
  const [privilege, setPrivilege] = useState<PrivilegeInfo | null>(null);
  const [granting, setGranting] = useState(false);
  const [awaitingGrant, setAwaitingGrant] = useState(false);

  // Группы пресетов: выключенные секции и выбранные пресеты — в localStorage.
  const [enabledMap, setEnabledMap] = useState<Record<string, boolean>>(loadEnabled);
  const [defaultMap, setDefaultMap] = useState<Record<string, string>>(loadDefaults);

  // Детали пресета — best effort: новый контракт их не гарантирует.
  const [detail, setDetail] = useState<WsPresetDetail | null>(null);
  const [detailName, setDetailName] = useState("");

  // Инкремент журнала: с сервера просим строки после последнего total.
  const logTotalRef = useRef(0);
  const logRef = useRef<HTMLPreElement>(null);
  const stickBottomRef = useRef(true);

  // Группы пресетов по целевым сервисам: одна группа — один профиль.
  const groups = useMemo(() => buildGroups(presets), [presets]);

  const universalGroups = groups.filter((g) => isUniversal(g.target));
  const specificGroups = groups.filter((g) => !isUniversal(g.target));
  // Старое ядро может не отдать универсальных целей — тогда режим «Все сайты»
  // показать нечем и работаем как с точечными профилями. Пока пресеты не
  // загружены, судить об этом нельзя: иначе режим сбрасывался бы при старте.
  const hasUniversal = universalGroups.length > 0;
  const universalKnown = presets.length > 0;
  const effectiveMode: ProfileMode =
    universalKnown && !hasUniversal ? "profiles" : profileMode;

  // Выбор режима запоминается: пользователь возвращается к тому же экрану.
  const chooseProfileMode = useCallback((next: ProfileMode) => {
    setProfileMode(next);
    try {
      localStorage.setItem(PROFILE_MODE_KEY, next);
    } catch (_) {
      // localStorage недоступен — режим живёт до перезагрузки
    }
  }, []);

  useEffect(() => {
    if (universalKnown && !hasUniversal && profileMode === "all") {
      chooseProfileMode("profiles");
    }
  }, [universalKnown, hasUniversal, profileMode, chooseProfileMode]);

  // Включённость группы зависит от режима: универсальные работают только в
  // режиме «Все сайты», точечные — только в режиме профилей.
  const groupActive = useCallback(
    (group: PresetGroup): boolean =>
      isUniversal(group.target)
        ? effectiveMode === "all"
        : effectiveMode === "profiles" && isEnabled(group.target, enabledMap),
    [effectiveMode, enabledMap],
  );

  const visibleProfiles = specificGroups.filter((group) =>
    groupMatches(group, search),
  );
  const activeProfileCount = specificGroups.filter((group) =>
    isEnabled(group.target, enabledMap),
  ).length;
  const universalPresetCount = universalGroups.reduce(
    (total, group) => total + group.presets.length,
    0,
  );

  // --- разовая загрузка пресетов, статуса и состояния прав -----------------
  useEffect(() => {
    let alive = true;
    fetchPresets()
      .then((list) => alive && setPresets(list))
      .catch((e) => alive && setPollError(String(e.message)));
    fetchWsStatus()
      .then((s) => alive && setStatus(s))
      .catch((e) => alive && setPollError(String(e.message)));
    fetchPrivilege()
      .then((info) => alive && setPrivilege(info))
      .catch(() => {
        // Старый бэкенд без /api/ws/privilege — права проверит сам старт (409).
      });
    return () => {
      alive = false;
    };
  }, []);

  // --- поллинг: status 2с, logs 1.5с (пока вкладка «Обход» открыта) --------
  useEffect(() => {
    let alive = true;
    const pollStatus = () =>
      fetchWsStatus()
        .then((s) => {
          if (!alive) return;
          setStatus(s);
          setPollError("");
        })
        .catch((e) => alive && setPollError(String(e.message)));
    const pollLogs = () =>
      fetchWsLogs(logTotalRef.current)
        .then((data) => {
          if (!alive) return;
          logTotalRef.current = data.total;
          setDropped(data.dropped > 0 ? data.dropped : null);
          if (data.lines.length > 0) {
            setLogLines((prev) => [...prev, ...data.lines].slice(-LOG_KEEP));
          }
        })
        .catch(() => {
          // журнал недоступен — не спамим инфобар, статус покажет проблему
        });
    pollStatus();
    pollLogs();
    const statusTimer = setInterval(pollStatus, 2000);
    const logTimer = setInterval(pollLogs, 1500);
    return () => {
      alive = false;
      clearInterval(statusTimer);
      clearInterval(logTimer);
    };
  }, []);

  // --- журнал: автоскролл вниз, пока пользователь у нижнего края -----------
  useEffect(() => {
    const el = logRef.current;
    if (el && stickBottomRef.current) el.scrollTop = el.scrollHeight;
  }, [logLines]);

  // --- группы: переключатели и выбор пресета -------------------------------
  const toggleGroup = useCallback((target: string) => {
    setEnabledMap((prev) => {
      const next = !isEnabled(target, prev);
      saveEnabled(target, next);
      return { ...prev, [target]: next };
    });
  }, []);

  const choosePreset = useCallback((target: string, name: string) => {
    setDefaultMap((prev) => {
      saveDefault(target, name);
      return { ...prev, [target]: name };
    });
    // Детали — по возможности: старый бэкенд отдаёт план запуска.
    setDetail(null);
    setDetailName(name);
    fetchPreset(name)
      .then(setDetail)
      .catch(() => {
        // Эндпоинта может не быть в новом контракте — не спамим инфобар.
      });
  }, []);

  // Выбранный пресет секции: сохранённый, если он ещё существует, иначе —
  // помеченный автором как основной (так «Ростелеком» не становится
  // случайным выбором для всего трафика), иначе первый по алфавиту.
  const chosenFor = useCallback(
    (group: PresetGroup): string => {
      const saved = defaultMap[group.target];
      if (saved && group.presets.some((p) => p.name === saved)) return saved;
      const main = group.presets.find((preset) =>
        preset.description.toLowerCase().startsWith("основной пресет"),
      );
      return main?.name ?? group.presets[0]?.name ?? "";
    },
    [defaultMap],
  );

  // Эффективные дефолты секций — для бейджа «по умолчанию» и подсветки.
  const effectiveDefaults = useMemo(() => {
    const map: Record<string, string | undefined> = {};
    for (const group of groups) map[group.target] = chosenFor(group);
    return map;
  }, [groups, chosenFor]);

  // --- действия ------------------------------------------------------------
  async function runGrant(): Promise<boolean> {
    setGranting(true);
    setError("");
    try {
      await grantPrivilege();
      setPrivilege((prev) =>
        prev ? { ...prev, granted: true, needs_prompt: false } : prev,
      );
      return true;
    } catch (e) {
      const err = e as Error;
      setError(
        err.name === "TimeoutError"
          ? "Не дождались подтверждения пароля (90 с)"
          : String(err.message),
      );
      return false;
    } finally {
      setGranting(false);
    }
  }

  async function handleStart() {
    const enabledGroups = groups.filter(groupActive);
    if (enabledGroups.length === 0) {
      setError(
        effectiveMode === "all"
          ? "Универсальный профиль не выбран — проверьте режим «Все сайты»"
          : "Включите хотя бы один профиль или выберите режим «Все сайты»",
      );
      return;
    }
    const names = enabledGroups.map(chosenFor).filter(Boolean);
    if (names.length === 0) {
      setError("Не удалось определить пресеты для запуска");
      return;
    }
    const port = Math.floor(Number(qnum));
    if (!Number.isFinite(port) || port <= 0 || port > 65535) {
      setError("qnum должен быть числом от 1 до 65535");
      return;
    }
    setStarting(true);
    setError("");
    try {
      // Прав не хватает — сначала тихо просим polkit (системный диалог),
      // затем стартуем.
      if (privilege && privilege.needs_prompt && !privilege.granted) {
        setAwaitingGrant(true);
        const granted = await runGrant();
        setAwaitingGrant(false);
        if (!granted) return;
      }
      await startWs(names, port, mode);
    } catch (e) {
      const err = e as WsStartError;
      setError(String(err.message));
      // 400 с tail: показываем вывод dry-run в журнале с пометкой.
      if (err.tail) {
        const lines = err.tail
          .split("\n")
          .filter((line) => line.length > 0)
          .map((line) => `[dry-run] ${line}`);
        if (lines.length > 0) {
          stickBottomRef.current = true;
          setLogLines((prev) => [...prev, ...lines].slice(-LOG_KEEP));
        }
      }
    } finally {
      setStarting(false);
      setAwaitingGrant(false);
    }
  }

  async function handleStop() {
    setStopping(true);
    setError("");
    try {
      await stopWs();
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setStopping(false);
    }
  }

  const running = status?.running ?? false;
  const busy = starting || stopping || granting || awaitingGrant;
  const needsPrompt = Boolean(privilege?.needs_prompt && !privilege?.granted);
  // Платформа ядра: на Windows нет ни polkit, ни nftables, ни qnum —
  // движок winws2 фильтрует сам через WinDivert, а права даёт UAC.
  const isWindows = status?.platform === "windows";
  const engine = status?.engine ?? "nfqws2";
  const offline = !status && Boolean(pollError);

  const engineState = offline
    ? "fail"
    : running
      ? "running"
      : busy
        ? "busy"
        : "idle";

  const stateWord = offline
    ? "Нет связи"
    : running
      ? "Запущен"
      : busy
        ? granting || awaitingGrant
          ? "Подтверждение"
          : "Подготовка"
        : "Остановлен";

  const stateLabel = offline
    ? "нет связи"
    : running
      ? "работает"
      : busy
        ? granting || awaitingGrant
          ? "права"
          : "запуск"
        : "остановлен";

  const stateNote = offline
    ? "Ядро не отвечает. Проверьте, запущен ли primecore-server и доступен ли локальный API."
    : running
      ? "Трафик проходит через выбранные стратегии. Журнал ниже обновляется автоматически."
      : busy
        ? "Проверяем права и собираем план запуска — это займёт несколько секунд."
        : "Движок остановлен. Включите нужные группы ниже и запустите обход.";

  const profileLabel = offline
    ? "неизвестно"
    : status?.preset || status?.names?.join(" · ") || "не выбран";

  const rightsGranted = Boolean(privilege?.granted || status?.root);
  const rightsKnown = Boolean(privilege || status);
  const rightsLabel = !rightsKnown
    ? "неизвестно"
    : rightsGranted
      ? "подтверждены"
      : "нужен запрос";
  const rightsTone = !rightsKnown ? "tone-mute" : rightsGranted ? "tone-ok" : "tone-warn";

  const universalChosen =
    universalGroups.length > 0 ? chosenFor(universalGroups[0]) : "";

  return (
    <div className="page bypass-page">
      <PageHeader
        index="01"
        group="Управление"
        title="Обход"
        description="Управление движком обхода блокировок: профили стратегий, параметры запуска и живой журнал."
      />

      {error && (
        <div className="infobar error with-icon" role="alert">
          <IconClose />
          <span>{error}</span>
        </div>
      )}
      {pollError && (
        <div className="infobar error with-icon" role="alert">
          <IconWarning />
          <span>Ядро не отвечает: {pollError}</span>
        </div>
      )}
      {status && !status.root && (
        <div className="infobar warn with-icon">
          <IconWarning />
          <span>
            {isWindows
              ? "Нет прав администратора: перезапустите приложение от имени администратора — движку winws2 нужен доступ к WinDivert"
              : "Нет root-прав: потребуются права через polkit при запуске"}
          </span>
        </div>
      )}

      <section
        className="card engine-card"
        data-state={engineState}
        aria-busy={busy}
      >
        <div className="engine-top">
          <span className="engine-label">
            <IconPower size={14} /> Движок обхода
          </span>
          <span
            className={`chip ${
              offline
                ? "tone-fail"
                : running
                  ? "tone-ok"
                  : busy
                    ? "tone-warn"
                    : "tone-neutral"
            }`}
          >
            <span
              className={`status-dot ${
                offline
                  ? "is-fail"
                  : running
                    ? "is-ok"
                    : busy
                      ? "is-busy"
                      : "is-idle"
              }`}
            />
            {stateLabel}
          </span>
        </div>

        <div className="engine-body">
          <div className="engine-state">
            <h2 className="engine-state-word" aria-live="polite">
              {stateWord}
            </h2>
            <p className="engine-state-note">{stateNote}</p>
          </div>
          <div className="engine-actions">
            <button
              type="button"
              className="btn accent lg"
              onClick={handleStart}
              disabled={busy || running}
            >
              {starting ? <span className="spinner" /> : <IconPlay />}
              {starting
                ? awaitingGrant
                  ? "Подтвердите права"
                  : "Запускаю…"
                : "Запустить обход"}
            </button>
            <button
              type="button"
              className="btn danger lg"
              onClick={handleStop}
              disabled={busy || !running}
            >
              {stopping ? <span className="spinner" /> : <IconStop />}
              {stopping ? "Останавливаю…" : "Остановить"}
            </button>
          </div>
        </div>

        <dl className="engine-meta">
          <div>
            <dt>Движок</dt>
            <dd>{offline ? "—" : engine}</dd>
          </div>
          <div>
            <dt>PID</dt>
            <dd>{status?.pid ?? "—"}</dd>
          </div>
          <div>
            <dt>Профиль</dt>
            <dd>{profileLabel}</dd>
          </div>
          <div>
            <dt>Права</dt>
            <dd className={rightsTone}>{rightsLabel}</dd>
          </div>
        </dl>

        <div className="signal" aria-hidden="true" />
      </section>

      <section className="card byp-presets-card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>02</b> Профили
            </span>
            <h2 className="card-title">Профиль обхода</h2>
            <p className="card-note">
              Выберите режим: один универсальный пресет на весь трафик или
              точечные профили под конкретные сервисы. Режимы не смешиваются —
              в запуск уходит только то, что включено в активном режиме.
            </p>
          </div>
          <span className="chip tone-neutral">всего {presets.length}</span>
        </div>

        <div className="mode-picker" role="radiogroup" aria-label="Режим профилей">
          <button
            type="button"
            role="radio"
            aria-checked={effectiveMode === "all"}
            disabled={!hasUniversal && universalKnown}
            className={`mode-card ${effectiveMode === "all" ? "active" : ""}`}
            onClick={() => chooseProfileMode("all")}
          >
            <span className="mode-card-head">
              <span className="mode-card-icon" aria-hidden="true">
                <IconShieldCheck />
              </span>
              <span className="mode-card-title">Все сайты</span>
            </span>
            <span className="mode-card-note">
              Один универсальный пресет на весь трафик: подходит большинству
              заблокированных сайтов и приложений.
            </span>
            <span className="mode-card-state">
              {effectiveMode === "all"
                ? universalChosen
                  ? `запустится: ${universalChosen}`
                  : "пресет не выбран"
                : "выключен"}
            </span>
          </button>

          <button
            type="button"
            role="radio"
            aria-checked={effectiveMode === "profiles"}
            className={`mode-card ${effectiveMode === "profiles" ? "active" : ""}`}
            onClick={() => chooseProfileMode("profiles")}
          >
            <span className="mode-card-head">
              <span className="mode-card-icon" aria-hidden="true">
                <IconUnlock />
              </span>
              <span className="mode-card-title">Точечные профили</span>
            </span>
            <span className="mode-card-note">
              Работают только выбранные сервисы: например, один Anthropic или
              Instagram — остальной трафик движок не трогает.
            </span>
            <span className="mode-card-state">
              {effectiveMode === "profiles"
                ? activeProfileCount > 0
                  ? `включено профилей: ${activeProfileCount}`
                  : "ничего не включено"
                : "выключен"}
            </span>
          </button>
        </div>

        {universalKnown && !hasUniversal && (
          <div className="infobar warn with-icon">
            <IconWarning />
            <span>
              Ядро не сообщило универсальных пресетов — доступны только точечные
              профили. Обновите ядро PrimeProxy.
            </span>
          </div>
        )}

        <label className="search-box">
          <IconSearch size={16} />
          <span className="sr-only">Поиск профиля</span>
          <input
            className="input"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Найти сервис или стратегию…"
            aria-label="Поиск пресета"
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

        {presets.length === 0 ? (
          <div className="empty-state">
            <strong>Пресеты не найдены</strong>
            <span>
              Похоже, ядро недоступно. Проверьте локальный API и повторите.
            </span>
          </div>
        ) : effectiveMode === "all" ? (
          <UniversalBlock
            groups={universalGroups}
            search={search}
            active
            chosen={(target) => effectiveDefaults[target]}
            onChoose={choosePreset}
            onSwitchMode={() => chooseProfileMode("profiles")}
          />
        ) : (
          <>
            <UniversalBlock
              groups={universalGroups}
              search={search}
              active={false}
              chosen={(target) => effectiveDefaults[target]}
              onChoose={choosePreset}
              onSwitchMode={() => chooseProfileMode("all")}
            />

            {visibleProfiles.length > 0 ? (
              categorizeProfiles(visibleProfiles).map((category) => (
                <div className="pcard-category" key={category.title}>
                  <h3 className="pcard-category-title">{category.title}</h3>
                  <div className="pcard-grid">
                    {category.groups.map((group) => (
                      <ProfileCard
                        key={group.target}
                        group={group}
                        enabled={isEnabled(group.target, enabledMap)}
                        chosen={effectiveDefaults[group.target]}
                        search={search}
                        open={openGroup === group.target}
                        onToggle={toggleGroup}
                        onChoose={choosePreset}
                        onOpen={setOpenGroup}
                      />
                    ))}
                  </div>
                </div>
              ))
            ) : (
              <div className="empty-state">
                <strong>Ничего не найдено</strong>
                <span>Измените запрос или очистите поиск.</span>
              </div>
            )}
          </>
        )}

        {groups.length > 0 && (
          <p className="byp-results-line">
            {effectiveMode === "all"
              ? `режим «Все сайты» · универсальных пресетов: ${universalPresetCount}`
              : `режим точечных профилей · включено ${activeProfileCount} из ${specificGroups.length}`}
          </p>
        )}
      </section>

      <section className="card byp-options-card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>03</b> Запуск
            </span>
            <h2 className="card-title">Параметры запуска</h2>
            <p className="card-note">
              Настройки применяются только к следующему запуску — текущий
              процесс они не меняют.
            </p>
          </div>
          {detail && <span className="chip tone-accent">план готов</span>}
        </div>

        {needsPrompt && (
          <div className="infobar warn priv-bar">
            <span>
              {isWindows
                ? "Обходу нужны права администратора: перезапустите приложение от имени администратора."
                : "Обходу нужны права администратора. Пароль запросят один раз — дальше без пароля."}
            </span>
            {!isWindows && (
              <button
                type="button"
                className="btn accent"
                onClick={runGrant}
                disabled={granting}
              >
                {granting ? "Ожидаю подтверждение…" : "Разрешить"}
              </button>
            )}
          </div>
        )}

        <div className="launch-row">
          {/* qnum — номер очереди NFQUEUE: он есть только у nfqws2, на
              Windows движок фильтрует сам через WinDivert. */}
          {!isWindows && (
            <label className="field">
              <span className="field-label">qnum</span>
              <input
                type="number"
                min={1}
                max={65535}
                value={qnum}
                onChange={(event) => setQnum(event.target.value)}
                disabled={busy}
              />
            </label>
          )}
          <label className="field">
            <span className="field-label">Списки</span>
            <select
              value={mode}
              onChange={(event) => setMode(event.target.value as HostlistMode)}
              disabled={busy}
            >
              {HOSTLIST_MODES.map((item) => (
                <option key={item.key} value={item.key}>
                  {item.title}
                </option>
              ))}
            </select>
          </label>
          <span className="byp-options-hint">
            <IconInfo size={14} />{" "}
            {isWindows
              ? "WinDivert управляет фильтрацией автоматически"
              : "NFQUEUE использует указанный номер очереди"}
          </span>
        </div>

        {detail && (
          <div className="plan-line">
            <span className="field-label">Команда · {detailName}</span>
            <code>
              {detail.plan.exe} {detail.plan.args.join(" ")}
            </code>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>04</b> Журнал
            </span>
            <h2 className="card-title">Журнал движка</h2>
            <p className="card-note">
              Вывод обновляется автоматически; в виде хранятся последние 500
              строк.
            </p>
          </div>
          <div className="page-actions">
            <span className="chip tone-neutral">{logLines.length} строк</span>
            <button
              type="button"
              className="btn ghost"
              onClick={() => {
                setLogLines([]);
                setDropped(null);
              }}
            >
              Очистить вид
            </button>
          </div>
        </div>
        <pre
          className="log-view"
          ref={logRef}
          onScroll={(event) => {
            const el = event.currentTarget;
            stickBottomRef.current =
              el.scrollTop + el.clientHeight >= el.scrollHeight - 24;
          }}
        >
          {logLines.length > 0
            ? logLines.join("\n")
            : "Журнал пуст — запустите обход, чтобы увидеть вывод."}
        </pre>
        {dropped !== null && (
          <div className="log-note">Пропущено старых строк: {dropped}</div>
        )}
      </section>
    </div>
  );
}
