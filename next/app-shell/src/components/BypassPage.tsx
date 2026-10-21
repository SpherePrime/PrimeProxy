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
  PresetGroups,
  buildGroups,
  isEnabled,
  saveDefault,
  saveEnabled,
} from "./PresetGroups";

// Страница «Обход» — управление nfqws2/zapret2: группы пресетов по сервисам,
// права администратора (polkit, один раз при старте), запуск/останов, журнал.
// Дизайн перенесён с PyQt6-эталона (FluentWindow): карточки со скруглениями,
// инфобары в духе SemanticNotice, оранжевый акцент #ff9800 для предупреждений.

// Режимы списков — подписи как в python-эталоне запуска.
const HOSTLIST_MODES: Array<{ key: HostlistMode; title: string }> = [
  { key: "none", title: "Без списков" },
  { key: "hostlist", title: "По спискам" },
  { key: "autohostlist", title: "Автосписок" },
];

const LOG_KEEP = 500; // сколько строк журнала держим в памяти вида

export function BypassPage() {
  const [presets, setPresets] = useState<PresetInfo[]>([]);
  const [search, setSearch] = useState("");
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const [status, setStatus] = useState<WsStatus | null>(null);
  const [qnum, setQnum] = useState("300");
  const [mode, setMode] = useState<HostlistMode>("none");
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState("");
  const [pollError, setPollError] = useState("");
  const [logLines, setLogLines] = useState<string[]>([]);
  const [dropped, setDropped] = useState<number | null>(null);

  // Права администратора: состояние с /api/ws/privilege + процесс выдачи.
  const [privilege, setPrivilege] = useState<PrivilegeInfo | null>(null);
  const [granting, setGranting] = useState(false);
  const [awaitingGrant, setAwaitingGrant] = useState(false);

  // Группы пресетов: выключенные секции и выбранные пресеты — в localStorage.
  const [enabledMap, setEnabledMap] = useState<Record<string, boolean>>({});
  const [defaultMap, setDefaultMap] = useState<Record<string, string>>({});

  // Детали пресета — best effort: новый контракт их не гарантирует.
  const [detail, setDetail] = useState<WsPresetDetail | null>(null);
  const [detailName, setDetailName] = useState("");

  // Инкремент журнала: с сервера просим строки после последнего total.
  const logTotalRef = useRef(0);
  const logRef = useRef<HTMLPreElement>(null);
  const stickBottomRef = useRef(true);

  const groups = useMemo(() => buildGroups(presets), [presets]);

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

  // Выбранный пресет секции: сохранённый, если он ещё существует, иначе
  // первый по алфавиту (список секции уже отсортирован).
  const chosenFor = useCallback(
    (group: PresetGroup): string => {
      const saved = defaultMap[group.target];
      if (saved && group.presets.some((p) => p.name === saved)) return saved;
      return group.presets[0]?.name ?? "";
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
    const enabledGroups = groups.filter((group) =>
      isEnabled(group.target, enabledMap),
    );
    if (enabledGroups.length === 0) {
      setError("Включите хотя бы одну группу");
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

  return (
    <div className="page">
      <header className="page-header">
        <h1>Обход</h1>
        <p className="subtitle">
          Управление nfqws2/zapret2: включите группы сервисов и запустите обход
          блокировок.
        </p>
      </header>

      {(error || pollError) && <div className="infobar error">✗ {error || pollError}</div>}
      {status && !status.root && (
        <div className="infobar warn">
          ⚠ Нет root-прав: потребуются права через polkit при запуске
        </div>
      )}

      <section className="status-line">
        <span className="eyebrow">Состояние обхода</span>
        <span className={`status-chip ${running ? "chip-run" : ""}`}>
          {running ? `Запущен · PID ${status?.pid ?? "—"}` : "Остановлен"}
        </span>
        {privilege?.granted && <span className="status-chip chip-ok">Права получены</span>}
        {status?.preset && <span className="status-chip">{status.preset}</span>}
      </section>

      {/* --- Карточка «Пресеты» --- */}
      <section className="card">
        <h2>Пресеты</h2>
        <div className="check-row">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="поиск по имени или описанию…"
            aria-label="Поиск пресета"
          />
        </div>
        <PresetGroups
          groups={groups}
          search={search}
          totalPresets={presets.length}
          enabled={enabledMap}
          defaults={effectiveDefaults}
          onToggle={toggleGroup}
          onChoose={choosePreset}
          openTarget={openGroup}
          onOpen={setOpenGroup}
        />
      </section>

      {/* --- Карточка «Запуск» --- */}
      <section className="card">
        <h2>Запуск</h2>
        {needsPrompt && (
          <div className="infobar warn priv-bar">
            <span>
              Обходу нужны права администратора. Пароль запросят один раз —
              дальше без пароля.
            </span>
            <button className="btn accent" onClick={runGrant} disabled={granting}>
              {granting ? "Ожидаю подтверждение…" : "Разрешить"}
            </button>
          </div>
        )}
        <div className="launch-row">
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
          <button className="btn accent" onClick={handleStart} disabled={busy || running}>
            ▶{" "}
            {starting
              ? awaitingGrant
                ? "Ожидаю подтверждение…"
                : "Запускаю…"
              : "Запустить"}
          </button>
          <button className="btn secondary" onClick={handleStop} disabled={busy || !running}>
            ⏹ {stopping ? "Останавливаю…" : "Остановить"}
          </button>
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

      {/* --- Карточка «Журнал» --- */}
      <section className="card">
        <div className="card-head">
          <h2>Журнал</h2>
          <button
            className="btn ghost"
            onClick={() => {
              setLogLines([]);
              setDropped(null);
            }}
          >
            Очистить вид
          </button>
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
