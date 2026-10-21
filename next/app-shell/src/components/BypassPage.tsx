import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  fetchPresets,
  fetchPreset,
  fetchWsLogs,
  fetchWsStatus,
  startWs,
  stopWs,
  HostlistMode,
  PresetInfo,
  WsPresetDetail,
  WsStatus,
} from "../api";

// Страница «Обход» — управление nfqws2/zapret2: выбор пресета, запуск/останов,
// журнал. Дизайн перенесён с PyQt6-эталона (FluentWindow): карточки со
// скруглениями, инфобары в духе SemanticNotice, оранжевый акцент #ff9800
// для предупреждений.

// Режимы списков — подписи как в python-эталоне запуска.
const HOSTLIST_MODES: Array<{ key: HostlistMode; title: string }> = [
  { key: "none", title: "Без списков" },
  { key: "hostlist", title: "По спискам" },
  { key: "autohostlist", title: "Автосписок" },
];

// Виртуальный список пресетов: фиксированная высота строки, рендерим только
// видимое окно (+ overscan) — все ~136 пунктов в DOM не нужны.
const ROW_HEIGHT = 62;
const LIST_HEIGHT = 340;
const OVERSCAN = 6;

const LOG_KEEP = 500; // сколько строк журнала держим в памяти вида

export function BypassPage() {
  const [presets, setPresets] = useState<PresetInfo[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [detail, setDetail] = useState<WsPresetDetail | null>(null);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<WsStatus | null>(null);
  const [qnum, setQnum] = useState("300");
  const [mode, setMode] = useState<HostlistMode>("none");
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState("");
  const [pollError, setPollError] = useState("");
  const [logLines, setLogLines] = useState<string[]>([]);
  const [dropped, setDropped] = useState<number | null>(null);

  // Инкремент журнала: с сервера просим строки после последнего total.
  const logTotalRef = useRef(0);
  const logRef = useRef<HTMLPreElement>(null);
  const stickBottomRef = useRef(true);

  // --- разовая загрузка пресетов и статуса --------------------------------
  useEffect(() => {
    let alive = true;
    fetchPresets()
      .then((list) => alive && setPresets(list))
      .catch((e) => alive && setPollError(String(e.message)));
    fetchWsStatus()
      .then((s) => alive && setStatus(s))
      .catch((e) => alive && setPollError(String(e.message)));
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

  // --- выбор пресета -------------------------------------------------------
  const selectPreset = useCallback((name: string) => {
    setSelected(name);
    setDetail(null);
    fetchPreset(name)
      .then(setDetail)
      .catch((e) => setPollError(String(e.message)));
  }, []);

  // Если обход уже запущен с каким-то пресетом — сразу его и показываем.
  useEffect(() => {
    if (status?.preset && !selected) setSelected(status.preset);
  }, [status?.preset, selected]);

  // --- поиск и виртуализация списка ---------------------------------------
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return presets;
    return presets.filter(
      (p) =>
        p.name.toLowerCase().includes(query) ||
        p.description.toLowerCase().includes(query),
    );
  }, [presets, search]);

  const [scrollTop, setScrollTop] = useState(0);
  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const last = Math.min(
    filtered.length,
    Math.ceil((scrollTop + LIST_HEIGHT) / ROW_HEIGHT) + OVERSCAN,
  );
  const visible = filtered.slice(first, last);

  // --- журнал: автоскролл вниз, пока пользователь у нижнего края -----------
  useEffect(() => {
    const el = logRef.current;
    if (el && stickBottomRef.current) el.scrollTop = el.scrollHeight;
  }, [logLines]);

  // --- действия ------------------------------------------------------------
  async function handleStart() {
    if (!selected) {
      setError("Выберите пресет для запуска");
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
      await startWs(selected, port, mode);
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setStarting(false);
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
  const busy = starting || stopping;

  return (
    <div className="page">
      <header className="page-header">
        <h1>Обход</h1>
        <p className="subtitle">
          Управление nfqws2/zapret2: выберите пресет и запустите обход блокировок.
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
        {status?.preset && <span className="status-chip">{status.preset}</span>}
      </section>

      {/* --- Карточка «Пресет» --- */}
      <section className="card">
        <h2>Пресет</h2>
        <div className="check-row">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="поиск по имени или описанию…"
            aria-label="Поиск пресета"
          />
          <span className="preset-count">
            {filtered.length} из {presets.length}
          </span>
        </div>
        {presets.length === 0 ? (
          <div className="preset-empty">Пресеты не найдены — сервер недоступен?</div>
        ) : (
          <div
            className="preset-list"
            style={{ height: LIST_HEIGHT }}
            onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
          >
            <div style={{ height: filtered.length * ROW_HEIGHT, position: "relative" }}>
              {visible.map((preset, index) => {
                const realIndex = first + index;
                const isSelected = preset.name === selected;
                return (
                  <button
                    key={preset.name}
                    className={`preset-item ${isSelected ? "selected" : ""}`}
                    style={{ top: realIndex * ROW_HEIGHT, height: ROW_HEIGHT }}
                    onClick={() => selectPreset(preset.name)}
                    title={preset.description}
                  >
                    <span className="preset-name">{preset.name}</span>
                    <span className="preset-desc">{preset.description}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* --- Карточка «Запуск» --- */}
      <section className="card">
        <h2>Запуск</h2>
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
          <button
            className="btn accent"
            onClick={handleStart}
            disabled={busy || running}
          >
            ▶ {starting ? "Запускаю…" : "Запустить"}
          </button>
          <button className="btn secondary" onClick={handleStop} disabled={busy || !running}>
            ⏹ {stopping ? "Останавливаю…" : "Остановить"}
          </button>
        </div>
        {detail && (
          <div className="plan-line">
            <span className="field-label">Команда</span>
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
