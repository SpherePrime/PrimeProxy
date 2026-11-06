import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  fetchCheckSites,
  fetchCheckStatus,
  fetchPreset,
  fetchPresets,
  fetchPrivilege,
  fetchTgProxy,
  fetchWsLogs,
  fetchWsStatus,
  grantPrivilege,
  HostlistMode,
  PresetInfo,
  PrivilegeInfo,
  SiteCheckResult,
  startTgProxy,
  startWs,
  stopTgProxy,
  stopWs,
  TgProxyStatus,
  WsPresetDetail,
  WsStartError,
  WsStatus,
} from "../../api";
import {
  buildGroups,
  groupMatches,
  isEnabled,
  isUniversal,
  loadDefaults,
  loadEnabled,
  PresetGroup,
  ProfileMode,
  readProfileMode,
  saveDefault,
  saveEnabled,
  saveProfileMode,
  targetProbe,
} from "./presetCatalog";
import { readAutoMode, readWithTelegram, saveAutoMode, saveWithTelegram } from "./autoPrefs";

const AUTO_PICK_POLLS = 120;
const LOG_KEEP = 500;
const STATUS_POLL_MS = 2000;
const LOG_POLL_MS = 1500;

export type EngineState = "fail" | "running" | "busy" | "idle";

export function useBypass() {
  const [presets, setPresets] = useState<PresetInfo[]>([]);
  const [search, setSearch] = useState("");
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const [profileMode, setProfileMode] = useState<ProfileMode>(readProfileMode);
  const [autoRunning, setAutoRunning] = useState(false);
  const [autoProgress, setAutoProgress] = useState({ done: 0, total: 0 });
  const [autoNote, setAutoNote] = useState("");
  const [autoMode, setAutoModeState] = useState(readAutoMode);
  const [withTelegram, setWithTelegramState] = useState(readWithTelegram);
  const [tg, setTg] = useState<TgProxyStatus | null>(null);
  const [tgBusy, setTgBusy] = useState(false);
  const [qnum, setQnum] = useState("300");
  const [mode, setMode] = useState<HostlistMode>("none");
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState("");
  const [pollError, setPollError] = useState("");
  const [logLines, setLogLines] = useState<string[]>([]);
  const [dropped, setDropped] = useState<number | null>(null);
  const [status, setStatus] = useState<WsStatus | null>(null);
  const [privilege, setPrivilege] = useState<PrivilegeInfo | null>(null);
  const [granting, setGranting] = useState(false);
  const [awaitingGrant, setAwaitingGrant] = useState(false);
  const [enabledMap, setEnabledMap] = useState<Record<string, boolean>>(loadEnabled);
  const [defaultMap, setDefaultMap] = useState<Record<string, string>>(loadDefaults);
  const [detail, setDetail] = useState<WsPresetDetail | null>(null);
  const [detailName, setDetailName] = useState("");
  const logTotalRef = useRef(0);

  const groups = useMemo(() => buildGroups(presets), [presets]);
  const universalGroups = groups.filter((g) => isUniversal(g.target));
  const specificGroups = groups.filter((g) => !isUniversal(g.target));
  const hasUniversal = universalGroups.length > 0;
  const universalKnown = presets.length > 0;
  const effectiveMode: ProfileMode = universalKnown && !hasUniversal ? "profiles" : profileMode;

  const chooseProfileMode = useCallback((next: ProfileMode) => {
    setProfileMode(next);
    saveProfileMode(next);
  }, []);

  useEffect(() => {
    if (universalKnown && !hasUniversal && profileMode === "all") chooseProfileMode("profiles");
  }, [universalKnown, hasUniversal, profileMode, chooseProfileMode]);

  const groupActive = useCallback(
    (group: PresetGroup): boolean =>
      isUniversal(group.target)
        ? effectiveMode === "all"
        : effectiveMode === "profiles" && isEnabled(group.target, enabledMap),
    [effectiveMode, enabledMap],
  );

  const visibleProfiles = specificGroups.filter((group) => groupMatches(group, search));
  const activeProfileCount = specificGroups.filter((group) => isEnabled(group.target, enabledMap)).length;

  useEffect(() => {
    let alive = true;
    fetchPresets()
      .then((list) => alive && setPresets(list))
      .catch((e) => alive && setPollError(String(e.message)));
    fetchPrivilege()
      .then((info) => alive && setPrivilege(info))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    let alive = true;
    const pollStatus = () =>
      fetchWsStatus()
        .then((s) => {
          if (!alive) return;
          setStatus(s);
          setPollError("");
        })
        .catch((e) => alive && setPollError(String(e.message)))
        .then(() => fetchTgProxy())
        .then((data) => alive && data && setTg(data))
        .catch(() => undefined);
    const pollLogs = () =>
      fetchWsLogs(logTotalRef.current)
        .then((data) => {
          if (!alive) return;
          logTotalRef.current = data.total;
          setDropped(data.dropped > 0 ? data.dropped : null);
          if (data.lines.length > 0) setLogLines((prev) => [...prev, ...data.lines].slice(-LOG_KEEP));
        })
        .catch(() => undefined);
    pollStatus();
    pollLogs();
    const statusTimer = setInterval(pollStatus, STATUS_POLL_MS);
    const logTimer = setInterval(pollLogs, LOG_POLL_MS);
    return () => {
      alive = false;
      clearInterval(statusTimer);
      clearInterval(logTimer);
    };
  }, []);

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
    setDetail(null);
    setDetailName(name);
    fetchPreset(name)
      .then(setDetail)
      .catch(() => undefined);
  }, []);

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

  const effectiveDefaults = useMemo(() => {
    const map: Record<string, string | undefined> = {};
    for (const group of groups) map[group.target] = chosenFor(group);
    return map;
  }, [groups, chosenFor]);

  const clearLog = useCallback(() => {
    setLogLines([]);
    setDropped(null);
  }, []);

  async function runGrant(): Promise<boolean> {
    setGranting(true);
    setError("");
    try {
      await grantPrivilege();
      setPrivilege((prev) => (prev ? { ...prev, granted: true, needs_prompt: false } : prev));
      return true;
    } catch (e) {
      const err = e as Error;
      setError(err.name === "TimeoutError" ? "Не дождались подтверждения пароля (90 с)" : String(err.message));
      return false;
    } finally {
      setGranting(false);
    }
  }

  async function startWithNames(names: string[]): Promise<boolean> {
    const port = Math.floor(Number(qnum));
    if (!Number.isFinite(port) || port <= 0 || port > 65535) {
      setError("qnum должен быть числом от 1 до 65535");
      return false;
    }
    setStarting(true);
    setError("");
    try {
      if (privilege && privilege.needs_prompt && !privilege.granted) {
        setAwaitingGrant(true);
        const granted = await runGrant();
        setAwaitingGrant(false);
        if (!granted) return false;
      }
      await startWs(names, port, mode);
      setStatus(await fetchWsStatus());
      return true;
    } catch (e) {
      const err = e as WsStartError;
      setError(String(err.message));
      if (err.tail) {
        const lines = err.tail
          .split("\n")
          .filter((line) => line.length > 0)
          .map((line) => `[dry-run] ${line}`);
        if (lines.length > 0) setLogLines((prev) => [...prev, ...lines].slice(-LOG_KEEP));
      }
      return false;
    } finally {
      setStarting(false);
      setAwaitingGrant(false);
    }
  }

  async function start(): Promise<boolean> {
    const enabledGroups = groups.filter(groupActive);
    if (enabledGroups.length === 0) {
      setError(
        effectiveMode === "all"
          ? "Универсальный профиль не выбран — проверьте режим «Все сайты»"
          : "Включите хотя бы один профиль или выберите режим «Все сайты»",
      );
      return false;
    }
    const names = enabledGroups.map(chosenFor).filter(Boolean);
    if (names.length === 0) {
      setError("Не удалось определить пресеты для запуска");
      return false;
    }
    return startWithNames(names);
  }

  async function startTelegram() {
    setTgBusy(true);
    try {
      const config = await fetchTgProxy();
      if (config.running) {
        setTg(config);
        return;
      }
      const front = config.front && config.front.includes(".") ? config.front : "";
      await startTgProxy(config.host || "127.0.0.1", config.port || 1353, front);
      setTg(await fetchTgProxy());
    } catch (e) {
      setError(`Прокси Telegram не поднялся: ${String((e as Error).message)}`);
    } finally {
      setTgBusy(false);
    }
  }

  async function stopTelegram() {
    setTgBusy(true);
    try {
      await stopTgProxy();
      setTg(await fetchTgProxy());
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setTgBusy(false);
    }
  }

  async function powerOn() {
    setAutoNote("");
    if (autoMode) {
      const picked = await runAutoPick(false);
      if (picked === null) await start();
      else if (picked.length > 0) await startWithNames(picked);
    } else {
      await start();
    }
    if (withTelegram) await startTelegram();
  }

  async function powerOff() {
    if (running) await stop();
    if (tg?.running) await stopTelegram();
  }

  const setAutoMode = (value: boolean) => {
    setAutoModeState(value);
    saveAutoMode(value);
  };

  const setWithTelegram = (value: boolean) => {
    setWithTelegramState(value);
    saveWithTelegram(value);
  };

  async function stop() {
    setStopping(true);
    setError("");
    try {
      await stopWs();
      setStatus(await fetchWsStatus());
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setStopping(false);
    }
  }

  async function runAutoPick(startAfter: boolean): Promise<string[] | null> {
    const probes = specificGroups
      .map((group) => ({ target: group.target, domain: targetProbe(group.target) }))
      .filter((item) => item.domain !== "");
    if (probes.length === 0) return null;
    setAutoRunning(true);
    setError("");
    setAutoNote("");
    setAutoProgress({ done: 0, total: probes.length });
    try {
      await fetchCheckSites(probes.map((item) => item.domain));
      let results: SiteCheckResult[] = [];
      let done = false;
      for (let attempt = 0; attempt < AUTO_PICK_POLLS && !done; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const checkStatus = await fetchCheckStatus();
        results = checkStatus.results ?? [];
        setAutoProgress({ done: results.length, total: probes.length });
        done = checkStatus.done;
      }
      if (!done) {
        setAutoNote(`Проверка не уложилась в ${AUTO_PICK_POLLS} с — запускаю текущий режим.`);
        return null;
      }
      const blocked = new Set(results.filter((item) => item.status !== "ok").map((item) => item.domain));
      const picked = probes.filter((item) => blocked.has(item.domain)).map((item) => item.target);
      const nextEnabled: Record<string, boolean> = {};
      for (const group of specificGroups) nextEnabled[group.target] = picked.includes(group.target);
      setEnabledMap(nextEnabled);
      for (const [target, value] of Object.entries(nextEnabled)) saveEnabled(target, value);
      chooseProfileMode("profiles");
      if (picked.length === 0) {
        setAutoNote("Ничего не заблокировано — движку обходить нечего.");
        return [];
      }
      const names = picked
        .map((target) => {
          const group = groups.find((item) => item.target === target);
          return group ? chosenFor(group) : "";
        })
        .filter(Boolean);
      setAutoNote(`Заблокировано: ${picked.join(", ")}.`);
      if (startAfter && names.length > 0) await startWithNames(names);
      return names;
    } catch (e) {
      setAutoNote(`Автоподбор не удался: ${String((e as Error).message)}`);
      return null;
    } finally {
      setAutoRunning(false);
    }
  }

  const running = status?.running ?? false;
  const busy = starting || stopping || granting || awaitingGrant;
  const needsPrompt = Boolean(privilege?.needs_prompt && !privilege?.granted);
  const platformKnown = Boolean(status);
  const isWindows = status ? status.platform === "windows" : true;
  const offline = !status && Boolean(pollError);
  const engineState: EngineState = offline ? "fail" : running ? "running" : busy ? "busy" : "idle";
  const rightsGranted = Boolean(privilege?.granted || status?.root);
  const rightsKnown = Boolean(privilege || status);
  const universalChosen = universalGroups.length > 0 ? chosenFor(universalGroups[0]) : "";
  const tgRunning = Boolean(tg?.running);
  const active = running || tgRunning;
  const powerBusy = busy || autoRunning || tgBusy;

  return {
    presets,
    groups,
    universalGroups,
    specificGroups,
    visibleProfiles,
    activeProfileCount,
    hasUniversal,
    universalKnown,
    effectiveMode,
    chooseProfileMode,
    search,
    setSearch,
    openGroup,
    setOpenGroup,
    enabledMap,
    effectiveDefaults,
    toggleGroup,
    choosePreset,
    universalChosen,
    autoRunning,
    autoProgress,
    autoNote,
    runAutoPick,
    autoMode,
    setAutoMode,
    withTelegram,
    setWithTelegram,
    tg,
    tgRunning,
    active,
    powerBusy,
    powerOn,
    powerOff,
    qnum,
    setQnum,
    mode,
    setMode,
    detail,
    detailName,
    status,
    running,
    busy,
    starting,
    stopping,
    granting,
    awaitingGrant,
    offline,
    engineState,
    platformKnown,
    isWindows,
    needsPrompt,
    rightsGranted,
    rightsKnown,
    runGrant,
    start,
    stop,
    error,
    pollError,
    logLines,
    dropped,
    clearLog,
  };
}

export type BypassModel = ReturnType<typeof useBypass>;
