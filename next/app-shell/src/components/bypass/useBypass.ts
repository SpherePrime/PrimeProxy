import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  fetchCheckSites,
  fetchCheckStatus,
  fetchPresets,
  fetchPrivilege,
  fetchWsLogs,
  fetchWsStatus,
  grantPrivilege,
  HostlistMode,
  PresetInfo,
  PrivilegeInfo,
  SiteCheckResult,
  startWs,
  stopWs,
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
  saveEnabled,
  saveProfileMode,
  targetProbe,
} from "./presetCatalog";

const AUTO_PICK_POLLS = 120;
const LOG_KEEP = 500;
const STATUS_POLL_MS = 2000;
const LOG_POLL_MS = 1500;

export function useBypass() {
  const [presets, setPresets] = useState<PresetInfo[]>([]);
  const [search, setSearch] = useState("");
  const [profileMode, setProfileMode] = useState<ProfileMode>(readProfileMode);
  const [autoRunning, setAutoRunning] = useState(false);
  const [autoProgress, setAutoProgress] = useState({ done: 0, total: 0 });
  const [autoNote, setAutoNote] = useState("");
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
  const [defaultMap] = useState<Record<string, string>>(loadDefaults);
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

  const visibleProfiles = specificGroups.filter((group) => groupMatches(group, search));
  const enabledTargets = specificGroups.filter((group) => isEnabled(group.target, enabledMap)).map((g) => g.target);

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
        .catch((e) => alive && setPollError(String(e.message)));
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

  const setAllProfiles = useCallback(
    (value: boolean) => {
      const next: Record<string, boolean> = {};
      for (const group of specificGroups) {
        next[group.target] = value;
        saveEnabled(group.target, value);
      }
      setEnabledMap((prev) => ({ ...prev, ...next }));
    },
    [specificGroups],
  );

  const chosenFor = useCallback(
    (group: PresetGroup): string => {
      const saved = defaultMap[group.target];
      if (saved && group.presets.some((p) => p.name === saved)) return saved;
      const main = group.presets.find((preset) => preset.description.toLowerCase().startsWith("основной пресет"));
      return main?.name ?? group.presets[0]?.name ?? "";
    },
    [defaultMap],
  );

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

  async function startWithNames(names: string[]) {
    const port = Math.floor(Number(qnum));
    if (!Number.isFinite(port) || port <= 0 || port > 65535) {
      setError("qnum должен быть числом от 1 до 65535");
      return;
    }
    setStarting(true);
    setError("");
    try {
      if (privilege && privilege.needs_prompt && !privilege.granted) {
        setAwaitingGrant(true);
        const granted = await runGrant();
        setAwaitingGrant(false);
        if (!granted) return;
      }
      await startWs(names, port, mode);
      setStatus(await fetchWsStatus());
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
    } finally {
      setStarting(false);
      setAwaitingGrant(false);
    }
  }

  async function start() {
    const activeGroups =
      effectiveMode === "all"
        ? universalGroups.slice(0, 1)
        : specificGroups.filter((group) => isEnabled(group.target, enabledMap));
    if (activeGroups.length === 0) {
      setError(
        effectiveMode === "all"
          ? "Ядро не отдало универсальный пресет — выберите «Точечно»"
          : "Выберите хотя бы один сервис или переключитесь на «Все сайты»",
      );
      return;
    }
    const names = [...new Set(activeGroups.map(chosenFor).filter(Boolean))];
    await startWithNames(names);
  }

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

  async function runAutoPick() {
    const probes = specificGroups
      .map((group) => ({ target: group.target, domain: targetProbe(group.target) }))
      .filter((item) => item.domain !== "");
    if (probes.length === 0) return;
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
        setError(`Проверка не завершилась за ${AUTO_PICK_POLLS} с`);
        return;
      }
      const blocked = new Set(results.filter((item) => item.status !== "ok").map((item) => item.domain));
      const picked = probes.filter((item) => blocked.has(item.domain)).map((item) => item.target);
      const next: Record<string, boolean> = {};
      for (const group of specificGroups) {
        next[group.target] = picked.includes(group.target);
        saveEnabled(group.target, next[group.target]);
      }
      setEnabledMap(next);
      setAutoNote(
        picked.length > 0
          ? `Заблокировано и выбрано: ${picked.join(", ")}.`
          : "Ничего не заблокировано — выбор снят.",
      );
    } catch (e) {
      setError(String((e as Error).message));
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
  const rightsGranted = Boolean(privilege?.granted || status?.root);
  const rightsKnown = Boolean(privilege || status);
  const universalChosen = universalGroups.length > 0 ? chosenFor(universalGroups[0]) : "";

  return {
    presets,
    specificGroups,
    visibleProfiles,
    enabledTargets,
    hasUniversal,
    universalKnown,
    effectiveMode,
    chooseProfileMode,
    search,
    setSearch,
    enabledMap,
    toggleGroup,
    setAllProfiles,
    universalChosen,
    autoRunning,
    autoProgress,
    autoNote,
    runAutoPick,
    qnum,
    setQnum,
    mode,
    setMode,
    status,
    running,
    busy,
    stopping,
    granting,
    awaitingGrant,
    offline,
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
