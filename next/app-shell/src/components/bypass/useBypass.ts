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
import {
  getBestProfileForTarget,
  getTop5Profiles,
  ProfileScore,
  reportProfileFailure,
  setActiveProfileInTop5,
  updateAllRankingsFromCheckResults,
} from "./profileRanking";
import { elevationBridge } from "../../electronBridge";

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
  const [elevating, setElevating] = useState(false);
  const [autostart, setAutostart] = useState(false);
  const [enabledMap, setEnabledMap] = useState<Record<string, boolean>>(loadEnabled);
  const [defaultMap] = useState<Record<string, string>>(loadDefaults);
  const [rankingVersion, setRankingVersion] = useState(0);
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
      void rankingVersion;
      return getBestProfileForTarget(group.target, group.presets);
    },
    [rankingVersion],
  );

  const getTop5 = useCallback(
    (target: string, groupPresets: PresetInfo[]): ProfileScore[] => {
      void rankingVersion;
      return getTop5Profiles(target, groupPresets);
    },
    [rankingVersion],
  );

  const selectPreset = useCallback(
    (target: string, presetName: string) => {
      const group = groups.find((g) => g.target === target);
      if (!group) return;
      setActiveProfileInTop5(target, presetName, group.presets);
      setRankingVersion((v) => v + 1);
    },
    [groups],
  );

  const triggerFailover = useCallback(
    async (target: string) => {
      const group = groups.find((g) => g.target === target);
      if (!group || group.presets.length < 2) return;
      const currentActive = chosenFor(group);
      const result = reportProfileFailure(target, currentActive, group.presets);
      if (result) {
        setRankingVersion((v) => v + 1);
        setAutoNote(
          `Сбой профиля «${result.failedProfile}» для ${target}. Автоматически переключено на 2-й лучший: «${result.nextBestProfile}» (задержка: ${result.latencyMs} мс).`,
        );
        if (status?.running) {
          try {
            await stopWs();
            await new Promise((r) => setTimeout(r, 400));
            const activeGroups =
              effectiveMode === "all"
                ? (enabledTargets.length > 0
                    ? [
                        ...universalGroups.slice(0, 1),
                        ...specificGroups.filter((g) => isEnabled(g.target, enabledMap)),
                      ]
                    : universalGroups.slice(0, 1))
                : specificGroups.filter((g) => isEnabled(g.target, enabledMap));
            const newNames = [
              ...new Set(
                activeGroups
                  .map((g) => (g.target === target ? result.nextBestProfile : chosenFor(g)))
                  .filter(Boolean),
              ),
            ];
            await startWithNames(newNames);
          } catch (e) {
            setError(String((e as Error).message));
          }
        }
      }
    },
    [groups, chosenFor, status?.running, effectiveMode, enabledTargets, specificGroups, universalGroups, enabledMap],
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
      // Автоматический фолбэк при сбое старта: переключаем сбойный профиль на 2-й лучший из Топ-5
      for (const target of enabledTargets) {
        const group = specificGroups.find((g) => g.target === target);
        if (group && group.presets.length > 1) {
          const current = chosenFor(group);
          if (names.includes(current) && (err.message.includes(current) || names.length === 1)) {
            const failover = reportProfileFailure(target, current, group.presets);
            if (failover) {
              setRankingVersion((v) => v + 1);
              setAutoNote(
                `Профиль «${failover.failedProfile}» дал сбой для ${target}. Автоматически переключено на 2-й лучший: «${failover.nextBestProfile}» (задержка: ${failover.latencyMs} мс). Нажмите «Включить» ещё раз.`,
              );
              break;
            }
          }
        }
      }
    } finally {
      setStarting(false);
      setAwaitingGrant(false);
    }
  }

  async function requestElevation(): Promise<boolean> {
    const bridge = elevationBridge();
    if (!bridge) {
      setError("Нет прав администратора: запустите ядро от имени администратора.");
      return false;
    }
    setElevating(true);
    setError("");
    try {
      const result = await bridge.request();
      if (result.ok && result.already) return true;
      if (!result.ok) setError(result.error ?? "Права не выданы — без них движок не запустится.");
      return false;
    } finally {
      setElevating(false);
    }
  }

  async function start() {
    if (status && !status.root && status.platform === "windows") {
      const ready = await requestElevation();
      if (!ready) return;
    }
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

      // Обновляем замеры задержки и рейтинги Топ-5 для каждого приложения
      updateAllRankingsFromCheckResults(
        results,
        specificGroups.map((group) => group.target),
        presets,
      );
      setRankingVersion((v) => v + 1);

      const blocked = new Set(results.filter((item) => item.status !== "ok").map((item) => item.domain));
      const picked = probes.filter((item) => blocked.has(item.domain)).map((item) => item.target);
      const next: Record<string, boolean> = {};
      for (const group of specificGroups) {
        next[group.target] = picked.includes(group.target);
        saveEnabled(group.target, next[group.target]);
      }
      setEnabledMap(next);
      chooseProfileMode("profiles");
      setAutoNote(
        picked.length > 0
          ? `Автоматически определено: ${results.length - picked.length} сервисов идут напрямую (максимальная скорость), а для ${picked.length} заблокированных (${picked.join(", ")}) включены лучшие профили обхода.`
          : "Все сервисы работают напрямую без блокировки — обход не требуется.",
      );

      // Если обход уже работал, сразу перезапускаем его с новым оптимизированным набором
      if (status?.running && picked.length > 0) {
        try {
          await stopWs();
          await new Promise((r) => setTimeout(r, 400));
          const activeGroups = specificGroups.filter((g) => next[g.target]);
          const names = [...new Set(activeGroups.map(chosenFor).filter(Boolean))];
          await startWithNames(names);
        } catch (e) {
          setError(String((e as Error).message));
        }
      }
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setAutoRunning(false);
    }
  }

  useEffect(() => {
    let restart = false;
    try {
      if (localStorage.getItem("pp.restart_needed") === "1") {
        localStorage.removeItem("pp.restart_needed");
        restart = true;
      }
    } catch {
      // ignore
    }
    if (restart && presets.length > 0 && status) {
      setEnabledMap(loadEnabled());
      chooseProfileMode("profiles");
      setRankingVersion((v) => v + 1);
      if (status.running) {
        void stop().then(() => void start());
      } else {
        void start();
      }
    }
  });

  useEffect(() => {
    elevationBridge()
      ?.takeAutostart()
      .then((flag) => flag && setAutostart(true))
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!autostart || presets.length === 0 || !status) return;
    setAutostart(false);
    if (!status.running) void start();
  });

  const running = status?.running ?? false;
  const busy = starting || stopping || granting || awaitingGrant || elevating;
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
    chosenFor,
    getTop5,
    selectPreset,
    triggerFailover,
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
    elevating,
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
