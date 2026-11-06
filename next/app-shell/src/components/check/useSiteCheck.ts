import { useEffect, useState } from "react";
import { fetchCheckSites, fetchCheckStatus, SiteCheckResult } from "../../api";
import { ALL_DOMAINS, CheckGroup } from "../../data/checkDomains";

const MAX_POLLS = 120;

export function useSiteCheck() {
  const [checked, setChecked] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(ALL_DOMAINS.map((domain) => [domain, true])),
  );
  const [running, setRunning] = useState(false);
  const [finished, setFinished] = useState(false);
  const [results, setResults] = useState<SiteCheckResult[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!running) return;
    let alive = true;
    let attempts = 0;
    const tick = async () => {
      attempts += 1;
      try {
        const status = await fetchCheckStatus();
        if (!alive) return;
        setResults(status.results ?? []);
        if (status.done) {
          setFinished(true);
          setRunning(false);
          return;
        }
        if (attempts >= MAX_POLLS) {
          setError(`Проверка не завершилась за ${MAX_POLLS} с`);
          setRunning(false);
        }
      } catch (e) {
        if (!alive) return;
        setError(String((e as Error).message));
        setRunning(false);
      }
    };
    void tick();
    const timer = window.setInterval(() => void tick(), 1000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [running]);

  const toggle = (domain: string) => setChecked((prev) => ({ ...prev, [domain]: !prev[domain] }));

  const toggleGroup = (group: CheckGroup) => {
    const domains = group.services.map((service) => service.domain);
    const allOn = domains.every((domain) => checked[domain]);
    setChecked((prev) => {
      const next = { ...prev };
      for (const domain of domains) next[domain] = !allOn;
      return next;
    });
  };

  const selectedCount = ALL_DOMAINS.filter((domain) => checked[domain]).length;
  const allSelected = selectedCount === ALL_DOMAINS.length;

  const toggleAll = () =>
    setChecked(Object.fromEntries(ALL_DOMAINS.map((domain) => [domain, !allSelected])));

  async function run() {
    const domains = ALL_DOMAINS.filter((domain) => checked[domain]);
    if (domains.length === 0) {
      setError("Отметьте хотя бы один домен");
      return;
    }
    setError("");
    setResults([]);
    setFinished(false);
    setTotal(domains.length);
    try {
      await fetchCheckSites(domains);
      setRunning(true);
    } catch (e) {
      setError(String((e as Error).message));
    }
  }

  const okCount = results.filter((r) => r.status === "ok").length;
  const blocked = results.filter((r) => r.status === "blocked");
  const slowCount = results.filter((r) => r.status === "slow").length;

  return {
    checked,
    toggle,
    toggleGroup,
    toggleAll,
    allSelected,
    selectedCount,
    running,
    finished,
    results,
    total,
    error,
    run,
    okCount,
    blocked,
    slowCount,
  };
}

export type SiteCheckModel = ReturnType<typeof useSiteCheck>;
