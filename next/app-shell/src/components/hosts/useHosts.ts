import { useCallback, useEffect, useMemo, useState } from "react";
import { applyHosts, fetchHostsFile, HostsApplyResponse, HostsFileResponse } from "../../api";
import { BLOCK_ADDRESS, CATEGORIES, countIn, Service, SERVICES } from "../../data/hostsServices";

export function useHosts() {
  const [file, setFile] = useState<HostsFileResponse | null>(null);
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

  const current = useMemo(() => new Set((file?.managed_rows ?? []).map((row) => row[0])), [file]);
  const added = useMemo(() => [...desired].filter((domain) => !current.has(domain)), [desired, current]);
  const removed = useMemo(() => [...current].filter((domain) => !desired.has(domain)), [desired, current]);
  const dirty = added.length > 0 || removed.length > 0;

  const unlockedCount = SERVICES.filter((service) => countIn(current, service.domains) === service.domains.length).length;
  const selectedCount = SERVICES.filter((service) => countIn(desired, service.domains) > 0).length;

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
    setConfirmOpen(false);
  };

  const fillAll = () => {
    setDesired(new Set(SERVICES.flatMap((service) => service.domains)));
    setNotice(null);
  };

  const clearAll = () => {
    setDesired(new Set());
    setNotice(null);
  };

  const reset = () => {
    void load();
    setConfirmOpen(false);
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
      setNotice(`Блок записан: ${result.blocked_count} строк, бэкап .primebak создан.`);
      await load();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      setConfirmOpen(false);
    } finally {
      setBusy(false);
    }
  };

  return {
    file,
    desired,
    current,
    loaded,
    search,
    setSearch,
    confirmOpen,
    setConfirmOpen,
    busy,
    error,
    notice,
    applied,
    added,
    removed,
    dirty,
    unlockedCount,
    selectedCount,
    visibleCategories,
    toggleService,
    fillAll,
    clearAll,
    reset,
    reload: load,
    apply,
  };
}

export type HostsModel = ReturnType<typeof useHosts>;
