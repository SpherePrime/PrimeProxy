import { useCallback, useEffect, useState } from "react";
import { fetchTgProxy, fetchTgWorker, startTgProxy, stopTgProxy, TgProxyStatus, TgWorkerData } from "../../api";

export const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 1353;
const POLL_MS = 2000;

export function bytesLabel(value: number): string {
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} МБ`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} КБ`;
  return `${value} Б`;
}

export function useTgProxy() {
  const [status, setStatus] = useState<TgProxyStatus | null>(null);
  const [host, setHost] = useState(DEFAULT_HOST);
  const [port, setPort] = useState(String(DEFAULT_PORT));
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [worker, setWorker] = useState<TgWorkerData | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await fetchTgProxy();
      setStatus(data);
      return data;
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      return null;
    }
  }, []);

  useEffect(() => {
    let alive = true;
    void load().then((data) => {
      if (!alive || !data) return;
      if (data.host) setHost(data.host);
      if (data.port) setPort(String(data.port));
      if (data.front && data.front.includes(".")) setDomain(data.front);
    });
    const timer = window.setInterval(() => void load(), POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [load]);

  const running = status?.running ?? false;
  const link = status?.link ?? `tg://socks?server=${host}&port=${port}`;

  async function connect() {
    const value = Math.floor(Number(port));
    if (!Number.isFinite(value) || value <= 0 || value > 65535) {
      setError("Порт должен быть числом от 1 до 65535");
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await startTgProxy(host.trim() || DEFAULT_HOST, value, domain.trim());
      setNotice("Прокси поднят — добавьте ссылку в Telegram.");
      await load();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await stopTgProxy();
      setNotice("Прокси остановлен.");
      await load();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      setNotice(`${what} скопирован в буфер обмена.`);
      setError("");
    } catch (e) {
      setError(`Не удалось скопировать: ${String((e as Error).message)}`);
    }
  }

  async function loadWorker() {
    setError("");
    try {
      setWorker(await fetchTgWorker());
      setNotice("Код воркера готов — скопируйте его в Cloudflare.");
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  }

  return {
    status,
    running,
    link,
    host,
    setHost,
    port,
    setPort,
    domain,
    setDomain,
    busy,
    error,
    notice,
    worker,
    connect,
    disconnect,
    copy,
    loadWorker,
  };
}

export type TgModel = ReturnType<typeof useTgProxy>;
