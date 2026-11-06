import { useEffect, useState } from "react";
import { fetchHealth, fetchTgProxy, fetchWsStatus, WsStatus } from "../api";

const POLL_MS = 3000;

export type CoreLink = "checking" | "online" | "offline";

export interface EngineSnapshot {
  link: CoreLink;
  status: WsStatus | null;
  tgRunning: boolean;
}

export function useEngineStatus(): EngineSnapshot {
  const [snapshot, setSnapshot] = useState<EngineSnapshot>({ link: "checking", status: null, tgRunning: false });

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      const healthy = await fetchHealth();
      if (!alive) return;
      if (!healthy) {
        setSnapshot({ link: "offline", status: null, tgRunning: false });
        return;
      }
      const [status, tg] = await Promise.all([
        fetchWsStatus().catch(() => null),
        fetchTgProxy().catch(() => null),
      ]);
      if (alive) setSnapshot({ link: "online", status, tgRunning: Boolean(tg?.running) });
    };
    void poll();
    const timer = window.setInterval(() => void poll(), POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  return snapshot;
}
