import { useEffect, useState } from "react";
import { API, fetchHealth } from "../api";

// Нижний блок панели: живое состояние ядра.
//
// Раньше здесь была декоративная точка и адрес — она горела бирюзой всегда,
// даже когда ядро не отвечало. Теперь точка и подпись отражают настоящую
// связь: панель раз в пять секунд спрашивает /health.

const POLL_MS = 5000;

type CoreState = "checking" | "online" | "offline";

const STATE_LABELS: Record<CoreState, string> = {
  checking: "проверяю",
  online: "на связи",
  offline: "нет связи",
};

export function CoreStatus() {
  const [state, setState] = useState<CoreState>("checking");
  // Адрес без схемы — так его удобнее читать в узкой панели.
  const address = API.replace(/^https?:\/\//, "");

  useEffect(() => {
    let alive = true;
    const check = async () => {
      const ok = await fetchHealth();
      if (alive) setState(ok ? "online" : "offline");
    };
    void check();
    const timer = window.setInterval(() => void check(), POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <div className="side-foot" data-state={state}>
      <span className="side-foot-label">
        <span className="side-foot-dot" aria-hidden="true" />
        Ядро · {STATE_LABELS[state]}
      </span>
      <code className="side-foot-value">{address}</code>
      <span className="side-foot-note">
        {state === "offline"
          ? "ядро не отвечает — проверьте, запущен ли primecore-server"
          : "локальный HTTP API"}
      </span>
    </div>
  );
}
