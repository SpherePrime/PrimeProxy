import { useState } from "react";
import { BypassPage } from "./components/bypass/BypassPage";
import { CheckPage } from "./components/check/CheckPage";
import { DnsPage } from "./components/dns/DnsPage";
import { HostsPage } from "./components/hosts/HostsPage";
import { LogsPage } from "./components/logs/LogsPage";
import { Backdrop } from "./components/shell/Backdrop";
import { NavTabs } from "./components/shell/NavTabs";
import { PageId } from "./components/shell/pages";
import { TopBar } from "./components/shell/TopBar";
import { TelegramPage } from "./components/telegram/TelegramPage";
import { useEngineStatus } from "./hooks/useEngineStatus";

export function App() {
  const [page, setPage] = useState<PageId>("bypass");
  const engine = useEngineStatus();

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        К содержимому
      </a>
      <Backdrop />
      <TopBar current={page} engine={engine} onNavigate={setPage} />
      <div className="app__body">
        <main className="content" id="main" tabIndex={-1}>
          {page === "bypass" && <BypassPage />}
          {page === "hosts" && <HostsPage />}
          {page === "check" && <CheckPage onNavigate={setPage} />}
          {page === "logs" && <LogsPage />}
          {page === "dns" && <DnsPage />}
          {page === "telegram" && <TelegramPage />}
        </main>
        <NavTabs current={page} onNavigate={setPage} variant="bottom" />
      </div>
    </div>
  );
}
