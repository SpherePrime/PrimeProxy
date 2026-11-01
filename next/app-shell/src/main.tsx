import React, { useState } from "react";
import ReactDOM from "react-dom/client";
import { DnsToolsPage } from "./components/DnsToolsPage";
import { BypassPage } from "./components/BypassPage";
import { CheckPage } from "./components/CheckPage";
import { TelegramPage } from "./components/TelegramPage";
import { HostsPage } from "./components/HostsPage";
import { LogAnalyzerPage } from "./components/LogAnalyzerPage";
import { TitleBar } from "./components/TitleBar";
import { CoreStatus } from "./components/CoreStatus";
import {
  IconChart,
  IconGlobe,
  IconSearch,
  IconSend,
  IconShield,
  IconUnlock,
} from "./components/Icons";
import "./styles.css";

// Боковая навигация: слева «патч-панель» из групп инструментов.
// Маршрутизатор не нужен — страницы грузятся только по одной, достаточно
// useState. Номер пункта совпадает с номером в шапке страницы.
type PageId = "bypass" | "hosts" | "check" | "logs" | "dns" | "telegram";

interface NavItem {
  id: PageId;
  index: string;
  icon: (props: { size?: number }) => React.JSX.Element;
  title: string;
}

const NAV_GROUPS: Array<{ label: string; items: NavItem[] }> = [
  {
    label: "Управление",
    items: [
      { id: "bypass", index: "01", icon: IconShield, title: "Обход" },
      { id: "hosts", index: "02", icon: IconUnlock, title: "Разблокировка" },
    ],
  },
  {
    label: "Диагностика",
    items: [
      { id: "check", index: "03", icon: IconSearch, title: "Проверка" },
      { id: "logs", index: "04", icon: IconChart, title: "Анализ лога" },
    ],
  },
  {
    label: "Сеть",
    items: [
      { id: "dns", index: "05", icon: IconGlobe, title: "DNS" },
      { id: "telegram", index: "06", icon: IconSend, title: "Telegram" },
    ],
  },
];

function App() {
  const [page, setPage] = useState<PageId>("bypass");

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        К содержимому
      </a>
      {/* Атмосфера сайта студии: два дышащих пятна и зерно под всем окном. */}
      <div className="atmosphere" aria-hidden="true">
        <span className="atmosphere__orb atmosphere__orb--violet" />
        <span className="atmosphere__orb atmosphere__orb--cyan" />
        <span className="atmosphere__grain" />
      </div>
      <TitleBar title="PrimeBypass" />
      <div className="app-body">
        <aside className="sidebar">
          <nav className="nav" aria-label="Основная навигация">
            {NAV_GROUPS.map((group) => (
              <div className="nav-group" key={group.label}>
                <span className="nav-group-label">{group.label}</span>
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const current = page === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      className={`nav-item ${current ? "active" : ""}`}
                      onClick={() => setPage(item.id)}
                      aria-current={current ? "page" : undefined}
                      title={item.title}
                    >
                      <span className="nav-icon" aria-hidden="true">
                        <Icon size={18} />
                      </span>
                      <span className="nav-label">{item.title}</span>
                      <span className="nav-num">{item.index}</span>
                    </button>
                  );
                })}
              </div>
            ))}
          </nav>
          <CoreStatus />
        </aside>
        <main className="content" id="main" tabIndex={-1}>
          {page === "bypass" && <BypassPage />}
          {page === "hosts" && <HostsPage />}
          {page === "check" && <CheckPage />}
          {page === "logs" && <LogAnalyzerPage />}
          {page === "dns" && <DnsToolsPage />}
          {page === "telegram" && <TelegramPage />}
        </main>
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
