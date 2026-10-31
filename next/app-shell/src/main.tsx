import React, { useState } from "react";
import ReactDOM from "react-dom/client";
import { API } from "./api";
import { DnsToolsPage } from "./components/DnsToolsPage";
import { BypassPage } from "./components/BypassPage";
import { CheckPage } from "./components/CheckPage";
import { TelegramPage } from "./components/TelegramPage";
import { HostsPage } from "./components/HostsPage";
import { LogAnalyzerPage } from "./components/LogAnalyzerPage";
import { FakesPage } from "./components/FakesPage";
import { TitleBar } from "./components/TitleBar";
import {
  IconChart,
  IconGlobe,
  IconLayers,
  IconSearch,
  IconSend,
  IconShield,
  IconUnlock,
} from "./components/Icons";
import "./styles.css";

// Боковая навигация: слева «патч-панель» из групп инструментов.
// Маршрутизатор не нужен — страницы грузятся только по одной, достаточно
// useState. Номер пункта совпадает с номером в шапке страницы.
type PageId = "bypass" | "hosts" | "check" | "logs" | "dns" | "telegram" | "fakes";

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
  {
    label: "Библиотека",
    items: [{ id: "fakes", index: "07", icon: IconLayers, title: "Фейки" }],
  },
];

// Адрес ядра без схемы — так его удобнее читать в узкой панели.
const ENGINE_ADDRESS = API.replace(/^https?:\/\//, "");

function App() {
  const [page, setPage] = useState<PageId>("bypass");

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        К содержимому
      </a>
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
          <div className="side-foot">
            <span className="side-foot-label">Ядро</span>
            <code className="side-foot-value">{ENGINE_ADDRESS}</code>
            <span className="side-foot-note">локальный HTTP API</span>
          </div>
        </aside>
        <main className="content" id="main" tabIndex={-1}>
          {page === "bypass" && <BypassPage />}
          {page === "hosts" && <HostsPage />}
          {page === "check" && <CheckPage />}
          {page === "logs" && <LogAnalyzerPage />}
          {page === "dns" && <DnsToolsPage />}
          {page === "telegram" && <TelegramPage />}
          {page === "fakes" && <FakesPage />}
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
