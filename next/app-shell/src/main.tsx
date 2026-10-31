import React, { useState } from "react";
import ReactDOM from "react-dom/client";
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

// Боковая навигация: слева фиксированная панель с пунктами «иконка + подпись»,
// активный пункт подсвечен. Иконки — свои SVG (см. Icons.tsx), без эмодзи:
// они одинаково выглядят на любой системе и наследуют цвет текста.
// Маршрутизатор не нужен — страницы грузятся только по одной, достаточно useState.
type PageId = "bypass" | "hosts" | "check" | "logs" | "dns" | "telegram" | "fakes";

const NAV_ITEMS: Array<{
  id: PageId;
  icon: (props: { size?: number }) => React.JSX.Element;
  title: string;
}> = [
  { id: "bypass", icon: IconShield, title: "Обход" },
  { id: "hosts", icon: IconUnlock, title: "Разблокировка" },
  { id: "check", icon: IconSearch, title: "Проверка" },
  { id: "logs", icon: IconChart, title: "Анализ лога" },
  { id: "dns", icon: IconGlobe, title: "DNS" },
  { id: "telegram", icon: IconSend, title: "Telegram" },
  { id: "fakes", icon: IconLayers, title: "Фейки" },
];

function App() {
  const [page, setPage] = useState<PageId>("bypass");

  return (
    <div className="app-shell">
      <TitleBar title="PrimeBypass" />
      <div className="app-body">
        <nav className="nav" aria-label="Основная навигация">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                className={`nav-item ${page === item.id ? "active" : ""}`}
                onClick={() => setPage(item.id)}
                aria-current={page === item.id ? "page" : undefined}
              >
                <span className="nav-icon" aria-hidden="true">
                  <Icon size={18} />
                </span>
                <span>{item.title}</span>
              </button>
            );
          })}
        </nav>
        <main className="content">
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
