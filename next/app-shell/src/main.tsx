import React, { useState } from "react";
import ReactDOM from "react-dom/client";
import { DnsPage } from "./components/DnsPage";
import { BypassPage } from "./components/BypassPage";
import "./styles.css";

// Боковая навигация в духе FluentWindow из PyQt6-эталона: слева фиксированная
// панель с пунктами «иконка + подпись», активный пункт подсвечен. Маршрутизатор
// не нужен — страницы грузятся только по одной, достаточно useState.
type PageId = "bypass" | "dns";

const NAV_ITEMS: Array<{ id: PageId; icon: string; title: string }> = [
  { id: "bypass", icon: "🛡", title: "Обход" },
  { id: "dns", icon: "🌐", title: "DNS" },
];

function App() {
  const [page, setPage] = useState<PageId>("bypass");

  return (
    <div className="app-shell">
      <nav className="nav" aria-label="Основная навигация">
        <div className="nav-brand">PrimeBypass</div>
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${page === item.id ? "active" : ""}`}
            onClick={() => setPage(item.id)}
            aria-current={page === item.id ? "page" : undefined}
          >
            <span className="nav-icon" aria-hidden="true">
              {item.icon}
            </span>
            <span>{item.title}</span>
          </button>
        ))}
      </nav>
      <main className="content">
        {page === "bypass" ? <BypassPage /> : <DnsPage />}
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
