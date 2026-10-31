import { useEffect, useState } from "react";
import { IconClose, IconMaximize, IconMinimize, IconRestore } from "./Icons";

// Мост оболочки (см. electron/preload.cjs): кнопки окна живут в интерфейсе,
// а само окно слушается главного процесса.
type WindowBridge = {
  minimize: () => void;
  toggleMaximize: () => void;
  close: () => void;
  onState: (callback: (state: { maximized: boolean }) => void) => void;
};

function windowBridge(): WindowBridge | undefined {
  const api = (window as unknown as { electronAPI?: { window?: WindowBridge } }).electronAPI;
  return api?.window;
}

/** Знак приложения: щит с разрывом — «обход», без эмодзи и внешних картинок. */
function AppMark() {
  return (
    <svg
      className="titlebar-mark"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.9}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M12 3l7 3v5.5c0 4-2.9 7.4-7 8.5-4.1-1.1-7-4.5-7-8.5V6z" />
      <path d="M9.5 12.2l1.9 1.9 3.4-3.6" />
    </svg>
  );
}

/**
 * Своя полоса заголовка: у окна отключена системная рамка (`frame: false`),
 * поэтому перетаскивание и кнопки свернуть/развернуть/закрыть рисуем сами.
 *
 * В обычном браузере моста нет — полоса остаётся как шапка без кнопок.
 */
export function TitleBar({ title }: { title: string }) {
  const [maximized, setMaximized] = useState(false);
  const bridge = windowBridge();

  useEffect(() => {
    bridge?.onState((state) => setMaximized(state.maximized));
  }, [bridge]);

  return (
    <header className="titlebar">
      <div className="titlebar-drag">
        <AppMark />
        <span className="titlebar-title">{title}</span>
        <span className="titlebar-sep" aria-hidden="true" />
        <span className="titlebar-sub">консоль обхода</span>
      </div>
      {bridge && (
        <div className="titlebar-buttons">
          <button
            type="button"
            className="titlebar-btn"
            onClick={() => bridge.minimize()}
            title="Свернуть"
            aria-label="Свернуть окно"
          >
            <IconMinimize />
          </button>
          <button
            type="button"
            className="titlebar-btn"
            onClick={() => bridge.toggleMaximize()}
            title={maximized ? "Вернуть размер" : "Во весь экран"}
            aria-label={maximized ? "Вернуть размер окна" : "Развернуть на весь экран"}
          >
            {maximized ? <IconRestore /> : <IconMaximize />}
          </button>
          <button
            type="button"
            className="titlebar-btn titlebar-close"
            onClick={() => bridge.close()}
            title="Закрыть"
            aria-label="Закрыть окно"
          >
            <IconClose size={13} />
          </button>
        </div>
      )}
    </header>
  );
}
