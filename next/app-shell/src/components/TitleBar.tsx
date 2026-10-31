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
        <span className="titlebar-mark" aria-hidden="true" />
        <span className="titlebar-title">{title}</span>
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
