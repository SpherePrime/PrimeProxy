import { useEffect, useState } from "react";
import { IconClose, IconMaximize, IconMinimize, IconRestore } from "../Icons";

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

export function WindowButtons() {
  const [maximized, setMaximized] = useState(false);
  const bridge = windowBridge();

  useEffect(() => {
    bridge?.onState((state) => setMaximized(state.maximized));
  }, [bridge]);

  if (!bridge) return null;

  return (
    <div className="window-buttons">
      <button type="button" className="window-btn" onClick={() => bridge.minimize()} aria-label="Свернуть окно">
        <IconMinimize />
      </button>
      <button
        type="button"
        className="window-btn"
        onClick={() => bridge.toggleMaximize()}
        aria-label={maximized ? "Вернуть размер окна" : "Развернуть окно"}
      >
        {maximized ? <IconRestore /> : <IconMaximize />}
      </button>
      <button
        type="button"
        className="window-btn window-btn--close"
        onClick={() => bridge.close()}
        aria-label="Закрыть окно"
      >
        <IconClose size={13} />
      </button>
    </div>
  );
}
