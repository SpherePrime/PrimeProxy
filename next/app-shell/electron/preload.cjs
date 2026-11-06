//! Мост безопасного контекста: что страница может звать у оболочки.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  ping: () => "оболочка готова",
  // Своя полоса заголовка: кнопки окна живут в интерфейсе, а само окно
  // слушается главного процесса.
  window: {
    minimize: () => ipcRenderer.send("window:minimize"),
    toggleMaximize: () => ipcRenderer.send("window:toggle-maximize"),
    close: () => ipcRenderer.send("window:close"),
    onState: (callback) => {
      ipcRenderer.on("window:state", (_event, state) => callback(state));
    },
  },
  elevation: {
    request: (options) => ipcRenderer.invoke("app:elevate", options),
    takeAutostart: () => ipcRenderer.invoke("app:take-autostart"),
  },
  files: {
    pick: (options) => ipcRenderer.invoke("files:pick", options),
    open: (target) => ipcRenderer.invoke("files:open", target),
    reveal: (target) => ipcRenderer.invoke("files:reveal", target),
  },
});
