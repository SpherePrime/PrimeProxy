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
});
