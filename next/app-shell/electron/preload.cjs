//! Мост безопасного контекста: что страница может звать у оболочки.
const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  ping: () => "оболочка готова",
});
