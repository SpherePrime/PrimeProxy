const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("installerAPI", {
  info: () => ipcRenderer.invoke("installer:info"),
  pickDir: (current) => ipcRenderer.invoke("installer:pick-dir", current),
  install: (options) => ipcRenderer.invoke("installer:install", options),
  uninstall: (options) => ipcRenderer.invoke("installer:uninstall", options),
  launch: (exe) => ipcRenderer.send("installer:launch", exe),
  close: () => ipcRenderer.send("installer:close"),
  minimize: () => ipcRenderer.send("installer:minimize"),
  openFolder: (dir) => ipcRenderer.send("installer:open-folder", dir),
  onProgress: (callback) => ipcRenderer.on("installer:progress", (_event, state) => callback(state)),
});
