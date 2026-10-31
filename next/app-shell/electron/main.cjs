//! Главный процесс Electron: поднимает sidecar primecore-server (Rust-ядро)
//! и открывает окно с Vite-сборкой интерфейса.
//!
//! Адрес sidecar берётся из PRIMECORE_PORT (7290 по умолчанию), путь к
//! бинарнику — PRIMECORE_BIN или соседний target/release. Пока сервер не
//! ответил на /health, окно не открывается: интерфейс без ядра бесполезен.

const { app, BrowserWindow, ipcMain } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const PORT = Number(process.env.PRIMECORE_PORT || 7290);
const BASE = `http://127.0.0.1:${PORT}`;

// Репозиторий: electron/ → app-shell; Resources читаются от корня репо.
const repoRoot = path.join(__dirname, "..", "..", "..");

// Бинарник sidecar: рядом в target/release или из переменной окружения.
function sidecarPath() {
  if (process.env.PRIMECORE_BIN) return process.env.PRIMECORE_BIN;
  // Windows: у собранного бинарника расширение .exe, поэтому проверяем оба
  // имени — иначе оболочка падала на «голое» имя и не находила ядро.
  const names = process.platform === "win32"
    ? ["primecore-server.exe", "primecore-server"]
    : ["primecore-server"];
  for (const name of names) {
    const candidate = path.join(repoRoot, "target", "release", name);
    if (fs.existsSync(candidate)) return candidate;
  }
  return "primecore-server";
}

let sidecar = null;

function startSidecar() {
  sidecar = spawn(sidecarPath(), [], {
    cwd: repoRoot,
    env: { ...process.env, PRIMECORE_PORT: String(PORT) },
    stdio: ["ignore", "inherit", "inherit"],
    // Ядро — консольная программа: без этого Windows открывает ей отдельное
    // чёрное окно рядом с интерфейсом.
    windowsHide: true,
  });
  sidecar.on("exit", (code) => console.log(`primecore-server завершён (код ${code})`));
  sidecar.on("error", (error) => console.error(`primecore-server не запущен: ${error.message}`));
}

// Ждём /health: интерфейс стартует только с живым ядром.
async function waitHealth() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await fetch(`${BASE}/health`);
      if (response.ok) return true;
    } catch (_) {
      // сервер ещё не поднялся — пробуем снова
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return false;
}

async function createWindow() {
  const healthy = await waitHealth();
  if (!healthy) {
    console.error("primecore-server не ответил на /health — окно не открыто");
    app.quit();
    return;
  }
  const window = new BrowserWindow({
    width: 1360,
    height: 900,
    minWidth: 900,
    minHeight: 640,
    title: "PrimeBypass",
    // Своя полоса заголовка: рисуем её в интерфейсе (свернуть/развернуть/
    // закрыть), поэтому системную рамку убираем.
    frame: false,
    backgroundColor: "#0f172a",
    webPreferences: { preload: path.join(__dirname, "preload.cjs") },
  });

  // Кнопки заголовка из интерфейса: окно ими управляет главный процесс.
  ipcMain.on("window:minimize", () => window.minimize());
  ipcMain.on("window:toggle-maximize", () => {
    if (window.isMaximized()) window.unmaximize();
    else window.maximize();
  });
  ipcMain.on("window:close", () => window.close());
  const sendState = () =>
    window.webContents.send("window:state", { maximized: window.isMaximized() });
  window.on("maximize", sendState);
  window.on("unmaximize", sendState);
  window.webContents.on("did-finish-load", sendState);

  // В dev грузим dev-сервер Vite, в сборке — собранные файлы.
  const devUrl = process.env.VITE_URL;
  if (devUrl) {
    window.loadURL(devUrl);
  } else {
    window.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }
}

app.whenReady().then(() => {
  startSidecar();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (sidecar) sidecar.kill();
  if (process.platform !== "darwin") app.quit();
});
