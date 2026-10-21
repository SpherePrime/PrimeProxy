//! Главный процесс Electron: поднимает sidecar primecore-server (Rust-ядро)
//! и открывает окно с Vite-сборкой интерфейса.
//!
//! Адрес sidecar берётся из PRIMECORE_PORT (7290 по умолчанию), путь к
//! бинарнику — PRIMECORE_BIN или соседний target/release. Пока сервер не
//! ответил на /health, окно не открывается: интерфейс без ядра бесполезен.

const { app, BrowserWindow } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const PORT = Number(process.env.PRIMECORE_PORT || 7290);
const BASE = `http://127.0.0.1:${PORT}`;

// Бинарник sidecar: рядом в target/release или из переменной окружения.
function sidecarPath() {
  if (process.env.PRIMECORE_BIN) return process.env.PRIMECORE_BIN;
  const candidate = path.join(__dirname, "..", "..", "target", "release", "primecore-server");
  return fs.existsSync(candidate) ? candidate : "primecore-server";
}

let sidecar = null;

function startSidecar() {
  sidecar = spawn(sidecarPath(), [], {
    env: { ...process.env, PRIMECORE_PORT: String(PORT) },
    stdio: ["ignore", "inherit", "inherit"],
  });
  sidecar.on("exit", (code) => console.log(`primecore-server завершён (код ${code})`));
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
    width: 1200,
    height: 800,
    title: "PrimeBypass",
    webPreferences: { preload: path.join(__dirname, "preload.cjs") },
  });
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
