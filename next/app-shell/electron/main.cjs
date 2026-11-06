//! Главный процесс Electron: поднимает sidecar primecore-server (Rust-ядро)
//! и открывает окно с Vite-сборкой интерфейса.
//!
//! Адрес sidecar берётся из PRIMECORE_PORT (7290 по умолчанию), путь к
//! бинарнику — PRIMECORE_BIN или соседний target/release. Пока сервер не
//! ответил на /health, окно не открывается: интерфейс без ядра бесполезен.

const { app, BrowserWindow, dialog, ipcMain } = require("electron");
const { spawn, execFileSync } = require("child_process");
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

// ─────────────────────────── Права администратора (Windows) ─────────────
// Движку обхода (winws2) в манифесте нужен уровень High: без него Windows
// отказывает в запуске с ошибкой 740, потому что движок ставит драйвер
// WinDivert. Приложение стартует без прав, а UAC показывается в момент
// включения обхода: оболочка перезапускается повышенной с флагом
// --pb-autostart, и интерфейс сразу запускает движок. Отказ от запроса
// ничего не ломает — проверка, DNS и Telegram работают и без прав.

const HIGH_INTEGRITY_SID = "S-1-16-12288";
const SYSTEM32 = path.join(process.env.SystemRoot || "C:\\Windows", "System32");
const WHOAMI = path.join(SYSTEM32, "whoami.exe");
const POWERSHELL = path.join(SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe");

// Повышен ли текущий процесс: `whoami /groups` показывает уровень
// обязательного контроля, S-1-16-12288 — High («от имени администратора»).
// Тот же признак использует ядро в /api/ws/privilege.
function isElevated() {
  if (process.platform !== "win32") return true;
  try {
    const groups = execFileSync(WHOAMI, ["/groups"], {
      encoding: "utf8",
      windowsHide: true,
    });
    return groups.includes(HIGH_INTEGRITY_SID);
  } catch (error) {
    console.error(`не удалось определить права: ${error.message}`);
    return false;
  }
}

// Перезапуск себя через UAC. `true` — повышенная копия запущена и текущей
// нужно выйти; `false` — пользователь отказался или запрос недоступен.
//
// Аргументы едут строкой в переменной окружения: PowerShell передаёт её
// содержимое без изменений, поэтому пути с пробелами и кавычками доезжают
// так же, как были.
const AUTOSTART_FLAG = "--pb-autostart";

function relaunchElevated(extraArgs = []) {
  const base = process.argv.slice(1).filter((value) => value !== AUTOSTART_FLAG);
  const args = [...base, ...extraArgs].map((value) => `"${value}"`).join(" ");
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$start = @{ FilePath = $env:PB_ELEVATE_EXE; WorkingDirectory = $env:PB_ELEVATE_CWD; Verb = 'RunAs' }",
    "if ($env:PB_ELEVATE_ARGS) { $start.ArgumentList = $env:PB_ELEVATE_ARGS }",
    "Start-Process @start",
  ].join("; ");
  try {
    execFileSync(POWERSHELL, ["-NoProfile", "-NonInteractive", "-Command", script], {
      env: {
        ...process.env,
        PB_ELEVATE_TRIED: "1",
        PB_ELEVATE_EXE: process.execPath,
        PB_ELEVATE_ARGS: args,
        PB_ELEVATE_CWD: process.cwd(),
      },
      stdio: "ignore",
      windowsHide: true,
    });
    return true;
  } catch (error) {
    console.error(`повышение прав не выполнено: ${error.message}`);
    return false;
  }
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

// Уже поднятое ядро на нашем порту: `true`/`false` — отвечает и сообщает про
// права, `null` — порт свободен (или отвечает не наше ядро).
//
// Проверка нужна перед запуском своего ядра. Второй процесс порт не займёт и
// молча завершится, а интерфейс станет работать со старым ядром — если у
// того нет прав, запуск обхода упадёт с 740 и без объяснения.
async function runningCoreIsElevated() {
  try {
    const response = await fetch(`${BASE}/api/ws/privilege`);
    if (!response.ok) return null;
    const data = await response.json();
    return data.granted === true;
  } catch (_) {
    return null;
  }
}

async function waitCoreRelease() {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const state = await runningCoreIsElevated();
    if (state !== false) return state;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return false;
}

let autostartPending = process.argv.includes(AUTOSTART_FLAG);

ipcMain.handle("app:take-autostart", () => {
  const pending = autostartPending;
  autostartPending = false;
  return pending;
});

ipcMain.handle("app:elevate", async () => {
  if (process.platform !== "win32") return { ok: false, error: "повышение через UAC есть только в Windows" };
  if (isElevated() && (await runningCoreIsElevated()) !== false) return { ok: true, already: true };
  if (!relaunchElevated([AUTOSTART_FLAG])) {
    return { ok: false, error: "Запрос прав отклонён — без них движок обхода не запустится." };
  }
  setTimeout(() => app.quit(), 100);
  return { ok: true };
});

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
    // Тот же тёмный фон, что и `--bg-deep` в tokens.css: окно не мигает
    // чужим цветом, пока интерфейс ещё не отрисован.
    backgroundColor: "#050609",
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

app.whenReady().then(async () => {
  const elevated = isElevated();
  const coreElevated = elevated ? await waitCoreRelease() : await runningCoreIsElevated();
  if (coreElevated === false && elevated) {
    // Повышенному приложению досталось ядро без прав — движок обхода в нём
    // не запустится. Говорим об этом прямо, вместо непонятной ошибки 740.
    dialog.showErrorBox(
      "Ядро уже запущено без прав администратора",
      "Порт 7290 занят другим ядром PrimeProxy. Закройте все окна PrimeBypass, "
        + "завершите оставшийся процесс primecore-server в диспетчере задач и "
        + "запустите приложение снова — тогда ядро поднимется с нужными правами.",
    );
    app.quit();
    return;
  }

  // Чужое живое ядро переиспользуем: свой процесс порт всё равно не займёт.
  if (coreElevated === null) startSidecar();
  else console.log("ядро уже запущено — используем существующее");

  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

async function stopEngine() {
  try {
    await fetch(`${BASE}/api/ws/stop`, { method: "POST", signal: AbortSignal.timeout(4000) });
  } catch (_) {
    return;
  }
}

let quitting = false;

app.on("before-quit", (event) => {
  if (quitting || !sidecar) return;
  event.preventDefault();
  quitting = true;
  stopEngine().finally(() => {
    if (sidecar) sidecar.kill();
    app.quit();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
