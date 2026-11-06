const { app, BrowserWindow, dialog, ipcMain, shell } = require("electron");
const { execFile, spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const APP_NAME = "PrimeBypass";
const EXE_NAME = `${APP_NAME}.exe`;
const UNINSTALL_KEY = `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APP_NAME}`;
const SYSTEM32 = path.join(process.env.SystemRoot || "C:\\Windows", "System32");
const POWERSHELL = path.join(SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe");
const REG = path.join(SYSTEM32, "reg.exe");

function installerMode() {
  if (process.argv.includes("--uninstall")) return "uninstall";
  if (process.argv.includes("--pb-installer")) return "install";
  if (process.env.PORTABLE_EXECUTABLE_FILE && !process.argv.includes("--pb-run")) return "install";
  return null;
}

function defaultInstallDir() {
  const base = process.env.LOCALAPPDATA || path.join(app.getPath("home"), "AppData", "Local");
  return path.join(base, "Programs", APP_NAME);
}

function sourceDir() {
  if (process.env.PB_INSTALLER_SOURCE) return process.env.PB_INSTALLER_SOURCE;
  return path.dirname(process.execPath);
}

function run(file, args, env = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, env: { ...process.env, ...env } }, (error, stdout, stderr) => {
      if (error) reject(new Error((stderr || error.message).toString().trim()));
      else resolve(stdout.toString());
    });
  });
}

function listFiles(root) {
  const result = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else result.push(full);
    }
  };
  walk(root);
  return result;
}

function folderSizeKb(root) {
  return Math.round(listFiles(root).reduce((total, file) => total + fs.statSync(file).size, 0) / 1024);
}

async function createShortcut(linkPath, target, workingDir) {
  const script = [
    "$shell = New-Object -ComObject WScript.Shell",
    "$link = $shell.CreateShortcut($env:PB_LINK)",
    "$link.TargetPath = $env:PB_TARGET",
    "$link.WorkingDirectory = $env:PB_WORKDIR",
    "$link.IconLocation = \"$env:PB_TARGET,0\"",
    "$link.Description = 'PrimeBypass'",
    "$link.Save()",
  ].join("; ");
  await run(POWERSHELL, ["-NoProfile", "-NonInteractive", "-Command", script], {
    PB_LINK: linkPath,
    PB_TARGET: target,
    PB_WORKDIR: workingDir,
  });
}

function shortcutPaths() {
  const startMenu = path.join(app.getPath("appData"), "Microsoft", "Windows", "Start Menu", "Programs");
  return {
    desktop: path.join(app.getPath("desktop"), `${APP_NAME}.lnk`),
    startMenu: path.join(startMenu, `${APP_NAME}.lnk`),
  };
}

async function writeUninstallEntry(installDir) {
  const exe = path.join(installDir, EXE_NAME);
  const values = [
    ["DisplayName", "REG_SZ", APP_NAME],
    ["DisplayVersion", "REG_SZ", app.getVersion()],
    ["Publisher", "REG_SZ", "SpherePrime"],
    ["DisplayIcon", "REG_SZ", `${exe},0`],
    ["InstallLocation", "REG_SZ", installDir],
    ["UninstallString", "REG_SZ", `"${exe}" --uninstall`],
    ["NoModify", "REG_DWORD", "1"],
    ["NoRepair", "REG_DWORD", "1"],
    ["EstimatedSize", "REG_DWORD", String(folderSizeKb(installDir))],
  ];
  for (const [name, type, data] of values) {
    await run(REG, ["add", UNINSTALL_KEY, "/v", name, "/t", type, "/d", data, "/f"]);
  }
}

async function readInstallLocation() {
  try {
    const output = await run(REG, ["query", UNINSTALL_KEY, "/v", "InstallLocation"]);
    const match = output.match(/InstallLocation\s+REG_SZ\s+(.+)/);
    return match ? match[1].trim() : null;
  } catch {
    return null;
  }
}

async function install(window, options) {
  const send = (state) => window.webContents.send("installer:progress", state);
  const target = path.resolve(options.dir);
  const source = sourceDir();
  if (path.resolve(source).toLowerCase() === target.toLowerCase()) throw new Error("Приложение уже установлено в эту папку.");

  send({ stage: "prepare", percent: 2, label: "Готовлю файлы…" });
  const files = listFiles(source);
  fs.mkdirSync(target, { recursive: true });

  let copied = 0;
  for (const file of files) {
    const relative = path.relative(source, file);
    const destination = path.join(target, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    try {
      await fs.promises.copyFile(file, destination);
    } catch (error) {
      if (error.code === "EBUSY" || error.code === "EPERM") {
        throw new Error("PrimeBypass сейчас запущен. Закройте его и повторите установку.");
      }
      throw error;
    }
    copied += 1;
    if (copied % 8 === 0 || copied === files.length) {
      send({ stage: "copy", percent: 4 + Math.round((copied / files.length) * 84), label: relative });
    }
  }

  send({ stage: "shortcuts", percent: 92, label: "Создаю ярлыки…" });
  const exe = path.join(target, EXE_NAME);
  const links = shortcutPaths();
  fs.mkdirSync(path.dirname(links.startMenu), { recursive: true });
  await createShortcut(links.startMenu, exe, target);
  if (options.desktop) await createShortcut(links.desktop, exe, target);

  send({ stage: "register", percent: 97, label: "Регистрирую в системе…" });
  await writeUninstallEntry(target);

  send({ stage: "done", percent: 100, label: "Готово" });
  return { exe };
}

function launchInstalled(exe) {
  const env = { ...process.env };
  delete env.PORTABLE_EXECUTABLE_FILE;
  delete env.PORTABLE_EXECUTABLE_DIR;
  delete env.PORTABLE_EXECUTABLE_APP_FILENAME;
  delete env.PB_INSTALLER_SOURCE;
  spawn(exe, [], { detached: true, stdio: "ignore", cwd: path.dirname(exe), env }).unref();
}

async function uninstall(window, options) {
  const send = (state) => window.webContents.send("installer:progress", state);
  const installDir = (await readInstallLocation()) || path.dirname(process.execPath);
  send({ stage: "shortcuts", percent: 25, label: "Удаляю ярлыки…" });
  const links = shortcutPaths();
  for (const link of [links.desktop, links.startMenu]) fs.rmSync(link, { force: true });

  send({ stage: "register", percent: 55, label: "Убираю запись из системы…" });
  await run(REG, ["delete", UNINSTALL_KEY, "/f"]).catch(() => undefined);

  if (options.removeData) {
    send({ stage: "data", percent: 75, label: "Удаляю настройки…" });
    const dataDir = path.join(process.env.LOCALAPPDATA || "", "primebypass");
    if (process.env.LOCALAPPDATA) fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(app.getPath("userData"), { recursive: true, force: true });
  }

  send({ stage: "done", percent: 100, label: "Готово" });
  const cmd = path.join(SYSTEM32, "cmd.exe");
  spawn(cmd, ["/c", `ping 127.0.0.1 -n 3 > nul & rmdir /s /q "${installDir}"`], {
    detached: true,
    stdio: "ignore",
    windowsHide: true,
  }).unref();
  return { dir: installDir };
}

function openInstallerWindow(mode) {
  const window = new BrowserWindow({
    width: 820,
    height: 520,
    resizable: false,
    maximizable: false,
    frame: false,
    show: false,
    title: mode === "install" ? "Установка PrimeBypass" : "Удаление PrimeBypass",
    backgroundColor: "#0c0c0c",
    webPreferences: { preload: path.join(__dirname, "installer-preload.cjs") },
  });

  ipcMain.handle("installer:info", async () => ({
    mode,
    version: app.getVersion(),
    defaultDir: (await readInstallLocation()) || defaultInstallDir(),
    installed: Boolean(await readInstallLocation()),
  }));
  ipcMain.handle("installer:pick-dir", async (_event, current) => {
    const result = await dialog.showOpenDialog(window, {
      title: "Папка установки",
      defaultPath: current,
      properties: ["openDirectory", "createDirectory"],
    });
    if (result.canceled || !result.filePaths[0]) return null;
    const chosen = result.filePaths[0];
    return path.basename(chosen).toLowerCase() === APP_NAME.toLowerCase() ? chosen : path.join(chosen, APP_NAME);
  });
  ipcMain.handle("installer:install", async (_event, options) => {
    try {
      return { ok: true, ...(await install(window, options)) };
    } catch (error) {
      return { ok: false, error: error.message };
    }
  });
  ipcMain.handle("installer:uninstall", async (_event, options) => {
    try {
      return { ok: true, ...(await uninstall(window, options)) };
    } catch (error) {
      return { ok: false, error: error.message };
    }
  });
  ipcMain.on("installer:launch", (_event, exe) => {
    launchInstalled(exe);
    app.quit();
  });
  ipcMain.on("installer:close", () => app.quit());
  ipcMain.on("installer:minimize", () => window.minimize());
  ipcMain.on("installer:open-folder", (_event, dir) => shell.openPath(dir));

  window.once("ready-to-show", () => window.show());
  const devUrl = process.env.VITE_URL;
  if (devUrl) window.loadURL(`${devUrl.replace(/\/$/, "")}/installer.html`);
  else window.loadFile(path.join(__dirname, "..", "dist", "installer.html"));
  return window;
}

module.exports = { installerMode, openInstallerWindow };
