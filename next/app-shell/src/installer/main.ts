import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./installer.css";
import { installerApi, InstallerInfo, ProgressState } from "./api";
import { doneView, errorView, progressView, shell, uninstallView, welcomeView } from "./views";

type Screen = "welcome" | "progress" | "done" | "error";

const INSTALL_STEPS = ["Папка", "Установка", "Готово"];
const UNINSTALL_STEPS = ["Подтверждение", "Удаление", "Готово"];

const root = document.getElementById("installer")!;

const state = {
  info: null as InstallerInfo | null,
  screen: "welcome" as Screen,
  dir: "",
  desktop: true,
  launch: true,
  removeData: false,
  exe: "",
  error: "",
  progress: { stage: "prepare", percent: 0, label: "" } as ProgressState,
};

function stepIndex(): number {
  if (state.screen === "progress") return 1;
  if (state.screen === "done") return 3;
  return 0;
}

function body(): string {
  const info = state.info!;
  const uninstalling = info.mode === "uninstall";
  switch (state.screen) {
    case "progress":
      return progressView(uninstalling ? "Удаляю…" : "Устанавливаю…", state.progress.percent, state.progress.label);
    case "done":
      return uninstalling
        ? doneView("PrimeBypass удалён", "Спасибо, что пользовались. Окно можно закрыть.", null)
        : doneView("Готово!", "PrimeBypass установлен. Ярлык есть в меню «Пуск».", "Запустить PrimeBypass");
    case "error":
      return errorView(state.error);
    default:
      return uninstalling
        ? uninstallView(state.removeData)
        : welcomeView(state.dir, state.desktop, state.launch, info.installed);
  }
}

function render(): void {
  if (!state.info) return;
  const steps = state.info.mode === "uninstall" ? UNINSTALL_STEPS : INSTALL_STEPS;
  root.innerHTML = shell(state.info.version, steps, stepIndex(), body());
  root.querySelector(".screen")?.classList.add("is-entering");
}

function updateProgress(progress: ProgressState): void {
  state.progress = progress;
  if (state.screen !== "progress") return;
  const percent = root.querySelector<HTMLElement>('[data-role="percent"]');
  const bar = root.querySelector<HTMLElement>('[data-role="bar"]');
  const label = root.querySelector<HTMLElement>('[data-role="label"]');
  if (percent) percent.textContent = String(progress.percent);
  if (bar) bar.style.width = `${progress.percent}%`;
  if (label) label.textContent = progress.label;
}

async function runInstall(): Promise<void> {
  state.screen = "progress";
  state.progress = { stage: "prepare", percent: 0, label: "Готовлю файлы…" };
  render();
  const result = await installerApi.install({ dir: state.dir, desktop: state.desktop });
  if (!result.ok) {
    state.error = result.error ?? "Неизвестная ошибка";
    state.screen = "error";
    render();
    return;
  }
  state.exe = result.exe ?? "";
  if (state.launch && state.exe) {
    installerApi.launch(state.exe);
    return;
  }
  state.screen = "done";
  render();
}

async function runUninstall(): Promise<void> {
  state.screen = "progress";
  state.progress = { stage: "prepare", percent: 0, label: "Останавливаю…" };
  render();
  const result = await installerApi.uninstall({ removeData: state.removeData });
  state.screen = result.ok ? "done" : "error";
  state.error = result.error ?? "";
  render();
}

root.addEventListener("click", async (event) => {
  const target = (event.target as HTMLElement).closest<HTMLElement>("[data-action]");
  if (!target) return;
  switch (target.dataset.action) {
    case "close":
      installerApi.close();
      break;
    case "minimize":
      installerApi.minimize();
      break;
    case "pick": {
      const chosen = await installerApi.pickDir(state.dir);
      if (chosen) {
        state.dir = chosen;
        render();
      }
      break;
    }
    case "toggle-desktop":
      state.desktop = !state.desktop;
      render();
      break;
    case "toggle-launch":
      state.launch = !state.launch;
      render();
      break;
    case "toggle-data":
      state.removeData = !state.removeData;
      render();
      break;
    case "install":
      await runInstall();
      break;
    case "uninstall":
      await runUninstall();
      break;
    case "launch":
      if (state.exe) installerApi.launch(state.exe);
      break;
    case "retry":
      state.screen = "welcome";
      render();
      break;
  }
});

installerApi.onProgress(updateProgress);

installerApi.info().then((info) => {
  state.info = info;
  state.dir = info.defaultDir;
  document.title = info.mode === "uninstall" ? "Удаление PrimeBypass" : "Установка PrimeBypass";
  render();
});
