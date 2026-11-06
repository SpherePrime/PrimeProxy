export interface InstallerInfo {
  mode: "install" | "uninstall";
  version: string;
  defaultDir: string;
  installed: boolean;
}

export interface ProgressState {
  stage: string;
  percent: number;
  label: string;
}

export interface ActionResult {
  ok: boolean;
  error?: string;
  exe?: string;
  dir?: string;
}

interface InstallerApi {
  info: () => Promise<InstallerInfo>;
  pickDir: (current: string) => Promise<string | null>;
  install: (options: { dir: string; desktop: boolean }) => Promise<ActionResult>;
  uninstall: (options: { removeData: boolean }) => Promise<ActionResult>;
  launch: (exe: string) => void;
  close: () => void;
  minimize: () => void;
  openFolder: (dir: string) => void;
  onProgress: (callback: (state: ProgressState) => void) => void;
}

const preview: InstallerApi = {
  info: async () => ({
    mode: new URLSearchParams(location.search).get("mode") === "uninstall" ? "uninstall" : "install",
    version: "0.1.0",
    defaultDir: "C:\\Users\\user\\AppData\\Local\\Programs\\PrimeBypass",
    installed: false,
  }),
  pickDir: async () => null,
  install: async () => ({ ok: true, exe: "" }),
  uninstall: async () => ({ ok: true }),
  launch: () => undefined,
  close: () => undefined,
  minimize: () => undefined,
  openFolder: () => undefined,
  onProgress: () => undefined,
};

export const installerApi: InstallerApi =
  (window as unknown as { installerAPI?: InstallerApi }).installerAPI ?? preview;
