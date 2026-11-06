export interface ElevationResult {
  ok: boolean;
  already?: boolean;
  error?: string;
}

interface ElevationBridge {
  request: (options?: { autostart?: boolean }) => Promise<ElevationResult>;
  takeAutostart: () => Promise<boolean>;
}

export interface FileFilter {
  name: string;
  extensions: string[];
}

interface FilesBridge {
  pick: (options?: { title?: string; filters?: FileFilter[] }) => Promise<string | null>;
  open: (target: string) => Promise<{ ok: boolean; error?: string }>;
  reveal: (target: string) => Promise<{ ok: boolean }>;
}

interface ShellApi {
  elevation?: ElevationBridge;
  files?: FilesBridge;
}

function shellApi(): ShellApi | undefined {
  return (window as unknown as { electronAPI?: ShellApi }).electronAPI;
}

export function elevationBridge(): ElevationBridge | undefined {
  return shellApi()?.elevation;
}

export function filesBridge(): FilesBridge | undefined {
  return shellApi()?.files;
}

export function fileName(path: string): string {
  return path.split(/[\\/]/).pop() || path;
}
