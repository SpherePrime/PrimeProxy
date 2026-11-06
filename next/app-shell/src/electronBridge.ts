export interface ElevationResult {
  ok: boolean;
  already?: boolean;
  error?: string;
}

interface ElevationBridge {
  request: () => Promise<ElevationResult>;
  takeAutostart: () => Promise<boolean>;
}

export function elevationBridge(): ElevationBridge | undefined {
  const api = (window as unknown as { electronAPI?: { elevation?: ElevationBridge } }).electronAPI;
  return api?.elevation;
}
