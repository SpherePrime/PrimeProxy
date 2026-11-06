export interface ConnectionRow {
  proto: string;
  remote_ip: string;
  remote_port: number;
  hostname: string;
  l7proto: string;
  profiles: string[];
  packets_total: number;
  packets_out: number;
  packets_in: number;
  verdicts: { kind: string; count: number }[];
  positive_lists: string[];
}

export interface AnalyzeState {
  summary: {
    lines: number;
    profiles: { id: number; name: string }[];
    hostlists: { path: string; hosts: number }[];
    ipsets: { path: string; subnets: number }[];
    packets_total: number;
    connections_total: number;
    positive_checks_total: number;
    unparsed_blocks: number;
    unrecognized_packet_lines: number;
  };
  connections: ConnectionRow[];
  file_path?: string;
  file_bytes?: number;
}

export function sizeLabel(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
  return `${bytes} Б`;
}
