import { EmptyState } from "../ui/EmptyState";
import { Panel } from "../ui/Panel";
import { Stat } from "../ui/Stat";
import { AnalyzeState, sizeLabel } from "./types";

export function LogSummary({ result }: { result: AnalyzeState | null }) {
  if (!result) {
    return (
      <Panel title="Сводка">
        <EmptyState title="Пока пусто">Разберите лог — здесь появятся счётчики, профили и списки.</EmptyState>
      </Panel>
    );
  }

  const { summary } = result;
  const source = result.file_path ? result.file_path : "вставленный текст";
  const size = typeof result.file_bytes === "number" ? ` · ${sizeLabel(result.file_bytes)}` : "";

  return (
    <Panel title="Сводка" note={`${source}${size}`}>
      <div className="stats logs-stats">
        <Stat value={summary.lines} label="строк" />
        <Stat value={summary.connections_total} label="соединений" tone="accent" />
        <Stat value={summary.packets_total} label="пакетов" />
        <Stat value={summary.positive_checks_total} label="позитивных" tone="ok" />
        <Stat
          value={summary.unparsed_blocks}
          label="не распознано"
          tone={summary.unparsed_blocks ? "warn" : undefined}
        />
      </div>

      {summary.profiles.length > 0 && (
        <div className="logs-group">
          <span className="field__label">Профили</span>
          <div className="chips">
            {summary.profiles.map((profile) => (
              <span className="chip chip--accent" key={profile.id}>
                {profile.id} · {profile.name}
              </span>
            ))}
          </div>
        </div>
      )}

      {(summary.hostlists.length > 0 || summary.ipsets.length > 0) && (
        <div className="logs-group">
          <span className="field__label">Списки</span>
          <div className="chips">
            {summary.hostlists.map((entry) => (
              <span className="chip" key={`h-${entry.path}`}>
                {entry.path} · {entry.hosts} хостов
              </span>
            ))}
            {summary.ipsets.map((entry) => (
              <span className="chip" key={`i-${entry.path}`}>
                {entry.path} · {entry.subnets} подсетей
              </span>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}
