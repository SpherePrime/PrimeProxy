import { EmptyState } from "../ui/EmptyState";
import { Panel } from "../ui/Panel";
import { ConnectionRow } from "./types";

export function ConnectionsTable({ rows }: { rows: ConnectionRow[] }) {
  return (
    <Panel
      title="Топ соединений"
      note="По объёму пакетов; вердикты — сработавшие DESYNC-профили."
      meta={<span className="chip">{rows.length}</span>}
    >
      {rows.length === 0 ? (
        <EmptyState title="Соединений нет">Проверьте, что это debug-лог winws2.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Узел</th>
                <th>Протокол</th>
                <th>Пакеты</th>
                <th>Вердикты</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={`${row.remote_ip}-${row.remote_port}-${index}`}>
                  <td className="mono strong">
                    {row.hostname || row.remote_ip}:{row.remote_port}
                  </td>
                  <td>{row.l7proto || row.proto}</td>
                  <td className="mono">
                    {row.packets_total} <span className="muted">({row.packets_out}↑ {row.packets_in}↓)</span>
                  </td>
                  <td className="mono">{row.verdicts.map((v) => `${v.kind}×${v.count}`).join(", ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
