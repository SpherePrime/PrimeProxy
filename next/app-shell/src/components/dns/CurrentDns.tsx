import { DnsCurrent } from "../../api";
import { EmptyState } from "../ui/EmptyState";
import { Panel } from "../ui/Panel";

interface CurrentDnsProps {
  current: DnsCurrent | null;
  error: string;
}

export function CurrentDns({ current, error }: CurrentDnsProps) {
  const dohUrls = current ? [...new Set(current.doh.map((entry) => entry.url))] : [];

  return (
    <Panel
      title="Сейчас в системе"
      note="Серверы, которые использует система, и активные DoH-шаблоны."
      meta={current ? <span className="chip">{current.system.length} серверов</span> : undefined}
    >
      {error ? (
        <EmptyState title="Не удалось прочитать настройки">{error}</EmptyState>
      ) : !current ? (
        <EmptyState title="Читаю системные настройки…" loading />
      ) : (
        <div className="dns-now">
          <div className="dns-now__col">
            <span className="field__label">Системные</span>
            {current.system.length > 0 ? (
              <div className="chips">
                {current.system.map((entry) => (
                  <span className="chip chip--accent" key={entry.server}>
                    {entry.server}
                    <span className="muted">{entry.kind}</span>
                  </span>
                ))}
              </div>
            ) : (
              <p className="hint">Не найдены — DNS, похоже, настраивается автоматически.</p>
            )}
          </div>
          <div className="dns-now__col">
            <span className="field__label">DoH · {dohUrls.length}</span>
            {dohUrls.length > 0 ? (
              <ul className="doh-list">
                {dohUrls.map((url) => {
                  const [host, ...rest] = url.replace(/^https:\/\//, "").split("/");
                  return (
                    <li className="doh" key={url} title={url}>
                      <span className="doh__dot" aria-hidden="true" />
                      <span className="doh__host">{host}</span>
                      <span className="doh__path">/{rest.join("/")}</span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="hint">DoH не используется.</p>
            )}
          </div>
        </div>
      )}
    </Panel>
  );
}
