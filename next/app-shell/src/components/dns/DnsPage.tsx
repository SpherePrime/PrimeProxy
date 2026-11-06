import { useCallback, useEffect, useState } from "react";
import { DnsCurrent, fetchDnsCurrent } from "../../api";
import { PageHead } from "../ui/PageHead";
import { Segmented } from "../ui/Segmented";
import { DnsChooser } from "./DnsChooser";
import { DnsProbe } from "./DnsProbe";
import { ServerCheck } from "./ServerCheck";
import "../../styles/pages/dns.css";

type DnsTab = "choose" | "check";

const FALLBACK_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

export function DnsPage() {
  const [tab, setTab] = useState<DnsTab>("choose");
  const [current, setCurrent] = useState<DnsCurrent | null>(null);

  const load = useCallback(() => {
    fetchDnsCurrent()
      .then(setCurrent)
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const system = current?.system.map((entry) => entry.server) ?? [];
  const servers = [...system, ...FALLBACK_SERVERS.filter((server) => !system.includes(server))];

  return (
    <div className="page">
      <PageHead
        eyebrow="Сеть"
        title={
          <>
            DNS <em>в один клик</em>
          </>
        }
        lead="Выберите DNS-сервер — он сразу встанет на активное подключение."
        actions={
          <Segmented<DnsTab>
            label="Раздел DNS"
            value={tab}
            onChange={setTab}
            options={[
              { value: "choose", label: "Выбор" },
              { value: "check", label: "Проверка" },
            ]}
          />
        }
      />

      {tab === "choose" && <DnsChooser current={current} onApplied={() => window.setTimeout(load, 800)} />}
      {tab === "check" && (
        <div className="stack">
          <DnsProbe servers={servers} />
          <ServerCheck />
        </div>
      )}
    </div>
  );
}
