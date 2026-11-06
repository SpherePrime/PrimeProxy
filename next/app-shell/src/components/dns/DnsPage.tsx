import { useEffect, useState } from "react";
import { DnsCurrent, fetchDnsCurrent } from "../../api";
import { PageHead } from "../ui/PageHead";
import { Segmented } from "../ui/Segmented";
import { CurrentDns } from "./CurrentDns";
import { DnsProbe } from "./DnsProbe";
import { DnsSet } from "./DnsSet";
import { ProviderCatalog } from "./ProviderCatalog";
import { ServerCheck } from "./ServerCheck";
import "../../styles/pages/dns.css";

type DnsTab = "overview" | "check" | "catalog";

const FALLBACK_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

export function DnsPage() {
  const [tab, setTab] = useState<DnsTab>("overview");
  const [current, setCurrent] = useState<DnsCurrent | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchDnsCurrent()
      .then(setCurrent)
      .catch((e) => setError(String((e as Error).message)));
  }, []);

  const system = current?.system.map((entry) => entry.server) ?? [];
  const servers = [...system, ...FALLBACK_SERVERS.filter((server) => !system.includes(server))];

  return (
    <div className="page">
      <PageHead
        eyebrow="Сеть"
        title={
          <>
            DNS <em>под контролем</em>
          </>
        }
        lead="Что стоит сейчас, как отвечают серверы и кто из провайдеров работает в вашем регионе."
        actions={
          <Segmented<DnsTab>
            label="Раздел DNS"
            value={tab}
            onChange={setTab}
            options={[
              { value: "overview", label: "Обзор" },
              { value: "check", label: "Сверка" },
              { value: "catalog", label: "Каталог" },
            ]}
          />
        }
      />

      {tab === "overview" && (
        <div className="stack">
          <CurrentDns current={current} error={error} />
          <div className="layout layout--even">
            <DnsProbe servers={servers} />
            <DnsSet />
          </div>
        </div>
      )}
      {tab === "check" && <ServerCheck />}
      {tab === "catalog" && <ProviderCatalog />}
    </div>
  );
}
