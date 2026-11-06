import { useEffect, useMemo, useState } from "react";
import { fetchProviders, FILTERS, GROUP_ORDER, Providers } from "../../api";
import { IconCheck } from "../Icons";
import { ServiceBadge } from "../ServiceBadge";
import { EmptyState } from "../ui/EmptyState";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";
import { Segmented } from "../ui/Segmented";

const STATUS_LABEL: Record<string, string> = {
  blocked: "блокируется",
  at_risk: "под риском",
};

const STATUS_TONE: Record<string, string> = {
  blocked: "chip--fail",
  at_risk: "chip--warn",
};

export function ProviderCatalog() {
  const [providers, setProviders] = useState<Providers>({});
  const [filter, setFilter] = useState<string>("all");
  const [error, setError] = useState("");

  useEffect(() => {
    fetchProviders()
      .then(setProviders)
      .catch((e) => setError(String(e.message)));
  }, []);

  const groups = useMemo(() => {
    const result: Array<{ group: string; tiles: Array<[string, Providers[string][string]]> }> = [];
    for (const group of GROUP_ORDER) {
      const tiles = Object.entries(providers[group] || {}).filter(
        ([, data]) => filter === "all" || data.status === filter,
      );
      if (tiles.length > 0) result.push({ group, tiles });
    }
    return result;
  }, [providers, filter]);

  const total = Object.values(providers).reduce((sum, group) => sum + Object.keys(group).length, 0);
  const visible = groups.reduce((sum, group) => sum + group.tiles.length, 0);

  return (
    <Panel
      title="Каталог провайдеров"
      note="Статус в вашем регионе и поддержка DoH."
      meta={
        <span className="chip">
          {visible} из {total}
        </span>
      }
    >
      <div className="toolbar">
        <Segmented<string>
          label="Фильтр провайдеров"
          value={filter}
          onChange={setFilter}
          options={FILTERS.map((item) => ({ value: item.key, label: item.title }))}
        />
      </div>

      {error && <Notice tone="error">{error}</Notice>}

      {total === 0 && !error ? (
        <EmptyState title="Загружаю каталог…" loading />
      ) : groups.length === 0 ? (
        <EmptyState title="Под фильтр ничего не подходит">Выберите другой статус.</EmptyState>
      ) : (
        <div className="categories">
          {groups.map(({ group, tiles }) => (
            <div className="category" key={group}>
              <h3 className="category__title">
                {group}
                <span>{tiles.length}</span>
              </h3>
              <div className="providers">
                {tiles.map(([name, data]) => (
                  <article className={`provider ${data.status ? `is-${data.status}` : ""}`} key={name} title={data.desc || ""}>
                    <div className="provider__head">
                      <ServiceBadge name={name} size={30} />
                      <span className="provider__name">{name}</span>
                      {data.doh && (
                        <span className="provider__doh">
                          <IconCheck size={11} /> DoH
                        </span>
                      )}
                    </div>
                    {data.desc && <p className="provider__desc">{data.desc}</p>}
                    {data.status && (
                      <span className={`chip ${STATUS_TONE[data.status] ?? ""}`}>
                        {STATUS_LABEL[data.status] ?? data.status}
                      </span>
                    )}
                  </article>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
