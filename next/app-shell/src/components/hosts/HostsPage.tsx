import { SERVICES } from "../../data/hostsServices";
import { IconLock, IconUnlock } from "../Icons";
import { EmptyState } from "../ui/EmptyState";
import { Notice } from "../ui/Notice";
import { PageHead } from "../ui/PageHead";
import { Panel } from "../ui/Panel";
import { SearchBox } from "../ui/SearchBox";
import { ChangesPanel } from "./ChangesPanel";
import { ServiceTile } from "./ServiceTile";
import { useHosts } from "./useHosts";
import "../../styles/pages/hosts.css";

export function HostsPage() {
  const model = useHosts();

  return (
    <div className="page">
      <PageHead
        eyebrow="Разблокировка"
        title={
          <>
            Сервисы <em>в один клик</em>
          </>
        }
        lead="Включите сервис тумблером и нажмите «Применить» — он откроется без запуска обхода."
        actions={
          <span className="chip chip--accent">
            разблокировано {model.unlockedCount} из {SERVICES.length}
          </span>
        }
      />

      <div className="notices">
        {model.error && <Notice tone="error">{model.error}</Notice>}
        {model.notice && <Notice tone="ok">{model.notice}</Notice>}
      </div>

      <div className="layout">
        <div className="layout__main">
          <Panel
            title="Каталог сервисов"
            note="Тумблер включает сервис целиком. Изменения копятся справа и пишутся одной кнопкой."
            meta={<span className="chip">выбрано {model.selectedCount}</span>}
          >
            <div className="toolbar">
              <SearchBox value={model.search} onChange={model.setSearch} placeholder="Найти сервис или домен…" />
              <button type="button" className="btn btn--outline btn--sm" onClick={model.fillAll} disabled={model.busy}>
                <IconUnlock size={14} />
                Все
              </button>
              <button type="button" className="btn btn--ghost btn--sm" onClick={model.clearAll} disabled={model.busy}>
                <IconLock size={14} />
                Очистить
              </button>
            </div>

            {model.visibleCategories.length === 0 ? (
              <EmptyState title="Ничего не найдено">Измените запрос или очистите поиск.</EmptyState>
            ) : (
              <div className="categories">
                {model.visibleCategories.map((category) => (
                  <div className="category" key={category.title}>
                    <h3 className="category__title">
                      {category.title}
                      <span>{category.services.length}</span>
                    </h3>
                    <div className="tiles">
                      {category.services.map((service) => (
                        <ServiceTile
                          key={service.id}
                          service={service}
                          desired={model.desired}
                          current={model.current}
                          disabled={model.busy}
                          onToggle={model.toggleService}
                        />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
        <aside className="layout__side layout__side--sticky">
          <ChangesPanel model={model} />
        </aside>
      </div>
    </div>
  );
}
