import { CHECK_GROUPS } from "../../data/checkDomains";
import { IconCheck } from "../Icons";
import { ServiceBadge } from "../ServiceBadge";
import { Panel } from "../ui/Panel";
import type { SiteCheckModel } from "./useSiteCheck";

export function DomainPicker({ model }: { model: SiteCheckModel }) {
  return (
    <Panel
      title="Что проверяем"
      note="Каждый сервис открывается напрямую из вашей сети. В системе ничего не меняется."
      meta={
        <button type="button" className="btn btn--ghost btn--sm" onClick={model.toggleAll} disabled={model.running}>
          {model.allSelected ? "Снять все" : "Выбрать все"}
        </button>
      }
    >
      <div className="categories">
        {CHECK_GROUPS.map((group) => {
          const selected = group.services.filter((service) => model.checked[service.domain]).length;
          return (
            <div className="category" key={group.title}>
              <h3 className="category__title">
                <button
                  type="button"
                  className="category__toggle"
                  onClick={() => model.toggleGroup(group)}
                  disabled={model.running}
                  title="Выбрать или снять всю группу"
                >
                  {group.title}
                </button>
                <span>
                  {selected}/{group.services.length}
                </span>
              </h3>
              <div className="picks">
                {group.services.map((service) => {
                  const on = Boolean(model.checked[service.domain]);
                  return (
                    <button
                      type="button"
                      key={service.domain}
                      className={`pick ${on ? "is-on" : ""}`}
                      aria-pressed={on}
                      onClick={() => model.toggle(service.domain)}
                      disabled={model.running}
                      title={service.domain}
                    >
                      <ServiceBadge name={service.name} size={30} />
                      <span className="pick__name">{service.name}</span>
                      <span className="pick__mark" aria-hidden="true">
                        {on && <IconCheck size={12} />}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
