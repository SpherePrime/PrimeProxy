import { CHECK_GROUPS } from "../../data/checkDomains";
import { Panel } from "../ui/Panel";
import type { SiteCheckModel } from "./useSiteCheck";

export function DomainPicker({ model }: { model: SiteCheckModel }) {
  return (
    <Panel
      title="Что проверяем"
      note="Каждый домен открывается напрямую из вашей сети. В системе ничего не меняется."
      meta={
        <button type="button" className="btn btn--ghost btn--sm" onClick={model.toggleAll} disabled={model.running}>
          {model.allSelected ? "Снять все" : "Выбрать все"}
        </button>
      }
    >
      <div className="categories">
        {CHECK_GROUPS.map((group) => {
          const allOn = group.domains.every((domain) => model.checked[domain]);
          return (
            <div className="category" key={group.title}>
              <h3 className="category__title">
                <button
                  type="button"
                  className="category__toggle"
                  onClick={() => model.toggleGroup(group)}
                  disabled={model.running}
                >
                  {group.title}
                </button>
                <span>{allOn ? "все" : group.domains.filter((d) => model.checked[d]).length}</span>
              </h3>
              <div className="pills">
                {group.domains.map((domain) => {
                  const on = Boolean(model.checked[domain]);
                  return (
                    <button
                      type="button"
                      key={domain}
                      className={`pill ${on ? "is-on" : ""}`}
                      aria-pressed={on}
                      onClick={() => model.toggle(domain)}
                      disabled={model.running}
                    >
                      {domain}
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
