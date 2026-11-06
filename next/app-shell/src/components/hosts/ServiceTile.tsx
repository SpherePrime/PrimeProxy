import { countIn, Service } from "../../data/hostsServices";
import { ServiceBadge } from "../ServiceBadge";
import { Switch } from "../ui/Switch";

interface ServiceTileProps {
  service: Service;
  desired: Set<string>;
  current: Set<string>;
  disabled: boolean;
  onToggle: (service: Service) => void;
}

export function ServiceTile({ service, desired, current, disabled, onToggle }: ServiceTileProps) {
  const inDesired = countIn(desired, service.domains);
  const inFile = countIn(current, service.domains);
  const total = service.domains.length;
  const allOn = inDesired === total;
  const partial = inDesired > 0 && !allOn;
  const pending = inDesired !== inFile;

  return (
    <article
      className={`tile ${allOn ? "is-on" : ""} ${partial ? "is-partial" : ""}`}
      title={service.domains.join("\n")}
    >
      <div className="tile__row">
        <button
          type="button"
          className="tile__main"
          onClick={() => onToggle(service)}
          disabled={disabled}
          aria-pressed={allOn}
        >
          <ServiceBadge name={service.title} size={36} />
          <span className="tile__text">
            <span className="tile__name">
              {service.title}
              {pending && <span className="tile__pending" title="Ещё не записано в hosts" />}
            </span>
            <span className="tile__desc">{partial ? `частично: ${inDesired} из ${total}` : service.note}</span>
          </span>
        </button>
        <Switch on={allOn} label={`Разблокировать ${service.title}`} onToggle={() => onToggle(service)} disabled={disabled} />
      </div>
    </article>
  );
}
