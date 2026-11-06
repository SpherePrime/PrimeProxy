import { countIn, Service } from "../../data/hostsServices";
import { IconChevronDown } from "../Icons";
import { ServiceBadge } from "../ServiceBadge";
import { Switch } from "../ui/Switch";

interface ServiceTileProps {
  service: Service;
  desired: Set<string>;
  current: Set<string>;
  open: boolean;
  disabled: boolean;
  onToggle: (service: Service) => void;
  onOpen: (id: string | null) => void;
}

export function ServiceTile({ service, desired, current, open, disabled, onToggle, onOpen }: ServiceTileProps) {
  const inDesired = countIn(desired, service.domains);
  const inFile = countIn(current, service.domains);
  const total = service.domains.length;
  const allOn = inDesired === total;
  const partial = inDesired > 0 && !allOn;
  const pending = inDesired !== inFile;

  const status = allOn ? "разблокирован" : partial ? `частично ${inDesired}/${total}` : service.note;

  return (
    <article className={`tile ${allOn ? "is-on" : ""} ${partial ? "is-partial" : ""} ${open ? "is-open" : ""}`}>
      <div className="tile__row">
        <button type="button" className="tile__main" aria-expanded={open} onClick={() => onOpen(open ? null : service.id)}>
          <ServiceBadge name={service.title} size={36} />
          <span className="tile__text">
            <span className="tile__name">
              {service.title}
              {pending && <span className="tile__pending" title="Изменение ещё не записано в hosts" />}
            </span>
            <span className="tile__desc">{status}</span>
          </span>
          <span className="tile__chevron" aria-hidden="true">
            <IconChevronDown size={14} />
          </span>
        </button>
        <Switch
          on={allOn}
          label={`Разблокировать ${service.title}`}
          onToggle={() => onToggle(service)}
          disabled={disabled}
        />
      </div>
      {open && (
        <div className="tile__body">
          <div className="tile__caption">
            {total} доменов · {service.note}
          </div>
          <div className="domains">
            {service.domains.map((domain) => (
              <span className={`domain ${desired.has(domain) ? "is-on" : ""}`} key={domain}>
                {domain}
              </span>
            ))}
          </div>
        </div>
      )}
    </article>
  );
}
