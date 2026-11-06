import { useEffect, useMemo, useState } from "react";
import { DnsCurrent, DnsSetError, fetchProviders, GROUP_ORDER, Providers, setDns } from "../../api";
import { elevationBridge } from "../../electronBridge";
import { IconCheck, IconRefresh } from "../Icons";
import { ServiceBadge } from "../ServiceBadge";
import { EmptyState } from "../ui/EmptyState";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";

const AUTO = "__auto__";

interface DnsOption {
  id: string;
  name: string;
  desc: string;
  servers: string[];
  doh: boolean;
  status?: string;
}

const STATUS_LABEL: Record<string, string> = { blocked: "блокируется", at_risk: "под риском" };
const STATUS_TONE: Record<string, string> = { blocked: "chip--fail", at_risk: "chip--warn" };

function buildOptions(providers: Providers): DnsOption[] {
  const seen = new Set<string>();
  const options: DnsOption[] = [];
  for (const group of GROUP_ORDER) {
    for (const [name, data] of Object.entries(providers[group] || {})) {
      const servers = data.ipv4 ?? [];
      if (seen.has(name) || servers.length === 0 || data.local_proxy) continue;
      seen.add(name);
      options.push({ id: name, name, desc: data.desc ?? "", servers, doh: Boolean(data.doh), status: data.status });
    }
  }
  return options;
}

interface DnsChooserProps {
  current: DnsCurrent | null;
  onApplied: () => void;
}

export function DnsChooser({ current, onApplied }: DnsChooserProps) {
  const [providers, setProviders] = useState<Providers>({});
  const [selected, setSelected] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    fetchProviders()
      .then(setProviders)
      .catch((e) => setError(String((e as Error).message)));
  }, []);

  const options = useMemo(() => buildOptions(providers), [providers]);
  const systemServers = useMemo(() => new Set(current?.system.map((entry) => entry.server) ?? []), [current]);
  const activeId = useMemo(() => {
    const match = options.find((option) => option.servers.some((server) => systemServers.has(server)));
    return match ? match.id : AUTO;
  }, [options, systemServers]);

  const chosen = selected ?? activeId;
  const chosenOption = options.find((option) => option.id === chosen);
  const changed = chosen !== activeId;

  async function apply() {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      if (chosen === AUTO) await setDns([], current?.interface ?? "", true);
      else if (chosenOption) await setDns(chosenOption.servers.slice(0, 2), current?.interface ?? "");
      setNotice(chosen === AUTO ? "DNS снова выдаётся автоматически." : `DNS переключён на ${chosenOption?.name}.`);
      setSelected(null);
      onApplied();
    } catch (e) {
      if (e instanceof DnsSetError && e.status === 409) {
        const bridge = elevationBridge();
        if (bridge) {
          const result = await bridge.request({ autostart: false });
          if (!result.ok) setError(result.error ?? "Права не выданы.");
          else setNotice("Приложение перезапускается с правами администратора — затем выберите DNS ещё раз.");
        } else {
          setError("Для смены DNS нужны права администратора.");
        }
      } else {
        setError(String((e as Error).message));
      }
    } finally {
      setSaving(false);
    }
  }

  const activeName = activeId === AUTO ? "автоматически" : options.find((option) => option.id === activeId)?.name;

  return (
    <Panel
      title="Какой DNS использовать"
      note={
        current?.interface
          ? `Подключение «${current.interface}» · сейчас: ${activeName ?? "—"}`
          : "Выберите сервер и нажмите «Применить»."
      }
      meta={
        <button
          type="button"
          className="btn btn--accent"
          onClick={() => void apply()}
          disabled={saving || !changed || !current}
        >
          {saving ? <span className="spinner" /> : <IconCheck size={16} />}
          {saving ? "Применяю…" : "Применить"}
        </button>
      }
    >
      {error && <Notice tone="error">{error}</Notice>}
      {notice && <Notice tone="ok">{notice}</Notice>}

      {options.length === 0 && !error ? (
        <EmptyState title="Загружаю список серверов…" loading />
      ) : (
        <div className="dns-options" role="radiogroup" aria-label="DNS-сервер">
          <button
            type="button"
            role="radio"
            aria-checked={chosen === AUTO}
            className={`dns-option ${chosen === AUTO ? "is-selected" : ""}`}
            onClick={() => setSelected(AUTO)}
          >
            <span className="dns-option__icon" aria-hidden="true">
              <IconRefresh size={16} />
            </span>
            <span className="dns-option__text">
              <span className="dns-option__name">Автоматически</span>
              <span className="dns-option__desc">DNS от роутера или провайдера</span>
            </span>
            {activeId === AUTO && <span className="chip chip--accent">сейчас</span>}
          </button>
          {options.map((option) => (
            <button
              type="button"
              role="radio"
              key={option.id}
              aria-checked={chosen === option.id}
              className={`dns-option ${chosen === option.id ? "is-selected" : ""}`}
              onClick={() => setSelected(option.id)}
              title={option.servers.join(", ")}
            >
              <ServiceBadge name={option.name} size={34} />
              <span className="dns-option__text">
                <span className="dns-option__name">{option.name}</span>
                <span className="dns-option__desc">{option.desc || option.servers[0]}</span>
              </span>
              {activeId === option.id ? (
                <span className="chip chip--accent">сейчас</span>
              ) : option.status ? (
                <span className={`chip ${STATUS_TONE[option.status] ?? ""}`}>
                  {STATUS_LABEL[option.status] ?? option.status}
                </span>
              ) : option.doh ? (
                <span className="chip chip--ok">DoH</span>
              ) : null}
            </button>
          ))}
        </div>
      )}
    </Panel>
  );
}
