import { IconPower } from "../Icons";

interface PowerButtonProps {
  on: boolean;
  busy: boolean;
  disabled?: boolean;
  label: string;
  onClick: () => void;
}

export function PowerButton({ on, busy, disabled = false, label, onClick }: PowerButtonProps) {
  const state = busy ? "is-busy" : on ? "is-on" : "";
  return (
    <button
      type="button"
      className={`power ${state}`}
      onClick={onClick}
      disabled={busy || disabled}
      aria-pressed={on}
      aria-label={label}
    >
      <span className="power__ring" aria-hidden="true" />
      <span className="power__wave" aria-hidden="true" />
      <span className="power__wave power__wave--late" aria-hidden="true" />
      <span className="power__core" aria-hidden="true">
        <IconPower size={50} />
      </span>
      <span className="power__label">{label}</span>
    </button>
  );
}
