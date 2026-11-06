interface SwitchProps {
  on: boolean;
  label: string;
  onToggle: () => void;
  disabled?: boolean;
}

export function Switch({ on, label, onToggle, disabled = false }: SwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      className={`switch ${on ? "is-on" : ""}`}
      onClick={(event) => {
        event.stopPropagation();
        onToggle();
      }}
      disabled={disabled}
    />
  );
}
