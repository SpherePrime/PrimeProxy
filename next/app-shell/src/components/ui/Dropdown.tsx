import { useEffect, useId, useRef, useState } from "react";
import { IconCheck, IconChevronDown } from "../Icons";

export interface DropdownOption<T extends string> {
  value: T;
  label: string;
  hint?: string;
}

interface DropdownProps<T extends string> {
  value: T;
  options: DropdownOption<T>[];
  onChange: (value: T) => void;
  label: string;
  disabled?: boolean;
  mono?: boolean;
}

export function Dropdown<T extends string>({ value, options, onChange, label, disabled = false, mono = false }: DropdownProps<T>) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const listId = useId();
  const current = options.find((option) => option.value === value) ?? options[0];

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const pick = (next: T) => {
    onChange(next);
    setOpen(false);
  };

  return (
    <div className={`dropdown ${open ? "is-open" : ""} ${mono ? "dropdown--mono" : ""}`} ref={rootRef}>
      <button
        type="button"
        className="dropdown__trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listId}
        aria-label={label}
        disabled={disabled}
        onClick={() => setOpen((value) => !value)}
      >
        <span className="dropdown__value">{current?.label}</span>
        <IconChevronDown size={14} className="dropdown__chevron" />
      </button>
      {open && (
        <ul className="dropdown__menu" role="listbox" id={listId} aria-label={label}>
          {options.map((option) => {
            const selected = option.value === value;
            return (
              <li key={option.value}>
                <button
                  type="button"
                  role="option"
                  aria-selected={selected}
                  className={`dropdown__option ${selected ? "is-selected" : ""}`}
                  onClick={() => pick(option.value)}
                >
                  <span className="dropdown__text">
                    <span className="dropdown__label">{option.label}</span>
                    {option.hint && <span className="dropdown__hint">{option.hint}</span>}
                  </span>
                  {selected && <IconCheck size={14} />}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
