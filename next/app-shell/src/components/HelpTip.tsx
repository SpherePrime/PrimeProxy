import { useEffect, useId, useRef, useState } from "react";

// Кнопка «?» с пояснением: короткий текст о том, что делает блок, зачем он
// нужен и что произойдёт после нажатия. Открывается по клику, закрывается
// по Escape и клику мимо — так подсказка не мешает и не «залипает».

interface HelpTipProps {
  /** Что объясняем: уходит в доступное имя кнопки. */
  label: string;
  children: React.ReactNode;
}

export function HelpTip({ label, children }: HelpTipProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLSpanElement>(null);
  const id = useId();

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    const onClick = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onClick);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onClick);
    };
  }, [open]);

  return (
    <span className="help" ref={rootRef}>
      <button
        type="button"
        className="help-btn"
        aria-label={`Подсказка: ${label}`}
        aria-expanded={open}
        aria-describedby={open ? id : undefined}
        onClick={() => setOpen((value) => !value)}
      >
        ?
      </button>
      {open && (
        <span className="help-pop" id={id} role="note">
          {children}
        </span>
      )}
    </span>
  );
}
