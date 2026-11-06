import type { ReactNode } from "react";

interface PanelProps {
  title?: ReactNode;
  note?: ReactNode;
  meta?: ReactNode;
  className?: string;
  id?: string;
  children?: ReactNode;
}

export function Panel({ title, note, meta, className = "", id, children }: PanelProps) {
  const hasHead = title !== undefined || meta !== undefined;
  return (
    <section className={`panel ${className}`.trim()} id={id}>
      {hasHead && (
        <div className="panel__head">
          <div>
            {title !== undefined && <h2 className="panel__title">{title}</h2>}
            {note && <p className="panel__note">{note}</p>}
          </div>
          {meta && <div className="panel__meta">{meta}</div>}
        </div>
      )}
      {children}
    </section>
  );
}
