import type { ReactNode } from "react";

export interface MetaItem {
  label: string;
  value: ReactNode;
  tone?: string;
}

export function MetaGrid({ items, className = "" }: { items: MetaItem[]; className?: string }) {
  return (
    <dl className={`meta-grid ${className}`.trim()}>
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd className={item.tone}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}
