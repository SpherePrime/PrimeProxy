interface StatProps {
  value: number | string;
  label: string;
  tone?: "ok" | "fail" | "warn" | "accent";
}

export function Stat({ value, label, tone }: StatProps) {
  return (
    <div className={`stat ${tone ? `stat--${tone}` : ""}`}>
      <span className="stat__value">{value}</span>
      <span className="stat__label">{label}</span>
    </div>
  );
}
