import type { ReactNode } from "react";

interface EmptyStateProps {
  title: string;
  children?: ReactNode;
  loading?: boolean;
}

export function EmptyState({ title, children, loading = false }: EmptyStateProps) {
  return (
    <div className="empty" role={loading ? "status" : undefined}>
      {loading && <span className="spinner" />}
      <strong>{title}</strong>
      {children && <span>{children}</span>}
    </div>
  );
}
