import type { ReactNode } from "react";

interface PageHeadProps {
  eyebrow: string;
  title: ReactNode;
  lead?: string;
  actions?: ReactNode;
}

export function PageHead({ eyebrow, title, lead, actions }: PageHeadProps) {
  return (
    <header className="page-head">
      <div className="page-head__text">
        <span className="eyebrow">{eyebrow}</span>
        <h1 className="page-head__title">{title}</h1>
        {lead && <p className="page-head__lead">{lead}</p>}
      </div>
      {actions && <div className="page-head__actions">{actions}</div>}
    </header>
  );
}
