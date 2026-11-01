import React from "react";

interface PageHeaderProps {
  /** Номер пункта в навигации: держит страницу и меню в одном порядке. */
  index: string;
  /** Группа инструментов: «СЕТЬ», «ДИАГНОСТИКА», «БИБЛИОТЕКА». */
  group: string;
  title: string;
  description: string;
  actions?: React.ReactNode;
}

/**
 * Общая шапка страницы: служебный код, дисплейный заголовок и пояснение.
 * Одна структура на всех вкладках — чтобы переключение не сдвигало макет.
 */
export function PageHeader({
  index,
  group,
  title,
  description,
  actions,
}: PageHeaderProps) {
  return (
    <header className="page-header" data-index={index}>
      <div className="page-heading">
        <div className="page-kicker">
          <span className="page-index">{index}</span>
          {group}
        </div>
        <h1 className="page-title">{title}</h1>
        <p className="page-sub">{description}</p>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}
