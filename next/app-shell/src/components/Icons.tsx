// Иконки интерфейса: штриховые SVG вместо эмодзи.
//
// Все иконки наследуют цвет текста (`currentColor`) и масштабируются
// размером: так они одинаково выглядят в сайдбаре, на кнопках и в чипах,
// и не зависят от того, есть ли в системе эмодзи-шрифт.

type IconProps = {
  size?: number;
  className?: string;
};

function svgProps(size: number) {
  return {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.7,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
    focusable: false,
  };
}

/** Обход: щит. */
export function IconShield({ size = 18, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M12 3l7 3v6c0 4.2-2.9 7.7-7 9-4.1-1.3-7-4.8-7-9V6l7-3z" />
    </svg>
  );
}

/** Разблокировка: открытый замок. */
export function IconUnlock({ size = 18, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <rect x="4" y="11" width="16" height="9" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 7.6-1.7" />
    </svg>
  );
}

/** Проверка: лупа. */
export function IconSearch({ size = 18, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <circle cx="11" cy="11" r="6" />
      <path d="M20 20l-4.4-4.4" />
    </svg>
  );
}

/** Анализ лога: столбики. */
export function IconChart({ size = 18, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M4 20h16" />
      <path d="M6 20v-6M12 20V5M18 20v-9" />
    </svg>
  );
}

/** DNS: глобус. */
export function IconGlobe({ size = 18, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18" />
      <path d="M12 3c2.6 2.8 2.6 15.2 0 18M12 3c-2.6 2.8-2.6 15.2 0 18" />
    </svg>
  );
}

/** Telegram: самолётик. */
export function IconSend({ size = 18, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M21 3L3 10.6l6.2 2.4L11.6 19 21 3z" />
      <path d="M9.2 13l11.8-10" />
    </svg>
  );
}

/** Фейки: слои. */
export function IconLayers({ size = 18, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M12 3l9 5-9 5-9-5 9-5z" />
      <path d="M3 13l9 5 9-5" />
    </svg>
  );
}

/** Запуск. */
export function IconPlay({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M8 5.5l10.5 6.5L8 18.5v-13z" />
    </svg>
  );
}

/** Останов. */
export function IconStop({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <rect x="6" y="6" width="12" height="12" rx="2" />
    </svg>
  );
}

/** Ошибка/закрыть. */
export function IconClose({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  );
}

/** Предупреждение. */
export function IconWarning({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M12 4l9 16H3l9-16z" />
      <path d="M12 10v4M12 17.2h.01" />
    </svg>
  );
}

/** Успех. */
export function IconCheck({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M5 12.5l4.5 4.5L19 7" />
    </svg>
  );
}

/** Раскрыть группу. */
export function IconChevron({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M9 6l6 6-6 6" />
    </svg>
  );
}

/** Свернуть окно. */
export function IconMinimize({ size = 12, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M4 12h16" />
    </svg>
  );
}

/** Развернуть окно. */
export function IconMaximize({ size = 12, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <rect x="5" y="5" width="14" height="14" rx="2" />
    </svg>
  );
}

/** Вернуть из полного экрана. */
export function IconRestore({ size = 12, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <rect x="8" y="8" width="11" height="11" rx="2" />
      <path d="M5 16V6.5A1.5 1.5 0 0 1 6.5 5H16" />
    </svg>
  );
}

/** Замок. */
export function IconLock({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <rect x="4" y="11" width="16" height="9" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </svg>
  );
}

/** Молния. */
export function IconBolt({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M13 3L5 14h6l-1 7 8-11h-6l1-7z" />
    </svg>
  );
}

/** Обновить. */
export function IconRefresh({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M20 12a8 8 0 1 1-2.6-5.9" />
      <path d="M20 4v4h-4" />
    </svg>
  );
}

/** Скачать. */
export function IconDownload({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M12 4v10" />
      <path d="M8 10.5l4 4 4-4" />
      <path d="M5 19h14" />
    </svg>
  );
}

/** Загрузить. */
export function IconUpload({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M12 20V10" />
      <path d="M8 13.5l4-4 4 4" />
      <path d="M5 5h14" />
    </svg>
  );
}

/** Удалить. */
export function IconTrash({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M4 7h16" />
      <path d="M9 7V5h6v2" />
      <path d="M6 7l1 13h10l1-13" />
    </svg>
  );
}

/** Копировать. */
export function IconCopy({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3" />
    </svg>
  );
}

/** Внешняя ссылка. */
export function IconExternal({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M14 5h5v5" />
      <path d="M19 5l-7 7" />
      <path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" />
    </svg>
  );
}

/** Подсказка. */
export function IconInfo({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </svg>
  );
}

/** Время. */
export function IconClock({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </svg>
  );
}

/** Сеть. */
export function IconWifi({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M3 9a14 14 0 0 1 18 0" />
      <path d="M6.5 12.5a9 9 0 0 1 11 0" />
      <path d="M10 16a4 4 0 0 1 4 0" />
      <path d="M12 19.5h.01" />
    </svg>
  );
}

/** Сервер. */
export function IconServer({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <rect x="4" y="4" width="16" height="6" rx="2" />
      <rect x="4" y="14" width="16" height="6" rx="2" />
      <path d="M8 7h.01M8 17h.01" />
    </svg>
  );
}

/** Файл. */
export function IconFile({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5z" />
      <path d="M14 3v5h5" />
    </svg>
  );
}

/** Терминал. */
export function IconTerminal({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M7 9l3 3-3 3M13 15h4" />
    </svg>
  );
}

/** Показать. */
export function IconEye({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M2.5 12S6 6.5 12 6.5 21.5 12 21.5 12 18 17.5 12 17.5 2.5 12 2.5 12z" />
      <circle cx="12" cy="12" r="2.6" />
    </svg>
  );
}

/** Добавить. */
export function IconPlus({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M12 5v14M5 12h14" />
    </svg>
  );
}

/** Убрать. */
export function IconMinus({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M5 12h14" />
    </svg>
  );
}

/** Шеврон вправо. */
export function IconChevronRight({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M9 6l6 6-6 6" />
    </svg>
  );
}

/** Шеврон вниз. */
export function IconChevronDown({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}

/** Вращающийся индикатор ожидания. */
export function IconSpinner({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M12 3a9 9 0 1 0 9 9" />
    </svg>
  );
}

/** Питание. */
export function IconPower({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M12 3v9" />
      <path d="M6.5 6.5a8 8 0 1 0 11 0" />
    </svg>
  );
}

/** Измеритель. */
export function IconGauge({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M4 17a9 9 0 1 1 16 0" />
      <path d="M12 17l4-5" />
    </svg>
  );
}

/** Фильтр. */
export function IconFilter({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M3 5h18l-7 8v6l-4-2v-4L3 5z" />
    </svg>
  );
}

/** Настройки. */
export function IconSettings({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3v2.5M12 18.5V21M4.2 7.5l2.2 1.3M17.6 15.2l2.2 1.3M4.2 16.5l2.2-1.3M17.6 8.8l2.2-1.3" />
    </svg>
  );
}

/** Щит с галочкой: защита подтверждена. */
export function IconShieldCheck({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M12 3l7 3v6c0 4.2-2.9 7.7-7 9-4.1-1.3-7-4.8-7-9V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

/** Тревога. */
export function IconAlert({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7.5v5M12 16h.01" />
    </svg>
  );
}

/** Успех в круге. */
export function IconCheckCircle({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M8 12.4l2.6 2.6L16 9.6" />
    </svg>
  );
}

/** Ошибка в круге. */
export function IconXCircle({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M9 9l6 6M15 9l-6 6" />
    </svg>
  );
}

/** Стрелка вправо. */
export function IconArrowRight({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M4 12h15" />
      <path d="M13 6l6 6-6 6" />
    </svg>
  );
}

/** Список. */
export function IconList({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M8 6h12M8 12h12M8 18h12" />
      <path d="M4 6h.01M4 12h.01M4 18h.01" />
    </svg>
  );
}

/** Карта/маршрут. */
export function IconMap({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M9 4l6 2 6-2v14l-6 2-6-2-6 2V6l6-2z" />
      <path d="M9 4v14M15 6v14" />
    </svg>
  );
}

/** Активность: пульс. */
export function IconActivity({ size = 16, className }: IconProps) {
  return (
    <svg {...svgProps(size)} className={className}>
      <path d="M3 12h4l2.5-6 4 12L16 12h5" />
    </svg>
  );
}
