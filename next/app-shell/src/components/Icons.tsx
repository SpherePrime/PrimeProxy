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
