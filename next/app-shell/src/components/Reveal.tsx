import { useEffect, useRef, useState, type ReactNode } from "react";

// Появление при прокрутке — приём сайта студии: секции «оживают», когда
// попадают в поле зрения. Наблюдатель один на элемент и после первого
// показа отключается: повторные появления отвлекают от работы.
//
// При системной настройке «меньше движения» элемент виден сразу — иначе
// содержимое осталось бы скрытым для тех, кто отключил анимации.

type RevealVariant = "fade" | "pop" | "blur";

interface RevealProps {
  children: ReactNode;
  /** Задержка появления в миллисекундах — для «лестницы» из карточек. */
  delay?: number;
  variant?: RevealVariant;
  className?: string;
}

/** Системная настройка «меньше движения»: анимации не нужны. */
function reducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

export function Reveal({
  children,
  delay = 0,
  variant = "fade",
  className = "",
}: RevealProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(reducedMotion);

  useEffect(() => {
    const node = ref.current;
    if (!node || visible) return;
    // Старые движки без IntersectionObserver показывают содержимое сразу:
    // скрытый текст хуже отсутствия анимации.
    if (typeof IntersectionObserver === "undefined") {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [visible]);

  const classes = [
    "reveal",
    variant === "fade" ? "" : `reveal--${variant}`,
    visible ? "is-visible" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div
      ref={ref}
      className={classes}
      style={delay > 0 ? { transitionDelay: `${delay}ms` } : undefined}
    >
      {children}
    </div>
  );
}
