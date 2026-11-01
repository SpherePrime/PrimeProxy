// Значок сервиса: монограмма вместо логотипа.
//
// Логотипы чужих брендов в сборку не тащим (лицензии и вес), а буква плюс
// свой оттенок дают списку узнаваемость: цвет считается из имени, поэтому
// один и тот же сервис всегда выглядит одинаково на всех страницах.

interface ServiceBadgeProps {
  name: string;
  size?: number;
}

// Оттенки подобраны под графитовую тему: средняя насыщенность, светлее фона,
// чтобы монограмма читалась и не спорила с лаймовым акцентом «можно».
const HUES = [82, 150, 172, 196, 214, 236, 258, 280, 302, 326, 356, 22, 44];

/** Стабильный оттенок по имени: одна и та же строка — один и тот же цвет. */
function hueFor(name: string): number {
  let hash = 0;
  for (let index = 0; index < name.length; index += 1) {
    hash = (hash * 31 + name.charCodeAt(index)) % 100_000;
  }
  return HUES[hash % HUES.length];
}

/** Монограмма: первая буква первого слова и первого слова после разделителя. */
function initialsFor(name: string): string {
  const words = name.split(/[\s/._-]+/).filter((word) => word.length > 0);
  // Скобки и прочие знаки в начале слова в монограмму не годятся:
  // «Anthropic (Claude)» должно дать «AC», а не «A(».
  const letters = words
    .map((word) => word.match(/[\p{L}\p{N}]/u)?.[0])
    .filter((letter): letter is string => Boolean(letter));
  if (letters.length === 0) return "?";
  const first = letters[0];
  const second = letters.length > 1 ? letters[letters.length - 1] : "";
  return (first + second).toUpperCase();
}

export function ServiceBadge({ name, size = 34 }: ServiceBadgeProps) {
  const hue = hueFor(name);
  return (
    <span
      className="svc-badge"
      aria-hidden="true"
      style={{
        width: size,
        height: size,
        fontSize: Math.round(size * 0.4),
        // Оттенок передаём переменной, остальное — в CSS: так значок
        // остаётся частью общей темы, а не отдельным стилем.
        ["--badge-hue" as string]: String(hue),
      }}
    >
      {initialsFor(name)}
    </span>
  );
}
