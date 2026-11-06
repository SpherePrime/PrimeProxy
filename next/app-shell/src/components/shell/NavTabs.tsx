import { NAV_PAGES, PageId } from "./pages";

interface NavTabsProps {
  current: PageId;
  onNavigate: (page: PageId) => void;
  variant?: "top" | "bottom";
}

export function NavTabs({ current, onNavigate, variant = "top" }: NavTabsProps) {
  return (
    <nav className={`nav ${variant === "bottom" ? "nav--bottom" : ""}`} aria-label="Разделы">
      {NAV_PAGES.map((page) => {
        const Icon = page.icon;
        const active = page.id === current;
        return (
          <button
            key={page.id}
            type="button"
            className={`nav__item ${active ? "is-active" : ""}`}
            onClick={() => onNavigate(page.id)}
            aria-current={active ? "page" : undefined}
            title={page.title}
          >
            <Icon size={16} />
            <span className="nav__label">{page.title}</span>
          </button>
        );
      })}
    </nav>
  );
}
