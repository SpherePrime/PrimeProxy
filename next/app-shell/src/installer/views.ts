const MARK = `<svg class="mark" viewBox="0 0 36 36" aria-hidden="true"><g transform="translate(8 2) skewX(-20)"><rect y="7" width="7" height="22" rx="2"/><rect x="11" width="7" height="32" rx="2"/><rect x="22" y="7" width="7" height="22" rx="2"/></g></svg>`;

const ARROW = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>`;
const CHECK = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>`;
const FOLDER = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>`;

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (symbol) => `&#${symbol.charCodeAt(0)};`);
}

export function shell(version: string, steps: string[], active: number, body: string): string {
  const stepItems = steps
    .map(
      (step, index) =>
        `<li class="${index < active ? "is-done" : index === active ? "is-active" : ""}"><span>${index < active ? CHECK : String(index + 1).padStart(2, "0")}</span>${step}</li>`,
    )
    .join("");
  return `
  <div class="frame">
    <aside class="side">
      <div class="side__grid"></div>
      <div class="side__glow"></div>
      <div class="side__content">
        <div class="brand">${MARK}<span><b>Prime</b>Bypass</span></div>
        <ol class="steps">${stepItems}</ol>
        <p class="side__foot">Версия ${escapeHtml(version)}<br/>© 2026 SpherePrime</p>
      </div>
    </aside>
    <main class="main">
      <header class="bar">
        <button class="bar__btn" data-action="minimize" aria-label="Свернуть"><svg viewBox="0 0 24 24"><path d="M6 12h12"/></svg></button>
        <button class="bar__btn bar__btn--close" data-action="close" aria-label="Закрыть"><svg viewBox="0 0 24 24"><path d="M7 7l10 10M17 7L7 17"/></svg></button>
      </header>
      <section class="screen">${body}</section>
    </main>
  </div>`;
}

export function welcomeView(dir: string, desktop: boolean, launch: boolean, installed: boolean): string {
  return `
    <span class="eyebrow">${installed ? "Обновление" : "Установка"}</span>
    <h1>Интернет без границ.<br/><em>Одной кнопкой.</em></h1>
    <p class="lead">PrimeBypass открывает YouTube, Discord, Telegram и другие сервисы. Установка займёт меньше минуты.</p>
    <div class="field">
      <span class="field__label">Папка установки</span>
      <div class="path">
        <span class="path__icon">${FOLDER}</span>
        <span class="path__value" title="${escapeHtml(dir)}">${escapeHtml(dir)}</span>
        <button class="btn btn--ghost" data-action="pick">Изменить</button>
      </div>
    </div>
    <div class="options">
      <button class="option ${desktop ? "is-on" : ""}" data-action="toggle-desktop" aria-pressed="${desktop}"><span class="switch"></span>Ярлык на рабочем столе</button>
      <button class="option ${launch ? "is-on" : ""}" data-action="toggle-launch" aria-pressed="${launch}"><span class="switch"></span>Запустить после установки</button>
    </div>
    <div class="actions">
      <button class="btn btn--accent btn--lg" data-action="install">${installed ? "Обновить" : "Установить"}<span class="btn__arrow">${ARROW}</span></button>
    </div>`;
}

export function progressView(title: string, percent: number, label: string): string {
  return `
    <span class="eyebrow">Идёт работа</span>
    <h1>${escapeHtml(title)}</h1>
    <div class="meter">
      <div class="meter__value"><span data-role="percent">${percent}</span><small>%</small></div>
      <div class="progress"><span data-role="bar" style="width:${percent}%"></span></div>
      <p class="meter__label" data-role="label">${escapeHtml(label)}</p>
    </div>`;
}

export function doneView(title: string, text: string, primary: string | null): string {
  return `
    <div class="done">
      <div class="done__badge">${CHECK}</div>
      <h1>${escapeHtml(title)}</h1>
      <p class="lead">${escapeHtml(text)}</p>
      <div class="actions">
        ${primary ? `<button class="btn btn--accent btn--lg" data-action="launch">${escapeHtml(primary)}<span class="btn__arrow">${ARROW}</span></button>` : ""}
        <button class="btn btn--ghost btn--lg" data-action="close">Закрыть</button>
      </div>
    </div>`;
}

export function errorView(message: string): string {
  return `
    <span class="eyebrow eyebrow--fail">Ошибка</span>
    <h1>Не получилось</h1>
    <div class="notice">${escapeHtml(message)}</div>
    <div class="actions">
      <button class="btn btn--accent btn--lg" data-action="retry">Попробовать снова</button>
      <button class="btn btn--ghost btn--lg" data-action="close">Закрыть</button>
    </div>`;
}

export function uninstallView(removeData: boolean): string {
  return `
    <span class="eyebrow eyebrow--fail">Удаление</span>
    <h1>Удалить<br/><em>PrimeBypass?</em></h1>
    <p class="lead">Программа, ярлыки и запись в системе будут удалены. Обход блокировок перестанет работать.</p>
    <div class="options">
      <button class="option ${removeData ? "is-on" : ""}" data-action="toggle-data" aria-pressed="${removeData}"><span class="switch"></span>Удалить также настройки и профили</button>
    </div>
    <div class="actions">
      <button class="btn btn--danger btn--lg" data-action="uninstall">Удалить</button>
      <button class="btn btn--ghost btn--lg" data-action="close">Отмена</button>
    </div>`;
}
