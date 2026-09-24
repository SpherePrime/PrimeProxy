# PrimeProxy — AGENTS.md (карта проекта)

> Быстрый навигатор. Читай каждый раз. Обновляй при добавлении модулей.

## Лицензия: BUSL-1.1 (с 2026-09-14, была MIT)

- Файл `LICENSE` — Business Source License 1.1, Licensor LilKALINOV.
- Бесплатно: только запуск официальных сборок. Код — view-only.
- Production-использование кода (сборка из исходников, модификация,
  встраивание, редистрибуция) — только по коммерческой лицензии.
- Change Date: 4 года с публикации каждой версии → дальше GPLv2+.
- ВАЖНО: всё опубликованное под MIT до смены (релиз v0.1.0, старые коммиты)
  остаётся MIT навсегда — BSL действует только вперёд.
- Места с лицензией: `LICENSE`, `pyproject.toml` (license + classifier),
  `.github/workflows/build.yml` (--license), `packaging/version_info.txt`
  (LegalCopyright), `docs/README.md`, `docs/EN/README.md`.

## Запуск

```
cd D:\GitHub\PrimeProxy
python main.py            # GUI (pywebview, порт 1443)
python main.py --headless # только прокси-движки, без UI
python main.py --cli      # консольный режим
```

## Тесты и валидация

```
python -m pytest -q                                    # все тесты (~416+)
node --check ui/web/js/app.js                          # JS-синтаксис
node --check ui/web/js/i18n.js
node C:\Users\kiril\AppData\Local\Temp\opencode\verify_ui.js   # UI: bridge/ids/i18n
```

Cache-bust: в `index.html` все ссылки на `.css`/`.js`都有 `?v=N` — **при каждом UI-изменении инкрементировать**.

## Структура каталогов

```
D:\GitHub\PrimeProxy
├── main.py                  # точка входа (pywebview + tray)
├── ui/
│   ├── api.py               # SwiftAPI — все методы bridge (JS ↔ Python)
│   ├── window.py             # pywebview окно (glass/transparent/full_glass)
│   ├── i18n/                 # серверный i18n (не UI)
│   └── web/                  # статический фронт (вшитый в pywebview)
│       ├── index.html         # единый HTML-файл (все страницы)
│       ├── js/
│       │   ├── app.js         # главный JS: UI-логика, рендеринг, обработчики
│       │   ├── api.js         # bridge-обёртка (window.pywebview.api.*)
│       │   ├── i18n.js        # 3 блока ключей: ru / uk / en (инлайн, не JSON!)
│       │   ├── components.js  # переиспользуемые UI-компоненты
│       │   └── icons.js       # SVG-иконки
│       └── theme/
│           ├── dark.css        # тёмная тема (основная)
│           ├── light.css       # светлая тема
│           └── glass.css       # стеклянные эффекты, glass-переменные
├── config/
│   ├── store.py              # SettingsStore (JSON-хранилище с секциями)
│   └── __init__.py           # __version__
├── proxy/                    # MTProto WebSocket Bridge Proxy (ядро)
│   ├── core.py               # handshake, fake_tls, bridge
│   ├── server.py             # TCP-слушатель
│   └── utils.py              # DC-константы, шифрование
├── blockcheck/
│   ├── blockcheck.py         # DPI-детект (DNS/HTTP80/TLS12/TLS13/DPI/Ping)
│   └── orchestra/            # авто-выбор стратегий
│       ├── strategy_selector.py   # 50 стратегий gs_*, ранжирование
│       ├── symptom_mapping.py     # извлечение симптомов из blockcheck
│       └── strategy_applier.py    # применение стратегии к профилю
├── winws/
│   ├── profiles/             # профильный движок (serializer, instance)
│   │   ├── serializer.py     # parse/round_trip/validate/apply_strategy
│   │   └── instance.py       # read/write/reset/delete/list
│   ├── paths.py              # exe_dir(), find_engine()
│   └── run.py                # запуск winws
├── dns/
│   ├── poisoning.py          # DNS-poisoning check (DoH/UDP)
│   ├── quick_check.py        # быстрый DNS-чек (4 домена)
│   ├── adapters.py           # сетевые адаптеры (PowerShell)
│   ├── check.py              # полный connectivity check
│   └── providers.py          # DNS-провайдеры
├── hosts/
│   ├── catalog.py            # нормализация, 74 сервиса, fallback 14
│   └── catalog_repository.py # read-only sqlite (resources/hosts/hosts_catalog.sqlite3)
├── logs/
│   └── winws_log_analyzer.py # детект статуса из логов winws
├── autostart/
│   ├── scheduled_task_api.py # Windows Task Scheduler
│   ├── startup_shortcut_api.py # .lnk в Startup
│   ├── nssm_service.py       # NSSM-служба
│   └── service_api.py        # unified API
├── telegram/
│   └── TelegramWSProxy       # SOCKS5/WS proxy для Telegram
├── utils/
│   ├── update_check.py       # GitHub Releases check (RELEASES_API)
│   ├── updater.py            # скачивание/установка/откат релизов
│   ├── hardened_file_ops.py  # sha256, atomic_write, safe_join
│   ├── fast_download.py      # download с sha256/retry
│   ├── file_integrity.py     # fingerprint движка
│   ├── versioning.py         # версионирование
│   └── tray_common.py        # tray, APP_DIR
├── tests/                    # 21 модуль (~416+ тестов)
├── resources/
│   └── hosts/hosts_catalog.sqlite3 # bundled каталог (72 сервиса/818 доменов)
├── exe/                      # winws.exe, winws2.exe
├── lists/                    # списки доменов
└── tools/                    # вспомогательные скрипты
```

## Страницы UI (index.html — data-page)

| Страница     | Навигация                        | Описание |
|-------------|----------------------------------|----------|
| `dashboard` | nav.g_main → «Главная»          | Тумблеры MTProto/SOCKS5/Zapret, статистика, Telegram |
| `proxy`     | nav.g_main → «MTProto»          | Настройки MTProto-прокси |
| `profiles`  | nav.g_main → «Zapret»           | Движок (auto/winws1/winws2), drawer-редактор профилей, стратегии |
| `internet`  | nav.g_main → «Internet»         | Тест соединения, DNS, hosts |
| `tools`     | nav.g_tools                      | WinWS health, лог-анализатор, оркестратор |
| `updates`   | nav.g_sys → «Обновления»       | GitHub Releases, скачивание/откат, целостность движка |
| `logs`      | nav.g_sys → «Журналы»           | Логи приложения |
| `help`      | nav.g_sys → «Справка»           | FAQ |
| `settings`  | nav.g_sys → «Настройки»         | Оформление (Тема: Авто/Светлая/Тёмная), автозапуск, язык, прочее |

## Конвенции

- **Нет комментариев** в Python/JS-коде.
- **i18n** — инлайн в `ui/web/js/i18n.js`, 3 каталога (ru/uk/en). Ключи: `ns.key`. Не JSON.
- **Bridge**: все IPC-вызовы через `ui/api.py` (SwiftAPI). Методы регистрация — `self.<method>` публичны.
- **Кэширование статуса**: дорогие проверки (DNS,驱动,адаптеры) кэшируются с TTL через polling (см. `blockcheck/`, `winws/`).
- **Высокие привилегии**:一部分操作 (hosts, DNS, driver) требуют elevation — в pywebview на Windows UAC при старте.
- **Secret**: MTProxy secret фиксированный: `58a2307c18c00cee662daec0b23c638f`.
- **Порт UI**: 1443 (pywebview).
- **Порт MTProto**: 1443 (по умолчанию в `config/store.py`).
- **Recommended profile**: `Default (circular) v2.txt`.

## Основные IPC-методы (bridge)

```python
# Прокси
get_proxy_status / start_proxy / stop_proxy
get_tg_proxy_status / start_tg_proxy / stop_tg_proxy

# DPI / Zapret
get_dpi_status / get_zapret_engine / start_dpi / stop_dpi
profile_list / profile_read / profile_write / profile_reset / profile_delete
orchestra_recommend / apply_strategy / list_strategies

# DNS / Hosts
run_dns_check / flush_dns / get_network_adapters
get_hosts_selection / apply_hosts / clear_hosts

# Обновления
check_updates(force)      # GitHub Releases (встроенный!)
download_update / get_update_job / rollback_to(tag)
list_available_versions(limit)
engine_fingerprint / reset_engine_baseline

# Вспомогательные
get_version / get_winws_health / get_winws_log_status / read_winws_log_last
get_autostart_status / autostart_install / autostart_remove
```

## Цикл правки UI

1. Правь файлы в `ui/web/` (index.html, js/app.js, theme/glass.css, js/i18n.js)
2. Инкрементируй `?v=N` в `index.html` (всего 8 ссылок)
3. Проверь: `node --check js/app.js && node --check js/i18n.js`
4. Запусти: `node verify_ui.js` — 8 known false-positives (id, hosts.cat_, pf.group_, pf.tag_, dg.verdict/group/msg/detail_)
5. `python -m pytest -q` — 416+ passed
6. Рестарт приложения (Stop-Process python; Start-Process python main.py hidden)
7. Проверь порт: `Get-NetTCPConnection -LocalPort 1443 -State Listen`

## Common gotchas

- `winws/profiles.py` старый файл был удалён — теперь `winws/profiles/` (пакет с serializer/instance).
- `winws_log_analyzer.py` был реализован по ТЗ (оригинал отсутствовал в zapretgui).
- `hardened_file_ops.py`, `fast_download.py`, `file_integrity.py`, `versioning.py` — новые утилиты, реализованы по ТЗ.
- `SettingsStore` секция `proxy` отвечает за MTProto (порт 1443). Секция `mtproto` отсутствует → `get('mtproto')` → None.
- `api.py` НЕ имеет `get_dpi_config` — используй `get_dpi_status` / `get_zapret_engine`.
- Источники из `D:\zapretgui\src` частично отсутствуют — агенты реализовывали по ТЗ координатора.
- 2026-09-14, фиксы после ruff-аудита (184 замечания, из них 2 реальных + 1 краш):
  - `winws/health/system_ops.py`: `winreg` импортировался локально, а `_read_dword`/`_read_str`
    видели глобал → тихий NameError, статусы WinDivert всегда None. Теперь модульный guarded-import.
  - `utils/icon.py`: аннотации `Image.Image` без импорта → добавлен TYPE_CHECKING-import.
  - `ui/window.py`: `background_color="#00000000"` ронял старт GUI (pywebview принимает только
    hex-триплет) → теперь `#000000` при `transparent=True` (full_glass).
  - 2026-09-14, прозрачность окна: убран битый режим — добавлен настоящий DWM-blur позади окна
    (`_set_dwm_blur` через `DwmEnableBlurBehindWindow`, HWND поиском по заголовку).
    Bridge `apply_window_effect` (api.py + api.js) вызывается из JS при старте и на тогглах —
    живьём, без рестарта.
  - 2026-09-14, КРИТИЧНО: `transparent=True` (TransparencyKey) + WebView2 с GPU-композитом
    (`Intermediate D3D Window`) = клики проходят сквозь окно (D3D-оверлей рисует, хит-тест идёт
    в красный keyed-слой). Лечение: `transparent=False` ВСЕГДА, прозрачность только через
    `SetLayeredWindowAttributes` LWA_ALPHA (`appearance.window_opacity` 0.3-1.0, слайдер
    `setWindowOpacity`, живьём без рестарта). Тоггл full_glass и cuRestartRow удалены из UI.
  - Кастомизация: слайдер `setBlurAmount` → `appearance.blur_intensity` (0-100 → `--glass-blur`
    0-30px), ключ `cu.blur_amount` в 3 языках.
  - 2026-09-14, глаз и журнал: одна кнопка `#glassEye` (Liquid Glass, пресет вкл/выкл,
    `appearance.liquid_glass`, слайдеры ниже — тонкая настройка, `syncGlassControls`).
    `save()` больше не тостит «Сохранено» (убраны 4 явных вызова) — только ошибки.
    Ошибки: `toast(msg,'error')` авто-пишет в журнал через bridge `report_ui_error(source,msg)`
    → `proxy.log` → вкладка «Журнал». `copyText()` + кнопка `cmn.copy` в боксе ошибок
    обновлений (`renderCheckError`). mono-block/log-view — `user-select:text`.
  - Версия: `check_updates` возвращает `current` (был «?» в `up.ahead_of_release`); текст —
    «Установлена последняя официальная версия {cur}».
  - 2026-09-14, раздача/ошибки из журнала: `setShare` не сохранял `share_lan` (сохранение без
    значения) → после рестарта тоггл OFF, а host оставался 0.0.0.0; исправлено + самолечение
    при старте (heal 0.0.0.0→127.0.0.1 + рестарт прокси). SOCKS-ссылка брала host из proxy-секции —
    теперь из telegram.bind_host. Share-бокс: два ряда MTProto (tg:// + Connect) и SOCKS5
    (host:port + Connect через tg://socks), bridge `open_link` (только tg://), ключи pg.copy/pg.connect.
    `start_dpi` без профиля → авто-подстановка recommended. `runner.start` WinError 740 →
    needs_admin с русским текстом. UI `pf.err_start` показывает detail вместо кода. `packaging/version_info.txt`
    обновлён до 0.2.0.
  - 2026-09-14, DevTools + логи ошибок + кастомизация: `webview.start` теперь `debug=False` +
    `OPEN_DEVTOOLS_IN_DEBUG=False` (DevTools сам не открывается). Bridge `open_devtools()` включает
    `AreDevToolsEnabled` в рантайме и вызывает `OpenDevToolsWindow()` (работает при debug=False, проверено
    живым тестом). JS: перехват `window.onerror`/`unhandledrejection`/`console.error` → `report_ui_error`
    → `proxy.log` (throttle 4s/сообщение). Shift+F1 (capture) → `bridge.open_devtools()`.
    Кастомизация: единая стандартная палитра STD_COLORS (белый/чёрный/серый/оранжевый/синий/красный/зелёный/фиолетовый)
    для всех контролов (акцент/сайдбар/активная вкладка/текст). Клик свотча пишет реальный цвет в picker.
    Свотч активной вкладки ставит цвет текста И фон (тот же цвет при текущей альфе). Текст тянет
    label/dim (0.75/0.5 альфы). Кнопка «Сбросить цвета» (`cuResetColors`, ключ cu.reset_colors).
  - 2026-09-14, цвет без палитры: свотчи-палитры удалены полностью (JS + CSS + HTML). У каждого цвета
    (акцент/сайдбар/активная вкладка/текст) теперь только «По умолчанию» (`chip-btn.active`, ключ cmn.default)
    либо кастомный picker. Клик Default чистит сохранённый цвет и CSS var; любой ввод пикера снимает
    Default. `cuResetColors` сбрасывает и акцент, и кнопки Default. Палитра STD_COLORS удалена.
  - 2026-09-14, НАСТОЯЩЕЕ жидкое стекло. Прямая прозрачность WebView2 на Win (pywebview 5.4 edgechromium)
    не работает (колоркей не пробивает DirectComposition — эмпирически: окно рендерится сплошным листом).
    Решение: окно НЕПРОЗРАЧНОЕ, а живое стекло даёт `ui/glass.py`: фон.поток периодически (каждые 3с)
    и по оседаниям move/resize/shown делает снимок экрана за окном (кратковременно прячет окно LWA_ALPHA=0
    на ~60мс), ресайзит до ~560px, шлёт JPEG base64 через `window.evaluate_js` в `window.__glassRefresh`.
    JS ставит картинку фоном `#glassBackdrop` (fixed, z0, inset -3%, `filter: blur(26px) saturate(1.45)`,
    crossfade 350мс). Тела/сайдбар/карточки полупрозрачные → сквозь них виден размытый живой десктоп =
    реальное стекло. Объём в CSS: `--card-shadow` заглублён, у `.glass-card` ::before — specular-блик сверху,
    ::after — внутренняя нижняя тень. Бридж `set_live_glass(enabled)` (api.js 109-й метод); в app.js
    `syncLiveGlass()` вызывается при включении material/blur/reduce и в boot. Клампинг снимка — по
    ВИРТУАЛЬНОМУ экрану (SM_X/CXVIRTUALSCREEN 76-79), а не первичному (иначе мультимонитор: кадры молча
    пропускаются). Дебаунс: при движении спек capture ждёт 450мс тишины (window.events.moved/resized
    эмитятся в winforms) — окно не мигает при драге. Верифицировано скриншотами: за чёрным пустым монитором
    фон чёрный, над тёмным терминалом — пурпурный размытый.
  - 2026-09-14, ЭФФЕКТЫ ОКНА + ФОН (+поверхность). appearance-ключи: `window_effect` (acrylic|glass|wallpaper),
    `wallpaper` (""|threads|dark_veil|gradient|image|video), `wallpaper_src` (путь фото/видео),
    `gradient_a/b` (2 цвета градиента), `surface_color` (глобальный тон панелей, ""=по теме).
    Эффекты: acrylic = живой десктоп с блюром (по умолчанию); glass = живой десктоп РЕЗКО (без блюра,
    прозрачные панели — `wx-glass` снимает backdrop-filter у .glass-card, захват sharp выше разрешение
    target 920/q72); wallpaper = выбранный фон вместо живого экрана. Пресеты: threads (#0a0a0c),
    dark_veil (радиальный фиолетовый ореол + тёмный вертикальный градиент), gradient (135deg,
    var(--grad-a/b)), image (data:URL через `bridge.wallpaper_url` для расширений png/jpg/webp/gif/bmp ≤8МБ),
    video (стримится через локальный `ui/asset_server.py` — HTTP 127.0.0.1:0, токен `k=`, отдаёт ТОЛЬКО
    указанный путь, MIME по расширению; при старте лениво). Выбор файла — `bridge.pick_wallpaper(kind)`
    (tkinter-диалог, фолбэк ctypes GetOpenFileNameW). Выбор пресета в UI автоматически ставит
    window_effect=wallpaper. Слои: `#wallpaperBg` (fixed z0) + `<video>#wallpaperVid` (autoplay muted loop).
    surface_color → inline `--surface-rgb`/`--surface-color`, подменяет базовый `rgba(var(--surface-rgb),
    var(--glass-bg-opacity))` у .glass-card (дефолт: тёмная тема 0,0,0 / светлая 255,255,255 из
    glass.css/light.css). VAЖНО: reduce_transparency НЕ скрывает wallpaperBg (это выбранный фон, не эффект
    прозрачности) — прячет только живой #glassBackdrop. Диагностика чёрных кадров: сначала проверяй
    reduce_transparency в config.json. validate: bridge 111, ids 239, i18n 702 (8 ложных позитивов), pytest 416.
  - 2026-09-14, прозрачность карточек = ТОГГЛ, а не ползунок: ключ `card_transparency` (bool) —
    вкл → card_opacity=0.3 (панели прозрачные), выкл → 1.0 (непрозрачные); слайдер setCardOpacity удалён
    (id setCardTransparent). ApplyGlassPreset on/off тоже ставит card_transparency. Убранных ids: 2 (опции).
  - 2026-09-14, live-стекло БОЛЬШЕ НЕ блокируется reduce_transparency: syncLiveGlass live = material_enabled &&
    (wx==acrylic|glass) БЕЗ проверки !reduce_transparency; CSS больше не прячет #glassBackdrop под
    :root.reduce-transparency (reduce влияет только на непрозрачность карточек в dark.css). Пресеты фонов
    сделаны заметно разными: threads=#000, dark_veil=сильный фиолетовый ореол rgba(150,130,255,.22),
    gradient=по умолчанию #2e2459→#0b0e26 (васильковый, НЕ похож на дефолтный #0a0a1a). Живой блюр
    подтверждён скриншотом: синяя картинка за окном просвечивает в панели (lum 46/uniq 189) при тёмных
    телах карточек. Прозрачность карточек по умолчанию вкл (30%), эффект по умолчанию acrylic, reduce off.
  - 2026-09-14, каденция живого стекла: _period 0.9с (~1 кадр/с при простое, было 3с), shutter окна
    LWA_ALPHA=0 укорочен 0.06→0.025с, _settle 0.3с = ПРИ ДВИЖЕНИИ захват не выполняется (нет мигания при
    перетаскивании; кадр обновляется через ~300мс после остановки). Плавность между кадрами:
    __glassRefresh создаёт ghost-слой .glass-fade со старым кадром и затухает его 220мс поверх нового
    (кросс-фейд, no pops). Проверено: idle-интервалы dips альфы ~1.0с. Железное правило: окно прячем
    ТОЛЬКО на мгновение захвата, при драге — никогда (иначе «жёстко моргает»).

## 2026-09-15, Кастомизация удалена — осталась только тема

- Раздел «Кастомизация» (`data-page-view="customization"`) и пункт навигации удалены
  полностью из `index.html`, `app.js`, `i18n.js` (ключи `cu.*`, `nav.customization`,
  `nav.g_custom`), `theme/glass.css` (правила пресетов фона, `no-tab-glass`, анимация
  `petrolShift`). Верифицировано: в навигации только Главная/Прокси/Zapret/Internet/
  Инструменты/Обновления/Журнал/Помощь/Настройки.
- Оформление сведено к теме: в **«Настройки»** добавлена карточка «Оформление»
  (заголовок `st.appearance`, `segmented-control id="themeMode"` Авто/Светлая/Тёмная,
  ключи `st.theme`/`st.auto`/`st.light`/`st.dark`). Хендлер/`syncTheme`/`applyThemeUI`/
  `setAppearance`/`themeValue` сохранены.
- `applyTheme(ap)` теперь только переключает классы `light`/`dark` на `<html>`;
  синхронизация цветов/пресетов/тогглов убрана. Удалены из app.js: `renderWallpaper`,
  `wallpaperUrlOf`, `_wpUrls`, `syncGlassControls`, `hexToRgba`/`hexToRgbTriplet`/
  `rgbaToHex`, все `on("...")`-хендлеры кастомизации.
- Фон: `<div id="wallpaperBg" class="wp-standard">` фиксирован как «Стандартный»
  (`--bg-root`, за `body { background: transparent }`); `#wallpaperVid` удалён из разметки.
- Из конфига appearance реально читается только `mode`; остальные ключи пользовательского
  config.json игнорируются (можно почистить вручную, не обязательно).
- Мёртвый код оставлен намеренно: bridge `apply_window_effect`/`set_live_glass`/
  `pick_wallpaper`/`wallpaper_url` (api.js + ui/api.py) — не вызываются из UI, безопасны.

## 2026-09-15, Автопилот «Обход Zapret» (+ «Создать профиль», сегменты Журнала)

- Вкладка «Обход Zapret» (`data-page="profiles"`, nav «Обход Zapret») получила
  карточку **«Автопилот»**: полный цикл «проверка сайтов → подбор стратегии →
  авто-профиль «auto» → запуск winws → мониторинг с перебором стратегий при
  сбое». Кнопки `#autoStartBtn`/`#autoStopBtn`/`#autoResetBtn`, статус
  `#autoStatus`, мета `#autoMeta`, рекомендации `#autoRecommendations`, журнал
  `#autoJournal`. Рендер — `renderAutopilot()` (вызывается из `showPage`/
  `renderDynamic`/`loadData` + поллинг 2с пока открыта страница profiles).
- `blockcheck/autopilot.py` — state machine (модуль, глобалок нет):
  idle→scanning→planning→applying→starting→monitoring (+error/stopped), попытки
  до `max_attempts` (`config zapret.auto.max_attempts`, дефолт 4; в `_IDLE` и в
  `_run` пишется под локом). Скан: `run_single_domain_check` +
  `get_default_https_targets_domains` (~100 доменов) + `load_user_domains`.
  План: `extract_symptoms` + `rank_recommendations` (orchestra). Применение:
  `apply_strategy_to_profile("auto")` с `backup_profile`. Остановка — асинхронный
  флаг `_cancel` (`auto_stop`/`auto_reset`). Контракт `status()`: phase, active,
  message, progress{tested,total,blocked}, symptoms, recommendations[],
  chosen{strategy,name,attempt}, attempt, max_attempts, profile, mode,
  last_error, started_at, engine_ok, journal[].
- Bridge: `auto_status/auto_start/auto_stop/auto_reset/auto_journal(limit)` — в
  `ui/api.py` (секция после `list_locked_strategies`, ~стр. 1620; Python-методы
  `auto_*`) и в `ui/web/js/api.js` (обёртка `bridge.auto_*`). ВАЖНО: если
  Python-методы добавили, а JS-обёртку забыли — бут падает
  `TypeError: bridge.auto_status is not a function` (регистрируется в proxy.log
  через `report_ui_error`). Порядок правки: api.py → api.js → `?v++`.
- **Цели скана автопилота следуют за hosts-каталогом**: `_run()` использует
  `get_default_scan_domains()` = встроенный `HTTPS_TARGETS` + домены
  `hosts_catalog.sqlite3` (новая `hosts/catalog_repository.catalog_domain_names()`:
  hostname из `hosts_entries` hosts-сервисов + `domains` dns-сервисов,
  включённые сервисы, lowercase/dedup/sorted, read-only без content-валидации) +
  пользовательские домены. Кап из каталога — `zapret.auto.catalog_limit`
  (дефолт 250, 0 = все 818+427). В статусе автопилота появляется `scan_sources`
  {builtin, catalog, user}; в журнале — счётчики целей. `get_catalog_target_domains()`
  при ошибке чтения каталога возвращает `[]` (скан не падает).
- **«Подбор стратегии вручную»**: `#pfOrSymptoms` (текст симптомов) +
  `#pfOrRunBtn` → `orchestra_recommend` + кнопка применить (обёртки
  `orRecommendation(r, statusFn)`/`orchestraApply(strategyId, name, statusFn)` в
  app.js). Ряд «применить стратегию к профилю» из каталога лейнов убран — см.
  ниже про `strategies/*.txt`.
- **«Создать профиль»**: кнопка `#pfCreateBtn` + inline-ряд `#pfCreateRow`
  (поле `#pfCreateName`, select `#pfCreateTemplate`, кнопки Создать/Отмена).
  Шаблоны (`pfCreateTemplatesList`): empty / based_recommended (из
  `profile_list().recommended`) / based_winws2 (первые 12 профилей winws2).
  «Создать» открывает `openProfileDrawer(name, content, {user:true})`.
  Ключи: `pf.create_*`, `pf.based_recommended`, `pf.based_winws2`,
  `pf.create_empty`.
- **Журнал** (`data-page="logs"`): сегмент-контрол `#logSeg` —
  gen/sessions/errors/warnings/auto, контейнер `#logStatusBox`,
  `renderLogSeg()` + чекбокс автообновления. Сегмент autopilot рендерит
  `auto_journal` (пусто → «Журнал пуст.»). Контракт `get_winws_log_status()`: ok,
  has_log, lines_total, sessions_count, ok/fail/warn/open_count, sessions[]
  (started_at, mode, pid, cwd, ended_at, exit_code, stopped_by_app,
  immediate_exit, lifetime_seconds, ok), errors[], warnings[], last_session,
  verdict{has_log,status,reason,detail,lines_total}.
- **Обновлены** `ui/web/index.html` (?v сейчас 48; pfStrategyRow удалён),
  `app.js`, `i18n.js` (au.*, pf.create_*, lg.seg_*/*none_*/*ok_count и пр.,
  все 3 языка), `icons.js` (иконка `plus`), `config/store.py` (zapret.auto).
- ВАЖНО: `resources/zapret/strategies/{http80,tcp,udp,voice}.txt` — round-robin
  каталоги ЛЕЙНОВ (по 1 на профиль), а НЕ gs_*-стратегии оркестратора.
  `list_strategies` — стратегии оркестратора. Не путай.
- Верификация UI без Vision-AI: скриншот + UIA-дамп через
  `C:\Users\kiril\AppData\Local\Temp\opencode\uia_invoke.ps1` (`-Seg`:
  profile/logsnav/sess/errs/warns/auto/gen/create/cancel). КООРДИНАТНЫЕ клики
  (SetCursorPos+mouse_event) в WebView2-окно НЕ срабатывают — нужен UIA
  `InvokePattern` (работает и по кириллице). `uia.ps1 -Click` по кириллице из
  аргументов глючит (теряется кодировка) — паттерны держи ВНУТРИ ps1-файла.
- **Потокобезопасность и ownership**: `_state["last_error"]` в `_monitor`
  пишется под `_lock` (было вне — гонка с `status()`). `stop()` убивает winws
  **только** если `_state.get("mode")` установлен (autopilot его запустил):
  ручной winws автопилот не трогает. `_finish_error`/`_finish_stopped` обнуляют
  `mode` — после завершения повторный `stop()` не убьёт чужой процесс.
  Буфер журнала 800 (было 400 — 265+ целей заполняют быстро).
  Фатальные ошибки старта (`engine_missing`, `needs_admin`, `validate`,
  `missing_files`) в `_run()` → сразу `_finish_error` без retry-попыток
  (раньше крутил все 4 стратегии впустую). `start()` сам проверяет движок и
  `autostart.is_admin()` ДО запуска потока — без прав админа winws всё равно
  не поднимется (WinDivert), скан отменяется мгновенно с понятным сообщением.
- Запуск приложения: `Start-Process 'C:\Users\kiril\AppData\Local\Programs\
  Python\Python312\python.exe' -ArgumentList 'D:\GitHub\PrimeProxy\main.py'
  -WorkingDirectory 'D:\GitHub\PrimeProxy'` (.venv в репо нет). UI-порт
  фактически 26824 (не 1443). JS-ошибки искать в
  `C:\Users\kiril\AppData\Roaming\PrimeProxy\proxy.log` (`[ui:console]`) —
  ОБЯЗАТЕЛЬНО читать при фиксах ([как просил пользователь]).
- **Self-elevation**: `main.py` при старте сам запрашивает права админа через
  UAC (`tools.windows_tools.ensure_elevated` → `ShellExecuteW("runas")`),
  если процесс не администратор (winws/WinDivert требует админ). Перезапуск
  идёт с `--no-elevate`, старый процесс выходит (`state == "started"`).
  Отклонённый UAC (`"cancel"`) НЕ блокирует запуск — приложение работает без
  админа, но winws не поднимется. Флаг `--no-elevate` отключает авто-UAC.
  ВАЖНО (баг, починен 2026-09-15): `ShellExecuteW("runas", python.exe, cmd)`
  пишет ПЕРВЫЙ токен cmd как имя скрипта — раньше передавали
  `--no-elevate main.py ...` и elevated-процесс молча падал («python:
  can't open file --no-elevate»). Теперь cmdline собирается как
  `[sys.argv[0], *rest]` — script первым. Поэтому приложение РЕАЛЬНО
  поднимается (проверено на статусе токена живого PID: S-1-5-32-544 в группах
  с SE_GROUP_ENABLED), элевация работает и в песочнице KALINOV-OS (UAC
  auto-approve).
  `_admin_capable()` НЕ должен использовать CheckTokenMembership как финальный
  ответ: у неэлевированного админ-процесса группа 544 помечена deny-only и
  функция возвращает False (это нормальный UAC-фильтр). Решение: фоллбэк
  `_sid_in_token()` — сырой перебор групп через GetTokenInformation(TokenGroups)
  + EqualSid. Чистая логика вынесена в `_admin_capable_for(membership, present)`.
  Тесты этого уровня — на хелпере, не через фейк `ctypes.windll` (у `byref()`
  CArgObject нет `.contents` — фейки падали в except→True и тесты были слепые).
  ВАЖНО: запуск вида `python.exe --no-elevate main.py` НЕ работает — Python
  принимает `--no-elevate` за скрипт. Флаг ставится ПОСЛЕ пути к скрипту:
  `python.exe main.py --no-elevate`.

## 2026-09-15, UI-тексты: чисто и без «воды» (запрос «перепи на нормальную информацию»)

- Переписаны на простой русский и укорочены пользовательские тексты (RU):
  - `blockcheck/autopilot.py` (журнал/статус, виден юзеру): «Целей сканирования:
    встроенные N...» → «Планирую проверку: N сайтов (N встроенных, N из каталога,
    N своих)»; «Подобрано стратегий: N. Лучшая:...» → «Обнаружено: X. Лучшая
    стратегия: Y (из N)»; убран технический `mode='auto'` из сообщения о запуске
    («winws запущен с профилем X. Начинаю мониторинг...»); «Следующая попытка
    N/M» → «Повторная попытка N из M»; «Исчерпано попыток: N» → «Испробованы все
    стратегии (N). winws не запустился стабильно.»; исправлен баг буквы «N» в
    «Профиль X сохранён (N параметров: {n})» → «({n} параметров)»; ошибка запуска
    без технич. ключа: «Не удалось запустить winws: {detail}»
    (`winws/runner.py` needs_admin: «Нужны права администратора (WinDivert)...»).
  - `ui/web/js/i18n.js` RU-секция: ужаты `hp.what_text/what_more/mt_more/tg_more/
    dns_more/hosts_more/presets_more/share_more/settings_more/logs_more/
    router_more (сводка правил по вендорам)/server_more/docker_more`,
    подсказки `pf.subtitle/pf.engine_hint/au.hint/pr.subtitle` без жаргона
    (winws1/winws2, DPI, «мост»). uk/en не трогали.
- Cache-bust: `index.html` `?v=48` → `?v=49` (все 8 ссылок).
- Верификация: `py_compile` правленных .py, node VM-парсинг i18n.js (3 каталога
  живы), `pytest` = 432 passed + 9 subtests. JS-ошибок в proxy.log нет.
- Тесты НЕ привязаны к строкам журнала автопилота (grep по tests/ — 0 совпадений),
  тексты можно править свободно.

## 2026-09-23, Вкладка Zapret: фиксы багов аудита + UX (продолжение 2026-09-15)

- `blockcheck/autopilot.py`:
  - `_ACTIVE` включил `dns_repair` (фазу пропускали, UI «зависал»).
  - `_write_profile` бэкапит профиль ОДИН раз за сессию (`_backed_up`-реестр,
    чистится в `start()`), иначе 2-я попытка перезаписывала бэкап свежим
    содержимым — оригинал терялся.
  - `_start_winws`: `_state["mode"/"profile"]` пишутся под `_lock`.
  - `chosen` в `_run` пишется под `_lock`.
  - `next_attempt = attempt_index + 2` (старая арифметика `+= 1` давала двойной
    шаг; теперь `attempt_index = next_attempt - 1`).
  - `_monitor`: состояния `None`/`starting` не считаются «упало» — grace-контур
    (4 полла) перед возвратом False.
  - `_finish_stopped` чистит profile/chosen/progress/symptoms/
    recommendations/last_error (старый статус не светится в UI после стопа).
- `ui/web/js/app.js`:
  - `showPage('profiles')` вызывает renderAutopilot + renderDpiEngine +
    renderProfiles (карты движка и профилей больше не застывают).
  - Строки профилей несли `group` (strategies/user/winws1/2) — бейдж «активен»
    в `pfList` теперь реально ставится.
  - Свойства-тайлы убраны (tautology `sel === 'strategy'`), size=0 у
    стратегий/юзеров больше не показывает «1 KB».
  - Смена группы: `state.pfOpen = null`, прячется pfCreateRow (stale-профиль
    не светится в кнопке Edit).
  - `pfCreateOk`: шаблон «На базе рекомендуемого» читает
    `get_zapret_profile_text('winws2', recName)` (было
    `get_zapret_user_profile` → пустой профиль); имя валидируется
    `[\\/:\"<>|?*]` (Windows-illegal).
  - `pfOrRun`: успех → `notice` (нейтральный), ошибка → `notice error`;
    пустой результат показывает `or.no_data` без машинного кода.
  - `loadWinwsLog`: автоскролл только если пользователь был у низа (40px).
  - `renderAutopilot`: `#autoMeta` прячется когда пуст; `st.last_error`
    локализует через `au.err_*`; рекомендации в idle-state показывают
    `au.recs_empty`.
  - `orchestraApply`: если активен встроенный профиль → применяет к `auto`
    (авто-профиль автопилота), `apply_strategy` вызывается с 3 аргументами
    (section_name="").
  - auto-mode: вынесен `applyAutoMode()`, старт больше не инвертирует флаг
    (было `if (state.autoMode) toggleAutoMode()` → авто-режим ОТКЛЮЧАЛСЯ при
    запуске). CSS `.auto-mode` прячет `[data-manual-card]`, кроме открытых
    drawer/backdrop.
- `ui/web/theme/glass.css`: `#pfList .pf-row:last-child` без border-bottom;
  `.pf-drawer-params` — max-height 40vh + overflow; `.auto-mode` исключения
  для drawer.
- `ui/web/js/i18n.js`: добавлено 9 ключей × 3 языка (`au.err_*`, `au.recs_empty`)
  → 707 ключей во всех каталогах.
- `index.html`: `?v=50` → `?v=51` (все 8 ссылок).
- Верификация: py_compile (autopilot/ui), node --check (app.js/i18n.js),
  pytest = 443 passed + 9 subtests, i18n-паритет (707×3) через VM-парсинг.

## 2026-09-15, Автопилот: составные стратегии + авто-DNS + авто-режим в UI

- `blockcheck/autopilot.py` — новый `_run()` с тремя функциями:
  - `_collect_composite_strategies(symptoms)` — для каждого типа симптома берёт ЛУЧШУЮ
    стратегию из `SYMPTOM_TO_STRATEGY` (strategy_selector), дедупликация по `gs_*` id,
    фильтр `gs_pass`. Возвращает `[{strategy_id, strategy_name, strategy_obj}]`.
  - `_auto_dns_repair(symptoms)` — при `dns_poisoning`: пробует провайдеры
    Cloudflare → Google → Quad9 через `dns.force_dns()`. Дополнительно вызывает
    `dns.flush_dns_cache()`. Логирует результат в журнал. Фаза `dns_repair`.
  - `_apply_composite_strategies(base_text, strategies)` — последовательно применяет
    каждую стратегию к профилю через `apply_strategy_to_profile(circular)`, без
    удаления существующих лейнов (additive).
  - `_run()`: scan → plan → dns_repair → collect composite → retry loop (попытка 0 =
    все стратегии, попытка 1 = минус первая и т.д.) → monitor.
  - Новая фаза `dns_repair` ( новая строка в `AU_PHASE_KEYS` и `AU_ACTIVE`/`AU_PHASE_WARN`).
  - `_state["chosen"]` теперь `{"strategy": "composite", "name": "Strategy1, Strategy2, ...", "attempt": N}`.

- **UI auto-mode**: вкладка «Zapret» в автоматическом режиме показывает только карточку
  «Автопилот» + счётчик профилей. Engine card скрыта (`data-manual-card`).
  Кнопка «Auto mode» (`#autoModeBtn`) переключает `state.autoMode` и CSS-класс
  `.auto-mode [data-manual-card] { display: none !important; }`.
  Состояние `state.autoMode = true` по умолчанию (скрытие ручных карт при загрузке).

- Файлы: `ui/web/index.html` (?v=50), `ui/web/js/app.js` (toggleAutoMode, AU_PHASE_KEYS,
  state.autoMode), `ui/web/js/i18n.js` (au.auto_mode, au.phase_dns_repair — ru/uk/en),
  `ui/web/theme/glass.css` (.auto-mode правила).

- Верификация: `py_compile` autopilot.py (OK), `node --check` app.js/i18n.js (OK),
  `pytest` = 435 passed + 9 subtests.

## 2026-09-15, Автопилот: живой прогон end-to-end + фикс

- **Живой тест** (поднятый драйвером с `ensure_elevated`): скан 269 сайтов →
  80 blocked → симптомы (http_inject, isp_page, tls_reset, tls_mitm, full_block)
  → составной профиль из 4 стратегий → профиль `auto` (173 параметра) → winws
  запущен → мониторинг стабилен → stop() чистый (winws убит, phase=stopped).
  DNS не трогается, если нет симптома dns_poisoning («не мешать тому, что
  работает» соблюдено).
- **БАГ (починен)**: `_recommended_text()` в autopilot.py вызывал
  `pfp._recommended_name()` — он не реэкспортируется из `winws/profiles/__init__.py`
  (живёт в instance.py) → AttributeError → молчаливый None → автопилот падал с
  `recommended_missing`. Фикс: имя берётся из `pfp.profile_list().get("recommended")`.
- **Запуск автопилота для теста без GUI**: драйвер + `tools.windows_tools.ensure_elevated()`
  (ShellExecuteW runas, UAC auto-approve в песочнице), скрипт ОБЯЗАТЕЛЬНО класть в
  корень репо — `exe_dir()` резолвится из `sys.argv[0]` (из temp/ → engine_missing).
