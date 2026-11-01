# Оболочка PrimeBypass (Electron)

Ядро — Rust (sidecar `primecore-server`), интерфейс — Vite React. Та же
Vite-сборка идёт в Android через Capacitor (`../android`).

## Запуск

```bash
# 1. Ядро
cargo build -p primecore-server --release

# 2. Интерфейс
cd next/app-shell
npm install
npm run build

# 3. Окно
npm run electron:start          # возьмёт target/release/primecore-server
PRIMECORE_BIN=/путь/к/primecore-server npm run electron:start
```

## Разработка

```bash
npm run dev        # Vite на :5173
# в другом окне:
PRIMECORE_BIN=... VITE_URL=http://localhost:5173 npm run electron:start
```

## Привилегии Linux

При первом запуске оболочка запросит пароль один раз (`pkexec privd` /
`sudo privd`) — дальше демон держит привилегии, повторных запросов нет.
Схема и код: `crates/primecore-privilege`, `docs_linux-privileges.md`.

## Привилегии Windows

Движку обхода `winws2` в манифесте нужен уровень High: без него Windows
отказывает в запуске с ошибкой 740, потому что движок ставит драйвер
WinDivert. Поэтому оболочка при старте сама показывает запрос UAC и
перезапускается повышенной — один запрос на запуск приложения, как
`pkexec`/`sudo` на Linux. Код: `electron/main.cjs` (`isElevated`,
`relaunchElevated`).

Отказ от запроса приложение не закрывает: проверка, DNS, Telegram и
настройки работают и без прав, а запуск обхода честно скажет, чего не
хватает. Если ядро запускается отдельно от оболочки, его тоже нужно
запускать от имени администратора — иначе `winws2` не стартует.

Порт 7290 занимает ровно одно ядро. Перед запуском своего оболочка
спрашивает уже работающее ядро о правах (`runningCoreIsElevated`): живое
ядро с нужными правами переиспользуется, а если повышенной оболочке
досталось ядро без прав, она показывает объяснение и закрывается. Иначе
запуск обхода падал бы с 740, хотя само приложение уже повышено.
