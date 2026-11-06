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
WinDivert. Приложение открывается без прав, а запрос UAC появляется при
нажатии кнопки включения обхода: оболочка перезапускается повышенной с
флагом `--pb-autostart`, и интерфейс сразу включает обход. Код:
`electron/main.cjs` (`app:elevate`, `relaunchElevated`) и
`src/components/bypass/useBypass.ts` (`requestElevation`).

Отказ от запроса ничего не ломает: проверка, DNS и Telegram работают и без
прав. Если ядро запускается отдельно от оболочки, его нужно запускать от
имени администратора — иначе `winws2` не стартует. Повышенная оболочка
ждёт до 10 секунд, пока старое ядро без прав освободит порт.

Порт 7290 занимает ровно одно ядро. Перед запуском своего оболочка
спрашивает уже работающее ядро о правах (`runningCoreIsElevated`): живое
ядро с нужными правами переиспользуется, а если повышенной оболочке
досталось ядро без прав, она показывает объяснение и закрывается. Иначе
запуск обхода падал бы с 740, хотя само приложение уже повышено.
