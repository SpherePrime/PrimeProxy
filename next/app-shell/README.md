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
