# Android (Capacitor)

По карте переезда: Android берёт **ту же Vite-сборку** интерфейса
(`next/app-shell/dist`) в WebView, а Rust-ядро подключается через UniFFI
из тех же крейтов primecore-*.

## Заготовка

```bash
cd next/app-shell && npm run build   # соберёт dist
npm install -D @capacitor/cli @capacitor/core @capacitor/android
npx cap init                         # или используй capacitor.config.json
npx cap add android
npx cap sync
npx cap open android                 # сборка в Android Studio
```

## Отличия от десктопа

- адаптеры и службы Windows недоступны — соответствующие секции страницы
  скрываются по платформе (позже: флаг из ядра);
- привилегии — не sudo, а уровни Android (VPN-сервис), отдельная задача.
