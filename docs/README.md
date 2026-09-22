<div align="center">

**🇷🇺 Русский • [🇬🇧 English](./EN/README.md)**

</div>

<p align="center">
  <a href="https://github.com/SpherePrime/PrimeProxy/releases"><img src="https://img.shields.io/github/v/release/SpherePrime/PrimeProxy?label=release&color=%23ff7b00" alt="Release"></a>
  <a href="https://github.com/SpherePrime/PrimeProxy/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/SpherePrime/PrimeProxy/build.yml?label=build&color=%23ff7b00" alt="Build"></a>
  <a href="https://github.com/SpherePrime/PrimeProxy/blob/main/LICENSE"><img src="https://img.shields.io/github/license/SpherePrime/PrimeProxy?color=%23ff7b00" alt="License"></a>
</p>

<div align="center">
  <img width="180" alt="PrimeProxy" src="./images/primeproxy-mark.png" />
</div>

# PrimeProxy

**Локальный MTProto-прокси** для Telegram Desktop, который **ускоряет работу Telegram**, перенаправляя трафик через WebSocket-соединения. Данные передаются в том же зашифрованном виде, а для работы не нужны сторонние серверы.

> [!TIP]
>
> ### [🎉 Поддержать меня](./RU/Funding.md)

> [!CAUTION]
>
> ### Реакция антивирусов
>
> Антивирусы часто ошибочно помечают приложение как вирус из-за упаковщика.  
> Если вы не можете скачать из-за блокировки антивирусом, то:
>
> 1) **Попробуйте скачать версию для Windows 7 (по функциональности она не отличается)**
> 2) Отключите антивирус на время скачивания, добавьте файл в исключения и включите обратно  
>
> Всегда проверяйте, что скачиваете из интернета, тем более из непроверенных источников. Всегда лучше смотреть на детекты широко известных антивирусов на VirusTotal

## ✨ Возможности

- ⚡ **Ускорение Telegram** — трафик идёт через WebSocket-соединения к дата-центрам Telegram
- 🔒 **Без сторонних серверов** — всё работает на вашем устройстве, шифрование сохраняется
- 🪶 **Трей-приложение** для Windows, macOS и Linux с GUI-настройками
- 🔄 **Автоконфигурация** — один клик «Открыть в Telegram»
- 🛡 **Fake TLS маскировка** для блокирующих провайдеров
- ☁️ **Cloudflare-обход** — поддержка CF Proxy и Cloudflare Worker для самых сложных сетей
- 📦 **Готовые сборки** — Windows (включая ARM64 и Windows 7), macOS (universal), Linux (.deb/.rpm)

## 🚀 Быстрый старт

- **[Windows](./RU/README.windows.md)**
- **[macOS](./RU/README.macos.md)**
- **[Linux](./RU/README.linux.md)**
- **[Docker](./RU/README.docker.md)**

### Windows

Перейдите на [страницу релизов](https://github.com/SpherePrime/PrimeProxy/releases) и скачайте:

- `PrimeProxy_windows.exe` (Windows 10+ x64)
- `PrimeProxy_windows_arm64.exe` (Windows 10+ ARM64)
- `PrimeProxy_windows_7_64bit.exe` (Windows 7 x64)
- `PrimeProxy_windows_7_32bit.exe` (Windows 7 x32)

При первом запуске откроется окно с инструкцией по подключению Telegram Desktop. **Приложение сворачивается в системный трей.**

## 📖 Документация

- [Настройка Cloudflare Worker'а (бесплатный аналог CF-прокси)](./RU/CfWorker.md)
- [Настройка Cloudflare-домена (CF-прокси)](./RU/CfProxy.md)
- [Тестовое окружение Telegram (тестовые DC)](./RU/TestDc.md)
- [Fake TLS + upstream в Nginx](./RU/FakeTlsNginx.md)
- [Файлы конфигурации Tray-приложения](./RU/TrayConfig.md)
- [Установка из исходников](./RU/BuildFromSource.md)
- [Руководство для контрибьюторов](./CONTRIBUTING.md)

## 🖥 Меню трея

- **Открыть в Telegram** — автоматически настроить прокси через ссылку `tg://proxy`
- **Скопировать ссылку** — скопировать ссылку для подключения
- **Перезапустить прокси** — перезапуск без выхода из приложения
- **Настройки...** — GUI-редактор конфигурации (версия, тема, язык, опциональная проверка обновлений с GitHub)
- **Открыть логи** — открыть файл логов
- **Выход** — остановить прокси и закрыть приложение

## 🔧 Настройка Telegram Desktop

**Автоматическая настройка**

Щелкните правой кнопкой мыши по значку в трее и выберите **«Открыть в Telegram»**.

Если не сработало (Telegram не открылся с подключением), выполните шаги ниже:

1. Щелкните правой кнопкой мыши по значку в трее и выберите **«Скопировать ссылку»**
2. Отправьте ссылку в «Избранное» в Telegram и нажмите по ней левой кнопкой мыши
3. Подключитесь

**Ручная настройка**

1. Telegram → **Настройки** → **Продвинутые настройки** → **Тип подключения** → **Прокси**
2. Добавьте прокси:
   - **Тип:** MTProto
   - **Сервер:** `127.0.0.1` (или переопределенный вами)
   - **Порт:** `1443` (или переопределенный вами)
   - **Secret:** из настроек или логов

## ⚙️ Как это работает

```
Telegram Desktop → MTProto Proxy (127.0.0.1:1443) → WebSocket → Telegram DC
```

1. Приложение поднимает MTProto прокси на `127.0.0.1:1443`
2. Перехватывает подключения к IP-адресам Telegram
3. Извлекает DC ID из MTProto obfuscation init-пакета
4. Устанавливает WebSocket-соединение (TLS) к соответствующему DC через домены Telegram
5. Если WS недоступен (302 redirect) — автоматически переключается на CfProxy / прямое TCP-соединение

> [!IMPORTANT] 
> ### Не грузит фото/видео?
> **Удалите в настройках прокси в DC → IP всё, кроме `4:149.154.167.220`**  
> **Если это не помогло, полностью очистите это поле**  
> Подобная проблема встречается на аккаунтах без Premium  
> Если это не помогло, настройте собственный домен по инструкции: [CfProxy.md](./RU/CfProxy.md)

## 🛠 Автоматическая сборка

Проект содержит спецификацию PyInstaller ([`packaging/primeproxy.spec`](../packaging/primeproxy.spec)) и GitHub Actions workflow ([`.github/workflows/build.yml`](../.github/workflows/build.yml)) для автоматической сборки.

Минимально поддерживаемые версии ОС для текущих бинарных сборок:

- Windows 10+ x64 для `PrimeProxy_windows.exe`
- Windows 10+ ARM64 для `PrimeProxy_windows_arm64.exe`
- Windows 7 (x64) для `PrimeProxy_windows_7_64bit.exe`
- Windows 7 (x32) для `PrimeProxy_windows_7_32bit.exe`
- Intel macOS 10.15+
- Apple Silicon macOS 11.0+
- Linux x86_64 (требуется AppIndicator для системного трея)

## 📄 Лицензия

[Business Source License 1.1](../LICENSE) — приложение бесплатно, код только для изучения; любое использование кода в production — только по коммерческой лицензии.