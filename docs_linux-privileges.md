# Привилегии Linux: sudo один раз при первом запуске

## Схема

1. **Первый запуск.** Electron обнаруживает, что привилегий нет
   (`needs_prompt` вернул `true`: нет `privilege.json` либо сессия
   старше 12 часов), и запускает повышение:
   - есть `pkexec` → `pkexec privd`;
   - нет → `sudo privd`.
   Пользователь вводит пароль **один раз**.
2. **Демон держит привилегии.** Запущенный от root процесс `privd`
   слушает unix-сокет (`PRIMECORE_PRIV_SOCK`, по умолчанию
   `/tmp/primecore-privd.sock`). Дальше sudo-таймстамп не нужен:
   пароль больше не спрашивается, пока жив демон.
3. **Последующие повышения.** Приложение шлёт запросы в сокет
   (клиент `connect_and_ping`) — без пароля. Пока протокол заготовка:
   на любую строку демон отвечает `{"ok": true}`.
4. **Истечение/перезагрузка.** Демон умер (перезагрузка) или прошло
   больше `SESSION_TTL_S = 12*3600` секунд с записи `granted_at` —
   `needs_prompt` снова возвращает `true`, и пользователь вводит
   пароль ещё раз (снова один).

Состояние хранится в `privilege.json` (файл состояния внутри каталога
состояния): `{"granted": bool, "granted_at_epoch_s": i64, "helper_path": str}`.

## Пример вызова

```bash
# 1. Первый запуск: повышение и старт демона (пароль один раз)
pkexec privd &          # или: sudo privd

# 2. Проверка, что сокет живой (пароль не нужен)
PRIMECORE_PRIV_SOCK=/tmp/primecore-privd.sock \
  cargo run -p primecore-privilege --example ping
# ping: ок — демон /tmp/primecore-privd.sock ответил {"ok": true}
```

Из Rust:

```rust
let state = primecore_privilege::load_state(&dir)?;      // Option<PrivilegeState>
let cmd = primecore_privilege::helper_command(|| which("pkexec").is_some());
if primecore_privilege::needs_prompt(state.as_ref(), now) {
    // запустить cmd[0] cmd[1], дождаться готовности демона,
    // сохранить PrivilegeState { granted: true, granted_at_epoch_s: now, .. }
}
primecore_privilege::client::connect_and_ping("/tmp/primecore-privd.sock")?;
```

## Заметки

- Крейт `primecore-privilege` Linux-only (unix-сокеты `std::os::unix::net`);
  на других платформах он в сборку не включается.
- Чистая логика (`PrivilegeState`, `load_state`/`save_state`,
  `is_valid`/`needs_prompt`, `helper_command`) покрыта тестами; проверка
  PATH для `pkexec` — замыкание-параметр, платформенный слой.
