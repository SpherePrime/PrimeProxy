//! Порт `src/utils/probe_gate.py` — шлюз проб: единственная дверь, через
//! которую проверки сети уходят в сеть.
//!
//! Оборудование провайдера (ТСПУ) видит не только отдельные пакеты, но и
//! узор: пачку соединений к разным адресам в одну секунду, одинаковый
//! всплеск при каждом запуске программы, обход соседних подсетей. Поэтому
//! каждая проверка, прежде чем стучаться в сеть, спрашивает шлюз — а не
//! решает сама, когда и сколько.
//!
//! Правила (одни на всю программу):
//!
//! 1. **По кнопке** ([`Why::User`]). Человек сам захотел проверить —
//!    BlockCheck, подбор стратегий, «Проверка домена», проверка
//!    DNS-серверов, переключение сервиса в hosts. Такая проверка берёт
//!    пропуск на весь прогон ([`begin_user_run`]); пока пропуск у
//!    кого-то есть, фоновые проверки не идут, чтобы их соединения не
//!    смешивались с чужим прогоном.
//! 2. **По расписанию** ([`Why::Schedule`]). Без повода трогается только
//!    то, чем человек пользуется сейчас (у hosts — первый записанный
//!    адрес имени), и не чаще интервала своего вида. Время прошлой
//!    плановой проверки хранится в настройках, поэтому перезапуск
//!    программы не повторяет её. Фоновая проверка идёт одна за раз
//!    ([`try_background`]).
//! 3. **По сигналу беды** ([`Why::Signal`]). Плановая проверка увидела,
//!    что текущее не работает, — только тогда разрешён поиск замены
//!    ([`may_search`]): свежие адреса у DNS, запас прошлых находок,
//!    обход соседних адресов.
//!
//! Рядом живёт `core.runtime.long_tasks` — отметка «не перезапускать
//! программу ради обновления». Это другое правило: пропуск здесь — про
//! сеть, отметка там — про перезапуск.
//!
//! Отличия от python: `threading.Lock` заменён на `Mutex`,
//! `contextmanager user_run` — страж [`UserRunGuard`] с `Drop`, хранилище
//! времени прошлой плановой проверки приходит замыканиями (python по
//! умолчанию звал `settings.store.get/set_probe_gate_last_run`; они
//! появятся в primecore-settings — пока у вызывающего).

use std::collections::HashMap;
use std::sync::Mutex;

/// python `Why` — повод проверки: от него зависит, что ей разрешено.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Человек нажал кнопку или переключил сервис и ждёт результата.
    User,
    /// Плановая проверка без повода.
    Schedule,
    /// Плановая проверка увидела беду: текущее не отвечает.
    Signal,
}

impl Why {
    /// python-значение перечисления.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Schedule => "schedule",
            Self::Signal => "signal",
        }
    }
}

/// python `BackgroundKind` — вид фоновой проверки.
///
/// `key` — имя в настройках, `min_interval_s` — не чаще.
#[derive(Debug, Clone, PartialEq)]
pub struct BackgroundKind {
    pub key: String,
    pub min_interval_s: f64,
}

impl BackgroundKind {
    /// python-конструктор `BackgroundKind(key, min_interval_s)`.
    #[must_use]
    pub fn new(key: &str, min_interval_s: f64) -> Self {
        Self {
            key: key.to_string(),
            min_interval_s,
        }
    }
}

/// python `HOSTS_ADDRESSES` — адреса включённых сервисов hosts
/// (hosts.address_engine): программа живёт в трее сутками, а адрес может
/// перестать отвечать в любой день.
#[must_use]
pub fn hosts_addresses() -> BackgroundKind {
    BackgroundKind::new("hosts_addresses", 6.0 * 3600.0)
}

/// python `may_search` — можно ли искать замену (DNS, запас, соседние
/// адреса), а не только проверить текущее.
#[must_use]
pub fn may_search(why: Why) -> bool {
    matches!(why, Why::User | Why::Signal)
}

// --- Пропуск на прогон по кнопке ------------------------------------------------

/// python `_ids`/`_user_runs` под `_LOCK`: счётчик пропусков и активные
/// прогоны по кнопке.
static USER_RUNS: std::sync::LazyLock<Mutex<(u64, HashMap<u64, String>)>> =
    std::sync::LazyLock::new(|| Mutex::new((0, HashMap::new())));

/// python `begin_user_run` — начался прогон по кнопке `name`; возвращает
/// номер пропуска для [`end_user_run`].
///
/// Вместо пары «номер + ручной конец» есть страж [`UserRunGuard`].
pub fn begin_user_run(name: &str) -> u64 {
    let mut state = USER_RUNS.lock().expect("замок прогонов по кнопке");
    state.0 += 1;
    let token = state.0;
    state.1.insert(token, name.to_string());
    token
}

/// python `end_user_run` — прогон закончился; повторный вызов безвреден.
pub fn end_user_run(token: u64) {
    USER_RUNS
        .lock()
        .expect("замок прогонов по кнопке")
        .1
        .remove(&token);
}

/// python `user_run_active` — идёт ли сейчас хоть один прогон по кнопке.
#[must_use]
pub fn user_run_active() -> bool {
    !USER_RUNS
        .lock()
        .expect("замок прогонов по кнопке")
        .1
        .is_empty()
}

/// python `user_run` (contextmanager) — прогон по кнопке одним стражем:
/// пропуск снимается при выходе из области видимости.
#[must_use]
pub fn begin_user_run_guard(name: &str) -> UserRun {
    let token = begin_user_run(name);
    UserRun { token }
}

/// Страж прогона по кнопке (python `user_run`): снимает пропуск в `Drop`.
pub struct UserRun {
    token: u64,
}

impl Drop for UserRun {
    fn drop(&mut self) {
        end_user_run(self.token);
    }
}

// --- Фоновые проверки -----------------------------------------------------------

/// python `_BACKGROUND` — одна фоновая проверка за раз: две сразу — это
/// уже пачка соединений.
static BACKGROUND_TAKEN: Mutex<bool> = Mutex::new(false);

/// python `BackgroundPermit` — разрешение на одну фоновую проверку.
///
/// Освобождается через [`BackgroundPermit::release`] или автоматически
/// при выпадении из области видимости (`Drop` вместо `__exit__`).
pub struct BackgroundPermit {
    /// Вид проверки.
    pub kind: BackgroundKind,
    /// Повод — у фоновых всегда [`Why::Schedule`].
    pub why: Why,
    released: bool,
}

impl BackgroundPermit {
    /// python `release` — вернуть разрешение; повторный вызов безвреден.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.released = true;
            let mut taken = BACKGROUND_TAKEN.lock().expect("замок фоновых проверок");
            *taken = false;
        }
    }
}

impl Drop for BackgroundPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// python `try_background` — разрешение на плановую проверку вида `kind`
/// или `None` — сейчас нельзя.
///
/// Нельзя, когда идёт прогон по кнопке, когда уже идёт другая фоновая
/// проверка и когда прошлая плановая была меньше `min_interval_s` назад.
/// Время проверки записывается сразу при выдаче разрешения: даже если
/// она оборвётся, перезапуск программы не устроит её заново (python при
/// ошибке записи выпускал разрешение и поднимал исключение — здесь
/// ошибка записи приходит значением).
pub fn try_background(
    kind: &BackgroundKind,
    clock: &dyn Fn() -> f64,
    last_run: &dyn Fn(&str) -> f64,
    store_last_run: &dyn Fn(&str, f64) -> Result<(), String>,
) -> Result<Option<BackgroundPermit>, String> {
    if user_run_active() {
        return Ok(None);
    }
    let now = clock();
    let previous = last_run(&kind.key);
    if 0.0 < now - previous && now - previous < kind.min_interval_s {
        return Ok(None);
    }
    {
        let mut taken = BACKGROUND_TAKEN.lock().expect("замок фоновых проверок");
        if *taken {
            return Ok(None);
        }
        *taken = true;
    }
    if user_run_active() {
        release_background();
        return Ok(None);
    }
    if let Err(error) = store_last_run(&kind.key, now) {
        release_background();
        return Err(error);
    }
    Ok(Some(BackgroundPermit {
        kind: kind.clone(),
        why: Why::Schedule,
        released: false,
    }))
}

fn release_background() {
    let mut taken = BACKGROUND_TAKEN.lock().expect("замок фоновых проверок");
    *taken = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Сериализация тестов: шлюз — глобальное состояние, тесты по нему
    /// гоняются строго по одному.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// python `_Clock` — часы и хранилище времени прошлой проверки.
    #[derive(Clone)]
    struct Clock {
        now: f64,
        stored: BTreeMap<String, f64>,
    }

    impl Clock {
        fn new() -> Self {
            Self {
                now: 1_000_000.0,
                stored: BTreeMap::new(),
            }
        }
    }

    static KIND_LAZY: std::sync::LazyLock<BackgroundKind> =
        std::sync::LazyLock::new(|| BackgroundKind::new("test_kind", 6.0 * 3600.0));
    fn kind() -> &'static BackgroundKind {
        &KIND_LAZY
    }

    #[test]
    fn search_only_by_button_or_trouble() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert!(may_search(Why::User));
        assert!(may_search(Why::Signal));
        assert!(!may_search(Why::Schedule));
    }

    #[test]
    fn scheduled_check_runs_once_per_interval_even_across_restarts() {
        let _guard = TEST_LOCK.lock().unwrap();
        let clock = std::sync::Arc::new(std::sync::Mutex::new(Clock::new()));
        let permit = ask_with_shared(&clock).unwrap();
        let permit = permit.unwrap();
        permit.release();
        // Время записано сразу: перезапуск через час (то же хранилище)
        // проверку не повторяет.
        assert_eq!(
            clock.lock().unwrap().stored.get("test_kind").copied(),
            Some(1_000_000.0)
        );
        clock.lock().unwrap().now += 3600.0;
        assert!(ask_with_shared(&clock).unwrap().is_none());
        clock.lock().unwrap().now += 6.0 * 3600.0;
        let again = ask_with_shared(&clock).unwrap().unwrap();
        again.release();
    }

    /// python `clock.ask()` с общим хранилищем (Arc<Mutex>).
    fn ask_with_shared(
        clock: &std::sync::Arc<std::sync::Mutex<Clock>>,
    ) -> Result<Option<BackgroundPermit>, String> {
        let snapshot = clock.lock().unwrap().clone();
        let store_clock = std::sync::Arc::clone(clock);
        try_background(
            &kind(),
            &|| snapshot.now,
            &move |key| snapshot.stored.get(key).copied().unwrap_or(0.0),
            &move |key, when| {
                store_clock
                    .lock()
                    .unwrap()
                    .stored
                    .insert(key.to_string(), when);
                Ok(())
            },
        )
    }

    #[test]
    fn no_background_check_while_a_button_run_is_going() {
        let _guard = TEST_LOCK.lock().unwrap();
        let clock = Clock::new();
        let ask = |clock: &Clock| {
            try_background(
                &kind(),
                &|| clock.now,
                &|key| clock.stored.get(key).copied().unwrap_or(0.0),
                &|_key, _when| Ok(()),
            )
            .unwrap()
        };
        let run = begin_user_run_guard("blockcheck");
        assert!(user_run_active());
        assert!(ask(&clock).is_none());
        drop(run);
        assert!(!user_run_active());
        // Время не записано: проверка не выдавалась.
        assert!(clock.stored.is_empty());
        let permit = ask(&clock).unwrap();
        permit.release();
    }

    #[test]
    fn only_one_background_check_at_a_time() {
        let _guard = TEST_LOCK.lock().unwrap();
        let clock = Clock::new();
        let ask = |clock: &Clock| {
            try_background(
                &kind(),
                &|| clock.now,
                &|key| clock.stored.get(key).copied().unwrap_or(0.0),
                &|_key, _when| Ok(()),
            )
            .unwrap()
        };
        let held = ask(&clock).unwrap();
        assert!(ask(&clock).is_none());
        held.release();
        let later = ask(&clock).unwrap();
        later.release();
    }

    #[test]
    fn interval_is_checked_from_stored_time() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Прошлая проверка «в будущем» (сдвиг часов) не блокирует: python
        // требует 0 < now - previous.
        let clock = Clock::new();
        let ask = |clock: &Clock| {
            try_background(
                &kind(),
                &|| clock.now,
                &|key| clock.stored.get(key).copied().unwrap_or(0.0),
                &|_key, _when| Ok(()),
            )
            .unwrap()
        };
        let mut future = Clock::new();
        future
            .stored
            .insert("test_kind".to_string(), future.now + 10_000.0);
        assert!(ask(&future).is_some());
        // Ровно на границе интервала — уже можно.
        let mut boundary = Clock::new();
        boundary.stored.insert(
            "test_kind".to_string(),
            boundary.now - kind().min_interval_s,
        );
        assert!(ask(&boundary).is_some());
        let _ = clock;
    }

    #[test]
    fn nested_and_parallel_button_runs_are_counted() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (started_send, started_recv) = std::sync::mpsc::channel::<()>();
        let (finish_send, finish_recv) = std::sync::mpsc::channel::<()>();

        let worker = std::thread::spawn(move || {
            let run = begin_user_run_guard("scan");
            started_send.send(()).unwrap();
            // python: finish.wait(2) — ждём сигнала не дольше 2 с.
            let _ = finish_recv.recv_timeout(std::time::Duration::from_secs(2));
            drop(run);
        });
        started_recv
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        {
            let nested = begin_user_run_guard("scan");
            assert!(user_run_active());
            drop(nested);
        }
        // Параллельный прогон ещё жив — активен.
        assert!(user_run_active());
        finish_send.send(()).unwrap();
        worker.join().unwrap();
        assert!(!user_run_active());
    }

    #[test]
    fn store_failure_releases_the_permit() {
        let _guard = TEST_LOCK.lock().unwrap();
        let clock = Clock::new();
        let result = try_background(&kind(), &|| clock.now, &|_key| 0.0, &|_key, _when| {
            Err("база недоступна".to_string())
        });
        // Ошибка записи — наверх; разрешение отпущено: следующий вызов
        // с исправленным хранилищем succeeds.
        assert!(result.is_err());
        let ok =
            try_background(&kind(), &|| clock.now, &|_key| 0.0, &|_key, _when| Ok(())).unwrap();
        assert!(ok.is_some());
        ok.unwrap().release();
    }
}
