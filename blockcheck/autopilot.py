"""Автопилот «Обход Zapret»: самостоятельная проверка сайтов, подбор стратегии
и запуск winws с авто-подобранным профилем.

Модель: фоновый поток + защищённое состояние (по образцу blockcheck service).

Сценарий ``start()``:
  1) сканирование: встроенные ``HTTPS_TARGETS`` + домены hosts-каталога
     (``hosts_catalog.sqlite3``) + пользовательский список, контрольные хосты
     через ``blockcheck.service.run_single_domain_check``;
  2) планирование: ``extract_symptoms(report)`` -> ``rank_recommendations``
     (топ стратегий);
  3) автонастройка DNS: при обнаружении подмены — автоматическая смена
     DNS на надёжный провайдер (Cloudflare/Google/Quad9);
  4) сбор составных стратегий: для каждого типа симптома подбирается лучшая
     стратегия, все применяются к профилю (circular-секции не ломаются);
  5) применение: на базе рекомендуемого профиля применяются составные
     стратегии, профиль ``auto`` (с бэкапом) сохраняется через
     ``winws.profiles``;
  6) запуск winws (переиспользуем runner);
  7) мониторинг: при внезапном завершении процесса перебираем следующую
     комбинацию стратегий до ``max_attempts`` попыток.

Все сообщения журнала пишутся напрямую (русский), статусы/фазы — машинные
ключи, которые фронтенд локализует.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("swift-autopilot")

# Имя пользовательского профиля, в который пишет автопилот.
DEFAULT_PROFILE = "auto"
MAX_ATTEMPTS = 4
MONITOR_POLL_SECONDS = 2.0
SCAN_DEADLINE_SECONDS = 600.0

_IDLE: Dict[str, Any] = {
    "status": "idle",
    "phase": "idle",
    "message": "",
    "progress": {"tested": 0, "total": 0, "blocked": 0},
    "symptoms": [],
    "recommendations": [],
    "chosen": None,
    "attempt": 0,
    "max_attempts": MAX_ATTEMPTS,
    "profile": None,
    "mode": None,
    "last_error": "",
    "started_at": "",
    "engine_ok": False,
    "journal": [],
    "scan_sources": {},
}

# Фазы, в которых поток живёт (нельзя запускать повторно, нужен stop).
_ACTIVE = frozenset({"scanning", "planning", "dns_repair", "applying", "starting", "monitoring"})

_lock = threading.RLock()
_thread: Optional[threading.Thread] = None
_cancel = threading.Event()
_state: Dict[str, Any] = dict(_IDLE)
_backed_up: Dict[str, bool] = {}


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _to_plain(obj: Any) -> Any:
    """Плоский JSON-совместимый снимок дерева BlockCheck (как в ui/api)."""
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj):
        return {field_.name: _to_plain(getattr(obj, field_.name)) for field_ in fields(obj)}
    if isinstance(obj, dict):
        return {str(key): _to_plain(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_to_plain(value) for value in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _journal(kind: str, text: str) -> None:
    with _lock:
        _state["journal"].append({"ts": _ts(), "kind": kind, "text": str(text)})
        if len(_state["journal"]) > 800:
            del _state["journal"][:-800]


def _engine() -> Dict[str, Any]:
    from winws import paths as wp
    return wp.find_engine()


def _store_cfg() -> Dict[str, Any]:
    from config import get_store as _store
    return _store().get("zapret") or {}


def _auto_cfg(default: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _store_cfg().get("auto") or {}
    out = dict(default)
    out.update({k: v for k, v in cfg.items() if v is not None})
    return out


# ---------------------------------------------------------------------------
# Планирование стратегий
# ---------------------------------------------------------------------------

def _plan(report_plain: Dict[str, Any]) -> Dict[str, Any]:
    """Симптомы + топ стратегий по отчёту BlockCheck."""
    from blockcheck.orchestra import extract_symptoms, orchestra_recommend
    try:
        rec = orchestra_recommend(symptoms_text="", report=report_plain)
    except Exception as exc:  # noqa: BLE001
        log.warning("orchestra recommend failed", exc_info=True)
        return {"ok": False, "symptoms": [], "recommendations": [], "error": str(exc)}
    if not rec or not rec.get("ok"):
        return {"ok": False, "symptoms": [], "recommendations": [], "error": (rec or {}).get("error", "")}
    return {
        "ok": True,
        "symptoms": list(rec.get("symptoms") or []),
        "recommendations": list(rec.get("recommendations") or []),
    }


def _collect_composite_strategies(symptoms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Собирает лучшие стратегии для каждого типа симптома (без дубликатов)."""
    from blockcheck.orchestra.strategy_selector import SYMPTOM_TO_STRATEGY, find_strategy_by_id
    seen: set = set()
    strategies: List[Dict[str, Any]] = []
    for symptom in symptoms:
        key = symptom.get("key", "")
        for sid in SYMPTOM_TO_STRATEGY.get(key, []):
            if sid in seen or sid == "gs_pass":
                continue
            s = find_strategy_by_id(sid)
            if s:
                seen.add(sid)
                strategies.append(s)
                break
    return strategies


def _auto_dns_repair(symptoms: List[Dict[str, Any]]) -> bool:
    """Автоматическая настройка DNS при обнаружении подмены."""
    keys = {s.get("key") for s in symptoms}
    if "dns_poisoning" not in keys:
        return False
    try:
        from dns import force_dns, flush_dns_cache
        from dns.providers import get_provider
        for provider_id in ("cloudflare", "google_dns", "quad9"):
            provider = get_provider(provider_id)
            if not provider:
                continue
            servers = provider.get("ipv4", [])
            if not servers:
                continue
            result = force_dns(servers)
            if result.get("ok"):
                flush_dns_cache()
                name = provider.get("name", provider_id)
                _journal("ok", f"DNS исправлен: {name} ({', '.join(servers)})")
                return True
        _journal("warn", "Не удалось автоматически настроить DNS — ни один провайдер не отвечает.")
        return False
    except Exception as exc:
        _journal("warn", f"Ошибка автонастройки DNS: {exc!r}")
        return False


def _apply_composite_strategies(
    base_text: str,
    strategies: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Применяет несколько стратегий к профилю (каждая добавляет лейны в circular)."""
    content = base_text
    applied: List[str] = []
    for strategy in strategies:
        result = _profile_with_strategy(content, strategy)
        if result.get("ok"):
            content = result["content"]
            name = strategy.get("name", strategy.get("id", ""))
            if name:
                applied.append(name)
    return {"ok": True, "content": content, "applied": applied}


# ---------------------------------------------------------------------------
# Применение стратегии к профилю + запись + запуск
# ---------------------------------------------------------------------------

def _recommended_text() -> Optional[str]:
    """Текст рекомендуемого (circular) профиля из ресурсов приложения."""
    from winws import profiles as pfp
    try:
        pfp.ensure_recommended()
        plist = pfp.profile_list()
        name = plist.get("recommended") if isinstance(plist, dict) else None
        if not name:
            return None
        read = pfp.profile_read(name)
        if read.get("ok"):
            return read["content"]
    except Exception:  # noqa: BLE001
        return None
    return None


def _profile_with_strategy(base_text: str, strategy: Dict[str, Any]) -> Dict[str, Any]:
    """Применяет стратегию к базовому тексту профиля; при no_change возвращает базовый."""
    from blockcheck.orchestra import apply_strategy_to_profile
    applied = apply_strategy_to_profile(base_text, strategy)
    if applied.get("ok"):
        return {"ok": True, "content": applied["content"]}
    if applied.get("error") == "no_change":
        return {"ok": True, "content": base_text}
    return {"ok": False, "error": applied.get("error", "apply_failed")}


def _write_profile(name: str, content: str) -> Dict[str, Any]:
    from blockcheck.orchestra import backup_profile
    from winws import profiles as pfp
    try:
        existing = pfp.profile_read(name)
        if existing.get("ok") and not _backed_up.get(name):
            backup_profile(name)
            _backed_up[name] = True
    except Exception:  # noqa: BLE001
        pass
    return pfp.profile_write(name, content)


def _compute_mode() -> str:
    from winws.profiles import engine_mode_for
    cfg = _store_cfg()
    return engine_mode_for("user", cfg.get("mode", "auto"))


def _start_winws(name: str) -> Dict[str, Any]:
    """Запускает winws с пользовательским профилем (аналог api.start_dpi)."""
    from winws import paths as wp
    from winws import profiles as pfp
    from winws import runner

    res = pfp.resolve_profile("user", name)
    if not res.get("ok"):
        return res
    mode = _compute_mode()
    mode = wp.preferred_mode(mode) or (mode if mode in ("winws1", "winws2") else None)
    exe_path = wp.resolve_mode_exe(mode or "auto")
    if not exe_path:
        return {"ok": False, "error": "engine_missing",
                "detail": "Поместите winws.exe или winws2.exe в папку exe/ рядом с приложением"}
    work_dir = wp.engine_dir()
    result = runner.start(mode=mode or "winws2", exe_path=exe_path, work_dir=str(work_dir),
                          text=res.get("text", ""), label=res.get("file", name))
    if result.get("ok"):
        from config import get_store as _store
        _store().set_section("zapret", {
            "enabled": True,
            "profile_group": "user",
            "profile": name,
            "mode": mode or "auto",
        })
        with _lock:
            _state["mode"] = mode or "auto"
            _state["profile"] = name
    return result


# ---------------------------------------------------------------------------
# Основной поток
# ---------------------------------------------------------------------------

def _run() -> None:
    from blockcheck.service import run_single_domain_check
    from blockcheck.targets import (
        get_default_https_targets_domains,
        get_catalog_target_domains,
        load_user_domains,
    )
    from blockcheck.orchestra import find_strategy_by_id

    with _lock:
        _state.update({
            "status": "scanning",
            "phase": "scanning",
            "message": "Сканирование сайтов...",
            "last_error": "",
            "recommendations": [],
            "chosen": None,
            "attempt": 0,
        })
        _state["started_at"] = _ts()

    auto_cfg = _auto_cfg({"profile": DEFAULT_PROFILE, "max_attempts": MAX_ATTEMPTS})
    profile_name = str(auto_cfg.get("profile") or DEFAULT_PROFILE)
    max_attempts = max(1, int(auto_cfg.get("max_attempts") or MAX_ATTEMPTS))
    try:
        catalog_limit = int(auto_cfg.get("catalog_limit") or 250)
    except (TypeError, ValueError):
        catalog_limit = 250
    catalog_limit = max(0, catalog_limit)
    with _lock:
        _state["max_attempts"] = max_attempts

    _journal("info", "Автопилот запущен. Сканирование сайтов...")

    # 1) Сканирование: встроенный список + hosts-каталог + пользовательские домены
    builtin_domains = get_default_https_targets_domains()
    catalog_domains = get_catalog_target_domains(limit=catalog_limit)
    user_domains = load_user_domains()
    extras = list(dict.fromkeys(builtin_domains + catalog_domains + user_domains))
    primary = extras[0] if extras else "www.google.com"
    with _lock:
        _state["scan_sources"] = {
            "builtin": len(builtin_domains),
            "catalog": len(catalog_domains),
            "user": len(user_domains),
        }
    _journal(
        "info",
        f"Планирую проверку: {len(extras)} сайтов "
        f"({len(builtin_domains)} встроенных, {len(catalog_domains)} из каталога, {len(user_domains)} своих).",
    )
    lines: List[str] = []

    def _on_log(message: Any) -> None:
        lines.append(str(message))
        if len(lines) > 600:
            del lines[:100]
        with _lock:
            _state["message"] = str(message)

    try:
        report = run_single_domain_check(
            primary,
            log=_on_log,
            is_cancelled=_cancel.is_set,
            extra_domains=extras,
            deadline_seconds=SCAN_DEADLINE_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001
        _journal("err", f"Ошибка сканирования: {exc!r}")
        _finish_error("scan_failed", str(exc))
        return

    if _cancel.is_set():
        _journal("warn", "Автопилот остановлен во время сканирования.")
        _finish_stopped()
        return

    report_plain = _to_plain(report)
    targets = report_plain.get("targets") or []
    total = len(targets)
    blocked = sum(1 for t in targets if (t or {}).get("outcome") == "blocked")
    with _lock:
        _state["progress"] = {"tested": total, "total": total, "blocked": blocked}

    # 2) Планирование
    _set_phase("planning", "Подбор стратегии по симптомам...")
    plan = _plan(report_plain)
    if not plan.get("ok"):
        _journal("err", f"Не удалось подобрать стратегию: {plan.get('error')}")
        _finish_error("plan_failed", plan.get("error") or "")
        return

    recs = plan["recommendations"]
    with _lock:
        _state["symptoms"] = plan["symptoms"]
        _state["recommendations"] = recs

    if recs:
        syms = ', '.join(s.get('label') or s.get('key') for s in plan['symptoms']) or 'не определены'
        _journal("ok", f"Обнаружено: {syms}.")
        _journal("ok", f"Лучшая стратегия: {recs[0].get('name') or recs[0].get('strategy')} (из {len(recs)}).")
    else:
        _journal("warn", "Симптомы не определены — использую рекомендуемый профиль без правок.")

    # 3) Автонастройка DNS при обнаружении подмены
    _set_phase("dns_repair", "Настройка DNS...")
    _auto_dns_repair(plan["symptoms"])

    # 4) Сбор составных стратегий
    composite = _collect_composite_strategies(plan["symptoms"])
    if composite:
        _journal("ok", f"Подобрано {len(composite)} стратегий для обхода всех блокировок.")

    # 5-7) Применение + запуск + мониторинг (перебор стратегий)
    attempt_index = 0
    while attempt_index < max_attempts:
        if _cancel.is_set():
            _finish_stopped()
            return

        with _lock:
            _state["attempt"] = attempt_index + 1
            _state["phase"] = "applying"
            _state["status"] = "applying"
            _state["message"] = "Применяю стратегию к профилю..."

        base_text = _recommended_text()
        if not base_text:
            _journal("err", "Не найден рекомендуемый профиль для копирования.")
            _finish_error("no_base_profile", "recommended_missing")
            return

        content = base_text
        subset = composite[attempt_index:] if attempt_index < len(composite) else []
        if subset:
            result = _apply_composite_strategies(content, subset)
            if result.get("ok"):
                content = result["content"]
                applied_names = result.get("applied", [])
                with _lock:
                    _state["chosen"] = {
                        "strategy": "composite",
                        "name": ", ".join(applied_names),
                        "attempt": attempt_index + 1,
                    }
                _journal("ok", f"Применено {len(applied_names)} стратегий (попытка {attempt_index + 1})")
            else:
                _journal("warn", f"Ошибка применения стратегий: {result.get('error')}")
        else:
            _journal("warn", f"Все стратегии испробованы, используются базовые настройки (попытка {attempt_index + 1})")

        # пишем профиль
        written = _write_profile(profile_name, content)
        if not written.get("ok"):
            _journal("err", f"Не удалось сохранить профиль {profile_name}: {written.get('error')}")
            _finish_error("write_failed", str(written.get("error")))
            return
        _journal("ok", f"Профиль {profile_name} сохранён ({len(content.splitlines())} параметров).")

        # запуск
        _set_phase("starting", "Запуск winws...")
        started = _start_winws(profile_name)
        if not started.get("ok"):
            error_key = started.get("error", "")
            _journal("err", f"Не удалось запустить winws: {started.get('detail') or error_key}")
            # Фатальные ошибки окружения: повтор со стратегиями не поможет.
            if error_key in ("engine_missing", "needs_admin", "validate", "missing_files"):
                _finish_error(error_key or "start_failed", started.get("detail", error_key))
                return
            attempt_index += 1
            continue

        _journal("ok", f"winws запущен с профилем {profile_name}. Начинаю мониторинг...")
        _set_phase("monitoring", "winws работает. Наблюдаю за процессом...")

        monitor_ok = _monitor(profile_name)
        if monitor_ok:
            _finish_stopped()  # остановлен пользователем
            return

        # процесс упал — перебираем следующую стратегию
        next_attempt = attempt_index + 2
        _journal("warn", f"winws завершился. Повторная попытка {next_attempt} из {max_attempts}...")
        attempt_index = next_attempt - 1

    _finish_error("attempts_exhausted", f"Испробованы все стратегии ({max_attempts}). winws не запустился стабильно.")


def _monitor(profile_name: str) -> bool:
    """Следит за winws. Возвращает True, если остановлено пользователем."""
    from winws import runner
    grace = 0
    while not _cancel.is_set():
        time.sleep(MONITOR_POLL_SECONDS)
        st = runner.status()
        state_ = st.get("state")
        if state_ == "running":
            grace = 0
            continue
        if state_ in (None, "starting"):
            grace += 1
            if grace <= 4:
                continue
        error = st.get("last_error") or (f"exit_{st.get('exit_code')}" if st.get("exit_code") is not None else "")
        with _lock:
            _state["last_error"] = error
        return False
    return True


# ---------------------------------------------------------------------------
# Завершение
# ---------------------------------------------------------------------------

def _set_phase(phase: str, message: str) -> None:
    with _lock:
        _state.update({"phase": phase, "status": phase, "message": message})


def _finish_error(error: str, detail: str = "") -> None:
    with _lock:
        _state.update({
            "status": "error",
            "phase": "error",
            "last_error": error,
            "message": detail or error,
            "chosen": _state.get("chosen"),
            "mode": None,
        })
    _journal("err", f"Автопилот завершился с ошибкой: {detail or error}")


def _finish_stopped() -> None:
    with _lock:
        _state.update({
            "status": "stopped",
            "phase": "stopped",
            "message": "Автопилот остановлен.",
            "mode": None,
            "profile": None,
            "chosen": None,
            "progress": {"tested": 0, "total": 0, "blocked": 0},
            "symptoms": [],
            "recommendations": [],
            "last_error": "",
        })
    _journal("warn", "Автопилот остановлен.")


# ---------------------------------------------------------------------------
# Публичный API
# ---------------------------------------------------------------------------

def status() -> Dict[str, Any]:
    """JSON-совместимый снимок состояния автопилота."""
    with _lock:
        snap = json_safe(_state)
    snap["active"] = snap["status"] in _ACTIVE
    return snap


def journal(limit: int = 250) -> Dict[str, Any]:
    with _lock:
        rows = list(_state["journal"][-max(1, int(limit)):])
    return {"ok": True, "lines": rows}


def start() -> Dict[str, Any]:
    """Запускает автопилот в фоновом потоке."""
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return {"ok": False, "error": "already_running", "detail": "Автопилот уже работает."}

    probe = _engine()
    if not probe.get("ok"):
        with _lock:
            _state.update({
                "status": "error",
                "phase": "error",
                "message": "Не найден движок - поместите winws.exe/winws2.exe в папку exe/ рядом с приложением.",
                "last_error": "engine_missing",
                "engine_ok": False,
            })
        return {"ok": False, "error": "engine_missing",
                "detail": "Поместите winws.exe или winws2.exe в папку exe/ рядом с приложением"}

    # winws с WinDivert требует прав администратора: без них скан бессмыслен.
    from autostart import is_admin
    if not is_admin():
        with _lock:
            _state.update({
                "status": "error",
                "phase": "error",
                "message": "Нужны права администратора (WinDivert). Запустите приложение от имени администратора.",
                "last_error": "needs_admin",
                "engine_ok": True,
            })
        return {"ok": False, "error": "needs_admin",
                "detail": "Нужны права администратора (WinDivert). Запустите приложение от имени администратора."}

    with _lock:
        _cancel.clear()
        _state.update(dict(_IDLE))
        _state["engine_ok"] = True
        _state["journal"] = []
        _backed_up.clear()

    _journal("info", "Запуск автопилота...")
    _thread = threading.Thread(target=_run, name="swift-autopilot", daemon=True)
    _thread.start()
    return {"ok": True, "detail": "started"}


def stop() -> Dict[str, Any]:
    """Останавливает автопилот и останавливает winws, если он был запущен им."""
    global _thread
    from winws import runner
    was_active = False
    owns_winws = False
    with _lock:
        _cancel.set()
        was_active = _state["status"] in _ACTIVE or (_thread is not None and _thread.is_alive())
        owns_winws = bool(_state.get("mode")) if was_active else False

    if owns_winws:
        runner.stop()
        _journal("warn", "winws остановлен автопилотом.")
    return {"ok": True, "detail": "stopped"}


def reset() -> Dict[str, Any]:
    """Сбрасывает состояние и журнал в idle."""
    with _lock:
        if _thread is not None and _thread.is_alive():
            return {"ok": False, "error": "already_running"}
        _state.clear()
        _state.update(dict(_IDLE))
    return {"ok": True, "detail": "reset"}


# ---------------------------------------------------------------------------
# Служебное
# ---------------------------------------------------------------------------

def json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


__all__ = ["journal", "reset", "start", "status", "stop"]