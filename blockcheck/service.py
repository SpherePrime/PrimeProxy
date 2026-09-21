"""Одиночная проверка сайта — точка входа для веб-страницы «Проверка сайтов».

Для одного домена строится компактный список целей: контрольные хосты служат
опорной точкой прямо в списке, сам домен проверяется на фоне рабочей сети.
Отдельная цель TCP 16-20KB, DNS-integrity и STUN в таком прогоне не нужны —
это тесты, а не диагностика одного сайта.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from blockcheck.hosts import host_of
from blockcheck.models import BlockcheckReport
from blockcheck.runner import BlockcheckCallback, BlockcheckRunner, RunMode

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Нейтральные хосты контрольной группы: доступность всех трёх говорит о том,
# что сеть в целом работает и выводы по целевому домену достоверны.
CONTROL_HOSTS: tuple[str, ...] = (
    "google.com",
    "cloudflare.com",
    "yandex.ru",
)


# ---------------------------------------------------------------------------
# Список целей
# ---------------------------------------------------------------------------

def build_targets(
    domain: str,
    extra_domains: list[str] | None = None,
) -> list[dict]:
    """Контрольные хосты + целевой домен (и дополнительные, если заданы)."""
    target_domain = host_of(str(domain or "").strip())
    extras = extra_domains or []

    targets: list[dict] = []

    # Целевой домен идёт первым — он в заголовке результата.
    if target_domain:
        targets.append({"name": f"[U] {_display_name(target_domain)}", "value": f"https://{target_domain}"})

    seen: set[str] = {target_domain} if target_domain else set()
    for extra in extras:
        host = host_of(str(extra or "").strip())
        if not host or host in seen:
            continue
        seen.add(host)
        targets.append({"name": f"[E] {_display_name(host)}", "value": f"https://{host}"})

    for host in CONTROL_HOSTS:
        if host in seen:
            continue
        seen.add(host)
        targets.append({"name": f"[C] {_display_name(host)}", "value": f"https://{host}"})

    return targets


def _display_name(domain: str) -> str:
    if "." in domain:
        return domain.split(".")[0].capitalize()
    return domain


# ---------------------------------------------------------------------------
# Адаптер колбэков
# ---------------------------------------------------------------------------

class _HeadlessCallback:
    """Адаптирует пару (log, is_cancelled) к протоколу BlockcheckCallback.

    Прогресс и фазы сюда не нужны: веб-страница показывает только лог и статус.
    """

    def __init__(
        self,
        log: Callable[[str], None] | None = None,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self._log = log
        self._is_cancelled = is_cancelled

    # -- BlockcheckCallback protocol --
    def on_target_started(self, name: str, index: int, total: int) -> None:
        pass

    def on_test_result(self, result) -> None:
        pass

    def on_target_complete(self, result) -> None:
        pass

    def on_progress(self, current: int, total: int, message: str) -> None:
        self._emit(message)

    def on_phase_change(self, phase: str) -> None:
        self._emit(phase)

    def on_log(self, message: str) -> None:
        self._emit(message)

    def is_cancelled(self) -> bool:
        if callable(self._is_cancelled):
            try:
                return bool(self._is_cancelled())
            except Exception:  # noqa: BLE001 — отказавший колбэк = не отменено
                return False
        return False

    def _emit(self, message: object) -> None:
        if not callable(self._log):
            return
        try:
            self._log(str(message))
        except Exception:  # noqa: BLE001 — лог не должен ронять проверку
            pass


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def run_single_domain_check(
    domain: str,
    *,
    log: Callable[[str], None] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
    extra_domains: list[str] | None = None,
    timeout: int | None = None,
    deadline_seconds: float = 90.0,
) -> BlockcheckReport:
    """Проверяет один домен на фоне контрольных хостов.

    Возвращает готовый ``BlockcheckReport``: targets, baseline, verdict.
    Синхронный вызов — выполняйте в фоновом потоке.

    Args:
        domain: целевой домен (hostname, порт/www-префиксы отбрасываются).
        log: приёмник строк лога прогона.
        is_cancelled: callable, возвращающий True для досрочной остановки.
        extra_domains: дополнительные домены для параллельной проверки.
        timeout: таймаут одной HTTPS-пробы (сек).
        deadline_seconds: общий бюджет прогона (сек).
    """
    target_domain = host_of(str(domain or "").strip())
    if not target_domain:
        raise ValueError("empty domain")

    adapter = _HeadlessCallback(log=log, is_cancelled=is_cancelled)
    runner = BlockcheckRunner(
        mode=RunMode.DPI_ONLY,
        timeout=timeout,
        callback=adapter,
        deadline_seconds=max(15.0, float(deadline_seconds)),
        targets=build_targets(target_domain, extra_domains),
    )
    return runner.run()