from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ._log import log

ERROR_NOT_READY = 21
ERROR_DEVICE_IN_USE = 31
ERROR_BAD_DRIVER = 577
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_DISABLED = 1058
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
ERROR_DEPENDENCY_FAIL = 1068
ERROR_ABANDONED_WAIT = 735
RPC_S_SERVER_UNAVAILABLE = 1722
FWP_E_IN_USE = 0x80320010

_RAW_TABLE = {
    5: (
        "Отказано в доступе",
        "winws не может получить доступ к драйверу или службе WinDivert",
        "Запусти winws от имени администратора. Проверь, что служба и драйвер WinDivert не заблокированы антивирусом.",
        "Подожди и перезапусти winws",
        True,
    ),
    8: (
        "Недостаточно памяти",
        "Системе не хватает памяти для инициализации WinDivert",
        "Заверши лишние процессы и перезапусти winws",
        None,
        True,
    ),
    31: (
        "Сетевое устройство занято",
        "Драйвер WinDivert не может захватить сетевой стек — его уже использует другая программа",
        "Закрой программы с сетевым фильтром: GoodbyeDPI, другие VPN/антивирусные драйверы, приложения с WinDivert.",
        "Рекомендуется остановить конфликтующий процесс вручную",
        True,
    ),
    87: (
        "Служба WinDivert нарушена (конфликт разрядностей)",
        "Параметр драйвера некорректен: обычно это установка драйвера WinDivert из 32-битной сборки в 64-битной системе",
        "Очисти WinDivert стандартной очисткой и переустанови драйвер из корректной сборки.",
        "Переустановка драйвера",
        True,
    ),
    161: (
        "Каталог драйвера не найден",
        "Драйвер WinDivert или его каталог отсутствует",
        "Очисти WinDivert и переустанови драйвер.",
        None,
        False,
    ),
    433: (
        "Сетевое устройство не найдено",
        "WinDivert не может найти сетевой стек (LWF-фильтр 'WinDivert' не активен)",
        "Убедись, что драйвер WinDivert зарегистрирован и служба работает. Проверь Hyper-V, сторонние сетевые стеки.",
        "Исправить автоматически (переконфигурировать драйвер)",
        True,
    ),
    577: (
        "Устаревший или повреждённый драйвер",
        "Установленный драйвер WinDivert устарел или повреждён",
        "Очисти WinDivert агрессивной очисткой и переустанови драйвер.",
        "Агрессивная очистка и переустановка драйвера",
        True,
    ),
    654: (
        "Служба WinDivert не зарегистрирована",
        "Служба, обеспечивающая поддержку написанных драйверов, не зарегистрирована в системе",
        "Очисти WinDivert стандартной очисткой и переустанови драйвер.",
        "Переустановка драйвера",
        False,
    ),
    1058: (
        "Служба WinDivert отключена",
        "Служба, обеспечивающая работу драйвера, отключена",
        "Включи службу WinDivert (тип запуска «Автоматически») или очисти WinDivert.",
        "Автоматически включить службу",
        True,
    ),
    1060: (
        "Служба WinDivert не существует",
        "Служба, обеспечивающая работу драйвера, не зарегистрирована (или не требует действий)",
        "Ты используешь нединамический режим WinDivert: он ожидается, поэтому ошибка безвредна.",
        None,
        True,
    ),
    1067: (
        "Процесс службы WinDivert аварийно завершился",
        "Служба, обеспечивающая работу драйвера, аварийно завершилась",
        "Проверь подключение процесса к каналу, питание и стабильность системы, перезапусти winws.",
        None,
        False,
    ),
    1068: (
        "Зависимая служба WinDivert не запущена",
        "Служба сетевых фильтров (BFE и др.), необходимая WinDivert, не запущена",
        "Проверь состояние службы BFE (Base Filtering Engine).",
        "Автоматически включить BFE",
        False,
    ),
    1072: (
        "Служба WinDivert помечена на удаление",
        "Служба WinDivert удалена, но система ещё не удалила её до конца",
        "Очисти WinDivert агрессивной очисткой (удаляет службы и драйвер вручную).",
        "Агрессивная очистка WinDivert",
        True,
    ),
    1275: (
        "Драйвер WinDivert заблокирован или повреждён",
        "Система не может загрузить драйвер WinDivert",
        "Драйвер может быть повреждён/заблокирован антивирусом. Очисти WinDivert агрессивной очисткой.",
        "Агрессивная очистка WinDivert",
        True,
    ),
    1753: (
        "Служба WinDivert ещё не зарегистрирована",
        "Сети RPC: служба-приёмник WinDivert ещё не зарегистрирована (часто при первом запуске)",
        "Подожди несколько секунд и перезапусти winws.",
        "Автоматическая чистка и перезапуск",
        True,
    ),
    FWP_E_IN_USE: (
        "WinDivert переведён в состояние «Используется»",
        "Диагностическая ошибка (не влияет на работу). Некоторые приложения с сетевыми фильтрами держат драйвер занятым.",
        "Если winws работает — игнорируй. Если нет — закрой конфликтующие программы и перезапусти winws.",
        "Автоматически закрыть конфликтующие процессы",
        True,
    ),
}

_WINDIVERT_DRIVER_SERVICE_NAMES = (
    "WinDivert",
    "WinDivert14",
    "WinDivert64",
    "windivert",
    "Monkey",
)

WINDIVERT_ERROR_TABLE: Dict[int, Dict[str, object]] = {
    code: {
        "code": code,
        "meaning": meaning,
        "cause": cause,
        "solution": solution,
        "auto_fix": auto_fix,
        "transient": transient,
    }
    for code, (meaning, cause, solution, auto_fix, transient) in _RAW_TABLE.items()
}

FALLBACK_WINDIVERT_ERROR_TABLE: Dict[Tuple[str, str], Dict[str, object]] = {}


def _build_fallback_table() -> Dict[str, Dict[str, object]]:
    table: Dict[str, Dict[str, object]] = {}
    for name in _WINDIVERT_DRIVER_SERVICE_NAMES:
        for state in ("disabled", "missing", "marked"):
            table[(name, state)] = {
                "code": None,
                "meaning": f"Служба {name} {state}",
                "cause": f"Служба WinDivert ({name}) находится в состоянии {state}",
                "solution": "Очисти WinDivert и переустанови драйвер.",
                "auto_fix": "Исправить автоматически",
                "transient": False,
            }
    return table


def _get_fallback_table() -> Dict[str, Dict[str, object]]:
    if not FALLBACK_WINDIVERT_ERROR_TABLE:
        FALLBACK_WINDIVERT_ERROR_TABLE.update(_build_fallback_table())
    return FALLBACK_WINDIVERT_ERROR_TABLE


class WindivertDiagnosisError(Exception):
    """Ошибка, связанная с диагностикой WinDivert (например, кэш драйвера не найден)."""


def describe_windivert_error(
    error_code: int,
    *,
    extra_hint: Optional[str] = None,
    stage: Optional[str] = None,
) -> str:
    """Возвращает русскоязычное описание ошибки WinDivert."""
    if hasattr(error_code, "get"):
        return "Ошибка WinDivert (неопределённый формат кода)"
    if error_code is None:
        return "Ошибка WinDivert (без кода)"
    code = int(error_code)
    entry = WINDIVERT_ERROR_TABLE.get(code)
    prefix = ""
    if stage:
        prefix = f"Проверка WinDivert на этапе «{stage}»: "
    if entry is None:
        return f"{prefix}Ошибка WinDivert (код {code})"
    meaning = entry["meaning"]
    cause = entry["cause"]
    solution = entry["solution"]
    detail = f"{prefix}Ошибка WinDivert (код {code}): {meaning}. {cause}"
    if solution:
        detail = f"{detail} Рекомендация: {solution}."
    if extra_hint:
        detail = f"{detail} Дополнительно: {extra_hint}."
    return detail


def is_windivert_ready_stage(stage: Optional[str]) -> bool:
    return stage == "ready"


def describe_windivert_error_by_readiness(record: object) -> str:
    """Сериализует результат пробы готовности в человекочитаемое описание."""
    ready = getattr(record, "ready", False)
    error_code = getattr(record, "error_code", None)
    stage = getattr(record, "stage", None)
    installed = getattr(record, "installed", False)
    if ready:
        return "WinDivert готов к работе"
    if not installed:
        return "WinDivert не установлен (драйвер/служба не найдены)"
    return describe_windivert_error(error_code, stage=stage)


def format_windows_error_code(win32_error: int) -> str:
    """Форматирует код ошибки Windows, оставляя оба варианта записи для hex-кодов."""
    if win32_error is None:
        return "0"
    code = int(win32_error)
    if code > 0x7FFFFFFF:
        unsigned = code & 0xFFFFFFFF
        return f"{unsigned} / 0x{unsigned:08X}"
    return str(code)


def describe_windivert_conflict_hint(
    holder_processes: List[Dict[str, str]],
    foreign_services: List[str],
) -> Optional[str]:
    """Формирует подсказку о конфликтах с WinDivert."""
    if not holder_processes and not foreign_services:
        return None
    parts: List[str] = []
    if holder_processes:
        names = ", ".join(p.get("name", "?") for p in holder_processes[:3])
        parts.append(f"активные {len(holder_processes)} процессы держат WinDivert (например, {names})")
    if foreign_services:
        names = ", ".join(foreign_services[:3])
        parts.append(f"посторонние службы WinDivert: {names}")
    return "Обнаружен конфликт WinDivert: " + "; ".join(parts) + "."


def describe_layer_config_incompatibility() -> str:
    return "Конфигурация сетевых слоёв WinDivert несовместима с текущей системой"


def is_known_launch_conflict_exit_code(code: Optional[int]) -> bool:
    return code is not None and int(code) in _RAW_TABLE