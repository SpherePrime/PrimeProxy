from __future__ import annotations

from typing import Iterator, List, Optional

_BANNER_PATTERNS = (
    "<<",
    ">=>>>",
)


def is_banner_line(line: str) -> bool:
    stripped = line.strip()
    return any(stripped.startswith(pat) for pat in _BANNER_PATTERNS)


_WINDIVERT_MARKERS = (
    "windivert:",
    "error opening filter",
    "windivert.dll",
    "windivert",
)


def has_diagnostic_output(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in _WINDIVERT_MARKERS)


def _looks_like_error(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in ("error", "не найдена", "не найдено", "ошибка", "требует прав"))


def relevant_error_line(lines: List[str]) -> Optional[str]:
    for line in lines:
        stripped = line.strip()
        if _looks_like_error(stripped):
            return stripped
    return None


def diagnostic_lines(lines: List[str]) -> List[str]:
    return [line.strip() for line in lines if _looks_like_error(line.strip())]


def iter_diagnostic_lines(lines: List[str]) -> Iterator[str]:
    for line in lines:
        stripped = line.strip()
        if _looks_like_error(stripped):
            yield stripped


fallback_text = "не указан (нет диагностического вывода)"