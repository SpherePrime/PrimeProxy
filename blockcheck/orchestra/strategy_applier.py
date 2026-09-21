"""Применение стратегии к профилю winws (с защитой round-robin секций).

Правила применения (в соответствии с ТЗ «Orchestra»):

- Профиль делится на секции по строкам ``--new``.
- Целевая секция: по явному ``section_name`` (любая строка ``--name=``,
  содержащая имя), иначе по категории стратегии (``udp``/``voice`` → секция
  с ``--filter-udp``; ``tcp`` → секция с ``--filter-tcp`` без ``--filter-udp``),
  иначе секция с наибольшим числом ``--lua-desync``, иначе весь профиль.
- Если секция круговая (есть ``circular:`` база или ``:strategy=N`` лейны),
  базовая строка и нумерация НЕ трогаются: новые ненумерованные лейны
  добавляются в конец секции.
- Линейная секция: существующие ``--lua-desync`` (и ``--payload/--out-range/
  --in-range``, если их добавляет стратегия) удаляются, параметры стратегии
  вставляются в конец секции.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from winws.profiles import get_user_profile_text, profile_dir
from winws.profiles.serializer import Line, parse_profile_text

__all__ = [
    "apply_strategy_to_profile",
    "backup_profile",
    "build_application_plan",
    "describe_strategy",
]

_LUA_KEY = "--lua-desync"
_ROBIN_MARKERS = ("circular:", ":strategy=")


def describe_strategy(strategy: Dict[str, Any]) -> Dict[str, Any]:
    params = strategy.get("parameters") or {}
    key_parameters: List[str] = []
    for key, values in params.get("add", {}).items():
        if key == _LUA_KEY:
            lanes = [values] if isinstance(values, str) else list(values)
            key_parameters.extend(lanes[:3])
    return {
        "id": strategy.get("id"),
        "strategy": strategy.get("id"),
        "name": strategy.get("name", strategy.get("id", "")),
        "category": strategy.get("category", "tcp"),
        "label": strategy.get("label", "stable"),
        "description": strategy.get("description", ""),
        "key_parameters": key_parameters,
        "parameters": params,
    }


def _lanes(strategy: Dict[str, Any]) -> List[str]:
    values = strategy.get("parameters") or {}
    values = values.get("add", {}).get(_LUA_KEY)
    return [values] if isinstance(values, str) else list(values or [])


def _extra_remove_keys(strategy: Dict[str, Any]) -> set:
    params = strategy.get("parameters") or {}
    keys = set(params.get("remove") or [])
    for optional in ("--payload", "--out-range", "--in-range"):
        if optional in params.get("add", {}):
            keys.add(optional)
    return keys


def _split_sections(model) -> List[List[Line]]:
    sections: List[List[Line]] = []
    current: List[Line] = []
    for line in model.lines:
        if line.kind == "param" and line.key == "--new":
            if current:
                sections.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        sections.append(current)
    return sections


def _first_name(section: List[Line]) -> str:
    return next(
        (line.value for line in section if line.kind == "param" and line.key == "--name"),
        "",
    )


def _route(sections, strategy, section_name):
    category = (strategy or {}).get("category", "")

    if section_name:
        for i, section in enumerate(sections):
            if any(
                line.kind == "param" and line.key == "--name" and section_name in line.value
                for line in section
            ):
                return i, "name"
        return None, "whole"

    if category in ("udp", "voice"):
        for i, section in enumerate(sections):
            if any(line.kind == "param" and line.key == "--filter-udp" for line in section):
                return i, "category"
    elif category == "tcp":
        for i, section in enumerate(sections):
            has_udp = any(line.kind == "param" and line.key == "--filter-udp" for line in section)
            has_tcp = any(line.kind == "param" and line.key == "--filter-tcp" for line in section)
            if has_tcp and not has_udp:
                return i, "category"

    best, best_n = None, 0
    for i, section in enumerate(sections):
        n = sum(1 for line in section if line.kind == "param" and line.key == _LUA_KEY)
        if n > best_n:
            best, best_n = i, n
    if best is not None:
        return best, "desync_count"

    return None, "whole"


def _is_round_robin(section: List[Line]) -> bool:
    return any(
        line.kind == "param"
        and line.key == _LUA_KEY
        and any(marker in (line.value or "") for marker in _ROBIN_MARKERS)
        for line in section
    )


def build_application_plan(
    profile_text,
    strategy: Dict[str, Any],
    section_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Описывает, что будет сделано при применении (текст не меняется)."""
    model = parse_profile_text(profile_text)
    sections = _split_sections(model)
    lanes = _lanes(strategy)

    if not lanes:
        return {
            "ok": False,
            "error": "no_strategy_lanes",
            "removed": [],
            "added": [],
            "n_removed": 0,
            "n_added": 0,
        }

    index, how = _route(sections, strategy, section_name)
    if how == "whole":
        target_sections = sections
        index = None
    else:
        target_sections = [sections[index]]

    round_robin = bool(target_sections) and all(_is_round_robin(sec) for sec in target_sections)

    if round_robin:
        removed: List[str] = []
    else:
        remove_keys = {_LUA_KEY} | _extra_remove_keys(strategy)
        removed = [
            line.raw
            for sec in target_sections
            for line in sec
            if line.kind == "param" and line.key in remove_keys
        ]

    added = [f"{_LUA_KEY}={lane}" for lane in lanes]
    return {
        "ok": True,
        "mode": "section" if how != "whole" else "whole",
        "how": how,
        "section": index,
        "section_name": _first_name(target_sections[-1]) if target_sections else "",
        "round_robin": round_robin,
        "removed": removed,
        "added": added,
        "n_removed": len(removed),
        "n_added": len(added),
    }


def _line_offsets(sections) -> List[int]:
    prefixes = [0]
    for section in sections:
        prefixes.append(prefixes[-1] + len(section))
    return prefixes


def apply_strategy_to_profile(
    profile_text,
    strategy: Dict[str, Any],
    section_name: Optional[str] = None,
) -> Dict[str, Any]:
    plan = build_application_plan(profile_text, strategy, section_name)
    if not plan["ok"]:
        return plan
    if plan["n_removed"] == 0 and plan["n_added"] == 0:
        return {"ok": False, "error": "no_change", "plan": plan}

    model = parse_profile_text(profile_text)
    sections = _split_sections(model)
    prefixes = _line_offsets(sections)
    if plan["mode"] == "whole":
        start, end = 0, prefixes[-1]
    else:
        start, end = prefixes[plan["section"]], prefixes[plan["section"] + 1]

    remove_keys = set()
    if not plan["round_robin"]:
        remove_keys = {_LUA_KEY} | _extra_remove_keys(strategy)

    lines: List[Line] = []
    removed = 0
    for i, line in enumerate(model.lines):
        if start <= i < end and line.kind == "param" and line.key in remove_keys:
            removed += 1
            continue
        lines.append(line)
    end -= removed

    lanes = plan["added"]
    for raw in lanes:
        value = raw.split("=", 1)[1]
        lines.insert(end, Line("param", raw, _LUA_KEY, value))
        end += 1

    content = "\n".join(line.raw for line in lines)
    result = dict(plan)
    result["content"] = content
    return result


def backup_profile(name: str) -> Dict[str, Any]:
    """Копия профиля в ``<профиль>.<YYYYmmdd-HHMMSS>.bak`` в папке профилей."""
    read = get_user_profile_text(name)
    if not read.get("ok"):
        return {"ok": False, "error": read.get("error", "not_found")}
    stem = (name or "").strip()
    if stem.lower().endswith(".txt"):
        stem = stem[:-4]
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = profile_dir() / f"{stem}.{timestamp}.bak"
    try:
        path.write_text(read["text"], encoding="utf-8", newline="\n")
    except OSError as exc:
        return {"ok": False, "error": "write_failed", "detail": str(exc)}
    return {"ok": True, "path": str(path), "name": read.get("name", name), "file": path.name}