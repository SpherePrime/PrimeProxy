# winws/args.py
"""Разбор текста профиля в argv движка winws (winws1/winws2)."""
from __future__ import annotations

import os
import re
import shlex
from typing import List, Optional

_INLINE_ARG_SPLIT_RE = re.compile(r"(?<=\S)\s+(?=--)")
_AT_REF_RE = re.compile(r"@[^\\/][^\s,]*")


def split_launch_line(raw_line: str) -> List[str]:
    """Разбивает строку профиля на один или несколько ``--``-аргументов.

    Циркулярные/исходные профили могут хранить несколько аргументов на одной
    строке; subprocess всё равно требует argv по одному элементу на аргумент,
    поэтому режем только по пробелу, за которым начинается следующий ``--``.
    """
    stripped = str(raw_line or "").strip()
    if not stripped:
        return []
    if not stripped.startswith("--"):
        return [stripped]
    return [part.strip() for part in _INLINE_ARG_SPLIT_RE.split(stripped) if part.strip()]


def launch_args_from_text(content: str) -> List[str]:
    """Собирает argv из текста профиля (комментарии/пустые строки пропускаются)."""
    args: List[str] = []
    for raw in str(content or "").splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        args.extend(split_launch_line(stripped))
    return args


def write_at_config(text: str, config_dir: str, digest_key: str) -> str:
    """Пишет @config для winws2 (по одному аргументу на строку, shlex-кавычки)."""
    args = launch_args_from_text(text)
    if not args:
        raise ValueError("profile_empty")
    config_text = "\n".join(shlex.quote(arg) for arg in args) + "\n"
    digest = str(abs(hash(digest_key)))[:16]
    path = os.path.join(config_dir, f"winws2_at_{digest}.txt")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(config_text)
    return path


def resolve_file_ref(arg: str, work_dir: str) -> str:
    """Заменяет ``@относительный/путь`` на абсолютный относительно work_dir.

    winws понимает относительные ссылки от текущей директории, поэтому это
    только страховка для диагностики — сам запуск идёт с cwd=work_dir.
    """
    v = str(arg or "")
    if v.startswith("@") and len(v) > 1 and not os.path.isabs(v[1:]):
        candidate = os.path.normpath(os.path.join(work_dir, v[1:]))
        if os.path.exists(candidate):
            return "@" + candidate
    return v


def missing_references(text: str, work_dir: str) -> List[str]:
    """Список ссылок на отсутствующие файлы (для диагностики перед стартом).

    Ссылки вида ``--key=@relative/path`` и ``--blob=name:@bin/path`` живут
    внутри аргументов, поэтому ищем все ``@...``-фрагменты в argv.
    """
    missing: List[str] = []
    seen = set()
    for arg in launch_args_from_text(text):
        for ref in _AT_REF_RE.findall(arg):
            rel = ref[1:]  # без "@"
            if os.path.isabs(rel):
                target = rel
            else:
                target = os.path.normpath(os.path.join(work_dir, rel))
            key = os.path.normcase(target)
            if target and not os.path.exists(target) and key not in seen:
                seen.add(key)
                missing.append(ref)
            if len(missing) >= 20:
                return missing
    return missing


def validate_profile_text(text: str) -> Optional[str]:
    """Возвращает строку ошибки, если профиль не содержит запускаемых аргументов."""
    if not launch_args_from_text(text):
        return "profile_empty"
    return None