"""
winws — управление DPI-движком zapret (winws.exe / winws2.exe).

Исполняемые файлы пользователь кладёт в папку ``exe/`` рядом с приложением
(загрузка не поддерживается — по решению пользователя). Профили-стратегии
приходят из resources/zapret (справочник) или из папки пользовательских
профилей ``<app_dir>/zapret/profiles``.
"""
from __future__ import annotations

from . import args, logs, paths, profiles, runner

__all__ = ["args", "logs", "paths", "profiles", "runner"]