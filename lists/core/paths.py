"""
Canonical paths for layered lists, kept next to the app data directory.

Adapted from ZapretGUI lists/core/paths.py to use the unified SwiftProxy
config.paths resolution instead of the old Zapret runtime layout.
"""
from __future__ import annotations

import os

from config.paths import app_dir, resources_dir

_local = {}


def get_lists_dir() -> str:
    base = app_dir()
    path = os.path.join(str(base), "lists")
    local_path = _local.get("lists_dir")
    if local_path:
        return local_path
    return path


def _set_local(key: str, value: str) -> None:
    _local[key] = value


def set_lists_dir(value: str) -> None:
    _set_local("lists_dir", value)


def get_lists_base_dir() -> str:
    bundled = os.path.join(str(resources_dir()), "lists", "base")
    os.makedirs(bundled, exist_ok=True)
    return bundled


def get_lists_user_dir() -> str:
    path = os.path.join(get_lists_dir(), "user")
    os.makedirs(path, exist_ok=True)
    return path


def get_list_path(file_name: str) -> str:
    return os.path.join(get_lists_dir(), file_name)


def get_list_base_path(list_name: str) -> str:
    return os.path.join(get_lists_base_dir(), f"{list_name}.txt")


def get_list_user_path(list_name: str) -> str:
    return os.path.join(get_lists_user_dir(), f"{list_name}.txt")


def get_list_final_path(list_name: str) -> str:
    return get_list_path(f"{list_name}.txt")