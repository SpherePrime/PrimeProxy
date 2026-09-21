import json
import sys

import pytest

from config import IS_FROZEN  # noqa: F401  (import ordering)
from cli import (
    cmd_config_get,
    cmd_config_set,
    cmd_link,
    cmd_lists_status,
    cmd_presets_list,
    cmd_status,
)


class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)
        if not hasattr(self, "lang"):
            self.lang = "ru"
        if not hasattr(self, "json"):
            self.json = False


def test_status_shape():
    st = cmd_status(_Args())
    assert "mtproto" in st and "telegram" in st
    assert isinstance(st["mtproto"]["running"], bool)
    assert st["mtproto"]["port"] > 0


def test_link_shape():
    link = cmd_link(_Args())
    assert link["link"].startswith("tg://proxy?server=")
    assert "&port=" in link["link"]


def test_config_get_set(monkeypatch, tmp_path):
    from config import get_store, reset_cache
    from config import paths
    monkeypatch.setattr(paths, "config_file", lambda: tmp_path / "config.json")
    reset_cache()
    get_store().load()
    cmd_config_set(_Args(key="proxy.port", value="19999"))
    assert cmd_config_get(_Args(key="proxy.port"))["value"] == 19999


def test_presets_localized(monkeypatch, tmp_path):
    from config import get_store, reset_cache
    from config import paths
    monkeypatch.setattr(paths, "config_file", lambda: tmp_path / "config.json")
    reset_cache()
    get_store().load()
    ru = cmd_presets_list(_Args(lang="ru"))
    uk = cmd_presets_list(_Args(lang="uk"))
    en = cmd_presets_list(_Args(lang="en"))
    assert len(ru) >= 5 and len(uk) == len(ru) and len(en) == len(ru)
    assert any("id" in p and "changes" in p for p in ru)
    assert ru != en


def test_lists_status_runs():
    st = cmd_lists_status(_Args())
    assert "user_path" in st and isinstance(st["user_count"], int)