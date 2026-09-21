# utils/presets.py
"""Уст-пресеты обхода для MTProto-движка.

Пресет — именованный набор значений ключей конфигурации ``proxy``/``telegram``,
который применяется одним действием из GUI или CLI. Каталог не зависит от
конкретного состояния движка: пресет просто перезаписывает выбранные ключи.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

# --- Каталог пресетов -------------------------------------------------------
# ``config`` — подмножество ключей, которые пресет перезаписывает в сторе.

PRESETS: List[Dict[str, Any]] = [
    {
        "id": "default",
        "category": "basic",
        "label": {"ru": "По умолчанию", "uk": "За замовчуванням", "en": "Default"},
        "description": {
            "ru": "Заводские настройки: сбалансированный пул, авто-домены Cloudflare.",
            "uk": "Заводські налаштування: збалансований пул, авто-домени Cloudflare.",
            "en": "Factory settings: balanced pool, automatic Cloudflare domains.",
        },
        "config": {
            "proxy": {
                "pool_size": 4,
                "buf_kb": 256,
                "cfproxy": True,
                "cfproxy_user_domain_enabled": False,
                "cfproxy_worker_enabled": False,
                "force_test_dc": False,
            }
        },
    },
    {
        "id": "stable",
        "category": "basic",
        "label": {"ru": "Максимальная стабильность", "uk": "Максимальна стабільність", "en": "Maximum stability"},
        "description": {
            "ru": "Больше WebSocket-сессий и тестовый DC для обхода блокировок.",
            "uk": "Більше WebSocket-сесій і тестовий DC для обходу блокувань.",
            "en": "More WebSocket sessions and a test DC to bypass blocking.",
        },
        "config": {
            "proxy": {
                "pool_size": 8,
                "buf_kb": 256,
                "cfproxy": True,
                "cfproxy_user_domain_enabled": False,
                "cfproxy_worker_enabled": False,
                "force_test_dc": True,
            }
        },
    },
    {
        "id": "speed",
        "category": "basic",
        "label": {"ru": "Скорость (низкий пинг)", "uk": "Швидкість (низький пінг)", "en": "Speed (low ping)"},
        "description": {
            "ru": "Меньше пул и буфер, без лишних релеев — минимум задержек.",
            "uk": "Менше пул і буфер, без зайвих релеїв — мінімум затримок.",
            "en": "Smaller pool and buffer, no extra relays — minimal latency.",
        },
        "config": {
            "proxy": {
                "pool_size": 2,
                "buf_kb": 128,
                "cfproxy": False,
                "cfproxy_user_domain_enabled": False,
                "cfproxy_worker_enabled": False,
                "force_test_dc": False,
            }
        },
    },
    {
        "id": "cfworker",
        "category": "advanced",
        "label": {"ru": "CF Worker релеи", "uk": "CF Worker релеї", "en": "CF Worker relays"},
        "description": {
            "ru": "Прокидывает трафик через ваши Cloudflare Worker-домены.",
            "uk": "Прокидає трафік через ваші Cloudflare Worker-домени.",
            "en": "Routes traffic through your Cloudflare Worker domains.",
        },
        "config": {
            "proxy": {
                "pool_size": 4,
                "buf_kb": 256,
                "cfproxy": True,
                "cfproxy_worker_enabled": True,
                "cfproxy_user_domain_enabled": False,
                "force_test_dc": False,
            }
        },
    },
    {
        "id": "custom-domains",
        "category": "advanced",
        "label": {"ru": "Свои CF-домены", "uk": "Свої CF-домени", "en": "Custom CF domains"},
        "description": {
            "ru": "Использовать ваши домены за Cloudflare вместо автоматического выбора.",
            "uk": "Використовувати ваші домени за Cloudflare замість автоматичного вибору.",
            "en": "Use your Cloudflare fronted domains instead of the automatic set.",
        },
        "config": {
            "proxy": {
                "pool_size": 4,
                "buf_kb": 256,
                "cfproxy": True,
                "cfproxy_user_domain_enabled": True,
                "cfproxy_worker_enabled": False,
                "force_test_dc": False,
            }
        },
    },
    {
        "id": "heavy",
        "category": "advanced",
        "label": {"ru": "Максимальный обход", "uk": "Максимальний обхід", "en": "Maximum bypass"},
        "description": {
            "ru": "Все средства сразу: CF-прокси, Worker-домены, тестовый DC, большой пул.",
            "uk": "Усі засоби одразу: CF-проксі, Worker-домени, тестовий DC, великий пул.",
            "en": "Everything at once: CF proxy, worker domains, test DC, large pool.",
        },
        "config": {
            "proxy": {
                "pool_size": 12,
                "buf_kb": 512,
                "cfproxy": True,
                "cfproxy_worker_enabled": True,
                "cfproxy_user_domain_enabled": True,
                "force_test_dc": True,
            }
        },
    },
    {
        "id": "ws-direct",
        "category": "advanced",
        "label": {"ru": "Прямой WS (без CF)", "uk": "Прямий WS (без CF)", "en": "Direct WS (no CF)"},
        "description": {
            "ru": "Без Cloudflare-прокси: чистый WebSocket к релеям. Для случаев, когда CF замедляет.",
            "uk": "Без Cloudflare-проксі: чистий WebSocket до релеїв. Для випадків, коли CF сповільнює.",
            "en": "No Cloudflare proxy: plain WebSocket to the relays. For cases where CF slows things down.",
        },
        "config": {
            "proxy": {
                "pool_size": 4,
                "buf_kb": 256,
                "cfproxy": False,
                "cfproxy_user_domain_enabled": False,
                "cfproxy_worker_enabled": False,
                "force_test_dc": False,
            }
        },
    },
    {
        "id": "media",
        "category": "basic",
        "label": {"ru": "Тяжёлый контент", "uk": "Важкий контент", "en": "Heavy content"},
        "description": {
            "ru": "Увеличенный буфер и пул для быстрой загрузки больших файлов и медиа.",
            "uk": "Збільшений буфер і пул для швидкого завантаження великих файлів і медіа.",
            "en": "Larger buffer and pool for fast downloads of big files and media.",
        },
        "config": {
            "proxy": {
                "pool_size": 8,
                "buf_kb": 1024,
                "cfproxy": True,
                "cfproxy_user_domain_enabled": False,
                "cfproxy_worker_enabled": False,
                "force_test_dc": False,
            }
        },
    },
]

_USER_PRESETS_FILE = "presets.json"

# Ключи, которые показываются пользователю как «что меняет пресет» (порядок).
KEY_LABELS: Dict[str, Dict[str, str]] = {
    "pool_size": {"ru": "Пул WS-сессий", "uk": "Пул WS-сесій", "en": "WS session pool"},
    "buf_kb":    {"ru": "Буфер, КБ", "uk": "Буфер, КБ", "en": "Buffer, KB"},
    "cfproxy":   {"ru": "Fallback CF-прокси", "uk": "Fallback CF-проксі", "en": "CF fallback proxy"},
    "cfproxy_worker_enabled": {"ru": "CF Worker домены", "uk": "CF Worker домени", "en": "CF Worker domains"},
    "cfproxy_user_domain_enabled": {"ru": "Свои CF-домены", "uk": "Свої CF-домени", "en": "Custom CF domains"},
    "force_test_dc": {"ru": "Тестовый DC (149.154)", "uk": "Тестовий DC (149.154)", "en": "Test DC (149.154)"},
}


def list_presets(lang: str = "ru") -> List[Dict[str, Any]]:
    """Возвращает каталог пресетов (встроенные + пользовательские) с локализованными полями."""
    lang = (lang or "ru").lower()
    if lang not in ("ru", "uk", "en"):
        lang = "en"
    out = []
    for p in PRESETS:
        label = p["label"].get(lang) or p["label"].get("en")
        desc = p["description"].get(lang) or p["description"].get("en")
        changes = []
        for section, values in (p.get("config") or {}).items():
            for key, val in values.items():
                changes.append({"section": section, "key": key, "value": val})
        out.append({"id": p["id"], "category": p["category"], "label": label, "description": desc, "changes": changes})
    for up in _read_user_presets():
        changes = []
        for section, values in (up.get("config") or {}).items():
            for key, val in values.items():
                changes.append({"section": section, "key": key, "value": val})
        out.append({
            "id": up["id"],
            "category": "custom",
            "label": up.get("label", up["id"]),
            "description": up.get("description", ""),
            "changes": changes,
            "user": True,
        })
    return out


def _user_presets_file() -> Path:
    from config.paths import app_dir
    return app_dir() / _USER_PRESETS_FILE


def _read_user_presets() -> List[Dict[str, Any]]:
    path = _user_presets_file()
    try:
        if not path.exists():
            return []
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_user_presets(items: List[Dict[str, Any]]) -> None:
    import json
    path = _user_presets_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")


def save_user_preset(
    label: str,
    description: str,
    changes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Сохраняет пользовательский пресет из списка изменений {section,key,value}."""
    import uuid
    if not label or not label.strip():
        return {"ok": False, "error": "empty label"}
    if not changes:
        return {"ok": False, "error": "empty changes"}
    config: Dict[str, Dict[str, Any]] = {}
    for ch in changes:
        section = (ch.get("section") or "").strip()
        key = (ch.get("key") or "").strip()
        if not section or not key or not (ch.get("value") is not None):
            continue
        config.setdefault(section, {})[key] = ch["value"]
    if not config:
        return {"ok": False, "error": "empty changes"}
    items = _read_user_presets()
    preset = {
        "id": f"user-{uuid.uuid4().hex[:8]}",
        "label": label.strip(),
        "description": (description or "").strip(),
        "config": config,
    }
    items.append(preset)
    _write_user_presets(items)
    return {"ok": True, "id": preset["id"]}


def delete_user_preset(preset_id: str) -> Dict[str, Any]:
    items = _read_user_presets()
    before = len(items)
    items = [p for p in items if p.get("id") != preset_id]
    if len(items) == before:
        return {"ok": False, "error": "not found"}
    _write_user_presets(items)
    return {"ok": True}


def get_preset(preset_id: str) -> Optional[Dict[str, Any]]:
    for p in PRESETS:
        if p["id"] == preset_id:
            return p
    for p in _read_user_presets():
        if p.get("id") == preset_id:
            return p
    return None


def apply_preset(
    preset_id: str,
    store,
    *,
    restart: bool = True,
    on_error=None,
) -> Dict[str, Any]:
    """Применяет пресет: записывает ключи в стор и при необходимости перезапускает прокси."""
    preset = get_preset(preset_id)
    if preset is None:
        return {"ok": False, "error": f"unknown preset: {preset_id}"}

    for section, values in (preset.get("config") or {}).items():
        try:
            store.set_section(section, values)
        except AttributeError:
            for key, value in values.items():
                store.set(section, key, value)

    if restart:
        from utils.tray_common import restart_proxy
        try:
            restart_proxy(store.snapshot().get("proxy", {}), on_error or (lambda msg: None))
        except Exception:
            pass

    return {"ok": True, "id": preset_id}


def detect_active_preset(snapshot: Dict[str, Any], lang: str = "ru") -> Optional[str]:
    """Находит пресет (встроенный или пользовательский), чьи ключи совпадают с текущим конфигом."""
    candidates = list(PRESETS) + _read_user_presets()
    for p in candidates:
        match = True
        for section, values in (p.get("config") or {}).items():
            cur = snapshot.get(section) or {}
            for key, value in values.items():
                if cur.get(key) != value:
                    match = False
                    break
            if not match:
                break
        if match:
            return p["id"]
    return None