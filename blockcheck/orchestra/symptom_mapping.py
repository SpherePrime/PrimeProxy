"""Симптомы блокировки и их извлечение из отчёта BlockCheck.

Симптом — именованное проявление DPI, достаточно специфичное, чтобы выбрать
стратегию: :data:`SYMPTOMS` описывает их (label/description/approach), а
:func:`extract_symptoms` выжимает набор ключей из «плоского» dict-отчёта
BlockCheck (уже сериализованного через ``ui.api._to_plain``).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

__all__ = [
    "SYMPTOMS",
    "FAILURE_TO_SYMPTOM",
    "extract_symptoms",
    "parse_symptoms_text",
    "symptom_info",
]

SYMPTOMS: Dict[str, Dict[str, str]] = {
    "dns_poisoning": {
        "label": "DNS-подмена",
        "description": "Резолвер отдаёт поддельные адреса для заблокированных доменов",
        "approach": "Лечится сменой DNS или записями в hosts — стратегия обхода не требуется",
    },
    "tls_reset": {
        "label": "Обрыв TLS (SNI-фильтрация)",
        "description": "TLS-соединение сбрасывается на этапе рукопожатия",
        "approach": "Перехват и нарезка TLS ClientHello по SNI",
    },
    "tls_mitm": {
        "label": "TLS MITM",
        "description": "Трафик перехватывается MITM-прокси с подменой сертификата",
        "approach": "Фейковые пакеты TLS с модификацией ClientHello",
    },
    "http_inject": {
        "label": "HTTP-инъекция",
        "description": "В HTTP-трафик подмешиваются заголовки или страницы блокировки",
        "approach": "Десинхронизация TCP для HTTP-потоков",
    },
    "isp_page": {
        "label": "Страница провайдера",
        "description": "Вместо сайта отдаётся страница блокировки",
        "approach": "Десинхронизация TCP для HTTP-потоков",
    },
    "tcp_reset": {
        "label": "TCP reset",
        "description": "Соединение обрывается RST-пакетами",
        "approach": "Фейковые fake-ответы и рассинхронизация TCP",
    },
    "tcp_16_20": {
        "label": "Обрыв на 16-20 КБ",
        "description": "Соединение рвётся после ~16-20 КБ полезной нагрузки",
        "approach": "Нарезка с перекрытием последовательности (seqovl)",
    },
    "stun_block": {
        "label": "STUN/голосовые",
        "description": "UDP-трафик STUN/Discord Voice не проходит",
        "approach": "Фейковые STUN-пакеты и fake-реплики QUIC",
    },
    "quic_drop": {
        "label": "QUIC/UDP режется",
        "description": "UDP-пакеты QUIC падают или сбрасываются",
        "approach": "Фейковые QUIC-пакеты (replicas whitelist QUIC)",
    },
    "full_block": {
        "label": "Полная блокировка",
        "description": "Недоступна подавляющая часть целей",
        "approach": "Проверьте сеть; начните с базового профиля обхода",
    },
    "just_block": {
        "label": "Блокировка сайта",
        "description": "Сайт заблокирован, тип DPI не определён",
        "approach": "Базовая комбинация fake + нарезка",
    },
}

# Тип сбоя (типизация для create_strategy_for_failure_type).
FAILURE_TYPE_SNI = "sni"
FAILURE_TYPE_TCP_RESET = "tcp_reset"
FAILURE_TYPE_16_20 = "16_20"
FAILURE_TYPE_TLS_MITM = "tls_mitm"
FAILURE_TYPE_HTTP_INJECT = "http_inject"
FAILURE_TYPE_DNS = "dns"
FAILURE_TYPE_STUN = "stun"
FAILURE_TYPE_QUIC = "quic"
FAILURE_TYPE_JUST_BLOCK = "just_block"

# Симптом → тип сбоя. У «полной блокировки» типа сбоя нет — это не стратегия,
# а состояние сети.
FAILURE_TO_SYMPTOM: Dict[str, str] = {
    FAILURE_TYPE_SNI: "tls_reset",
    FAILURE_TYPE_TCP_RESET: "tcp_reset",
    FAILURE_TYPE_16_20: "tcp_16_20",
    FAILURE_TYPE_TLS_MITM: "tls_mitm",
    FAILURE_TYPE_HTTP_INJECT: "http_inject",
    FAILURE_TYPE_DNS: "dns_poisoning",
    FAILURE_TYPE_STUN: "stun_block",
    FAILURE_TYPE_QUIC: "quic_drop",
    FAILURE_TYPE_JUST_BLOCK: "just_block",
}

_ORDER = [
    "dns_poisoning",
    "http_inject",
    "isp_page",
    "tls_reset",
    "tls_mitm",
    "tcp_reset",
    "tcp_16_20",
    "stun_block",
    "quic_drop",
    "full_block",
    "just_block",
]

# Коды ошибок TLS-проб, характерные для DPI (зеркалит verdict.signatures).
_TLS_DROP_CODES = frozenset({"TLS_RESET", "TCP_RESET", "TLS_EOF_EARLY"})
_WEB_TYPES = frozenset({"tls12", "tls13"})
_QUIC_HINT_WORDS = ("quic", "udp", "games", "discord", "dht")


def symptom_info(key: str) -> Dict[str, str]:
    return dict(SYMPTOMS.get(key, {"label": key, "description": "", "approach": ""}))


def extract_symptoms(report: Optional[dict]) -> List[str]:
    """Набор ключей симптомов по «плоскому» dict отчёта BlockCheck."""
    if not isinstance(report, dict):
        return []
    verdict = report.get("verdict") or {}
    code = verdict.get("code")
    if code in ("no_internet", "unreliable"):
        # Без опорной группы выводы невозможны — стратегию не выбираем.
        return []

    found: Set[str] = set()

    for dns in report.get("dns_integrity") or []:
        if (dns or {}).get("verdict") == "fake":
            found.add("dns_poisoning")

    targets = report.get("targets") or []
    for target in targets:
        cls = (target or {}).get("classification")
        detail = (target or {}).get("classification_detail") or ""
        if cls == "dns_fake":
            found.add("dns_poisoning")
        elif cls == "http_inject":
            found.add("http_inject")
        elif cls == "isp_page":
            found.add("isp_page")
        elif cls == "tls_dpi":
            found.add("tls_reset")
        elif cls == "tls_mitm":
            found.add("tls_mitm")
        elif cls == "tcp_reset":
            found.add("tcp_reset")
        elif cls == "tcp_16_20":
            found.add("tcp_16_20")
        elif cls == "stun_block":
            found.add("stun_block")
        elif cls == "full_block":
            found.add("full_block")
        elif cls in (None, "none") and target.get("outcome") == "blocked":
            lowered = detail.lower()
            found.add("quic_drop" if any(w in lowered for w in _QUIC_HINT_WORDS) else "just_block")

        for test in target.get("tests") or []:
            test = test or {}
            status = test.get("status")
            test_type = test.get("test_type") or ""
            error = (test.get("error_code") or "").upper()
            if test_type in _WEB_TYPES and error in _TLS_DROP_CODES:
                found.add("tls_reset")
            if test_type == "stun" and status not in (None, "ok"):
                found.add("stun_block")
            if test_type == "tcp_16_20" and status == "fail":
                found.add("tcp_16_20")

    if verdict.get("headline") == "full_block":
        found.add("full_block")

    return [key for key in _ORDER if key in found]


def parse_symptoms_text(text: str) -> List[str]:
    """Симптомы из ручного ввода («dns poisoning, tls reset, quic»)."""
    if not text:
        return []
    lowered = str(text).lower()
    found: Set[str] = set()

    def _has(*words: str) -> bool:
        return any(word in lowered for word in words)

    if _has("dns"):
        found.add("dns_poisoning")
    if _has("mitm"):
        found.add("tls_mitm")
    if _has("http", "inject"):
        found.add("http_inject")
    if _has("isp", "страница", "страниц"):
        found.add("isp_page")
    if _has("quic", "udp", "game", "игр", "dht"):
        found.add("quic_drop")
    if _has("stun", "voice", "голос", "discord", "звонк"):
        found.add("stun_block")
    if _has("16-20", "15-20", "16к", "20к", "16 кб", "20 кб", "16kb", "16_20"):
        found.add("tcp_16_20")
    if _has("reset", "обрыв", "sni", "sniff", "дпи", "dpi", "tls"):
        found.add("tls_reset")
    if _has("tcp", "rts", "rst", "сброс", "соединени"):
        found.add("tcp_reset")
    if _has("full", "полн", "all sites", "все сайты"):
        found.add("full_block")
    if _has("echo", "icmp", "ping") or _has("block", "заблок") or _has("сайт"):
        found.add("just_block")

    return [key for key in _ORDER if key in found]