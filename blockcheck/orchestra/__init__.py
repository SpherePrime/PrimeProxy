"""Orchestra — подбор стратегии обхода DPI по симптомам блокировки.

Примерный аналог одноимённого модуля ZapretGUI, но без Qt и без пересоздания
конфига: рекомендация строится по вердикту BlockCheck (или по ручному вводу
симптомов), а «применение» точечно правит выбранный профиль winws через наш
serializer.

Публичный API (чистая логика, без сети и без диалогов):
- :func:`orchestra_recommend` — рекомендации по симптомам;
- :func:`apply_strategy_to_profile` — применение стратегии к тексту профиля;
- :func:`available_strategies` / :func:`find_strategy_by_id` — справочник.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from blockcheck.orchestra.strategy_selector import (
    STRATEGIES,
    SYMPTOM_TO_STRATEGY,
    available_strategies,
    create_strategy_for_failure_type,
    find_strategy_by_id,
    rank_recommendations,
)
from blockcheck.orchestra.symptom_mapping import (
    FAILURE_TO_SYMPTOM,
    SYMPTOMS,
    extract_symptoms,
    parse_symptoms_text,
    symptom_info,
)
from blockcheck.orchestra.strategy_applier import (
    apply_strategy_to_profile,
    backup_profile,
    build_application_plan,
    describe_strategy,
)

__all__ = [
    "FAILURE_TO_SYMPTOM",
    "STRATEGIES",
    "SYMPTOMS",
    "SYMPTOM_TO_STRATEGY",
    "apply_strategy_to_profile",
    "available_strategies",
    "backup_profile",
    "build_application_plan",
    "create_strategy_for_failure_type",
    "describe_strategy",
    "extract_symptoms",
    "find_strategy_by_id",
    "orchestra_recommend",
    "parse_symptoms_text",
    "rank_recommendations",
    "symptom_info",
]


def orchestra_recommend(
    symptoms_text: Optional[str] = None,
    report: Optional[dict] = None,
    limit: int = 5,
) -> Dict[str, Any]:
    """Рекомендации по симптомам.

    ``symptoms_text`` — ручной ввод (симптомы через запятую/строку);
    ``report`` — «плоский» dict с отчётом BlockCheck (уже :func:`_to_plain`).
    Если задан текст — он приоритетнее отчёта.
    """
    if symptoms_text and str(symptoms_text).strip():
        keys = parse_symptoms_text(str(symptoms_text))
        source = "text"
    else:
        keys = extract_symptoms(report)
        source = "report"

    overview = [
        {"key": key, "label": SYMPTOMS[key]["label"], "description": SYMPTOMS[key]["description"]}
        for key in keys
    ]
    if not keys:
        return {
            "ok": True,
            "source": source,
            "symptoms": [],
            "failure_type": None,
            "recommendations": [],
        }

    top = rank_recommendations(keys, limit=limit)
    return {
        "ok": True,
        "source": source,
        "symptoms": overview,
        "failure_type": _primary_failure(keys),
        "recommendations": top,
    }


def _primary_failure(keys: List[str]) -> Optional[str]:
    revision = {symptom: failure for failure, symptom in FAILURE_TO_SYMPTOM.items()}
    fallback = None
    for key in keys:
        failure = revision.get(key)
        if not failure:
            continue
        if failure == "dns":
            fallback = fallback or failure
            continue
        return failure
    return fallback