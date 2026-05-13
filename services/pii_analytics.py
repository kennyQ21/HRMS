from __future__ import annotations

from typing import Any

RISK_WEIGHTS = {
    "password": 1.0,
    "cvv": 0.95,
    "credit_card": 0.9,
    "aadhaar": 0.85,
    "pan": 0.8,
    "bank_account": 0.75,
    "phone": 0.4,
    "email": 0.3,
    "name": 0.2,
}
EXCLUDED_ANALYTICS_TYPES = {"ORGANIZATION"}
GOVERNMENT_ID_TYPES = {"AADHAAR", "PAN", "DRIVING_LICENSE", "PASSPORT", "VOTER_ID"}


def calculate_distribution(entities: list[Any]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for e in entities:
        pii_type = str(getattr(e, "pii_type", "unknown")).upper()
        if pii_type in EXCLUDED_ANALYTICS_TYPES:
            continue
        distribution[pii_type] = distribution.get(pii_type, 0) + 1
    return distribution


def calculate_risk_score(distribution: dict[str, int]) -> float:
    filtered_distribution = {
        pii_type: count
        for pii_type, count in distribution.items()
        if pii_type not in EXCLUDED_ANALYTICS_TYPES
    }
    total_entities = sum(filtered_distribution.values())
    if total_entities == 0:
        return 0.0

    weighted_total = 0.0
    for pii_type, count in filtered_distribution.items():
        weight = RISK_WEIGHTS.get(pii_type.lower(), 0.2)
        weighted_total += weight * count

    return round(weighted_total / total_entities, 4)


def risk_level_from_score(score: float, distribution: dict[str, int] | None = None) -> str:
    distribution = distribution or {}
    filtered_distribution = {
        pii_type: count
        for pii_type, count in distribution.items()
        if pii_type not in EXCLUDED_ANALYTICS_TYPES
    }
    gov_id_total = sum(
        count for pii_type, count in filtered_distribution.items()
        if pii_type in GOVERNMENT_ID_TYPES
    )
    # Government IDs should never be LOW; multiple IDs are elevated to HIGH.
    if gov_id_total >= 2:
        return "HIGH"
    if gov_id_total == 1:
        return "MEDIUM"
    if score <= 0.3:
        return "LOW"
    if score <= 0.7:
        return "MEDIUM"
    return "HIGH"


def summarize_entities(entities: list[Any]) -> dict[str, Any]:
    distribution = calculate_distribution(entities)
    risk_score = calculate_risk_score(distribution)
    return {
        "total_entities": sum(distribution.values()),
        "unique_types": len(distribution),
        "risk_score": risk_score,
        "risk_level": risk_level_from_score(risk_score, distribution),
    }
