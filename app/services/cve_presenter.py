import ast
import math
from typing import Any


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value.strip().lower() in {"", "nan", "none", "null"}:
        return True
    return False


def _to_literal(raw_value: str | None):
    if _is_missing(raw_value):
        return []
    try:
        parsed = ast.literal_eval(raw_value)
    except (ValueError, SyntaxError):
        return []
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return []


def normalize_score(raw_value: str | None) -> float | None:
    if _is_missing(raw_value):
        return None
    try:
        numeric_value = float(raw_value)
    except (TypeError, ValueError):
        return None
    if math.isnan(numeric_value):
        return None
    return numeric_value


def score_to_severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def extract_description(raw_value: str | None) -> str | None:
    entries = _to_literal(raw_value)
    preferred_text = None
    fallback_text = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        value = entry.get("value")
        if _is_missing(value):
            continue
        if entry.get("lang") == "en":
            preferred_text = str(value).strip()
            break
        if fallback_text is None:
            fallback_text = str(value).strip()
    return preferred_text or fallback_text or (None if _is_missing(raw_value) else str(raw_value).strip())


def extract_problem_types(raw_value: str | None) -> list[str]:
    values: list[str] = []
    for entry in _to_literal(raw_value):
        if not isinstance(entry, dict):
            continue
        for description in entry.get("description", []):
            if not isinstance(description, dict):
                continue
            value = description.get("value")
            if _is_missing(value):
                continue
            values.append(str(value).strip())
    return list(dict.fromkeys(values))


def extract_references(raw_value: str | None) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    for entry in _to_literal(raw_value):
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if _is_missing(url):
            continue
        references.append(
            {
                "url": str(url).strip(),
                "name": str(entry.get("name") or url).strip(),
                "tags": [str(tag).strip() for tag in (entry.get("tags") or []) if not _is_missing(tag)],
            }
        )
    return references


def effective_severity(cve) -> str | None:
    for candidate in (getattr(cve, "severity", None), getattr(cve, "cvss3_base_severity", None)):
        if not _is_missing(candidate):
            return str(candidate).strip().upper()
    return score_to_severity(normalize_score(getattr(cve, "cvss3_base_score", None)))


def present_cve(cve) -> dict[str, Any]:
    numeric_score = normalize_score(getattr(cve, "cvss3_base_score", None))
    return {
        "cve_id": cve.cve_id,
        "published_date": None if _is_missing(cve.published_date) else cve.published_date,
        "last_modified_date": None if _is_missing(cve.last_modified_date) else cve.last_modified_date,
        "description": extract_description(cve.description),
        "severity": effective_severity(cve),
        "cvss3_base_score": numeric_score,
        "cvss3_base_severity": None if _is_missing(cve.cvss3_base_severity) else str(cve.cvss3_base_severity).strip().upper(),
        "attack_vector": None if _is_missing(cve.cvss3_attack_vector) else cve.cvss3_attack_vector,
        "attack_complexity": None if _is_missing(cve.cvss3_attack_complexity) else cve.cvss3_attack_complexity,
        "privileges_required": None if _is_missing(cve.cvss3_privileges_required) else cve.cvss3_privileges_required,
        "user_interaction": None if _is_missing(cve.cvss3_user_interaction) else cve.cvss3_user_interaction,
        "scope": None if _is_missing(cve.cvss3_scope) else cve.cvss3_scope,
        "exploitability_score": normalize_score(getattr(cve, "exploitability_score", None)),
        "impact_score": normalize_score(getattr(cve, "impact_score", None)),
        "problem_types": extract_problem_types(cve.problemtype_json),
        "references": extract_references(cve.reference_json),
    }
