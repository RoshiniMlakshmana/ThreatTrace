"""Pure, deterministic validator for one advisory "What Would Change My
Decision?" analysis object.

This module performs structural validation and canonicalization only:

- It validates a proposed decision-analysis object; it does not generate
  the analysis itself.
- It does not decide `decision_status` -- it only checks that a supplied
  value is one of the controlled vocabulary members. The status is always
  analyst- or caller-supplied, never computed here.
- It does not verify that `investigation_id` or any evidence ID actually
  exists in Supabase, and it does not verify evidence ownership. Those are
  contextual database checks that belong to a later, separate read-only
  orchestration layer -- this module never queries Supabase.
- `hypothesis_id` is restricted to `None` in this version. ThreatTrace has
  no structured hypothesis table or persisted hypothesis identifier today,
  so accepting a non-null value here would imply a database concept that
  doesn't exist. Every non-null `hypothesis_id` is rejected.
- Evidence IDs (`supporting_evidence_ids`, `contradicting_evidence_ids`)
  are references only -- structurally valid UUIDs, nothing more. Empty
  supporting and/or contradicting evidence is valid, including for
  `inconclusive` and `insufficient_evidence`.
- The condition-style fields (`unresolved_assumptions`, `evidence_gaps`,
  `strengthen_conditions`, `weaken_conditions`, `reversal_conditions`,
  `recommended_next_evidence`, `limitations`) are advisory free text
  supplied by an analyst or a later reasoning layer. This module trims,
  deduplicates, and shape-checks them -- it never reinterprets or
  categorizes their content, and it never decides whether a condition
  truly strengthens, weakens, or reverses an assessment.
- The object this module returns is not persisted anywhere by this module.
- No confidence or source-trust calculation occurs here, and no external
  side effect (Supabase, file, subprocess, network, AI model call) occurs
  anywhere in this module.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

DECISION_STATUSES = frozenset({
    "supported",
    "partially_supported",
    "contradicted",
    "inconclusive",
    "insufficient_evidence",
})

_CONDITION_FIELDS = (
    "unresolved_assumptions",
    "evidence_gaps",
    "strengthen_conditions",
    "weaken_conditions",
    "reversal_conditions",
    "recommended_next_evidence",
    "limitations",
)

_EVIDENCE_ID_FIELDS = ("supporting_evidence_ids", "contradicting_evidence_ids")

_ALLOWED_FIELDS = frozenset(
    (
        "investigation_id",
        "hypothesis_id",
        "current_assessment",
        "decision_status",
        "generated_at",
    )
    + _EVIDENCE_ID_FIELDS
    + _CONDITION_FIELDS
)


class DecisionAnalysisError(ValueError):
    """Raised when a proposed decision-analysis object is structurally invalid.

    This is only raised for malformed input (wrong type, unknown field,
    unsupported vocabulary value, malformed UUID/timestamp, duplicate
    entry). It is never raised because the analysis itself is weak, e.g.
    an empty supporting-evidence list is a normal, valid outcome, not an
    error.
    """


def _validate_uuid_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise DecisionAnalysisError(f"{field_name} must be a string")
    stripped = value.strip()
    if not stripped:
        raise DecisionAnalysisError(f"{field_name} must not be blank")
    try:
        parsed = uuid.UUID(stripped)
    except ValueError as exc:
        raise DecisionAnalysisError(f"{field_name} must be a structurally valid UUID") from exc
    return str(parsed)


def _require_uuid_field(payload: Mapping[str, Any], field_name: str) -> str:
    if field_name not in payload:
        raise DecisionAnalysisError(f"{field_name} is required")
    return _validate_uuid_string(payload[field_name], field_name)


def _require_nonblank_string(payload: Mapping[str, Any], field_name: str) -> str:
    if field_name not in payload:
        raise DecisionAnalysisError(f"{field_name} is required")
    value = payload[field_name]
    if not isinstance(value, str):
        raise DecisionAnalysisError(f"{field_name} must be a string")
    stripped = value.strip()
    if not stripped:
        raise DecisionAnalysisError(f"{field_name} must not be blank")
    return stripped


def _validate_hypothesis_id(payload: Mapping[str, Any]) -> None:
    if "hypothesis_id" not in payload:
        return None
    value = payload["hypothesis_id"]
    if value is None:
        return None
    raise DecisionAnalysisError(
        "hypothesis_id must be null -- non-null hypothesis identifiers are unsupported "
        "until a structured hypothesis model exists"
    )


def _validate_decision_status(payload: Mapping[str, Any]) -> str:
    value = _require_nonblank_string(payload, "decision_status")
    normalized = value.lower()
    if normalized not in DECISION_STATUSES:
        raise DecisionAnalysisError(
            f"decision_status must be one of {sorted(DECISION_STATUSES)}, got {normalized!r}"
        )
    return normalized


def _validate_evidence_id_list(payload: Mapping[str, Any], field_name: str) -> list[str]:
    if field_name not in payload:
        return []
    value = payload[field_name]
    if not isinstance(value, list):
        raise DecisionAnalysisError(f"{field_name} must be a list")

    canonical_ids: list[str] = []
    seen: set[str] = set()
    for item in value:
        canonical = _validate_uuid_string(item, f"{field_name} entry")
        if canonical in seen:
            raise DecisionAnalysisError(f"{field_name} contains a duplicate evidence ID: {canonical}")
        seen.add(canonical)
        canonical_ids.append(canonical)
    return canonical_ids


def _validate_condition_list(payload: Mapping[str, Any], field_name: str) -> list[str]:
    if field_name not in payload:
        return []
    value = payload[field_name]
    if value is None:
        raise DecisionAnalysisError(f"{field_name} must be a list, not null")
    if not isinstance(value, list):
        raise DecisionAnalysisError(f"{field_name} must be a list")

    entries: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise DecisionAnalysisError(f"{field_name} entries must be strings")
        stripped = item.strip()
        if not stripped:
            raise DecisionAnalysisError(f"{field_name} entries must not be blank")
        if stripped in seen:
            raise DecisionAnalysisError(f"{field_name} contains a duplicate entry: {stripped!r}")
        seen.add(stripped)
        entries.append(stripped)
    return entries


def _normalize_timestamp(value: Any, field_name: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise DecisionAnalysisError(f"{field_name} must not be blank")
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError as exc:
            raise DecisionAnalysisError(f"{field_name} is not a valid ISO-8601 timestamp") from exc
    else:
        raise DecisionAnalysisError(f"{field_name} must be a string or datetime")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DecisionAnalysisError(f"{field_name} must include timezone information")

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_generated_at(payload: Mapping[str, Any], now: datetime | None) -> str:
    if now is not None:
        if not isinstance(now, datetime):
            raise DecisionAnalysisError("now must be a datetime")
        if now.tzinfo is None or now.utcoffset() is None:
            raise DecisionAnalysisError("now must be timezone-aware")

    generated_at_value = payload.get("generated_at")
    if generated_at_value is None:
        base = now if now is not None else datetime.now(timezone.utc)
        return _normalize_timestamp(base, "generated_at")
    return _normalize_timestamp(generated_at_value, "generated_at")


def validate_decision_analysis(
    payload: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate and canonicalize one proposed decision-analysis object.

    Reads only the fourteen fields listed in the module docstring; any
    other top-level field is rejected. Neither `payload` nor any nested
    list within it is ever mutated -- a new, independently-owned dictionary
    is always returned.

    Raises DecisionAnalysisError for any structurally invalid input:
    `payload` not a mapping, an unknown top-level field, a missing/blank
    required field, a malformed UUID, a non-null `hypothesis_id`, an
    unsupported `decision_status`, a malformed condition/evidence-ID list,
    a duplicate evidence ID (within either list or across both), a
    duplicate condition entry, or a malformed/timezone-naive timestamp.
    """
    if not isinstance(payload, Mapping):
        raise DecisionAnalysisError("payload must be a mapping")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise DecisionAnalysisError(
            "unrecognized field(s): " + ", ".join(sorted(unknown_fields))
        )

    result: dict[str, Any] = {}

    result["investigation_id"] = _require_uuid_field(payload, "investigation_id")
    result["hypothesis_id"] = _validate_hypothesis_id(payload)
    result["current_assessment"] = _require_nonblank_string(payload, "current_assessment")
    result["decision_status"] = _validate_decision_status(payload)

    supporting = _validate_evidence_id_list(payload, "supporting_evidence_ids")
    contradicting = _validate_evidence_id_list(payload, "contradicting_evidence_ids")
    overlap = set(supporting) & set(contradicting)
    if overlap:
        raise DecisionAnalysisError(
            "evidence ID(s) appear in both supporting_evidence_ids and "
            "contradicting_evidence_ids: " + ", ".join(sorted(overlap))
        )
    result["supporting_evidence_ids"] = supporting
    result["contradicting_evidence_ids"] = contradicting

    for field in _CONDITION_FIELDS:
        result[field] = _validate_condition_list(payload, field)

    result["generated_at"] = _validate_generated_at(payload, now)

    return result
