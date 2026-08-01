"""Pure, deterministic validator for already-loaded investigation and
evidence mappings, producing a summarized context bundle for a future
"What Would Change My Decision?" preview.

This module validates already-loaded database-shaped mappings; it does not
load records itself. Existence checks (does this investigation or evidence
row actually exist in Supabase) remain entirely the caller's responsibility
-- this module only checks structural consistency among whatever it was
handed. Record-set completeness is validated only against the records
supplied in `evidence_records`, never against a live database.

Evidence ownership is verified structurally: every evidence record's
`investigation_id` must match the stated investigation, by simple
canonicalized-UUID comparison -- there is no database lookup involved.

Warnings are advisory metadata observations derived only from a record's
own stored fields (`trust_level`, `confidence`, `assertion_type`,
`supports_hypothesis`) and its analyst-assigned group. They never filter,
remove, or modify evidence, and they never change any calculated value --
there is nothing calculated here to change. Analyst-selected group
placement (which evidence is "supporting" vs. "contradicting") is always
preserved in its original order.

Complete evidence content (`details`, `provenance`, and every other
database column not explicitly required) is deliberately excluded from the
output -- only five summarized fields per evidence record are returned.

This module does not generate a decision analysis, does not calculate
`decision_status` or confidence, does not modify `trust_level`, and has no
persistence or other external side effect anywhere in it.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from core.evidence_normalizer import ASSERTION_TYPES, CONFIDENCE_LEVELS, TRUST_LEVELS

INVESTIGATION_STATUSES = frozenset({
    "open",
    "investigating",
    "awaiting_evidence",
    "escalated",
    "closed",
})

WARNING_CODES = frozenset({
    "EVIDENCE_TRUST_UNKNOWN",
    "EVIDENCE_TRUST_LOW",
    "EVIDENCE_CONFIDENCE_UNKNOWN",
    "EVIDENCE_IS_INTERPRETATION",
    "EVIDENCE_IS_HYPOTHESIS",
    "EVIDENCE_IS_RECOMMENDATION",
    "SUPPORTS_HYPOTHESIS_CONFLICT",
    "SUPPORTS_HYPOTHESIS_UNSPECIFIED",
})

_REQUIRED_EVIDENCE_RECORD_FIELDS = (
    "id",
    "investigation_id",
    "trust_level",
    "confidence",
    "assertion_type",
    "supports_hypothesis",
)

_REQUIRED_TOP_LEVEL_FIELDS = (
    "investigation_id",
    "investigation",
    "supporting_evidence_ids",
    "contradicting_evidence_ids",
    "evidence_records",
)

_ALLOWED_TOP_LEVEL_FIELDS = frozenset(_REQUIRED_TOP_LEVEL_FIELDS)


class DecisionContextError(ValueError):
    """Raised when a proposed decision-context request is structurally invalid.

    This is only raised for malformed input, ownership violations, or
    record-set mismatches (wrong type, unknown field, unsupported
    vocabulary value, malformed UUID, duplicate/overlapping IDs, a missing
    or unrequested evidence record, cross-investigation evidence). It is
    never raised because cited evidence is weak, low-trust, or
    interpretive -- those produce advisory warnings instead.
    """


def _validate_uuid_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise DecisionContextError(f"{field_name} must be a string")
    stripped = value.strip()
    if not stripped:
        raise DecisionContextError(f"{field_name} must not be blank")
    try:
        parsed = uuid.UUID(stripped)
    except ValueError as exc:
        raise DecisionContextError(f"{field_name} must be a structurally valid UUID") from exc
    return str(parsed)


def _require_controlled_string(value: Any, field_name: str, vocabulary: frozenset[str]) -> str:
    if not isinstance(value, str):
        raise DecisionContextError(f"{field_name} must be a string")
    normalized = value.strip().lower()
    if normalized not in vocabulary:
        raise DecisionContextError(
            f"{field_name} must be one of {sorted(vocabulary)}, got {normalized!r}"
        )
    return normalized


def _validate_supports_hypothesis(value: Any, field_name: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise DecisionContextError(f"{field_name} must be true, false, or null")
    return value


def _validate_investigation(investigation: Any, expected_investigation_id: str) -> dict[str, Any]:
    if not isinstance(investigation, Mapping):
        raise DecisionContextError("investigation must be a mapping")

    for field_name in ("id", "status", "confidence"):
        if field_name not in investigation:
            raise DecisionContextError(f"investigation.{field_name} is required")

    canonical_id = _validate_uuid_string(investigation["id"], "investigation.id")
    if canonical_id != expected_investigation_id:
        raise DecisionContextError(
            "investigation.id does not match the top-level investigation_id"
        )

    status = _require_controlled_string(investigation["status"], "investigation.status", INVESTIGATION_STATUSES)
    confidence = _require_controlled_string(
        investigation["confidence"], "investigation.confidence", CONFIDENCE_LEVELS
    )

    return {"id": canonical_id, "status": status, "confidence": confidence}


def _validate_evidence_id_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise DecisionContextError(f"{field_name} must be a list")

    canonical_ids: list[str] = []
    seen: set[str] = set()
    for item in value:
        canonical = _validate_uuid_string(item, f"{field_name} entry")
        if canonical in seen:
            raise DecisionContextError(f"{field_name} contains a duplicate evidence ID: {canonical}")
        seen.add(canonical)
        canonical_ids.append(canonical)
    return canonical_ids


def _validate_evidence_records(value: Any, expected_investigation_id: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise DecisionContextError("evidence_records must be a list")

    records_by_id: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, Mapping):
            raise DecisionContextError("each evidence_records entry must be a mapping")

        for field_name in _REQUIRED_EVIDENCE_RECORD_FIELDS:
            if field_name not in item:
                raise DecisionContextError(f"evidence_records entry is missing required field {field_name!r}")

        canonical_id = _validate_uuid_string(item["id"], "evidence_records entry id")
        if canonical_id in records_by_id:
            raise DecisionContextError(f"evidence_records contains a duplicate evidence record: {canonical_id}")

        canonical_investigation_id = _validate_uuid_string(
            item["investigation_id"], "evidence_records entry investigation_id"
        )
        if canonical_investigation_id != expected_investigation_id:
            raise DecisionContextError(
                f"evidence record {canonical_id} belongs to a different investigation"
            )

        trust_level = _require_controlled_string(item["trust_level"], "evidence_records entry trust_level", TRUST_LEVELS)
        confidence = _require_controlled_string(item["confidence"], "evidence_records entry confidence", CONFIDENCE_LEVELS)
        assertion_type = _require_controlled_string(
            item["assertion_type"], "evidence_records entry assertion_type", ASSERTION_TYPES
        )
        supports_hypothesis = _validate_supports_hypothesis(
            item["supports_hypothesis"], "evidence_records entry supports_hypothesis"
        )

        records_by_id[canonical_id] = {
            "id": canonical_id,
            "trust_level": trust_level,
            "confidence": confidence,
            "assertion_type": assertion_type,
            "supports_hypothesis": supports_hypothesis,
        }

    return records_by_id


def _collect_warnings(evidence_id: str, metadata: Mapping[str, Any], group: str) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []

    if metadata["trust_level"] == "unknown":
        warnings.append({"evidence_id": evidence_id, "code": "EVIDENCE_TRUST_UNKNOWN"})
    elif metadata["trust_level"] == "low":
        warnings.append({"evidence_id": evidence_id, "code": "EVIDENCE_TRUST_LOW"})

    if metadata["confidence"] == "unknown":
        warnings.append({"evidence_id": evidence_id, "code": "EVIDENCE_CONFIDENCE_UNKNOWN"})

    assertion_type = metadata["assertion_type"]
    if assertion_type == "interpretation":
        warnings.append({"evidence_id": evidence_id, "code": "EVIDENCE_IS_INTERPRETATION"})
    elif assertion_type == "hypothesis":
        warnings.append({"evidence_id": evidence_id, "code": "EVIDENCE_IS_HYPOTHESIS"})
    elif assertion_type == "recommendation":
        warnings.append({"evidence_id": evidence_id, "code": "EVIDENCE_IS_RECOMMENDATION"})

    supports_hypothesis = metadata["supports_hypothesis"]
    if supports_hypothesis is None:
        warnings.append({"evidence_id": evidence_id, "code": "SUPPORTS_HYPOTHESIS_UNSPECIFIED"})
    elif (group == "supporting" and supports_hypothesis is False) or (
        group == "contradicting" and supports_hypothesis is True
    ):
        warnings.append({"evidence_id": evidence_id, "code": "SUPPORTS_HYPOTHESIS_CONFLICT"})

    return warnings


def _build_summary(evidence_id: str, metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "trust_level": metadata["trust_level"],
        "confidence": metadata["confidence"],
        "assertion_type": metadata["assertion_type"],
        "supports_hypothesis": metadata["supports_hypothesis"],
    }


def validate_decision_context(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate already-loaded investigation/evidence mappings and build a context bundle.

    Reads exactly five required top-level fields: `investigation_id`,
    `investigation`, `supporting_evidence_ids`, `contradicting_evidence_ids`,
    `evidence_records`. Neither `payload` nor any nested mapping/list is
    ever mutated -- a new, independently-owned dictionary is always
    returned.

    Returns:

        {
            "investigation": {"id": ..., "status": ..., "confidence": ...},
            "supporting_evidence": [{"id": ..., "trust_level": ...,
                "confidence": ..., "assertion_type": ...,
                "supports_hypothesis": ...}, ...],
            "contradicting_evidence": [...],
            "warnings": [{"evidence_id": ..., "code": ...}, ...],
        }

    Raises DecisionContextError for any structurally invalid input: a
    non-mapping payload, an unknown or missing top-level field, a
    malformed UUID, an investigation/evidence-record shape or vocabulary
    violation, a duplicate or overlapping evidence ID, a missing or
    unrequested evidence record, or cross-investigation evidence. Weak
    evidence (low/unknown trust, interpretive assertion types, a
    supports_hypothesis conflict or None) is never rejected -- it produces
    an advisory warning instead.
    """
    if not isinstance(payload, Mapping):
        raise DecisionContextError("payload must be a mapping")

    unknown_fields = set(payload) - _ALLOWED_TOP_LEVEL_FIELDS
    if unknown_fields:
        raise DecisionContextError(
            "unrecognized field(s): " + ", ".join(sorted(unknown_fields))
        )

    missing_fields = [field for field in _REQUIRED_TOP_LEVEL_FIELDS if field not in payload]
    if missing_fields:
        raise DecisionContextError(
            "missing required field(s): " + ", ".join(missing_fields)
        )

    investigation_id = _validate_uuid_string(payload["investigation_id"], "investigation_id")
    investigation_summary = _validate_investigation(payload["investigation"], investigation_id)

    supporting_ids = _validate_evidence_id_list(payload["supporting_evidence_ids"], "supporting_evidence_ids")
    contradicting_ids = _validate_evidence_id_list(
        payload["contradicting_evidence_ids"], "contradicting_evidence_ids"
    )

    overlap = set(supporting_ids) & set(contradicting_ids)
    if overlap:
        raise DecisionContextError(
            "evidence ID(s) appear in both supporting_evidence_ids and "
            "contradicting_evidence_ids: " + ", ".join(sorted(overlap))
        )

    records_by_id = _validate_evidence_records(payload["evidence_records"], investigation_id)

    requested_ids = set(supporting_ids) | set(contradicting_ids)
    record_ids = set(records_by_id)

    missing_records = requested_ids - record_ids
    if missing_records:
        raise DecisionContextError(
            "no evidence record supplied for requested evidence ID(s): "
            + ", ".join(sorted(missing_records))
        )

    unrequested_records = record_ids - requested_ids
    if unrequested_records:
        raise DecisionContextError(
            "evidence_records contains unrequested evidence ID(s): "
            + ", ".join(sorted(unrequested_records))
        )

    supporting_evidence = [_build_summary(eid, records_by_id[eid]) for eid in supporting_ids]
    contradicting_evidence = [_build_summary(eid, records_by_id[eid]) for eid in contradicting_ids]

    warnings: list[dict[str, str]] = []
    for evidence_id in supporting_ids:
        warnings.extend(_collect_warnings(evidence_id, records_by_id[evidence_id], "supporting"))
    for evidence_id in contradicting_ids:
        warnings.extend(_collect_warnings(evidence_id, records_by_id[evidence_id], "contradicting"))

    return {
        "investigation": investigation_summary,
        "supporting_evidence": supporting_evidence,
        "contradicting_evidence": contradicting_evidence,
        "warnings": warnings,
    }
