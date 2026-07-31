"""Normalized evidence contract shared by every ThreatTrace evidence source.

This module standardizes the *structure* of an evidence record before it is
inserted into the `evidence` table (see `supabase/schema.sql`). It is a pure,
dependency-free transformation layer intended for reuse by `/add-evidence`,
Hayabusa ingestion, threat-intelligence ingestion, query-result ingestion,
and Threat Hunter findings.

What this module explicitly does NOT do:

- It does not determine whether evidence is true. Trimming, casing, and
  vocabulary checks are structural only -- they say nothing about accuracy.
- It does not perform MITRE ATT&CK mapping.
- It does not calculate an evidence hash.
- It does not infer source trust, confidence, hypotheses, or recommendations
  that the caller did not explicitly supply.

Where source-specific data belongs:

- Raw, source-specific fields that don't fit the normalized envelope belong
  in `details`.
- Metadata about how/where a record was produced (e.g. which tool run,
  which ingestion pipeline, transformation notes) belongs in `provenance`.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

SOURCE_TYPES = frozenset({
    "analyst",
    "hayabusa",
    "threat_intelligence",
    "query_result",
    "threat_hunter",
    "system",
    "unknown",
})

ASSERTION_TYPES = frozenset({
    "observation",
    "derived_fact",
    "hypothesis",
    "interpretation",
    "recommendation",
    "unknown",
})

TRUST_LEVELS = frozenset({"high", "medium", "low", "unknown"})

CONFIDENCE_LEVELS = frozenset({"high", "medium", "low", "unknown"})

_REQUIRED_STRING_FIELDS = ("investigation_id", "evidence_type", "source")

_FREEFORM_OPTIONAL_STRING_FIELDS = (
    "source_identifier",
    "source_location",
    "host_name",
    "user_name",
    "process_name",
    "command_line",
    "ip_address",
)

_CONTROLLED_FIELDS = (
    ("source_type", SOURCE_TYPES),
    ("assertion_type", ASSERTION_TYPES),
    ("trust_level", TRUST_LEVELS),
    ("confidence", CONFIDENCE_LEVELS),
)

_ALLOWED_FIELDS = frozenset(
    _REQUIRED_STRING_FIELDS
    + _FREEFORM_OPTIONAL_STRING_FIELDS
    + (
        "observed_at",
        "details",
        "supports_hypothesis",
        "ingested_at",
        "event_id",
        "file_hash",
        "provenance",
    )
    + tuple(field for field, _vocabulary in _CONTROLLED_FIELDS)
)


class EvidenceValidationError(ValueError):
    """Raised when a payload does not satisfy the normalized evidence contract."""


def _require_string(payload: Mapping[str, Any], field: str) -> str:
    if field not in payload:
        raise EvidenceValidationError(f"{field} is required")
    value = payload[field]
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{field} must be a string")
    stripped = value.strip()
    if not stripped:
        raise EvidenceValidationError(f"{field} must not be blank")
    return stripped


def _normalize_optional_string(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{field} must be a string or null")
    stripped = value.strip()
    return stripped or None


def _normalize_controlled_value(value: Any, field: str, vocabulary: frozenset[str]) -> str:
    if value is None:
        return "unknown"
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{field} must be a string")
    normalized = value.strip().lower()
    if not normalized:
        return "unknown"
    if normalized not in vocabulary:
        raise EvidenceValidationError(
            f"{field} must be one of {sorted(vocabulary)}, got {normalized!r}"
        )
    return normalized


def _normalize_mapping_field(value: Any, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise EvidenceValidationError(f"{field} must be a mapping")
    return copy.deepcopy(dict(value))


def _normalize_supports_hypothesis(value: Any) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise EvidenceValidationError("supports_hypothesis must be true, false, or null")
    return value


def _normalize_event_id(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise EvidenceValidationError("event_id must not be a boolean")
    if isinstance(value, str):
        text = value.strip()
    elif isinstance(value, int):
        text = str(value)
    else:
        raise EvidenceValidationError("event_id must be a string or integer")
    return text or None


def _normalize_file_hash(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EvidenceValidationError("file_hash must be a string")
    stripped = value.strip().lower()
    return stripped or None


def _normalize_timestamp(value: Any, field: str) -> str:
    """Normalize a tz-aware datetime or ISO-8601 string to UTC, ending in 'Z'."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise EvidenceValidationError(f"{field} must not be blank")
        # datetime.fromisoformat() does not accept a trailing 'Z' until
        # Python 3.11; this project supports 3.10, so normalize it first.
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError as exc:
            raise EvidenceValidationError(
                f"{field} is not a valid ISO-8601 timestamp"
            ) from exc
    else:
        raise EvidenceValidationError(f"{field} must be a string or datetime")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceValidationError(f"{field} must include timezone information")

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_optional_timestamp(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _normalize_timestamp(value, field)


def normalize_evidence(
    payload: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Normalize a raw evidence payload into the shape the `evidence` table expects.

    This performs structural validation and normalization only: required
    fields, controlled vocabularies, timestamp formatting, and type checks.
    It does not judge truth, does not map ATT&CK techniques, and does not
    compute a hash. The input `payload` is never mutated; a new,
    independently-owned dictionary is always returned.

    Raises EvidenceValidationError if `payload` is not a mapping, is missing
    a required field, contains a blank required field, contains an unknown
    top-level field (including database-generated fields like `id` or
    `created_at`), or contains a value that fails its field's rules.
    """
    if not isinstance(payload, Mapping):
        raise EvidenceValidationError("payload must be a mapping")

    unknown_fields = set(payload) - _ALLOWED_FIELDS
    if unknown_fields:
        raise EvidenceValidationError(
            "unrecognized field(s): "
            + ", ".join(sorted(unknown_fields))
            + " -- place source-specific information inside 'details' or 'provenance'"
        )

    result: dict[str, Any] = {}

    for field in _REQUIRED_STRING_FIELDS:
        result[field] = _require_string(payload, field)

    result["observed_at"] = _normalize_optional_timestamp(payload.get("observed_at"), "observed_at")

    ingested_at_value = payload.get("ingested_at")
    if ingested_at_value is None:
        base_now = now if now is not None else datetime.now(timezone.utc)
        result["ingested_at"] = _normalize_timestamp(base_now, "ingested_at")
    else:
        result["ingested_at"] = _normalize_timestamp(ingested_at_value, "ingested_at")

    result["details"] = _normalize_mapping_field(payload.get("details"), "details")
    result["provenance"] = _normalize_mapping_field(payload.get("provenance"), "provenance")

    result["supports_hypothesis"] = _normalize_supports_hypothesis(payload.get("supports_hypothesis"))

    for field, vocabulary in _CONTROLLED_FIELDS:
        result[field] = _normalize_controlled_value(payload.get(field), field, vocabulary)

    for field in _FREEFORM_OPTIONAL_STRING_FIELDS:
        result[field] = _normalize_optional_string(payload.get(field), field)

    result["event_id"] = _normalize_event_id(payload.get("event_id"))
    result["file_hash"] = _normalize_file_hash(payload.get("file_hash"))

    return result
