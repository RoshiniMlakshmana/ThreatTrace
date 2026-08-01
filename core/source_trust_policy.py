"""Deterministic, advisory source-trust policy for normalized evidence records.

This module evaluates the source and collection metadata already present on
a normalized evidence record (see `core/evidence_normalizer.py`) and
recommends a `trust_level` using fixed, explainable rules. It is a pure,
dependency-free advisory layer:

- It is a deterministic advisory policy only -- every recommendation is
  reproducible from the same input, and nothing here calls a model or
  invents a rating.
- It evaluates *available source and collection metadata* -- nothing more.
  Missing information never increases trust; it only ever lowers or caps it.
- It does not establish whether the evidence content is true. A high trust
  recommendation describes confidence in the source/collection method, not
  a verdict on the underlying claim.
- It does not modify evidence. The input mapping (and its nested
  `provenance` mapping) is only ever read, never mutated, and this module
  never writes to Supabase or any other store.
- It does not calculate `confidence`. That remains a separate, unrelated
  field this module does not touch.
- It does not access Supabase.
- It does not perform MITRE ATT&CK mapping.
- It does not calculate hashes.
- It does not perform approvals, execution, or any audit logic.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from core.evidence_normalizer import ASSERTION_TYPES, SOURCE_TYPES, TRUST_LEVELS

_DIRECT_ASSERTION_TYPES = frozenset({"observation", "derived_fact"})
_INTERPRETIVE_ASSERTION_TYPES = frozenset({"hypothesis", "interpretation", "recommendation"})

_PROVENANCE_STRING_FIELDS = ("collector", "collection_method", "source_reference", "captured_at")

_REASON_CODE_ORDER = (
    "SOURCE_TYPE_UNKNOWN",
    "MISSING_SOURCE_IDENTITY",
    "MISSING_SOURCE_REFERENCE",
    "MISSING_COLLECTION_METHOD",
    "MISSING_TIMESTAMP",
    "INTEGRITY_NOT_RECORDED",
    "INTEGRITY_VERIFIED",
    "INTEGRITY_CHECK_FAILED",
    "INTERPRETIVE_ASSERTION",
    "EXTERNAL_SOURCE_UNCORROBORATED",
    "EXTERNAL_SOURCE_MAX_MEDIUM",
    "CORROBORATION_PRESENT",
    "SUPPLIED_TRUST_MATCHES_RECOMMENDATION",
    "SUPPLIED_TRUST_DIFFERS_FROM_RECOMMENDATION",
    "UNKNOWN_SOURCE_CLAIMS_ELEVATED_TRUST",
)


class SourceTrustPolicyError(ValueError):
    """Raised when input to assess_source_trust() is structurally invalid.

    Missing provenance factors are never an error -- they are normal policy
    outcomes reflected in the recommendation and reason codes. This is only
    raised for malformed input: wrong types, or values outside the imported
    controlled vocabularies.
    """


def _is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    return True


def _check_optional_nonblank_string(value: Any, field_name: str) -> bool:
    """Return True if present (and valid); False if absent. Raises if malformed."""
    if value is None:
        return False
    if not isinstance(value, str) or value.strip() == "":
        raise SourceTrustPolicyError(f"provenance.{field_name} must be a non-empty string when supplied")
    return True


def _check_optional_bool(value: Any, field_name: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise SourceTrustPolicyError(f"provenance.{field_name} must be a boolean when supplied")
    return value


def _check_string_sequence(value: Any, field_name: str) -> None:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise SourceTrustPolicyError(f"provenance.{field_name} must be a list or tuple when supplied")
    for item in value:
        if not isinstance(item, str) or item.strip() == "":
            raise SourceTrustPolicyError(f"provenance.{field_name} entries must be non-empty strings")


def _validate_provenance(raw_provenance: Any) -> dict[str, Any]:
    if raw_provenance is None:
        raw_provenance = {}
    if not isinstance(raw_provenance, Mapping):
        raise SourceTrustPolicyError("provenance must be a mapping")

    presence = {
        field: _check_optional_nonblank_string(raw_provenance.get(field), field)
        for field in _PROVENANCE_STRING_FIELDS
    }

    integrity_verified_value = _check_optional_bool(raw_provenance.get("integrity_verified"), "integrity_verified")

    transformation_steps = raw_provenance.get("transformation_steps")
    if transformation_steps is not None:
        _check_string_sequence(transformation_steps, "transformation_steps")

    corroborated_by = raw_provenance.get("corroborated_by")
    corroborated = False
    if corroborated_by is not None:
        _check_string_sequence(corroborated_by, "corroborated_by")
        corroborated = len(corroborated_by) > 0

    return {
        "collector_present": presence["collector"],
        "collection_method_present": presence["collection_method"],
        "source_reference_present": presence["source_reference"],
        "captured_at_present": presence["captured_at"],
        "integrity_verified_value": integrity_verified_value,
        "corroborated": corroborated,
    }


def _clean_supplied_trust_level(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SourceTrustPolicyError(f"trust_level must be a string, got {type(value).__name__}")
    stripped = value.strip()
    if stripped == "":
        return None
    if stripped not in TRUST_LEVELS:
        raise SourceTrustPolicyError(f"trust_level must be one of {sorted(TRUST_LEVELS)}, got {stripped!r}")
    return stripped


def assess_source_trust(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Recommend a source-trust level for a normalized evidence-like mapping.

    Reads only `source_type`, `assertion_type`, `source_identifier`,
    `source_location`, `observed_at`, `provenance`, and `trust_level` from
    `evidence`; every other field is ignored. Neither `evidence` nor its
    nested `provenance` mapping is ever mutated.

    Returns a new dict:

        {
            "recommended_trust_level": "high" | "medium" | "low" | "unknown",
            "reason_codes": [...],
            "conflicts_with_supplied_trust_level": True | False | None,
        }

    Missing provenance factors are normal, expected outcomes -- they lower
    or cap the recommendation and appear as reason codes; they never raise.
    Raises SourceTrustPolicyError only for structurally invalid input:
    `evidence` or `provenance` not a mapping, or a `source_type`,
    `assertion_type`, or `trust_level` value outside its imported
    controlled vocabulary, or a malformed provenance field.
    """
    if not isinstance(evidence, Mapping):
        raise SourceTrustPolicyError("evidence must be a mapping")

    source_type = evidence.get("source_type")
    if source_type is None:
        source_type = "unknown"
    if source_type not in SOURCE_TYPES:
        raise SourceTrustPolicyError(f"source_type must be one of {sorted(SOURCE_TYPES)}, got {source_type!r}")

    assertion_type = evidence.get("assertion_type")
    if assertion_type is None:
        assertion_type = "unknown"
    if assertion_type not in ASSERTION_TYPES:
        raise SourceTrustPolicyError(
            f"assertion_type must be one of {sorted(ASSERTION_TYPES)}, got {assertion_type!r}"
        )

    provenance_info = _validate_provenance(evidence.get("provenance"))

    identity_known = _is_present(evidence.get("source_identifier")) or provenance_info["collector_present"]
    reference_known = _is_present(evidence.get("source_location")) or provenance_info["source_reference_present"]
    collection_method_known = provenance_info["collection_method_present"]
    timestamp_known = _is_present(evidence.get("observed_at")) or provenance_info["captured_at_present"]
    integrity_ok = provenance_info["integrity_verified_value"] is True
    integrity_failed = provenance_info["integrity_verified_value"] is False
    corroborated = provenance_info["corroborated"]
    interpretive = assertion_type in _INTERPRETIVE_ASSERTION_TYPES
    assertion_is_direct = assertion_type in _DIRECT_ASSERTION_TYPES
    external = source_type == "threat_intelligence"

    if source_type == "unknown" or not identity_known or not collection_method_known:
        tier = "unknown"
    else:
        medium_eligible = (
            identity_known
            and reference_known
            and collection_method_known
            and timestamp_known
            and assertion_is_direct
            and not integrity_failed
            and (integrity_ok or corroborated)
            and (not external or corroborated)
        )
        high_eligible = (
            medium_eligible
            and integrity_ok
            and corroborated
            and assertion_is_direct
            and not external
        )
        if high_eligible:
            tier = "high"
        elif medium_eligible:
            tier = "medium"
        else:
            tier = "low"

    applicable: set[str] = set()

    if source_type == "unknown":
        applicable.add("SOURCE_TYPE_UNKNOWN")
    if not identity_known:
        applicable.add("MISSING_SOURCE_IDENTITY")
    if not reference_known:
        applicable.add("MISSING_SOURCE_REFERENCE")
    if not collection_method_known:
        applicable.add("MISSING_COLLECTION_METHOD")
    if not timestamp_known:
        applicable.add("MISSING_TIMESTAMP")

    if integrity_failed:
        applicable.add("INTEGRITY_CHECK_FAILED")
    elif integrity_ok:
        applicable.add("INTEGRITY_VERIFIED")
    else:
        applicable.add("INTEGRITY_NOT_RECORDED")

    if interpretive:
        applicable.add("INTERPRETIVE_ASSERTION")

    if external and not corroborated:
        applicable.add("EXTERNAL_SOURCE_UNCORROBORATED")
    if external:
        applicable.add("EXTERNAL_SOURCE_MAX_MEDIUM")

    if corroborated:
        applicable.add("CORROBORATION_PRESENT")

    supplied_trust_level = _clean_supplied_trust_level(evidence.get("trust_level"))

    conflicts: bool | None
    if supplied_trust_level is None or supplied_trust_level == "unknown":
        conflicts = None
    else:
        if supplied_trust_level == tier:
            conflicts = False
            applicable.add("SUPPLIED_TRUST_MATCHES_RECOMMENDATION")
        else:
            conflicts = True
            applicable.add("SUPPLIED_TRUST_DIFFERS_FROM_RECOMMENDATION")
        if source_type == "unknown" and supplied_trust_level in ("high", "medium", "low"):
            applicable.add("UNKNOWN_SOURCE_CLAIMS_ELEVATED_TRUST")

    reason_codes = [code for code in _REASON_CODE_ORDER if code in applicable]

    return {
        "recommended_trust_level": tier,
        "reason_codes": reason_codes,
        "conflicts_with_supplied_trust_level": conflicts,
    }
