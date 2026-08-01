"""Pure, deterministic formatter for already-produced decision-context
warning objects.

This module formats existing structured warnings only -- it never
generates a warning itself. Warning generation and warning ordering both
belong entirely to `core.decision_context.validate_decision_context`; this
module receives whatever list that validator already produced and simply
attaches one fixed, deterministic explanation string to each entry, in the
same order it was given.

The formatter never infers a new warning, never re-derives or re-sorts
warning precedence, never interprets evidence, and never touches
`decision_status`, confidence, or `trust_level`. Every explanation is fixed
display text -- there is no model-generated or otherwise variable
commentary anywhere in this module. Warnings remain strictly advisory:
evidence referenced by a warning is never filtered, removed, or modified,
and no claim of maliciousness, guilt, or attribution is ever made.

No database lookup (Supabase or otherwise), file, subprocess, network,
AI-model call, or other external side effect occurs anywhere in this
module.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

_ALLOWED_WARNING_FIELDS = frozenset({"evidence_id", "code"})

_WARNING_EXPLANATIONS: dict[str, str] = {
    "EVIDENCE_TRUST_UNKNOWN": "Source trust for this evidence has not been recorded.",
    "EVIDENCE_TRUST_LOW": "Source trust for this evidence is recorded as low.",
    "EVIDENCE_CONFIDENCE_UNKNOWN": "Confidence for this evidence has not been recorded.",
    "EVIDENCE_IS_INTERPRETATION": "This evidence is recorded as an interpretation, not a direct observation.",
    "EVIDENCE_IS_HYPOTHESIS": "This evidence is recorded as a hypothesis, not a direct observation.",
    "EVIDENCE_IS_RECOMMENDATION": "This evidence is recorded as a recommendation, not a direct observation.",
    "SUPPORTS_HYPOTHESIS_CONFLICT": "This evidence's stored supports_hypothesis value conflicts with its assigned group.",
    "SUPPORTS_HYPOTHESIS_UNSPECIFIED": "This evidence's supports_hypothesis value was not specified.",
}


class DecisionWarningFormatError(ValueError):
    """Raised when a supplied warning list or entry is structurally invalid.

    This is only raised for malformed input (wrong type, unknown/missing
    field, malformed UUID, unrecognized warning code, duplicate
    evidence-ID/code pair). It is never raised because of what a warning
    means -- every structurally valid warning is formatted, regardless of
    how many warnings reference the same evidence or how many share a
    code.
    """


def _validate_evidence_id(value: Any) -> str:
    if not isinstance(value, str):
        raise DecisionWarningFormatError("evidence_id must be a string")
    stripped = value.strip()
    if not stripped:
        raise DecisionWarningFormatError("evidence_id must not be blank")
    try:
        parsed = uuid.UUID(stripped)
    except ValueError as exc:
        raise DecisionWarningFormatError("evidence_id must be a structurally valid UUID") from exc
    return str(parsed)


def _validate_code(value: Any) -> str:
    if not isinstance(value, str):
        raise DecisionWarningFormatError("code must be a string")
    stripped = value.strip()
    if not stripped:
        raise DecisionWarningFormatError("code must not be blank")
    if stripped not in _WARNING_EXPLANATIONS:
        raise DecisionWarningFormatError(
            f"code must be one of {sorted(_WARNING_EXPLANATIONS)}, got {stripped!r}"
        )
    return stripped


def format_decision_warnings(warnings: list[Mapping[str, Any]]) -> list[dict[str, str]]:
    """Format an already-produced list of decision-context warnings.

    Reads only the two required fields (`evidence_id`, `code`) from each
    warning mapping; any other field on a warning entry is rejected.
    Neither `warnings` nor any entry within it is ever mutated -- a new,
    independently-owned list of new dictionaries is always returned, in
    the exact order supplied.

    Raises DecisionWarningFormatError for any structurally invalid input:
    `warnings` not a list, a non-mapping entry, an unknown or missing
    field, a malformed UUID, an unrecognized warning code, or a duplicate
    (canonical evidence_id, code) pair.
    """
    if not isinstance(warnings, list):
        raise DecisionWarningFormatError("warnings must be a list")

    formatted: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for entry in warnings:
        if not isinstance(entry, Mapping):
            raise DecisionWarningFormatError("each warning entry must be a mapping")

        unknown_fields = set(entry) - _ALLOWED_WARNING_FIELDS
        if unknown_fields:
            raise DecisionWarningFormatError(
                "unrecognized field(s): " + ", ".join(sorted(unknown_fields))
            )

        missing_fields = [field for field in ("evidence_id", "code") if field not in entry]
        if missing_fields:
            raise DecisionWarningFormatError(
                "missing required field(s): " + ", ".join(missing_fields)
            )

        canonical_evidence_id = _validate_evidence_id(entry["evidence_id"])
        code = _validate_code(entry["code"])

        pair = (canonical_evidence_id, code)
        if pair in seen:
            raise DecisionWarningFormatError(
                f"duplicate warning for evidence_id {canonical_evidence_id!r} and code {code!r}"
            )
        seen.add(pair)

        formatted.append(
            {
                "evidence_id": canonical_evidence_id,
                "code": code,
                "explanation": _WARNING_EXPLANATIONS[code],
            }
        )

    return formatted
