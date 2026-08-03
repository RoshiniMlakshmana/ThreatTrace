"""Pure, deterministic validator for the request side of an approval
lifecycle: an analyst proposing a specific investigation-state update for
later review.

This module represents only the *request* half of a future approval
workflow -- it is not an approval decision, and it produces no approval
lifecycle status:

- It does not create an approval database row, assign an approval ID, or
  perform any Supabase operation of any kind.
- It does not approve or reject anything, and it never marks anything
  consumed. No `status`, `approved_by`, `approved_at`, `rejected_by`,
  `rejected_at`, `rejection_reason`, `expires_at`, `consumed_at`, or
  `revoked_at` field is ever accepted or produced here -- those all belong
  to a later, separate transition validator this module does not contain.
- `requested_by` is treated strictly as claimed identity, not verified
  identity. This module never queries Supabase Auth, never validates an
  email address, never resolves a user UUID, and never claims that
  authentication occurred.
- It never enforces the two-person rule (requester != reviewer) -- there is
  no reviewer identity anywhere in this module's input or output for that
  rule to apply to.
- It never checks whether the referenced investigation exists, never
  compares a proposed `status`/`confidence` value against the investigation's
  current stored value, and never updates the investigation. Those are all
  database-read/write concerns that belong to a later orchestration layer.
- It never calculates an action hash, never enforces expiry, and never
  calls an AI model.
- This module owns exactly one controlled vocabulary: `ACTION_TYPES`.
  Investigation-status and confidence vocabularies are imported and reused
  verbatim from `core.decision_context` and `core.evidence_normalizer`
  respectively -- never redefined here.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from core.approval_risk import ApprovalRiskError, classify_approval_risk, required_approvals_for_risk
from core.decision_context import INVESTIGATION_STATUSES
from core.evidence_normalizer import CONFIDENCE_LEVELS

ACTION_TYPES = frozenset({
    "update_investigation_state",
})

_REQUIRED_TOP_LEVEL_FIELDS = (
    "investigation_id",
    "action_type",
    "action_payload",
    "requested_by",
)
_OPTIONAL_TOP_LEVEL_FIELDS = ("requested_at",)
_ALLOWED_TOP_LEVEL_FIELDS = frozenset(_REQUIRED_TOP_LEVEL_FIELDS + _OPTIONAL_TOP_LEVEL_FIELDS)

_ALLOWED_ACTION_PAYLOAD_FIELDS = frozenset({"status", "confidence"})

_RISK_AWARE_CURRENT_INVESTIGATION_FIELDS = frozenset({"status", "confidence"})


class ApprovalRequestError(ValueError):
    """Raised when a proposed approval request is structurally invalid.

    This is only raised for malformed input (wrong type, unknown or missing
    field, unsupported vocabulary value, malformed UUID/timestamp, an empty
    action payload). It never raises because a proposed status or
    confidence value happens to equal (or differ from) the investigation's
    current stored value -- this module never reads that value in the
    first place.
    """


def _validate_uuid_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ApprovalRequestError(f"{field_name} must be a string")
    stripped = value.strip()
    if not stripped:
        raise ApprovalRequestError(f"{field_name} must not be blank")
    try:
        parsed = uuid.UUID(stripped)
    except ValueError as exc:
        raise ApprovalRequestError(f"{field_name} must be a structurally valid UUID") from exc
    return str(parsed)


def _validate_action_type(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalRequestError("action_type must be a string")
    normalized = value.strip().lower()
    if not normalized:
        raise ApprovalRequestError("action_type must not be blank")
    if normalized not in ACTION_TYPES:
        raise ApprovalRequestError(
            f"action_type must be one of {sorted(ACTION_TYPES)}, got {normalized!r}"
        )
    return normalized


def _validate_controlled_string(value: Any, field_name: str, vocabulary: frozenset[str]) -> str:
    if not isinstance(value, str):
        raise ApprovalRequestError(f"action_payload.{field_name} must be a string")
    normalized = value.strip().lower()
    if not normalized:
        raise ApprovalRequestError(f"action_payload.{field_name} must not be blank")
    if normalized not in vocabulary:
        raise ApprovalRequestError(
            f"action_payload.{field_name} must be one of {sorted(vocabulary)}, got {normalized!r}"
        )
    return normalized


def _validate_action_payload(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ApprovalRequestError("action_payload must be a mapping")

    unknown_fields = set(value) - _ALLOWED_ACTION_PAYLOAD_FIELDS
    if unknown_fields:
        raise ApprovalRequestError(
            "unrecognized action_payload field(s): " + ", ".join(sorted(unknown_fields))
        )

    if not value:
        raise ApprovalRequestError("action_payload must not be empty")

    result: dict[str, str] = {}

    if "status" in value:
        result["status"] = _validate_controlled_string(value["status"], "status", INVESTIGATION_STATUSES)

    if "confidence" in value:
        result["confidence"] = _validate_controlled_string(value["confidence"], "confidence", CONFIDENCE_LEVELS)

    if not result:
        raise ApprovalRequestError("action_payload must contain at least one of status, confidence")

    return result


def _validate_requested_by(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalRequestError("requested_by must be a string")
    stripped = value.strip()
    if not stripped:
        raise ApprovalRequestError("requested_by must not be blank")
    return stripped


def _normalize_timestamp(value: Any, field_name: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ApprovalRequestError(f"{field_name} must not be blank")
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError as exc:
            raise ApprovalRequestError(f"{field_name} is not a valid ISO-8601 timestamp") from exc
    else:
        raise ApprovalRequestError(f"{field_name} must be a string or datetime")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ApprovalRequestError(f"{field_name} must include timezone information")

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_requested_at(payload: Mapping[str, Any], now: datetime | None) -> str:
    if now is not None:
        if not isinstance(now, datetime):
            raise ApprovalRequestError("now must be a datetime")
        if now.tzinfo is None or now.utcoffset() is None:
            raise ApprovalRequestError("now must be timezone-aware")

    requested_at_value = payload.get("requested_at")
    if requested_at_value is None:
        base = now if now is not None else datetime.now(timezone.utc)
        return _normalize_timestamp(base, "requested_at")
    return _normalize_timestamp(requested_at_value, "requested_at")


def validate_approval_request(
    payload: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate and canonicalize one proposed approval request.

    Reads only the five fields listed in the module docstring
    (`investigation_id`, `action_type`, `action_payload`, `requested_by`,
    and the optional `requested_at`); any other top-level field is
    rejected. Neither `payload` nor its nested `action_payload` mapping is
    ever mutated -- a new, independently-owned dictionary is always
    returned, and no mutable object from `payload` is retained by
    reference in the result.

    Raises ApprovalRequestError for any structurally invalid input:
    `payload` not a mapping, an unknown or missing top-level field, a
    malformed UUID, an unsupported `action_type`, a non-mapping or empty
    `action_payload`, an unrecognized action-payload field, an unsupported
    `status`/`confidence` value, a blank `requested_by`, or a
    malformed/timezone-naive `requested_at`/`now`.
    """
    if not isinstance(payload, Mapping):
        raise ApprovalRequestError("payload must be a mapping")

    unknown_fields = set(payload) - _ALLOWED_TOP_LEVEL_FIELDS
    if unknown_fields:
        raise ApprovalRequestError(
            "unrecognized field(s): " + ", ".join(sorted(unknown_fields))
        )

    missing_fields = [field for field in _REQUIRED_TOP_LEVEL_FIELDS if field not in payload]
    if missing_fields:
        raise ApprovalRequestError(
            "missing required field(s): " + ", ".join(missing_fields)
        )

    investigation_id = _validate_uuid_string(payload["investigation_id"], "investigation_id")
    action_type = _validate_action_type(payload["action_type"])
    action_payload = _validate_action_payload(payload["action_payload"])
    requested_by = _validate_requested_by(payload["requested_by"])
    requested_at = _validate_requested_at(payload, now)

    return {
        "investigation_id": investigation_id,
        "action_type": action_type,
        "action_payload": action_payload,
        "requested_by": requested_by,
        "requested_at": requested_at,
    }


def validate_risk_aware_approval_request(
    request: Mapping[str, Any],
    current_investigation: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one proposed approval request exactly like
    `validate_approval_request`, then additionally derive its deterministic
    `risk_level` and `required_approvals`.

    `request` is validated by calling `validate_approval_request` first,
    entirely unchanged -- every existing rule (allowed top-level fields,
    UUID/timestamp canonicalization, action-payload shape, vocabulary
    membership) applies exactly as it already does, and that call alone is
    why a caller can never submit `risk_level`, `required_approvals`, a
    required-approval count, or a second-decision identity: none of those
    has ever been an allowed top-level field, so `validate_approval_request`
    itself already rejects any of them as an unrecognized field. This
    function never adds a second, separate allow-list of its own.

    `current_investigation` must be a mapping containing exactly `status`
    and `confidence` -- the investigation's own current values, supplied
    by the caller. This function never queries Supabase or reads an
    investigation itself.

    Risk classification is delegated entirely to
    `core.approval_risk.classify_approval_risk`, called only with the
    already-validated request's own `action_type`/`action_payload` and
    `current_investigation`'s own `status`/`confidence` -- never with a
    caller-supplied risk level, since no such field exists anywhere in
    either input's contract. `required_approvals` is derived from the
    classified risk level via
    `core.approval_risk.required_approvals_for_risk`.

    Returns a new, independently-owned dictionary containing every field
    `validate_approval_request` itself returns, plus exactly `risk_level`
    and `required_approvals`. Neither `request` nor `current_investigation`
    (nor any nested mapping within either) is ever mutated.

    Raises `ApprovalRequestError` for any failure `validate_approval_request`
    itself would raise, for a non-mapping `current_investigation`, for a
    `current_investigation` that does not contain exactly `status` and
    `confidence`, or for any risk-classification failure
    (`core.approval_risk.ApprovalRiskError` is caught and re-raised as this
    module's own exception type, never propagated directly).
    """
    validated_request = validate_approval_request(request)

    if not isinstance(current_investigation, Mapping):
        raise ApprovalRequestError("current_investigation must be a mapping")

    if set(current_investigation) != _RISK_AWARE_CURRENT_INVESTIGATION_FIELDS:
        raise ApprovalRequestError(
            "current_investigation must contain exactly: "
            + ", ".join(sorted(_RISK_AWARE_CURRENT_INVESTIGATION_FIELDS))
        )

    try:
        risk_level = classify_approval_risk(
            action_type=validated_request["action_type"],
            action_payload=validated_request["action_payload"],
            current_status=current_investigation["status"],
            current_confidence=current_investigation["confidence"],
        )
        required_approvals = required_approvals_for_risk(risk_level)
    except ApprovalRiskError as exc:
        raise ApprovalRequestError("risk classification failed") from exc

    result = dict(validated_request)
    result["risk_level"] = risk_level
    result["required_approvals"] = required_approvals
    return result
