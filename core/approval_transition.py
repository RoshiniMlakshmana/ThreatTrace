"""Pure, deterministic validator for one proposed approval lifecycle
transition, evaluated against one complete approval-record snapshot.

Supported transitions:

    pending  -> approved
    pending  -> rejected
    approved -> consumed

This module represents only the *transition* half of a future approval
workflow. It reuses (never duplicates) `core.approval_request`'s own
validation of the frozen request-side fields (`investigation_id`,
`action_type`, `action_payload`, `requested_by`, `requested_at`), and adds
lifecycle-only validation on top: the current record's `status` and its
conditional approve/reject/consume fields, plus one exact, independently
scoped transition-request envelope per transition.

This module does not:

- query Supabase, check whether an approval row exists, or perform any
  database read or write of any kind;
- perform a conditional update, a database transaction, or an
  affected-row-count check -- those belong entirely to a future Supabase
  command, which this module has no knowledge of;
- update an investigation, mark a real row consumed, or otherwise perform
  any approval, rejection, or consumption operationally;
- verify authenticated identity. Every identity field it reads or
  produces (`requested_by`, `reviewed_by`/`approved_by`/`rejected_by`,
  `consumed_by`) is claimed, not verified;
- calculate an action hash. `expected_investigation_id` and
  `expected_action_type` on a consume request are a lightweight
  referential-integrity check only -- they bind a consumption attempt to
  the investigation and action type it claims to be consuming, but they
  are not a cryptographic proof that the complete `action_payload` is
  unchanged;
- enforce two-person separation on rejection or consumption -- only
  approval requires the reviewer to differ from the requester. A
  requester may reject (withdraw) their own still-pending request, and a
  consumer may be the same principal as the requester or the approver,
  since consumption is execution bookkeeping, not a new authorization
  decision;
- secret-scan `rejection_reason`. Secret scanning is a command-
  orchestration concern in this project (see `core/evidence_normalizer.py`'s
  own docstring), never a pure-validator concern;
- create a `cancelled`/`withdrawn` status, a `target_type`/`target_id`
  pair, a revocation concept, a CLI, a slash command, or an approvals
  schema. All of these remain explicitly out of scope.

Its return value is exactly:

    Validated transition plan -- not persisted

a small, deterministic description of what a future Supabase command
could safely apply as one conditional update, never something this
module applies itself.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from core.approval_request import ACTION_TYPES, ApprovalRequestError, validate_approval_request

APPROVAL_STATUSES = frozenset({
    "pending",
    "approved",
    "rejected",
    "consumed",
})

_CURRENT_RECORD_FIELDS = (
    "id",
    "investigation_id",
    "action_type",
    "action_payload",
    "requested_by",
    "requested_at",
    "status",
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "rejection_reason",
    "expires_at",
    "consumed_by",
    "consumed_at",
    "created_at",
)
_CURRENT_RECORD_FIELDS_SET = frozenset(_CURRENT_RECORD_FIELDS)

_TRANSITIONS = frozenset({"approve", "reject", "consume"})

_APPROVE_REQUIRED_FIELDS = frozenset({"transition", "reviewed_by"})
_APPROVE_ALLOWED_FIELDS = _APPROVE_REQUIRED_FIELDS | {"reviewed_at"}

_REJECT_REQUIRED_FIELDS = frozenset({"transition", "reviewed_by", "rejection_reason"})
_REJECT_ALLOWED_FIELDS = _REJECT_REQUIRED_FIELDS | {"reviewed_at"}

_CONSUME_REQUIRED_FIELDS = frozenset(
    {"transition", "consumed_by", "expected_investigation_id", "expected_action_type"}
)
_CONSUME_ALLOWED_FIELDS = _CONSUME_REQUIRED_FIELDS | {"consumed_at"}


class ApprovalTransitionError(ValueError):
    """Raised when a proposed approval-lifecycle transition is structurally
    invalid.

    This is only raised for malformed input: a malformed current-record
    snapshot (wrong type, unknown/missing field, malformed UUID/timestamp,
    an internally inconsistent lifecycle-field combination), a malformed
    or irrelevant-field transition request, an unsupported state
    transition (including a repeated attempt at an already-completed
    transition), a same-principal approval, a chronological
    inconsistency, or an expired approval/consumption attempt. It is
    never raised because of who the requester or reviewer *actually* is
    -- identity here is always claimed, never verified.
    """


def _validate_uuid_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ApprovalTransitionError(f"{field_name} must be a string")
    stripped = value.strip()
    if not stripped:
        raise ApprovalTransitionError(f"{field_name} must not be blank")
    try:
        parsed = uuid.UUID(stripped)
    except ValueError as exc:
        raise ApprovalTransitionError(f"{field_name} must be a structurally valid UUID") from exc
    return str(parsed)


def _normalize_timestamp(value: Any, field_name: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ApprovalTransitionError(f"{field_name} must not be blank")
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError as exc:
            raise ApprovalTransitionError(f"{field_name} is not a valid ISO-8601 timestamp") from exc
    else:
        raise ApprovalTransitionError(f"{field_name} must be a string or datetime")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ApprovalTransitionError(f"{field_name} must include timezone information")

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_canonical(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_status(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalTransitionError("current_record.status must be a string")
    normalized = value.strip().lower()
    if not normalized:
        raise ApprovalTransitionError("current_record.status must not be blank")
    if normalized not in APPROVAL_STATUSES:
        raise ApprovalTransitionError(
            f"current_record.status must be one of {sorted(APPROVAL_STATUSES)}, got {normalized!r}"
        )
    return normalized


def _validate_optional_identity(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ApprovalTransitionError(f"{field_name} must be a string or null")
    stripped = value.strip()
    if not stripped:
        raise ApprovalTransitionError(f"{field_name} must not be blank when present")
    return stripped


def _validate_optional_timestamp(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    return _normalize_timestamp(value, field_name)


def _resolve_transition_timestamp(supplied_value: Any, now: datetime | None, field_name: str) -> str:
    """Validate and canonicalize a transition timestamp.

    When `supplied_value` is present, it is validated and used as-is --
    `now` is never inspected, so an invalid injected `now` has no effect
    when generation is not required. When `supplied_value` is None,
    `now` (when supplied) must be an aware datetime and is used as the
    generation basis; otherwise the current UTC time is used.
    """
    if supplied_value is not None:
        return _normalize_timestamp(supplied_value, field_name)

    if now is not None:
        if not isinstance(now, datetime):
            raise ApprovalTransitionError("now must be a datetime")
        if now.tzinfo is None or now.utcoffset() is None:
            raise ApprovalTransitionError("now must be timezone-aware")
        base = now
    else:
        base = datetime.now(timezone.utc)

    return _normalize_timestamp(base, field_name)


def _validate_current_record(current_record: Any) -> dict[str, Any]:
    if not isinstance(current_record, Mapping):
        raise ApprovalTransitionError("current_record must be a mapping")

    unknown_fields = set(current_record) - _CURRENT_RECORD_FIELDS_SET
    if unknown_fields:
        raise ApprovalTransitionError(
            "unrecognized current_record field(s): " + ", ".join(sorted(unknown_fields))
        )

    missing_fields = [field for field in _CURRENT_RECORD_FIELDS if field not in current_record]
    if missing_fields:
        raise ApprovalTransitionError(
            "missing required current_record field(s): " + ", ".join(missing_fields)
        )

    approval_id = _validate_uuid_string(current_record["id"], "current_record.id")

    requested_at_raw = current_record["requested_at"]
    if requested_at_raw is None:
        raise ApprovalTransitionError("current_record.requested_at must not be null")

    request_projection = {
        "investigation_id": current_record["investigation_id"],
        "action_type": current_record["action_type"],
        "action_payload": current_record["action_payload"],
        "requested_by": current_record["requested_by"],
        "requested_at": requested_at_raw,
    }
    try:
        validated_request = validate_approval_request(request_projection)
    except ApprovalRequestError as exc:
        raise ApprovalTransitionError("current_record request-side fields failed validation") from exc

    status = _validate_status(current_record["status"])

    approved_by = _validate_optional_identity(current_record["approved_by"], "current_record.approved_by")
    rejected_by = _validate_optional_identity(current_record["rejected_by"], "current_record.rejected_by")
    consumed_by = _validate_optional_identity(current_record["consumed_by"], "current_record.consumed_by")
    rejection_reason = _validate_optional_identity(
        current_record["rejection_reason"], "current_record.rejection_reason"
    )

    approved_at = _validate_optional_timestamp(current_record["approved_at"], "current_record.approved_at")
    rejected_at = _validate_optional_timestamp(current_record["rejected_at"], "current_record.rejected_at")
    consumed_at = _validate_optional_timestamp(current_record["consumed_at"], "current_record.consumed_at")
    expires_at = _validate_optional_timestamp(current_record["expires_at"], "current_record.expires_at")

    created_at_raw = current_record["created_at"]
    if created_at_raw is None:
        raise ApprovalTransitionError("current_record.created_at must not be null")
    created_at = _normalize_timestamp(created_at_raw, "current_record.created_at")

    requested_at = validated_request["requested_at"]

    if _parse_canonical(created_at) < _parse_canonical(requested_at):
        raise ApprovalTransitionError("current_record.created_at must be at or after requested_at")

    if expires_at is not None and _parse_canonical(expires_at) <= _parse_canonical(requested_at):
        raise ApprovalTransitionError("current_record.expires_at must be after requested_at")

    if status == "pending":
        for field_name, value in (
            ("approved_by", approved_by),
            ("approved_at", approved_at),
            ("rejected_by", rejected_by),
            ("rejected_at", rejected_at),
            ("rejection_reason", rejection_reason),
            ("consumed_by", consumed_by),
            ("consumed_at", consumed_at),
        ):
            if value is not None:
                raise ApprovalTransitionError(
                    f"current_record.{field_name} must be null when status is 'pending'"
                )

    elif status == "approved":
        if approved_by is None:
            raise ApprovalTransitionError("current_record.approved_by is required when status is 'approved'")
        if approved_at is None:
            raise ApprovalTransitionError("current_record.approved_at is required when status is 'approved'")
        for field_name, value in (
            ("rejected_by", rejected_by),
            ("rejected_at", rejected_at),
            ("rejection_reason", rejection_reason),
            ("consumed_by", consumed_by),
            ("consumed_at", consumed_at),
        ):
            if value is not None:
                raise ApprovalTransitionError(
                    f"current_record.{field_name} must be null when status is 'approved'"
                )

    elif status == "rejected":
        if rejected_by is None:
            raise ApprovalTransitionError("current_record.rejected_by is required when status is 'rejected'")
        if rejected_at is None:
            raise ApprovalTransitionError("current_record.rejected_at is required when status is 'rejected'")
        if rejection_reason is None:
            raise ApprovalTransitionError(
                "current_record.rejection_reason is required when status is 'rejected'"
            )
        for field_name, value in (
            ("approved_by", approved_by),
            ("approved_at", approved_at),
            ("consumed_by", consumed_by),
            ("consumed_at", consumed_at),
        ):
            if value is not None:
                raise ApprovalTransitionError(
                    f"current_record.{field_name} must be null when status is 'rejected'"
                )

    else:  # consumed
        if approved_by is None:
            raise ApprovalTransitionError("current_record.approved_by is required when status is 'consumed'")
        if approved_at is None:
            raise ApprovalTransitionError("current_record.approved_at is required when status is 'consumed'")
        if consumed_by is None:
            raise ApprovalTransitionError("current_record.consumed_by is required when status is 'consumed'")
        if consumed_at is None:
            raise ApprovalTransitionError("current_record.consumed_at is required when status is 'consumed'")
        for field_name, value in (
            ("rejected_by", rejected_by),
            ("rejected_at", rejected_at),
            ("rejection_reason", rejection_reason),
        ):
            if value is not None:
                raise ApprovalTransitionError(
                    f"current_record.{field_name} must be null when status is 'consumed'"
                )

    if approved_at is not None and _parse_canonical(approved_at) < _parse_canonical(requested_at):
        raise ApprovalTransitionError("current_record.approved_at must be at or after requested_at")

    if rejected_at is not None and _parse_canonical(rejected_at) < _parse_canonical(requested_at):
        raise ApprovalTransitionError("current_record.rejected_at must be at or after requested_at")

    if (
        consumed_at is not None
        and approved_at is not None
        and _parse_canonical(consumed_at) < _parse_canonical(approved_at)
    ):
        raise ApprovalTransitionError("current_record.consumed_at must be at or after approved_at")

    if (
        approved_at is not None
        and expires_at is not None
        and _parse_canonical(approved_at) >= _parse_canonical(expires_at)
    ):
        raise ApprovalTransitionError("current_record.approved_at must be before expires_at")

    if (
        consumed_at is not None
        and expires_at is not None
        and _parse_canonical(consumed_at) >= _parse_canonical(expires_at)
    ):
        raise ApprovalTransitionError("current_record.consumed_at must be before expires_at")

    return {
        "id": approval_id,
        "investigation_id": validated_request["investigation_id"],
        "action_type": validated_request["action_type"],
        "requested_by": validated_request["requested_by"],
        "requested_at": requested_at,
        "status": status,
        "expires_at": expires_at,
        "approved_at": approved_at,
    }


def _validate_approve(record: Mapping[str, Any], transition_request: Mapping[str, Any], now: datetime | None) -> dict[str, Any]:
    unknown_fields = set(transition_request) - _APPROVE_ALLOWED_FIELDS
    if unknown_fields:
        raise ApprovalTransitionError(
            "unrecognized approve field(s): " + ", ".join(sorted(unknown_fields))
        )
    missing_fields = [field for field in _APPROVE_REQUIRED_FIELDS if field not in transition_request]
    if missing_fields:
        raise ApprovalTransitionError(
            "missing required approve field(s): " + ", ".join(sorted(missing_fields))
        )

    if record["status"] != "pending":
        raise ApprovalTransitionError(
            f"cannot approve: current status must be 'pending', got {record['status']!r}"
        )

    reviewed_by_value = transition_request["reviewed_by"]
    if not isinstance(reviewed_by_value, str):
        raise ApprovalTransitionError("reviewed_by must be a string")
    reviewed_by = reviewed_by_value.strip()
    if not reviewed_by:
        raise ApprovalTransitionError("reviewed_by must not be blank")

    if reviewed_by.casefold() == record["requested_by"].strip().casefold():
        raise ApprovalTransitionError("reviewed_by must differ from the original requester")

    reviewed_at = _resolve_transition_timestamp(transition_request.get("reviewed_at"), now, "reviewed_at")

    if _parse_canonical(reviewed_at) < _parse_canonical(record["requested_at"]):
        raise ApprovalTransitionError("reviewed_at must be at or after requested_at")

    if record["expires_at"] is not None and _parse_canonical(reviewed_at) >= _parse_canonical(record["expires_at"]):
        raise ApprovalTransitionError("reviewed_at must be strictly before expires_at")

    return {
        "approval_id": record["id"],
        "from_status": "pending",
        "to_status": "approved",
        "set_fields": {
            "status": "approved",
            "approved_by": reviewed_by,
            "approved_at": reviewed_at,
        },
    }


def _validate_reject(record: Mapping[str, Any], transition_request: Mapping[str, Any], now: datetime | None) -> dict[str, Any]:
    unknown_fields = set(transition_request) - _REJECT_ALLOWED_FIELDS
    if unknown_fields:
        raise ApprovalTransitionError(
            "unrecognized reject field(s): " + ", ".join(sorted(unknown_fields))
        )
    missing_fields = [field for field in _REJECT_REQUIRED_FIELDS if field not in transition_request]
    if missing_fields:
        raise ApprovalTransitionError(
            "missing required reject field(s): " + ", ".join(sorted(missing_fields))
        )

    if record["status"] != "pending":
        raise ApprovalTransitionError(
            f"cannot reject: current status must be 'pending', got {record['status']!r}"
        )

    reviewed_by_value = transition_request["reviewed_by"]
    if not isinstance(reviewed_by_value, str):
        raise ApprovalTransitionError("reviewed_by must be a string")
    reviewed_by = reviewed_by_value.strip()
    if not reviewed_by:
        raise ApprovalTransitionError("reviewed_by must not be blank")

    rejection_reason_value = transition_request["rejection_reason"]
    if not isinstance(rejection_reason_value, str):
        raise ApprovalTransitionError("rejection_reason must be a string")
    rejection_reason = rejection_reason_value.strip()
    if not rejection_reason:
        raise ApprovalTransitionError("rejection_reason must not be blank")

    reviewed_at = _resolve_transition_timestamp(transition_request.get("reviewed_at"), now, "reviewed_at")

    if _parse_canonical(reviewed_at) < _parse_canonical(record["requested_at"]):
        raise ApprovalTransitionError("reviewed_at must be at or after requested_at")

    return {
        "approval_id": record["id"],
        "from_status": "pending",
        "to_status": "rejected",
        "set_fields": {
            "status": "rejected",
            "rejected_by": reviewed_by,
            "rejected_at": reviewed_at,
            "rejection_reason": rejection_reason,
        },
    }


def _validate_consume(record: Mapping[str, Any], transition_request: Mapping[str, Any], now: datetime | None) -> dict[str, Any]:
    unknown_fields = set(transition_request) - _CONSUME_ALLOWED_FIELDS
    if unknown_fields:
        raise ApprovalTransitionError(
            "unrecognized consume field(s): " + ", ".join(sorted(unknown_fields))
        )
    missing_fields = [field for field in _CONSUME_REQUIRED_FIELDS if field not in transition_request]
    if missing_fields:
        raise ApprovalTransitionError(
            "missing required consume field(s): " + ", ".join(sorted(missing_fields))
        )

    if record["status"] != "approved":
        raise ApprovalTransitionError(
            f"cannot consume: current status must be 'approved', got {record['status']!r}"
        )

    consumed_by_value = transition_request["consumed_by"]
    if not isinstance(consumed_by_value, str):
        raise ApprovalTransitionError("consumed_by must be a string")
    consumed_by = consumed_by_value.strip()
    if not consumed_by:
        raise ApprovalTransitionError("consumed_by must not be blank")

    expected_investigation_id = _validate_uuid_string(
        transition_request["expected_investigation_id"], "expected_investigation_id"
    )
    if expected_investigation_id != record["investigation_id"]:
        raise ApprovalTransitionError("expected_investigation_id does not match the current record")

    expected_action_type_value = transition_request["expected_action_type"]
    if not isinstance(expected_action_type_value, str):
        raise ApprovalTransitionError("expected_action_type must be a string")
    expected_action_type = expected_action_type_value.strip().lower()
    if not expected_action_type:
        raise ApprovalTransitionError("expected_action_type must not be blank")
    if expected_action_type not in ACTION_TYPES:
        raise ApprovalTransitionError(
            f"expected_action_type must be one of {sorted(ACTION_TYPES)}, got {expected_action_type!r}"
        )
    if expected_action_type != record["action_type"]:
        raise ApprovalTransitionError("expected_action_type does not match the current record")

    consumed_at = _resolve_transition_timestamp(transition_request.get("consumed_at"), now, "consumed_at")

    if _parse_canonical(consumed_at) < _parse_canonical(record["approved_at"]):
        raise ApprovalTransitionError("consumed_at must be at or after approved_at")

    if record["expires_at"] is not None and _parse_canonical(consumed_at) >= _parse_canonical(record["expires_at"]):
        raise ApprovalTransitionError("consumed_at must be strictly before expires_at")

    return {
        "approval_id": record["id"],
        "from_status": "approved",
        "to_status": "consumed",
        "set_fields": {
            "status": "consumed",
            "consumed_by": consumed_by,
            "consumed_at": consumed_at,
        },
    }


def validate_approval_transition(
    current_record: Mapping[str, Any],
    transition_request: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate one proposed lifecycle transition against one complete
    approval-record snapshot.

    `current_record` must contain exactly the sixteen fields documented in
    this module (nullable lifecycle fields explicitly present as `None`
    when unused); its five frozen request-side fields are revalidated by
    calling `core.approval_request.validate_approval_request` (never
    duplicated), with `requested_at` always forwarded explicitly so it is
    never silently regenerated.

    `transition_request` must contain a `transition` field
    (`"approve"`, `"reject"`, or `"consume"`) plus exactly that
    transition's own required/optional fields -- no other field, and
    never a field belonging to a different transition or to the frozen
    request-side envelope.

    Returns a new, independently-owned transition plan:

        {
            "approval_id": "...",
            "from_status": "...",
            "to_status": "...",
            "set_fields": {...},
        }

    This plan is a **validated transition plan -- not persisted**. Neither
    `current_record` nor `transition_request` (nor any nested mapping
    within either) is ever mutated, and no mutable object from either
    input is retained by reference in the result.

    Raises ApprovalTransitionError for any structurally invalid input,
    including: a malformed or internally inconsistent current-record
    snapshot, a malformed or irrelevant-field transition request, an
    unsupported state transition (including a repeated attempt at an
    already-completed transition), a same-principal approval attempt, a
    chronological inconsistency, or an expired approval/consumption
    attempt.
    """
    record = _validate_current_record(current_record)

    if not isinstance(transition_request, Mapping):
        raise ApprovalTransitionError("transition_request must be a mapping")

    if "transition" not in transition_request:
        raise ApprovalTransitionError("transition_request is missing required field: transition")

    transition_value = transition_request["transition"]
    if not isinstance(transition_value, str):
        raise ApprovalTransitionError("transition must be a string")
    transition = transition_value.strip().lower()
    if not transition:
        raise ApprovalTransitionError("transition must not be blank")
    if transition not in _TRANSITIONS:
        raise ApprovalTransitionError(
            f"transition must be one of {sorted(_TRANSITIONS)}, got {transition!r}"
        )

    if transition == "approve":
        return _validate_approve(record, transition_request, now)
    if transition == "reject":
        return _validate_reject(record, transition_request, now)
    return _validate_consume(record, transition_request, now)
