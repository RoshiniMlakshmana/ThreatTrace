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
from collections.abc import Mapping, Sequence
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

# ---------------------------------------------------------------------------
# Offline multi-review contract (Block 6, Step 2) -- an additional,
# independent public function, `validate_multi_review_transition`, layered
# on top of the fields and helpers above without changing any of them.
# `partially_approved` is a transitional status this new function alone
# understands; it is deliberately never added to APPROVAL_STATUSES or to
# `validate_approval_record`'s own sixteen-field contract in this step, so
# every existing caller of those two names is completely unaffected.
#
# The canonical risk_level -> required_approvals mapping is owned by
# `core.approval_risk`. This module intentionally does not import that
# module (avoiding a cycle, since `core.approval_request` already imports
# `core.approval_risk`, and this module already imports
# `core.approval_request`) -- so this small, closed mapping is
# independently re-declared here, exactly as instructed, purely to check
# that a stored current_record's own risk_level/required_approvals pair is
# internally consistent, never to reclassify anything.
# ---------------------------------------------------------------------------

_MULTI_REVIEW_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})

_MULTI_REVIEW_REQUIRED_APPROVALS_BY_RISK = {
    "low": 1,
    "medium": 1,
    "high": 2,
    "critical": 2,
}

_MULTI_REVIEW_STATUSES = APPROVAL_STATUSES | frozenset({"partially_approved"})

_MULTI_REVIEW_CURRENT_RECORD_EXTRA_FIELDS = ("risk_level", "required_approvals")
_MULTI_REVIEW_CURRENT_RECORD_FIELDS = _CURRENT_RECORD_FIELDS + _MULTI_REVIEW_CURRENT_RECORD_EXTRA_FIELDS
_MULTI_REVIEW_CURRENT_RECORD_FIELDS_SET = frozenset(_MULTI_REVIEW_CURRENT_RECORD_FIELDS)

_REVIEW_SUMMARY_FIELDS = (
    "approval_id",
    "reviewer_identity",
    "reviewer_identity_normalized",
    "decision",
    "decided_at",
)
_REVIEW_SUMMARY_FIELDS_SET = frozenset(_REVIEW_SUMMARY_FIELDS)

_REVIEW_DECISIONS = frozenset({"approve", "reject"})

_MULTI_REVIEW_APPROVE_REQUIRED_FIELDS = frozenset({"decision", "reviewed_by"})
_MULTI_REVIEW_REJECT_REQUIRED_FIELDS = frozenset({"decision", "reviewed_by", "rejection_reason"})

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
    """Validate a persisted (current-record) lifecycle identity or
    rejection-reason value.

    Unlike a transition-request value (which is trimmed and normalized on
    the way in, since it is analyst-authored input), a persisted value is
    expected to already be stored in its canonical, outer-trimmed form --
    matching the approvals schema's own `chk_approvals_*_nonblank` and
    `chk_approvals_lifecycle_rejected` CHECK constraints, which require
    `column = btrim(column)`. A padded stored value is therefore rejected
    outright, never silently trimmed and accepted.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ApprovalTransitionError(f"{field_name} must be a string or null")
    stripped = value.strip()
    if not stripped:
        raise ApprovalTransitionError(f"{field_name} must not be blank when present")
    if value != stripped:
        raise ApprovalTransitionError(f"{field_name} must already be stored in trimmed form")
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
        "action_payload": validated_request["action_payload"],
        "requested_by": validated_request["requested_by"],
        "requested_at": requested_at,
        "status": status,
        "approved_by": approved_by,
        "approved_at": approved_at,
        "rejected_by": rejected_by,
        "rejected_at": rejected_at,
        "rejection_reason": rejection_reason,
        "expires_at": expires_at,
        "consumed_by": consumed_by,
        "consumed_at": consumed_at,
        "created_at": created_at,
    }


def validate_approval_record(current_record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one complete approval-record snapshot in isolation.

    This is a thin public wrapper around the same current-record
    validation `validate_approval_transition` itself relies on -- no
    validation logic is duplicated. `current_record` must contain exactly
    the sixteen fields documented in this module (nullable lifecycle
    fields explicitly present as `None` when unused); its five frozen
    request-side fields are revalidated by calling
    `core.approval_request.validate_approval_request` (never duplicated).

    Returns a new dict containing exactly the same sixteen fields, in
    this fixed order: `id`, `investigation_id`, `action_type`,
    `action_payload`, `requested_by`, `requested_at`, `status`,
    `approved_by`, `approved_at`, `rejected_by`, `rejected_at`,
    `rejection_reason`, `expires_at`, `consumed_by`, `consumed_at`,
    `created_at`.

    This is a:

        Validated approval record -- not proof of persistence

    It does not check `expires_at` against the current time -- expiry is
    a transition-time concern, evaluated only when an approval or
    consumption is actually attempted, never a current-record-validation
    concern. It does not query Supabase, does not check whether the
    record actually exists in any database, and does not re-derive or
    enforce any two-person rule. `current_record` is never mutated, and
    no mutable object from it is retained by reference in the result.

    Raises ApprovalTransitionError for any structurally invalid input,
    including an unrecognized type, an unknown or missing field, a
    malformed UUID or timestamp, a non-canonical (padded) stored
    identity/reason value, an internally inconsistent lifecycle-field
    combination for the record's status, or a chronological
    inconsistency among its timestamps.
    """
    return _validate_current_record(current_record)


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
        "expected_investigation_id": expected_investigation_id,
        "expected_action_type": expected_action_type,
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

    A consume plan additionally carries the two independently-validated
    binding fields as top-level siblings of `set_fields` -- never inside
    it, since they describe what was validated, not a column written by
    the eventual approval-consumption update:

        {
            "approval_id": "...",
            "from_status": "approved",
            "to_status": "consumed",
            "set_fields": {"status": "consumed", "consumed_by": "...", "consumed_at": "..."},
            "expected_investigation_id": "...",
            "expected_action_type": "...",
        }

    This lets a future persistence function reconstruct and independently
    revalidate the genuine consume request from the plan alone, without
    discarding `expected_investigation_id`/`expected_action_type`.

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
    record = validate_approval_record(current_record)

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


# ---------------------------------------------------------------------------
# Offline multi-review contract (Block 6, Step 2)
# ---------------------------------------------------------------------------


def _validate_multi_review_current_record(current_record: Any) -> dict[str, Any]:
    if not isinstance(current_record, Mapping):
        raise ApprovalTransitionError("current_record must be a mapping")

    unknown_fields = set(current_record) - _MULTI_REVIEW_CURRENT_RECORD_FIELDS_SET
    if unknown_fields:
        raise ApprovalTransitionError(
            "unrecognized current_record field(s): " + ", ".join(sorted(unknown_fields))
        )

    missing_fields = [field for field in _MULTI_REVIEW_CURRENT_RECORD_FIELDS if field not in current_record]
    if missing_fields:
        raise ApprovalTransitionError(
            "missing required current_record field(s): " + ", ".join(missing_fields)
        )

    risk_level = current_record["risk_level"]
    if not isinstance(risk_level, str) or risk_level not in _MULTI_REVIEW_RISK_LEVELS:
        raise ApprovalTransitionError(
            f"current_record.risk_level must be one of {sorted(_MULTI_REVIEW_RISK_LEVELS)}"
        )

    required_approvals = current_record["required_approvals"]
    if (
        not isinstance(required_approvals, int)
        or isinstance(required_approvals, bool)
        or required_approvals not in (1, 2)
    ):
        raise ApprovalTransitionError("current_record.required_approvals must be 1 or 2")

    if _MULTI_REVIEW_REQUIRED_APPROVALS_BY_RISK[risk_level] != required_approvals:
        raise ApprovalTransitionError(
            "current_record.risk_level and current_record.required_approvals are inconsistent"
        )

    raw_status = current_record["status"]
    if not isinstance(raw_status, str):
        raise ApprovalTransitionError("current_record.status must be a string")
    normalized_status = raw_status.strip().lower()
    if not normalized_status or normalized_status not in _MULTI_REVIEW_STATUSES:
        raise ApprovalTransitionError(
            f"current_record.status must be one of {sorted(_MULTI_REVIEW_STATUSES)}, got {normalized_status!r}"
        )

    if normalized_status == "partially_approved" and required_approvals != 2:
        raise ApprovalTransitionError(
            "current_record.status 'partially_approved' requires required_approvals == 2"
        )

    # partially_approved shares the exact same null-lifecycle-field shape as
    # pending (see the module docstring for _validate_current_record's own
    # pending-status branch) -- substituting "pending" here reuses every
    # existing sixteen-field structural, chronology, and timestamp rule
    # unchanged, rather than duplicating any of it.
    base_record = {field: current_record[field] for field in _CURRENT_RECORD_FIELDS}
    if normalized_status == "partially_approved":
        base_record["status"] = "pending"

    validated_base = _validate_current_record(base_record)

    if normalized_status == "partially_approved":
        validated_base["status"] = "partially_approved"

    validated_base["risk_level"] = risk_level
    validated_base["required_approvals"] = required_approvals
    return validated_base


def _validate_existing_reviews(
    existing_reviews: Any,
    validated_current_record: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if isinstance(existing_reviews, (str, bytes)) or not isinstance(existing_reviews, Sequence):
        raise ApprovalTransitionError("existing_reviews must be a sequence")

    validated_reviews: list[dict[str, Any]] = []
    seen_normalized_identities: set[str] = set()
    has_rejection = False

    for review in existing_reviews:
        if not isinstance(review, Mapping):
            raise ApprovalTransitionError("each existing review must be a mapping")

        if set(review) != _REVIEW_SUMMARY_FIELDS_SET:
            raise ApprovalTransitionError(
                "each existing review must contain exactly: " + ", ".join(_REVIEW_SUMMARY_FIELDS)
            )

        review_approval_id = _validate_uuid_string(review["approval_id"], "existing_review.approval_id")
        if review_approval_id != validated_current_record["id"]:
            raise ApprovalTransitionError("existing_review.approval_id must match current_record.id")

        reviewer_identity_value = review["reviewer_identity"]
        if not isinstance(reviewer_identity_value, str):
            raise ApprovalTransitionError("existing_review.reviewer_identity must be a string")
        stripped_identity = reviewer_identity_value.strip()
        if not stripped_identity:
            raise ApprovalTransitionError("existing_review.reviewer_identity must not be blank")
        if reviewer_identity_value != stripped_identity:
            raise ApprovalTransitionError(
                "existing_review.reviewer_identity must already be stored in trimmed form"
            )

        normalized_value = review["reviewer_identity_normalized"]
        expected_normalized = reviewer_identity_value.strip().casefold()
        if normalized_value != expected_normalized:
            raise ApprovalTransitionError(
                "existing_review.reviewer_identity_normalized must equal reviewer_identity.strip().casefold()"
            )

        if normalized_value in seen_normalized_identities:
            raise ApprovalTransitionError("duplicate reviewer identity in existing_reviews")
        seen_normalized_identities.add(normalized_value)

        decision_value = review["decision"]
        if decision_value not in _REVIEW_DECISIONS:
            raise ApprovalTransitionError(
                f"existing_review.decision must be one of {sorted(_REVIEW_DECISIONS)}"
            )

        decided_at = _normalize_timestamp(review["decided_at"], "existing_review.decided_at")

        if decision_value == "reject":
            has_rejection = True

        validated_reviews.append({
            "approval_id": review_approval_id,
            "reviewer_identity": stripped_identity,
            "reviewer_identity_normalized": normalized_value,
            "decision": decision_value,
            "decided_at": decided_at,
        })

    if has_rejection and validated_current_record["status"] in ("pending", "partially_approved"):
        raise ApprovalTransitionError(
            "an existing rejection is incompatible with an active pending or partially_approved record"
        )

    return validated_reviews


def _validate_multi_review_transition_request(transition_request: Any) -> tuple[str, str, str, str | None]:
    if not isinstance(transition_request, Mapping):
        raise ApprovalTransitionError("transition_request must be a mapping")

    if "decision" not in transition_request:
        raise ApprovalTransitionError("transition_request is missing required field: decision")

    decision_value = transition_request["decision"]
    if not isinstance(decision_value, str):
        raise ApprovalTransitionError("decision must be a string")
    decision = decision_value.strip().lower()
    if decision not in _REVIEW_DECISIONS:
        raise ApprovalTransitionError(
            f"decision must be one of {sorted(_REVIEW_DECISIONS)}, got {decision!r}"
        )

    if decision == "approve":
        required_fields = _MULTI_REVIEW_APPROVE_REQUIRED_FIELDS
    else:
        required_fields = _MULTI_REVIEW_REJECT_REQUIRED_FIELDS

    unknown_fields = set(transition_request) - required_fields
    if unknown_fields:
        raise ApprovalTransitionError(
            "unrecognized field(s): " + ", ".join(sorted(unknown_fields))
        )
    missing_fields = [field for field in required_fields if field not in transition_request]
    if missing_fields:
        raise ApprovalTransitionError(
            "missing required field(s): " + ", ".join(sorted(missing_fields))
        )

    reviewed_by_value = transition_request["reviewed_by"]
    if not isinstance(reviewed_by_value, str):
        raise ApprovalTransitionError("reviewed_by must be a string")
    reviewed_by = reviewed_by_value.strip()
    if not reviewed_by:
        raise ApprovalTransitionError("reviewed_by must not be blank")
    reviewed_by_normalized = reviewed_by.casefold()

    rejection_reason: str | None = None
    if decision == "reject":
        rejection_reason_value = transition_request["rejection_reason"]
        if not isinstance(rejection_reason_value, str):
            raise ApprovalTransitionError("rejection_reason must be a string")
        rejection_reason = rejection_reason_value.strip()
        if not rejection_reason:
            raise ApprovalTransitionError("rejection_reason must not be blank")

    return decision, reviewed_by, reviewed_by_normalized, rejection_reason


def validate_multi_review_transition(
    current_record: Mapping[str, Any],
    existing_reviews: Sequence[Mapping[str, Any]],
    transition_request: Mapping[str, Any],
    *,
    reviewed_at: str | datetime | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate one proposed review decision (approve or reject) against one
    risk-aware approval snapshot and its already-recorded review history,
    producing a single immutable, persistence-ready transition plan.

    This is an additional, independent public function -- it does not
    replace, alter, or share any mutable state with `validate_approval_transition`.
    Existing single-review Block 5 behavior (`pending -> approved`,
    `pending -> rejected`, `approved -> consumed`) is untouched by this
    function's existence.

    `current_record` must contain the same sixteen fields
    `validate_approval_record` already requires, plus exactly `risk_level`
    (one of `low`/`medium`/`high`/`critical`) and `required_approvals` (`1`
    or `2`), consistent with the canonical `core.approval_risk` mapping.
    `current_record.status` may additionally be `"partially_approved"` --
    a transitional status this function alone understands; it is never
    added to `APPROVAL_STATUSES` or to `validate_approval_record`'s own
    sixteen-field contract by this function.

    `existing_reviews` must be a sequence of already-verified review
    summaries, each containing exactly `approval_id`, `reviewer_identity`,
    `reviewer_identity_normalized`, `decision` (`"approve"` or `"reject"`),
    and `decided_at`. Every summary must belong to `current_record["id"]`,
    `reviewer_identity` must already be stored trimmed and nonblank,
    `reviewer_identity_normalized` must exactly equal
    `reviewer_identity.strip().casefold()` (never PostgreSQL `lower()`,
    exactly like this project's existing `reviewed_by != requested_by`
    comparison), duplicate normalized identities are rejected, and an
    existing rejection recorded against an otherwise still-`pending`/
    `partially_approved` current record is rejected as an internal
    inconsistency.

    `transition_request` must contain `decision` (`"approve"` or
    `"reject"`) and `reviewed_by`; a reject decision additionally requires
    a nonblank `rejection_reason`, and an approve decision forbids it. No
    other field is accepted. `reviewed_by` is a caller-supplied claimed
    identity, normalized by `.strip()` (display form) and
    `.strip().casefold()` (comparison form), exactly like every other
    claimed identity in this module.

    `reviewed_at`/`now` resolve the decision's timestamp exactly like
    `validate_approval_transition`'s own timestamp parameters: an explicit
    `reviewed_at` is validated and used as-is; otherwise `now` (when
    supplied, must be an aware datetime) is used as the generation basis;
    otherwise the real current UTC time is used.

    Approve behavior:

    - `required_approvals == 1`: `current_record.status` must be
      `"pending"` with zero existing approve reviews; the decision moves
      `pending -> approved` directly, with `set_fields` containing
      exactly `status`, `approved_by`, `approved_at`.
    - `required_approvals == 2`, zero existing approve reviews:
      `current_record.status` must be `"pending"`; the decision moves
      `pending -> partially_approved`, with `set_fields` containing
      exactly `status`.
    - `required_approvals == 2`, exactly one existing approve review:
      `current_record.status` must be `"partially_approved"`; the
      decision moves `partially_approved -> approved`, with `set_fields`
      containing exactly `status`, `approved_by`, `approved_at` -- the
      completing (second) reviewer becomes `approved_by`.
    - Every approve attempt independently requires `reviewed_by` to differ,
      by trimmed casefold comparison, from both `current_record.requested_by`
      and every existing approve review's own `reviewer_identity_normalized`
      -- the same reviewer can never count twice, and the requester can
      never approve their own request, regardless of `required_approvals`.
    - An approve decision strictly before `current_record.expires_at` (when
      set) may succeed; at or after it, it is rejected -- identical to
      `validate_approval_transition`'s own approve-expiry rule.

    Reject behavior: allowed from `"pending"` or `"partially_approved"`
    only, from any claimed identity including the original requester
    (self-withdrawal remains allowed, exactly like Block 5), moves directly
    to `"rejected"` with `set_fields` containing exactly `status`,
    `rejected_by`, `rejected_at`, `rejection_reason`, and is never subject
    to the expiry check (a rejection after expiry remains allowed, exactly
    like Block 5).

    Neither an approve nor a reject decision is accepted when
    `current_record.status` is already `"approved"`, `"rejected"`, or
    `"consumed"`.

    Returns exactly:

        {
            "approval_id": "...",
            "from_status": "...",
            "to_status": "...",
            "required_approvals": 1 | 2,
            "approval_count_before": 0 | 1,
            "approval_count_after": 0 | 1 | 2,
            "review_record": {
                "approval_id": "...",
                "reviewer_identity": "...",
                "reviewer_identity_normalized": "...",
                "decision": "approve" | "reject",
                "decided_at": "...",
            },
            "set_fields": {...},
        }

    Dictionary key order is never security-significant anywhere in this
    result, exactly like every other transition plan this module produces.
    This plan contains no SQL, table name, RPC name, MCP argument, or
    persistence operation name of any kind -- it remains a
    **validated transition plan -- not persisted**, exactly like
    `validate_approval_transition`'s own output.

    Raises `ApprovalTransitionError` for any structurally invalid
    `current_record`, `existing_reviews`, or `transition_request`, an
    inconsistent stored `risk_level`/`required_approvals` pair, an
    unsupported state transition, a same-principal or duplicate approval
    attempt, a chronological inconsistency, or an expired approval attempt.
    Never mutates `current_record`, `existing_reviews`, or
    `transition_request` (nor any nested mapping within any of them), and
    never retains a reference to any caller-supplied mutable object.
    """
    validated_record = _validate_multi_review_current_record(current_record)
    validated_reviews = _validate_existing_reviews(existing_reviews, validated_record)
    decision, reviewer_identity, reviewer_identity_normalized, rejection_reason = (
        _validate_multi_review_transition_request(transition_request)
    )

    status = validated_record["status"]
    required_approvals = validated_record["required_approvals"]
    requested_by_normalized = validated_record["requested_by"].strip().casefold()

    approve_reviews = [review for review in validated_reviews if review["decision"] == "approve"]
    approval_count_before = len(approve_reviews)

    if status not in ("pending", "partially_approved"):
        raise ApprovalTransitionError(
            f"cannot review: current status must be 'pending' or 'partially_approved', got {status!r}"
        )

    decided_at = _resolve_transition_timestamp(reviewed_at, now, "decided_at")

    if _parse_canonical(decided_at) < _parse_canonical(validated_record["requested_at"]):
        raise ApprovalTransitionError("decided_at must be at or after requested_at")

    if decision == "reject":
        review_record = {
            "approval_id": validated_record["id"],
            "reviewer_identity": reviewer_identity,
            "reviewer_identity_normalized": reviewer_identity_normalized,
            "decision": "reject",
            "decided_at": decided_at,
        }

        return {
            "approval_id": validated_record["id"],
            "from_status": status,
            "to_status": "rejected",
            "required_approvals": required_approvals,
            "approval_count_before": approval_count_before,
            "approval_count_after": approval_count_before,
            "review_record": review_record,
            "set_fields": {
                "status": "rejected",
                "rejected_by": reviewer_identity,
                "rejected_at": decided_at,
                "rejection_reason": rejection_reason,
            },
        }

    # decision == "approve"
    if reviewer_identity_normalized == requested_by_normalized:
        raise ApprovalTransitionError("reviewed_by must differ from the original requester")

    for review in approve_reviews:
        if review["reviewer_identity_normalized"] == reviewer_identity_normalized:
            raise ApprovalTransitionError("reviewed_by has already reviewed this approval")

    if (
        validated_record["expires_at"] is not None
        and _parse_canonical(decided_at) >= _parse_canonical(validated_record["expires_at"])
    ):
        raise ApprovalTransitionError("decided_at must be strictly before expires_at")

    if required_approvals == 1:
        if status != "pending" or approval_count_before != 0:
            raise ApprovalTransitionError("cannot approve: an approve review already exists")
        to_status = "approved"
        set_fields = {"status": "approved", "approved_by": reviewer_identity, "approved_at": decided_at}
    elif approval_count_before == 0:
        if status != "pending":
            raise ApprovalTransitionError("cannot record first approval: current status must be 'pending'")
        to_status = "partially_approved"
        set_fields = {"status": "partially_approved"}
    elif approval_count_before == 1:
        if status != "partially_approved":
            raise ApprovalTransitionError(
                "cannot record second approval: current status must be 'partially_approved'"
            )
        to_status = "approved"
        set_fields = {"status": "approved", "approved_by": reviewer_identity, "approved_at": decided_at}
    else:
        raise ApprovalTransitionError("cannot approve: required approvals are already satisfied")

    review_record = {
        "approval_id": validated_record["id"],
        "reviewer_identity": reviewer_identity,
        "reviewer_identity_normalized": reviewer_identity_normalized,
        "decision": "approve",
        "decided_at": decided_at,
    }

    return {
        "approval_id": validated_record["id"],
        "from_status": status,
        "to_status": to_status,
        "required_approvals": required_approvals,
        "approval_count_before": approval_count_before,
        "approval_count_after": approval_count_before + 1,
        "review_record": review_record,
        "set_fields": set_fields,
    }
