"""Pure-Python-adjacent persistence boundary for the pending half of the
approval lifecycle: constructing an insert operation for a brand-new
pending approval, and loading one existing approval record by its
canonical primary key.

This module is a dependency-injected adapter, not a Supabase client:

- It never imports `supabase`, `requests`, `urllib`, `socket`, `subprocess`,
  any MCP module, any command module, or any AI/model library.
- It never creates a database client and never reads an environment
  variable. The only I/O it performs is calling the single `executor`
  callable supplied by the caller for each public function -- a future
  bridge (Supabase MCP tool call, Supabase Python client, or any other
  PostgreSQL-compatible implementation) is entirely out of scope here.
- It never issues a consume operation, never opens a database transaction,
  never calls a PostgreSQL RPC function, and never updates an
  investigation. Exactly three operations exist: inserting one pending
  approval row, selecting one approval row by `id`, and a single
  conditional update that moves one approval from `pending` to `approved`
  or from `pending` to `rejected` -- guarded by an `id` filter plus a
  full pending-lifecycle-shape filter, never a bare `id`-only update.
- It never authenticates anyone, never hashes an action, never enforces
  immutable history, and never performs containment or Red Team execution.

`validate_approval_request` (from `core.approval_request`) remains the
sole owner of the request-side contract, and `validate_approval_record`
(from `core.approval_transition`) remains the sole owner of the
sixteen-field record contract. This module never duplicates either
validator's rules -- it only shapes operation descriptors and normalizes
executor responses through them, exactly once per call.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Protocol

from core.approval_request import ApprovalRequestError, validate_approval_request
from core.approval_transition import (
    ApprovalTransitionError,
    validate_approval_record,
    validate_approval_transition,
)


class ApprovalExecutor(Protocol):
    def __call__(
        self,
        operation: Mapping[str, Any],
        /,
    ) -> object:
        ...


class ApprovalPersistenceError(Exception):
    """Raised for any failure at the approval-persistence boundary.

    This is the base of a small hierarchy: `ApprovalNotFoundError` (a
    valid lookup found no row), `ApprovalResponseError` (the executor
    returned a malformed or internally-inconsistent response), and
    `ApprovalTransportError` (the executor itself raised). Direct
    instances of this base class are raised for invalid adapter input
    (a malformed validated request, a malformed expiry, or a malformed
    approval identifier), before the executor is ever invoked. Messages
    are always fixed and generic -- never the caller's raw input, never a
    validator's original error text, and never any part of a returned
    database row.
    """


class ApprovalNotFoundError(ApprovalPersistenceError):
    """Raised when a structurally valid approval lookup finds no row."""


class ApprovalResponseError(ApprovalPersistenceError):
    """Raised when the executor's response is malformed, wrongly shaped,
    or fails record validation."""


class ApprovalTransportError(ApprovalPersistenceError):
    """Raised when the supplied executor itself raises. The original
    exception is never exposed -- only this fixed, generic error."""


class ApprovalConflictError(ApprovalPersistenceError):
    """Raised only when a structurally valid, genuinely re-verified
    approve/reject conditional update matches zero rows -- the approval
    was concurrently modified (or no longer pending) between load and
    update. Never retried."""


_VALIDATED_REQUEST_FIELDS = frozenset(
    {"investigation_id", "action_type", "action_payload", "requested_by", "requested_at"}
)

_RECORD_FIELDS = (
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

_NULLABLE_RECORD_FIELDS = (
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "rejection_reason",
    "expires_at",
    "consumed_by",
    "consumed_at",
)

_INVALID_REQUEST_MESSAGE = "Invalid validated approval request."
_INVALID_EXPIRY_MESSAGE = "Invalid approval expiry."
_INVALID_ID_MESSAGE = "Invalid approval identifier."
_INSERT_RESPONSE_MESSAGE = "Approval insert response was invalid."
_LOOKUP_RESPONSE_MESSAGE = "Approval lookup response was invalid."
_NOT_FOUND_MESSAGE = "Approval was not found."
_TRANSPORT_MESSAGE = "Approval persistence operation failed."
_INVALID_REVIEW_INPUT_MESSAGE = "Invalid review transition input."
_INVALID_REVIEW_PLAN_MESSAGE = "Invalid review transition plan."
_REVIEW_RESPONSE_MESSAGE = "Approval review response was invalid."
_REVIEW_CONFLICT_MESSAGE = "Approval review transition conflicted."

_REVIEW_TRANSITION_PLAN_FIELDS = frozenset({"approval_id", "from_status", "to_status", "set_fields"})
_REVIEW_TARGET_STATUSES = frozenset({"approved", "rejected"})

_APPROVE_SET_FIELDS_ORDER = ("status", "approved_by", "approved_at")
_REJECT_SET_FIELDS_ORDER = ("status", "rejected_by", "rejected_at", "rejection_reason")

_PENDING_LIFECYCLE_FILTER_FIELDS = (
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "rejection_reason",
    "consumed_by",
    "consumed_at",
)


def _validate_validated_request(validated_request: Any) -> dict[str, Any]:
    if not isinstance(validated_request, Mapping):
        raise ApprovalPersistenceError(_INVALID_REQUEST_MESSAGE)

    if set(validated_request) != _VALIDATED_REQUEST_FIELDS:
        raise ApprovalPersistenceError(_INVALID_REQUEST_MESSAGE)

    try:
        canonical = validate_approval_request(validated_request)
    except ApprovalRequestError:
        raise ApprovalPersistenceError(_INVALID_REQUEST_MESSAGE) from None

    if canonical != dict(validated_request):
        raise ApprovalPersistenceError(_INVALID_REQUEST_MESSAGE)

    return canonical


def _normalize_timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ApprovalPersistenceError(_INVALID_EXPIRY_MESSAGE)
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError:
            raise ApprovalPersistenceError(_INVALID_EXPIRY_MESSAGE) from None
    else:
        raise ApprovalPersistenceError(_INVALID_EXPIRY_MESSAGE)

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ApprovalPersistenceError(_INVALID_EXPIRY_MESSAGE)

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_canonical(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_expiry(expires_at: Any, requested_at: str) -> str | None:
    if expires_at is None:
        return None

    canonical_expires_at = _normalize_timestamp(expires_at)

    if _parse_canonical(canonical_expires_at) <= _parse_canonical(requested_at):
        raise ApprovalPersistenceError(_INVALID_EXPIRY_MESSAGE)

    return canonical_expires_at


def _validate_approval_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalPersistenceError(_INVALID_ID_MESSAGE)
    stripped = value.strip()
    if not stripped:
        raise ApprovalPersistenceError(_INVALID_ID_MESSAGE)
    try:
        parsed = uuid.UUID(stripped)
    except ValueError:
        raise ApprovalPersistenceError(_INVALID_ID_MESSAGE) from None
    return str(parsed)


def _invoke_executor(executor: ApprovalExecutor, operation: Mapping[str, Any]) -> object:
    try:
        return executor(copy.deepcopy(operation))
    except Exception:
        raise ApprovalTransportError(_TRANSPORT_MESSAGE) from None


def _validate_row_shape(row: Any, generic_message: str) -> dict[str, Any]:
    if not isinstance(row, Mapping):
        raise ApprovalResponseError(generic_message)

    restored = dict(row)
    for field_name in _NULLABLE_RECORD_FIELDS:
        if field_name not in restored:
            restored[field_name] = None

    try:
        record = validate_approval_record(restored)
    except ApprovalTransitionError:
        raise ApprovalResponseError(generic_message) from None

    return record


def insert_pending_approval(
    executor: ApprovalExecutor,
    validated_request: Mapping[str, Any],
    *,
    expires_at: str | datetime | None = None,
) -> dict[str, Any]:
    """Insert one new pending approval row and return its validated,
    canonical sixteen-field record.

    `validated_request` must already be the exact, unmodified output of
    `core.approval_request.validate_approval_request` -- this function
    re-validates it and rejects any input that validation would change,
    rather than silently canonicalizing it. `expires_at` is independent
    of the request contract; when supplied it must be an aware datetime
    or ISO-8601 string strictly after `requested_at`, and is canonicalized
    to a UTC `Z`-suffixed string.

    Invokes `executor` exactly once with an insert operation descriptor
    for the `approvals` table. The executor's response must be a Python
    list containing exactly one row mapping; that row is normalized
    (missing nullable lifecycle fields restored as `None`) and validated
    through `validate_approval_record` exactly once, then checked to
    confirm it actually reflects the request that was submitted.

    Raises `ApprovalPersistenceError` for invalid `validated_request` or
    `expires_at` input (before the executor is ever invoked),
    `ApprovalResponseError` for any malformed, mismatched, or invalid
    executor response, and `ApprovalTransportError` if `executor` itself
    raises. Never raises `ApprovalRequestError` or `ApprovalTransitionError`
    directly, and never returns a persistence receipt, row count, or
    operation descriptor -- only the validated record itself.
    """
    canonical_request = _validate_validated_request(validated_request)
    canonical_expires_at = _validate_expiry(expires_at, canonical_request["requested_at"])

    values: dict[str, Any] = {
        "investigation_id": canonical_request["investigation_id"],
        "action_type": canonical_request["action_type"],
        "action_payload": copy.deepcopy(canonical_request["action_payload"]),
        "requested_by": canonical_request["requested_by"],
        "requested_at": canonical_request["requested_at"],
        "status": "pending",
    }
    if canonical_expires_at is not None:
        values["expires_at"] = canonical_expires_at

    operation = {
        "operation": "insert",
        "table": "approvals",
        "values": values,
        "returning": list(_RECORD_FIELDS),
    }

    response = _invoke_executor(executor, operation)

    if not isinstance(response, list):
        raise ApprovalResponseError(_INSERT_RESPONSE_MESSAGE)
    if len(response) != 1:
        raise ApprovalResponseError(_INSERT_RESPONSE_MESSAGE)

    record = _validate_row_shape(response[0], _INSERT_RESPONSE_MESSAGE)

    if (
        record["investigation_id"] != canonical_request["investigation_id"]
        or record["action_type"] != canonical_request["action_type"]
        or record["action_payload"] != canonical_request["action_payload"]
        or record["requested_by"] != canonical_request["requested_by"]
        or record["requested_at"] != canonical_request["requested_at"]
    ):
        raise ApprovalResponseError(_INSERT_RESPONSE_MESSAGE)

    if record["status"] != "pending":
        raise ApprovalResponseError(_INSERT_RESPONSE_MESSAGE)

    if record["expires_at"] != canonical_expires_at:
        raise ApprovalResponseError(_INSERT_RESPONSE_MESSAGE)

    return record


def load_approval_record(
    executor: ApprovalExecutor,
    approval_id: str,
) -> dict[str, Any]:
    """Load one existing approval row by its canonical `id` and return
    its validated, canonical sixteen-field record.

    `approval_id` is canonicalized as a UUID before the executor is ever
    invoked. Invokes `executor` exactly once with a primary-key-only
    select operation descriptor for the `approvals` table (`filters`
    contains only `id`; no investigation, status, or claimed-identity
    filter is ever added). Does not check `expires_at` against wall-clock
    time -- a historically expired but structurally valid record still
    loads successfully.

    The executor's response must be a Python list. Zero rows raises
    `ApprovalNotFoundError`; more than one row raises
    `ApprovalResponseError`. The single returned row is normalized
    (missing nullable lifecycle fields restored as `None`) and validated
    through `validate_approval_record` exactly once.

    Raises `ApprovalPersistenceError` for a malformed `approval_id`
    (before the executor is ever invoked), `ApprovalResponseError` for
    any malformed or invalid executor response, and
    `ApprovalTransportError` if `executor` itself raises. Never raises
    `ApprovalTransitionError` directly, and never returns anything beyond
    the validated sixteen-field record.
    """
    canonical_id = _validate_approval_id(approval_id)

    operation = {
        "operation": "select",
        "table": "approvals",
        "columns": list(_RECORD_FIELDS),
        "filters": {"id": canonical_id},
        "limit": 2,
    }

    response = _invoke_executor(executor, operation)

    if not isinstance(response, list):
        raise ApprovalResponseError(_LOOKUP_RESPONSE_MESSAGE)
    if len(response) == 0:
        raise ApprovalNotFoundError(_NOT_FOUND_MESSAGE)
    if len(response) > 1:
        raise ApprovalResponseError(_LOOKUP_RESPONSE_MESSAGE)

    record = _validate_row_shape(response[0], _LOOKUP_RESPONSE_MESSAGE)

    if record["id"] != canonical_id:
        raise ApprovalResponseError(_LOOKUP_RESPONSE_MESSAGE)

    return record


def _validate_current_record_for_review(current_record: Any) -> dict[str, Any]:
    if not isinstance(current_record, Mapping):
        raise ApprovalPersistenceError(_INVALID_REVIEW_INPUT_MESSAGE)

    try:
        validated = validate_approval_record(current_record)
    except ApprovalTransitionError:
        raise ApprovalPersistenceError(_INVALID_REVIEW_INPUT_MESSAGE) from None

    if validated != dict(current_record):
        raise ApprovalPersistenceError(_INVALID_REVIEW_INPUT_MESSAGE)

    if validated["status"] != "pending":
        raise ApprovalPersistenceError(_INVALID_REVIEW_INPUT_MESSAGE)

    return validated


def _validate_review_transition_plan(
    transition_plan: Any,
    validated_current_record: Mapping[str, Any],
) -> tuple[str, str]:
    if not isinstance(transition_plan, Mapping):
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)

    if set(transition_plan) != _REVIEW_TRANSITION_PLAN_FIELDS:
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)

    approval_id = transition_plan["approval_id"]
    canonical_approval_id = _validate_approval_id(approval_id)
    if canonical_approval_id != approval_id:
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)
    if canonical_approval_id != validated_current_record["id"]:
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)

    from_status = transition_plan["from_status"]
    if from_status != "pending":
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)
    if from_status != validated_current_record["status"]:
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)

    to_status = transition_plan["to_status"]
    if to_status not in _REVIEW_TARGET_STATUSES:
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)

    set_fields = transition_plan["set_fields"]
    if not isinstance(set_fields, Mapping) or not set_fields:
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)

    if set_fields.get("status") != to_status:
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)

    return to_status, canonical_approval_id


def _verify_genuine_review_plan(
    to_status: str,
    transition_plan: Mapping[str, Any],
    validated_current_record: Mapping[str, Any],
) -> dict[str, Any]:
    set_fields = transition_plan["set_fields"]

    if to_status == "approved":
        if list(set_fields) != list(_APPROVE_SET_FIELDS_ORDER):
            raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)
        reconstructed_request = {
            "transition": "approve",
            "reviewed_by": set_fields.get("approved_by"),
            "reviewed_at": set_fields.get("approved_at"),
        }
    else:
        if list(set_fields) != list(_REJECT_SET_FIELDS_ORDER):
            raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)
        reconstructed_request = {
            "transition": "reject",
            "reviewed_by": set_fields.get("rejected_by"),
            "reviewed_at": set_fields.get("rejected_at"),
            "rejection_reason": set_fields.get("rejection_reason"),
        }

    try:
        recomputed_plan = validate_approval_transition(validated_current_record, reconstructed_request)
    except ApprovalTransitionError:
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE) from None

    if recomputed_plan != dict(transition_plan):
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)

    return recomputed_plan


def _compute_expected_updated_record(
    validated_current_record: Mapping[str, Any],
    set_fields: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = dict(copy.deepcopy(dict(validated_current_record)))
    candidate.update(copy.deepcopy(dict(set_fields)))
    try:
        return validate_approval_record(candidate)
    except ApprovalTransitionError:
        raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE) from None


def apply_approval_review_transition(
    executor: ApprovalExecutor,
    current_record: Mapping[str, Any],
    transition_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply one genuine pending -> approved or pending -> rejected
    transition plan as a single conditional update, and return the
    verified plan alongside the updated, canonical sixteen-field record.

    `current_record` must already be the exact, canonical output of
    `validate_approval_record`, with `status == "pending"` -- an
    approved, rejected, or consumed record is rejected before the
    executor is ever invoked, as is any record validation would change.
    `transition_plan` must contain exactly `approval_id`, `from_status`,
    `to_status`, and `set_fields`; only `pending -> approved` and
    `pending -> rejected` are supported (a consume plan, a pending
    target, a repeated-state plan, or any missing/unknown/noncanonical
    field is rejected before the executor is ever invoked).

    The supplied plan is never trusted at face value: this function
    reconstructs the equivalent transition request from `set_fields` and
    recomputes the plan by calling `validate_approval_transition` exactly
    once, requiring the result to equal the supplied plan exactly. This
    re-derives (and cannot bypass) self-approval prevention, Unicode
    casefold comparison, expiry enforcement, timestamp validation, and
    identity canonicalization -- self-rejection and rejection-after-
    expiry remain allowed, exactly as `validate_approval_transition`
    itself allows them.

    Invokes `executor` exactly once with a conditional update operation
    descriptor for the `approvals` table: `values` contains only the
    verified `set_fields`, and `filters` requires the canonical `id`,
    `status == "pending"`, and every lifecycle field still null -- so a
    concurrently modified or already-transitioned row can never match.
    Zero returned rows raises `ApprovalConflictError` (never retried).
    Exactly one row is required; it is normalized, validated through
    `validate_approval_record`, and required to equal the independently
    computed expected updated record exactly (proving the identifier,
    frozen request fields, `action_payload`, `expires_at`, and
    `created_at` are unchanged, and that only the plan's own `set_fields`
    were applied).

    Returns exactly:

        {
            "transition_plan": {...},
            "updated_record": {...},
        }

    This is a:

        Verified approval review update -- no consumption or investigation update

    Raises `ApprovalPersistenceError` for invalid `current_record` or
    `transition_plan` input (before the executor is ever invoked),
    `ApprovalConflictError` for a genuine plan matched against zero rows,
    `ApprovalResponseError` for any other malformed or mismatched executor
    response, and `ApprovalTransportError` if `executor` itself raises.
    Never raises `ApprovalTransitionError` directly. Never mutates
    `current_record`, its nested `action_payload`, `transition_plan`, or
    `transition_plan["set_fields"]`, and never returns a persistence
    receipt, row count, operation descriptor, authentication result, or
    investigation-update result.
    """
    validated_current_record = _validate_current_record_for_review(current_record)

    to_status, canonical_approval_id = _validate_review_transition_plan(
        transition_plan, validated_current_record
    )

    recomputed_plan = _verify_genuine_review_plan(to_status, transition_plan, validated_current_record)

    genuine_set_fields = recomputed_plan["set_fields"]

    expected_updated_record = _compute_expected_updated_record(validated_current_record, genuine_set_fields)

    filters: dict[str, Any] = {"id": canonical_approval_id, "status": "pending"}
    for field_name in _PENDING_LIFECYCLE_FILTER_FIELDS:
        filters[field_name] = None

    operation = {
        "operation": "update",
        "table": "approvals",
        "values": copy.deepcopy(dict(genuine_set_fields)),
        "filters": filters,
        "returning": list(_RECORD_FIELDS),
    }

    response = _invoke_executor(executor, operation)

    if not isinstance(response, list):
        raise ApprovalResponseError(_REVIEW_RESPONSE_MESSAGE)
    if len(response) == 0:
        raise ApprovalConflictError(_REVIEW_CONFLICT_MESSAGE)
    if len(response) > 1:
        raise ApprovalResponseError(_REVIEW_RESPONSE_MESSAGE)

    updated_record = _validate_row_shape(response[0], _REVIEW_RESPONSE_MESSAGE)

    if updated_record != expected_updated_record:
        raise ApprovalResponseError(_REVIEW_RESPONSE_MESSAGE)

    return {
        "transition_plan": copy.deepcopy(dict(recomputed_plan)),
        "updated_record": copy.deepcopy(updated_record),
    }
