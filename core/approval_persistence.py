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
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, Protocol

from core.approval_request import (
    ApprovalRequestError,
    validate_approval_request,
    validate_risk_aware_approval_request,
)
from core.approval_transition import (
    ApprovalTransitionError,
    validate_approval_record,
    validate_approval_review_record,
    validate_approval_transition,
    validate_multi_review_transition,
    validate_risk_aware_approval_record,
)
from core.decision_context import INVESTIGATION_STATUSES
from core.evidence_normalizer import CONFIDENCE_LEVELS


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
_RECORD_FIELDS_SET = frozenset(_RECORD_FIELDS)

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

_INVALID_CONSUMPTION_INPUT_MESSAGE = "Invalid approval consumption input."
_CONSUMPTION_CONFLICT_MESSAGE = "Approval consumption conflicted."
_CONSUMPTION_RESPONSE_MESSAGE = "Approval consumption response was invalid."

_CONSUME_TRANSITION_PLAN_FIELDS = (
    "approval_id",
    "from_status",
    "to_status",
    "set_fields",
    "expected_investigation_id",
    "expected_action_type",
)
_CONSUME_SET_FIELDS_ORDER = ("status", "consumed_by", "consumed_at")

_CONSUMPTION_RPC_FUNCTION_NAME = "consume_approval_and_update_investigation_state"
_CONSUMPTION_RPC_PARAMETER_ORDER = (
    "approval_id",
    "expected_investigation_id",
    "expected_action_type",
    "consumed_by",
    "consumed_at",
)

_INVESTIGATION_RESULT_FIELDS = (
    "investigation_status",
    "investigation_confidence",
    "investigation_updated_at",
)
_CONSUMPTION_ROW_FIELDS_SET = _RECORD_FIELDS_SET | frozenset(_INVESTIGATION_RESULT_FIELDS)

# ---------------------------------------------------------------------------
# Risk-aware persistence operations (Block 6, Step 4)
# ---------------------------------------------------------------------------

_RISK_AWARE_RECORD_FIELDS = _RECORD_FIELDS + ("risk_level", "required_approvals")
_RISK_AWARE_RECORD_FIELDS_SET = frozenset(_RISK_AWARE_RECORD_FIELDS)

_REVIEW_LOOKUP_COLUMNS = (
    "approval_id",
    "reviewer_identity",
    "reviewer_identity_normalized",
    "decision",
    "decided_at",
)
# Comfortably exceeds any currently-possible required_approvals count (max
# 2 today) -- a defensive bound, not a real limit on review history size.
_REVIEW_LOOKUP_LIMIT = 10

_INVALID_RISK_AWARE_REQUEST_MESSAGE = "Invalid risk-aware approval request."
_RISK_AWARE_INSERT_RESPONSE_MESSAGE = "Risk-aware approval insert response was invalid."
_RISK_AWARE_LOOKUP_RESPONSE_MESSAGE = "Risk-aware approval lookup response was invalid."
_REVIEW_LOOKUP_RESPONSE_MESSAGE = "Approval review lookup response was invalid."

_INVALID_MULTI_REVIEW_INPUT_MESSAGE = "Invalid multi-review transition input."
_INVALID_MULTI_REVIEW_PLAN_MESSAGE = "Invalid multi-review transition plan."
_MULTI_REVIEW_RESPONSE_MESSAGE = "Multi-review transition response was invalid."
_MULTI_REVIEW_CONFLICT_MESSAGE = "Multi-review transition conflicted."

_MULTI_REVIEW_TRANSITION_PLAN_FIELDS = frozenset({
    "approval_id",
    "from_status",
    "to_status",
    "required_approvals",
    "approval_count_before",
    "approval_count_after",
    "review_record",
    "set_fields",
})

_REVIEW_RPC_FUNCTION_NAME = "record_approval_review_and_promote_status"
_REVIEW_RPC_PARAMETER_ORDER = (
    "approval_id",
    "expected_from_status",
    "expected_to_status",
    "expected_required_approvals",
    "expected_approval_count_before",
    "reviewer_identity",
    "reviewer_identity_normalized",
    "decision",
    "decided_at",
    "rejection_reason",
)

_REVIEW_RPC_RESULT_EXTRA_FIELDS = (
    "review_approval_id",
    "reviewer_identity",
    "reviewer_identity_normalized",
    "review_decision",
    "review_decided_at",
    "approval_count",
)
_REVIEW_RPC_RESULT_FIELDS_SET = _RISK_AWARE_RECORD_FIELDS_SET | frozenset(_REVIEW_RPC_RESULT_EXTRA_FIELDS)


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


def _validate_risk_aware_row_shape(row: Any, generic_message: str) -> dict[str, Any]:
    if not isinstance(row, Mapping):
        raise ApprovalResponseError(generic_message)

    restored = dict(row)
    for field_name in _NULLABLE_RECORD_FIELDS:
        if field_name not in restored:
            restored[field_name] = None

    try:
        record = validate_risk_aware_approval_record(restored)
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
        # Key *set* membership is the real contract -- mapping insertion
        # order is never security-significant, exactly as this project's
        # own sort_keys=True JSON convention already treats it (see
        # core.approval_bridge._deep_ordered_equal). A genuine plan
        # round-tripped through core.approval_transition_cli's real
        # sort_keys=True output always parses back in alphabetical key
        # order, which must still be accepted here.
        if set(set_fields) != set(_APPROVE_SET_FIELDS_ORDER):
            raise ApprovalPersistenceError(_INVALID_REVIEW_PLAN_MESSAGE)
        reconstructed_request = {
            "transition": "approve",
            "reviewed_by": set_fields.get("approved_by"),
            "reviewed_at": set_fields.get("approved_at"),
        }
    else:
        if set(set_fields) != set(_REJECT_SET_FIELDS_ORDER):
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
    generic_message: str = _INVALID_REVIEW_PLAN_MESSAGE,
) -> dict[str, Any]:
    candidate = dict(copy.deepcopy(dict(validated_current_record)))
    candidate.update(copy.deepcopy(dict(set_fields)))
    try:
        return validate_approval_record(candidate)
    except ApprovalTransitionError:
        raise ApprovalPersistenceError(generic_message) from None


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


def _validate_current_record_for_consumption(current_record: Any) -> dict[str, Any]:
    if not isinstance(current_record, Mapping):
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    try:
        validated = validate_approval_record(current_record)
    except ApprovalTransitionError:
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE) from None

    if validated != dict(current_record):
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    if validated["status"] != "approved":
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    return validated


def _validate_consume_transition_plan(
    transition_plan: Any,
    validated_current_record: Mapping[str, Any],
) -> tuple[str, str]:
    if not isinstance(transition_plan, Mapping):
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    # Key *set* membership is the real contract -- mapping insertion order
    # is never security-significant (see the matching comments elsewhere in
    # this module). A genuine plan round-tripped through
    # core.approval_transition_cli's real sort_keys=True output always
    # parses back in alphabetical key order, not this tuple's literal order.
    if set(transition_plan) != set(_CONSUME_TRANSITION_PLAN_FIELDS):
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    approval_id = transition_plan["approval_id"]
    canonical_approval_id = _validate_approval_id(approval_id)
    if canonical_approval_id != approval_id:
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)
    if canonical_approval_id != validated_current_record["id"]:
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    if transition_plan["from_status"] != "approved":
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)
    if transition_plan["from_status"] != validated_current_record["status"]:
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    if transition_plan["to_status"] != "consumed":
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    expected_investigation_id = transition_plan["expected_investigation_id"]
    canonical_expected_investigation_id = _validate_approval_id(expected_investigation_id)
    if canonical_expected_investigation_id != expected_investigation_id:
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)
    if canonical_expected_investigation_id != validated_current_record["investigation_id"]:
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    expected_action_type = transition_plan["expected_action_type"]
    if not isinstance(expected_action_type, str):
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)
    if expected_action_type != expected_action_type.strip().lower():
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)
    if expected_action_type != validated_current_record["action_type"]:
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)
    if expected_action_type != "update_investigation_state":
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    set_fields = transition_plan["set_fields"]
    if not isinstance(set_fields, Mapping):
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)
    # Key *set* membership is the real contract -- mapping insertion order
    # is never security-significant (see the matching comment in
    # _verify_genuine_review_plan above). A genuine plan round-tripped
    # through core.approval_transition_cli's real sort_keys=True output
    # always parses back in alphabetical key order.
    if set(set_fields) != set(_CONSUME_SET_FIELDS_ORDER):
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)
    if set_fields.get("status") != "consumed":
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    return canonical_approval_id, canonical_expected_investigation_id


def _verify_genuine_consume_plan(
    transition_plan: Mapping[str, Any],
    validated_current_record: Mapping[str, Any],
) -> dict[str, Any]:
    set_fields = transition_plan["set_fields"]
    reconstructed_request = {
        "transition": "consume",
        "consumed_by": set_fields.get("consumed_by"),
        "consumed_at": set_fields.get("consumed_at"),
        "expected_investigation_id": transition_plan["expected_investigation_id"],
        "expected_action_type": transition_plan["expected_action_type"],
    }

    try:
        recomputed_plan = validate_approval_transition(validated_current_record, reconstructed_request)
    except ApprovalTransitionError:
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE) from None

    if recomputed_plan != dict(transition_plan):
        raise ApprovalPersistenceError(_INVALID_CONSUMPTION_INPUT_MESSAGE)

    return recomputed_plan


def _validate_investigation_status(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)
    stripped = value.strip()
    if not stripped or value != stripped:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)
    if value not in INVESTIGATION_STATUSES:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)
    return value


def _validate_investigation_confidence(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)
    stripped = value.strip()
    if not stripped or value != stripped:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)
    if value not in CONFIDENCE_LEVELS:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)
    return value


def apply_approval_consumption(
    executor: ApprovalExecutor,
    current_record: Mapping[str, Any],
    transition_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply one genuine approved -> consumed transition atomically, via a
    single PostgreSQL RPC call that consumes the approval and updates its
    referenced investigation together, and return the verified plan,
    consumed approval record, and investigation result.

    `current_record` must already be the exact, canonical output of
    `validate_approval_record`, with `status == "approved"` -- a pending,
    rejected, or consumed record is rejected before the executor is ever
    invoked, as is any record validation would change. `transition_plan`
    must contain exactly `approval_id`, `from_status`, `to_status`,
    `set_fields`, `expected_investigation_id`, and `expected_action_type`,
    in that exact order -- an approve/reject plan, an old four-field
    consume plan, or any missing/unknown/reordered field is rejected
    before the executor is ever invoked.

    The supplied plan is never trusted at face value: this function
    reconstructs the equivalent consume transition request from
    `set_fields` and the plan's own binding fields, and recomputes the
    plan by calling `validate_approval_transition` exactly once, requiring
    the result to equal the supplied plan exactly. This re-derives (and
    cannot bypass) the approved-and-unconsumed requirement, consumed
    identity/timestamp validation, `consumed_at >= approved_at`, strict
    `consumed_at < expires_at`, and both expected bindings.

    Invokes `executor` exactly once with one RPC operation descriptor
    naming `consume_approval_and_update_investigation_state` and exactly
    its five parameters. The PostgreSQL function performs the entire
    approval-consumption-and-investigation-update atomically; this
    function never issues that as two separate client-side calls. Zero
    returned rows raises `ApprovalConflictError` (never retried, and never
    followed by an automatic `load_approval_record` call) -- it represents
    any lifecycle, expiry, replay, or binding conflict, and the specific
    cause is never distinguished or exposed. Exactly one row is required;
    it must contain the sixteen approval-record fields plus exactly
    `investigation_status`, `investigation_confidence`, and
    `investigation_updated_at` -- no other field. The approval portion is
    normalized (missing nullable lifecycle fields restored as `None`,
    exactly as elsewhere in this module) and validated through
    `validate_approval_record` exactly once, then required to equal an
    independently computed expected consumed record exactly. The
    investigation portion is validated as a member of
    `core.decision_context.INVESTIGATION_STATUSES` /
    `core.evidence_normalizer.CONFIDENCE_LEVELS` (already-trimmed strings)
    and a canonical UTC timestamp, and is required to match whichever of
    `status`/`confidence` the already-validated `current_record`'s own
    `action_payload` specifies -- this function never accepts a
    caller-supplied replacement status, confidence, or `action_payload`.

    Returns exactly:

        {
            "transition_plan": {...},
            "updated_record": {...},
            "investigation_result": {
                "investigation_id": "...",
                "status": "...",
                "confidence": "...",
                "updated_at": "...",
            },
        }

    This is a:

        Verified atomic approval consumption -- approval and investigation changed together

    Raises `ApprovalPersistenceError` for invalid `current_record` or
    `transition_plan` input (before the executor is ever invoked),
    `ApprovalConflictError` for a genuine plan matched against zero rows,
    `ApprovalResponseError` for any other malformed or mismatched executor
    response, and `ApprovalTransportError` if `executor` itself raises.
    Never raises `ApprovalTransitionError` directly. Never mutates
    `current_record`, its nested `action_payload`, `transition_plan`, or
    `transition_plan["set_fields"]`, and never returns a persistence
    receipt, row count, operation descriptor, authentication result,
    action hash, or investigation title/description.
    """
    validated_current_record = _validate_current_record_for_consumption(current_record)

    canonical_approval_id, canonical_expected_investigation_id = _validate_consume_transition_plan(
        transition_plan, validated_current_record
    )

    recomputed_plan = _verify_genuine_consume_plan(transition_plan, validated_current_record)

    genuine_set_fields = recomputed_plan["set_fields"]

    expected_consumed_record = _compute_expected_updated_record(
        validated_current_record, genuine_set_fields, _INVALID_CONSUMPTION_INPUT_MESSAGE
    )

    operation = {
        "operation": "rpc",
        "function": _CONSUMPTION_RPC_FUNCTION_NAME,
        "parameters": {
            "approval_id": canonical_approval_id,
            "expected_investigation_id": canonical_expected_investigation_id,
            "expected_action_type": "update_investigation_state",
            "consumed_by": genuine_set_fields["consumed_by"],
            "consumed_at": genuine_set_fields["consumed_at"],
        },
    }

    response = _invoke_executor(executor, operation)

    if not isinstance(response, list):
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)
    if len(response) == 0:
        raise ApprovalConflictError(_CONSUMPTION_CONFLICT_MESSAGE)
    if len(response) > 1:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)

    row = response[0]
    if not isinstance(row, Mapping):
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)

    unknown_fields = set(row) - _CONSUMPTION_ROW_FIELDS_SET
    if unknown_fields:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)

    missing_investigation_fields = [field for field in _INVESTIGATION_RESULT_FIELDS if field not in row]
    if missing_investigation_fields:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)

    approval_portion = {key: value for key, value in row.items() if key in _RECORD_FIELDS_SET}
    approval_record = _validate_row_shape(approval_portion, _CONSUMPTION_RESPONSE_MESSAGE)

    if approval_record != expected_consumed_record:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)

    investigation_status = _validate_investigation_status(row["investigation_status"])
    investigation_confidence = _validate_investigation_confidence(row["investigation_confidence"])
    try:
        investigation_updated_at = _normalize_timestamp(row["investigation_updated_at"])
    except ApprovalPersistenceError:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE) from None

    stored_payload = validated_current_record["action_payload"]
    if "status" in stored_payload and investigation_status != stored_payload["status"]:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)
    if "confidence" in stored_payload and investigation_confidence != stored_payload["confidence"]:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)

    if canonical_expected_investigation_id != approval_record["investigation_id"]:
        raise ApprovalResponseError(_CONSUMPTION_RESPONSE_MESSAGE)

    investigation_result = {
        "investigation_id": canonical_expected_investigation_id,
        "status": investigation_status,
        "confidence": investigation_confidence,
        "updated_at": investigation_updated_at,
    }

    return {
        "transition_plan": copy.deepcopy(dict(recomputed_plan)),
        "updated_record": copy.deepcopy(approval_record),
        "investigation_result": investigation_result,
    }


# ---------------------------------------------------------------------------
# Risk-aware persistence operations (Block 6, Step 4)
# ---------------------------------------------------------------------------


def insert_risk_aware_pending_approval(
    executor: ApprovalExecutor,
    request: Mapping[str, Any],
    current_investigation: Mapping[str, Any],
    *,
    expires_at: str | datetime | None = None,
) -> dict[str, Any]:
    """Validate one proposed approval request and its investigation's
    current state, derive its deterministic risk classification, and
    insert one new risk-aware pending approval row.

    Unlike `insert_pending_approval` (which trusts an already-validated
    Block 5 request), this function receives the *original* `request` and
    `current_investigation` and calls
    `core.approval_request.validate_risk_aware_approval_request` itself --
    caller-supplied risk metadata is never trusted, because no such field
    exists anywhere in that validator's own input contract (exactly as
    that module's own docstring already establishes). `risk_level` and
    `required_approvals` are always derived, never accepted.

    `requested_by_normalized` (`requested_by.strip().casefold()`) is
    computed here and written to the insert descriptor's `values`, but is
    never requested back via `returning` and never appears in the
    returned record -- it exists purely for later database-side
    enforcement in `record_approval_review_and_promote_status` and
    `consume_approval_and_update_investigation_state`, and this module
    never reproduces Python `casefold()` with PostgreSQL `lower()`.

    Invokes `executor` exactly once with an insert operation descriptor
    for the `approvals` table, whose `returning` list is exactly the
    eighteen risk-aware fields (the existing sixteen plus `risk_level` and
    `required_approvals`). The executor's response must be a Python list
    containing exactly one row mapping; that row is normalized and
    validated through `validate_risk_aware_approval_record` exactly once,
    then checked to confirm it actually reflects the request that was
    submitted.

    Raises `ApprovalPersistenceError` for invalid `request` or
    `current_investigation` input (before the executor is ever invoked,
    covering every failure `validate_risk_aware_approval_request` itself
    raises) or invalid `expires_at`, `ApprovalResponseError` for any
    malformed, mismatched, or invalid executor response, and
    `ApprovalTransportError` if `executor` itself raises. Never mutates
    `request` or `current_investigation`, and never returns
    `requested_by_normalized`, a persistence receipt, row count, or
    operation descriptor -- only the validated eighteen-field record
    itself.
    """
    try:
        validated_request = validate_risk_aware_approval_request(request, current_investigation)
    except ApprovalRequestError:
        raise ApprovalPersistenceError(_INVALID_RISK_AWARE_REQUEST_MESSAGE) from None

    canonical_expires_at = _validate_expiry(expires_at, validated_request["requested_at"])

    requested_by_normalized = validated_request["requested_by"].strip().casefold()

    values: dict[str, Any] = {
        "investigation_id": validated_request["investigation_id"],
        "action_type": validated_request["action_type"],
        "action_payload": copy.deepcopy(validated_request["action_payload"]),
        "requested_by": validated_request["requested_by"],
        "requested_at": validated_request["requested_at"],
        "status": "pending",
        "risk_level": validated_request["risk_level"],
        "required_approvals": validated_request["required_approvals"],
        "requested_by_normalized": requested_by_normalized,
    }
    if canonical_expires_at is not None:
        values["expires_at"] = canonical_expires_at

    operation = {
        "operation": "insert",
        "table": "approvals",
        "values": values,
        "returning": list(_RISK_AWARE_RECORD_FIELDS),
    }

    response = _invoke_executor(executor, operation)

    if not isinstance(response, list):
        raise ApprovalResponseError(_RISK_AWARE_INSERT_RESPONSE_MESSAGE)
    if len(response) != 1:
        raise ApprovalResponseError(_RISK_AWARE_INSERT_RESPONSE_MESSAGE)

    record = _validate_risk_aware_row_shape(response[0], _RISK_AWARE_INSERT_RESPONSE_MESSAGE)

    if (
        record["investigation_id"] != validated_request["investigation_id"]
        or record["action_type"] != validated_request["action_type"]
        or record["action_payload"] != validated_request["action_payload"]
        or record["requested_by"] != validated_request["requested_by"]
        or record["requested_at"] != validated_request["requested_at"]
        or record["risk_level"] != validated_request["risk_level"]
        or record["required_approvals"] != validated_request["required_approvals"]
    ):
        raise ApprovalResponseError(_RISK_AWARE_INSERT_RESPONSE_MESSAGE)

    if record["status"] != "pending":
        raise ApprovalResponseError(_RISK_AWARE_INSERT_RESPONSE_MESSAGE)

    if record["expires_at"] != canonical_expires_at:
        raise ApprovalResponseError(_RISK_AWARE_INSERT_RESPONSE_MESSAGE)

    return record


def load_risk_aware_approval_record(
    executor: ApprovalExecutor,
    approval_id: str,
) -> dict[str, Any]:
    """Load one existing approval row by its canonical `id` and return its
    validated, canonical eighteen-field risk-aware record.

    `approval_id` is canonicalized as a UUID before the executor is ever
    invoked. Invokes `executor` exactly once with a primary-key-only
    select operation descriptor for the `approvals` table (`columns` is
    exactly the eighteen risk-aware fields; `filters` contains only `id`;
    no investigation, status, or claimed-identity filter is ever added).
    Risk metadata is never defaulted in Python -- `risk_level` and
    `required_approvals` must actually be present in the executor's
    response, exactly like every other field.

    The executor's response must be a Python list. Zero rows raises
    `ApprovalNotFoundError`; more than one row raises
    `ApprovalResponseError`. The single returned row is normalized and
    validated through `validate_risk_aware_approval_record` exactly once.

    Raises `ApprovalPersistenceError` for a malformed `approval_id`
    (before the executor is ever invoked), `ApprovalResponseError` for
    any malformed or invalid executor response, and
    `ApprovalTransportError` if `executor` itself raises. Never raises
    `ApprovalTransitionError` directly, and never returns anything beyond
    the validated eighteen-field record.
    """
    canonical_id = _validate_approval_id(approval_id)

    operation = {
        "operation": "select",
        "table": "approvals",
        "columns": list(_RISK_AWARE_RECORD_FIELDS),
        "filters": {"id": canonical_id},
        "limit": 2,
    }

    response = _invoke_executor(executor, operation)

    if not isinstance(response, list):
        raise ApprovalResponseError(_RISK_AWARE_LOOKUP_RESPONSE_MESSAGE)
    if len(response) == 0:
        raise ApprovalNotFoundError(_NOT_FOUND_MESSAGE)
    if len(response) > 1:
        raise ApprovalResponseError(_RISK_AWARE_LOOKUP_RESPONSE_MESSAGE)

    record = _validate_risk_aware_row_shape(response[0], _RISK_AWARE_LOOKUP_RESPONSE_MESSAGE)

    if record["id"] != canonical_id:
        raise ApprovalResponseError(_RISK_AWARE_LOOKUP_RESPONSE_MESSAGE)

    return record


def load_approval_reviews(
    executor: ApprovalExecutor,
    approval_id: str,
) -> list[dict[str, Any]]:
    """Load every existing review row recorded against one approval, in
    deterministic (`decided_at`-ascending) order, and return only the
    five-field review-summary contract for each.

    `approval_id` is canonicalized as a UUID before the executor is ever
    invoked. Invokes `executor` exactly once with an ordered select
    operation descriptor for the `approval_reviews` table, bound only to
    the supplied `approval_id`. `columns` is exactly the five fields
    `approval_id`, `reviewer_identity`, `reviewer_identity_normalized`,
    `decision`, `decided_at` -- the internal review row `id` and
    `created_at` are never selected or returned.

    The executor's response must be a Python list (zero rows is a valid,
    non-error result -- a not-yet-reviewed approval). Every returned row
    is validated through `core.approval_transition.validate_approval_review_record`
    exactly once, and each row's own `approval_id` is confirmed to equal
    the canonical `approval_id` supplied.

    Raises `ApprovalPersistenceError` for a malformed `approval_id`
    (before the executor is ever invoked), `ApprovalResponseError` for
    any malformed executor response or a row whose `approval_id` does not
    match, and `ApprovalTransportError` if `executor` itself raises.
    Never returns an internal review row `id` or `created_at`.
    """
    canonical_id = _validate_approval_id(approval_id)

    operation = {
        "operation": "select",
        "table": "approval_reviews",
        "columns": list(_REVIEW_LOOKUP_COLUMNS),
        "filters": {"approval_id": canonical_id},
        "order_by": "decided_at",
        "limit": _REVIEW_LOOKUP_LIMIT,
    }

    response = _invoke_executor(executor, operation)

    if not isinstance(response, list):
        raise ApprovalResponseError(_REVIEW_LOOKUP_RESPONSE_MESSAGE)

    reviews: list[dict[str, Any]] = []
    for row in response:
        try:
            validated = validate_approval_review_record(row)
        except ApprovalTransitionError:
            raise ApprovalResponseError(_REVIEW_LOOKUP_RESPONSE_MESSAGE) from None

        if validated["approval_id"] != canonical_id:
            raise ApprovalResponseError(_REVIEW_LOOKUP_RESPONSE_MESSAGE)

        reviews.append(validated)

    return reviews


def _validate_current_record_for_multi_review(current_record: Any) -> dict[str, Any]:
    if not isinstance(current_record, Mapping):
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_INPUT_MESSAGE)

    try:
        validated = validate_risk_aware_approval_record(current_record)
    except ApprovalTransitionError:
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_INPUT_MESSAGE) from None

    if validated != dict(current_record):
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_INPUT_MESSAGE)

    if validated["status"] not in ("pending", "partially_approved"):
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_INPUT_MESSAGE)

    return validated


def _validate_existing_reviews_for_multi_review(existing_reviews: Any) -> list[dict[str, Any]]:
    if isinstance(existing_reviews, (str, bytes)) or not isinstance(existing_reviews, Sequence):
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_INPUT_MESSAGE)

    validated_reviews: list[dict[str, Any]] = []
    for review in existing_reviews:
        try:
            validated = validate_approval_review_record(review)
        except ApprovalTransitionError:
            raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_INPUT_MESSAGE) from None

        if not isinstance(review, Mapping) or validated != dict(review):
            raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_INPUT_MESSAGE)

        validated_reviews.append(validated)

    return validated_reviews


def _validate_multi_review_transition_plan(transition_plan: Any) -> dict[str, Any]:
    if not isinstance(transition_plan, Mapping):
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_PLAN_MESSAGE)

    if set(transition_plan) != _MULTI_REVIEW_TRANSITION_PLAN_FIELDS:
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_PLAN_MESSAGE)

    return dict(transition_plan)


def _compute_expected_risk_aware_updated_record(
    validated_current_record: Mapping[str, Any],
    set_fields: Mapping[str, Any],
    generic_message: str,
) -> dict[str, Any]:
    candidate = dict(copy.deepcopy(dict(validated_current_record)))
    candidate.update(copy.deepcopy(dict(set_fields)))
    try:
        return validate_risk_aware_approval_record(candidate)
    except ApprovalTransitionError:
        raise ApprovalPersistenceError(generic_message) from None


def apply_multi_review_transition(
    executor: ApprovalExecutor,
    current_record: Mapping[str, Any],
    existing_reviews: Sequence[Mapping[str, Any]],
    transition_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply one genuine review decision (approve or reject) atomically,
    via a single PostgreSQL RPC call that records the immutable review row
    and promotes the approval's own summary status together, and return
    the verified updated record, review record, and approval count.

    `current_record` must already be the exact, canonical output of
    `validate_risk_aware_approval_record`, with `status` equal to
    `"pending"` or `"partially_approved"` -- an approved, rejected, or
    consumed record is rejected before the executor is ever invoked, as
    is any record validation would change. `existing_reviews` must be a
    sequence whose every entry is already the exact, canonical output of
    `validate_approval_review_record`.

    The supplied `transition_plan` is never trusted at face value: this
    function reconstructs the equivalent transition request from the
    plan's own `review_record` (and, for a reject decision, its
    `set_fields.rejection_reason`) and recomputes the plan by calling
    `core.approval_transition.validate_multi_review_transition` exactly
    once, requiring the result to equal the supplied plan exactly (plain
    dict equality, so key insertion order is never significant, exactly
    like every other plan-verification check in this module). This
    re-derives (and cannot bypass) self-approval prevention, duplicate-
    reviewer prevention, Unicode casefold comparison, expiry enforcement,
    the correct next status, and the correct approval count -- a forged
    approval ID, `from_status`, `to_status`, `required_approvals`,
    approval count, reviewer identity, normalization, decision, timestamp,
    or rejection reason is rejected before the executor is ever invoked,
    as is a missing or extra plan field.

    Invokes `executor` exactly once with one RPC operation descriptor
    naming `record_approval_review_and_promote_status` and exactly its
    ten parameters, generated entirely from the recomputed plan -- the
    caller never supplies an RPC descriptor directly. Zero returned rows
    raises `ApprovalConflictError` (never retried). Exactly one row is
    required; it must contain the eighteen risk-aware approval fields
    plus exactly `review_approval_id`, `reviewer_identity`,
    `reviewer_identity_normalized`, `review_decision`,
    `review_decided_at`, and `approval_count` -- the complete twenty-four-
    field atomic review RPC return contract. The approval portion is
    validated through `validate_risk_aware_approval_record` and required
    to equal an independently computed expected updated record exactly;
    the review portion is validated through `validate_approval_review_record`
    and required to equal the recomputed plan's own `review_record`
    exactly; `approval_count` is required to equal the recomputed plan's
    own `approval_count_after` exactly.

    Returns exactly:

        {
            "updated_record": {...},
            "review_record": {...},
            "approval_count": 0 | 1 | 2,
        }

    Raises `ApprovalPersistenceError` for invalid `current_record`,
    `existing_reviews`, or `transition_plan` input (before the executor is
    ever invoked), `ApprovalConflictError` for a genuine plan matched
    against zero rows, `ApprovalResponseError` for any other malformed or
    mismatched executor response, and `ApprovalTransportError` if
    `executor` itself raises. Never raises `ApprovalTransitionError`
    directly. Never mutates `current_record`, `existing_reviews`, or
    `transition_plan` (nor any nested mapping within any of them), and
    never returns a persistence receipt, row count, operation descriptor,
    or authentication result.
    """
    validated_current_record = _validate_current_record_for_multi_review(current_record)
    validated_reviews = _validate_existing_reviews_for_multi_review(existing_reviews)
    supplied_plan = _validate_multi_review_transition_plan(transition_plan)

    review_record = supplied_plan.get("review_record")
    if not isinstance(review_record, Mapping):
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_PLAN_MESSAGE)

    decision = review_record.get("decision")
    if decision == "approve":
        reconstructed_request: dict[str, Any] = {
            "decision": "approve",
            "reviewed_by": review_record.get("reviewer_identity"),
        }
    elif decision == "reject":
        set_fields = supplied_plan.get("set_fields")
        rejection_reason = set_fields.get("rejection_reason") if isinstance(set_fields, Mapping) else None
        reconstructed_request = {
            "decision": "reject",
            "reviewed_by": review_record.get("reviewer_identity"),
            "rejection_reason": rejection_reason,
        }
    else:
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_PLAN_MESSAGE)

    reviewed_at = review_record.get("decided_at")

    try:
        recomputed_plan = validate_multi_review_transition(
            validated_current_record,
            validated_reviews,
            reconstructed_request,
            reviewed_at=reviewed_at,
        )
    except ApprovalTransitionError:
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_PLAN_MESSAGE) from None

    if recomputed_plan != supplied_plan:
        raise ApprovalPersistenceError(_INVALID_MULTI_REVIEW_PLAN_MESSAGE)

    genuine_review_record = recomputed_plan["review_record"]
    genuine_set_fields = recomputed_plan["set_fields"]

    parameters = {
        "approval_id": recomputed_plan["approval_id"],
        "expected_from_status": recomputed_plan["from_status"],
        "expected_to_status": recomputed_plan["to_status"],
        "expected_required_approvals": recomputed_plan["required_approvals"],
        "expected_approval_count_before": recomputed_plan["approval_count_before"],
        "reviewer_identity": genuine_review_record["reviewer_identity"],
        "reviewer_identity_normalized": genuine_review_record["reviewer_identity_normalized"],
        "decision": genuine_review_record["decision"],
        "decided_at": genuine_review_record["decided_at"],
        "rejection_reason": genuine_set_fields.get("rejection_reason"),
    }

    operation = {
        "operation": "rpc",
        "function": _REVIEW_RPC_FUNCTION_NAME,
        "parameters": parameters,
    }

    response = _invoke_executor(executor, operation)

    if not isinstance(response, list):
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE)
    if len(response) == 0:
        raise ApprovalConflictError(_MULTI_REVIEW_CONFLICT_MESSAGE)
    if len(response) > 1:
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE)

    row = response[0]
    if not isinstance(row, Mapping):
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE)

    if set(row) != _REVIEW_RPC_RESULT_FIELDS_SET:
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE)

    approval_portion = {key: value for key, value in row.items() if key in _RISK_AWARE_RECORD_FIELDS_SET}
    updated_record = _validate_risk_aware_row_shape(approval_portion, _MULTI_REVIEW_RESPONSE_MESSAGE)

    expected_updated_record = _compute_expected_risk_aware_updated_record(
        validated_current_record, genuine_set_fields, _MULTI_REVIEW_RESPONSE_MESSAGE
    )
    if updated_record != expected_updated_record:
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE)

    if row["review_approval_id"] != recomputed_plan["approval_id"]:
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE)

    try:
        result_review_record = validate_approval_review_record({
            "approval_id": row["review_approval_id"],
            "reviewer_identity": row["reviewer_identity"],
            "reviewer_identity_normalized": row["reviewer_identity_normalized"],
            "decision": row["review_decision"],
            "decided_at": row["review_decided_at"],
        })
    except ApprovalTransitionError:
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE) from None

    if result_review_record != genuine_review_record:
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE)

    approval_count = row["approval_count"]
    if not isinstance(approval_count, int) or isinstance(approval_count, bool):
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE)
    if approval_count != recomputed_plan["approval_count_after"]:
        raise ApprovalResponseError(_MULTI_REVIEW_RESPONSE_MESSAGE)

    return {
        "updated_record": copy.deepcopy(updated_record),
        "review_record": copy.deepcopy(result_review_record),
        "approval_count": approval_count,
    }
