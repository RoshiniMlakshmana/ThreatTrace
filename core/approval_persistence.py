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
- It never issues an approve, reject, or consume operation, never builds a
  conditional update, never opens a transaction, and never updates an
  investigation. Only two operations exist: inserting one pending approval
  row, and selecting one approval row by `id`.
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
from core.approval_transition import ApprovalTransitionError, validate_approval_record


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
