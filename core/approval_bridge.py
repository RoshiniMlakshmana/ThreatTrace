"""Transport-neutral two-phase prepare/verify bridge for the approval
persistence functions in `core.approval_persistence`.

This module exists to solve exactly one problem: a Python subprocess (how
every existing CLI in this project is invoked from command Markdown) has
no access to Claude Code's own MCP tools -- only Claude itself can call
`mcp__supabase__execute_sql` or any other MCP tool. The four approval
persistence functions (`insert_pending_approval`, `load_approval_record`,
`apply_approval_review_transition`, `apply_approval_consumption`) are
written against a dependency-injected `ApprovalExecutor` callable that
performs exactly one database operation per call -- but nothing in this
project lets a Python process reach into an MCP tool call, and nothing
here adds a concrete Supabase client to do so either.

This bridge splits each persistence function's single injected-executor
call into two separately invokable phases, so that Claude itself can sit
in between them:

- **Prepare**: run every existing pre-executor validation rule (all of it
  reused, none of it duplicated) and capture the *exact* operation
  descriptor the persistence function would hand to its executor, without
  ever performing any I/O. A future command instructs Claude to perform
  the one real Supabase MCP call the descriptor describes.
- **Verify**: given the *same* original inputs again (never a serialized
  "expected result" a caller could tamper with) plus a canonical,
  already-normalized `{"kind": "rows", "rows": [...]}` (or
  `{"kind": "transport_error"}`) response envelope, independently
  regenerate the descriptor a second time, require it to match the one
  supplied, and then re-invoke the *same* persistence function -- reusing
  every one of its own existing response-validation rules unchanged -- to
  produce the final, fully verified result.

This module does not know what MCP is. It never imports `supabase`,
`requests`, `socket`, `subprocess`, `os`, or any MCP module; it never
creates a database client; it never executes SQL; it never reads an
environment variable; and it never guesses at, or normalizes, the actual
shape of a Supabase MCP tool response -- that remains an explicitly
unresolved, later concern for whatever eventually converts a real MCP
tool result into this module's own canonical `{"kind": "rows", ...}` /
`{"kind": "transport_error"}` envelope. Nothing in this module claims that
conversion exists yet.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from core.approval_persistence import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalPersistenceError,
    ApprovalResponseError,
    apply_approval_consumption,
    apply_approval_review_transition,
    apply_multi_review_transition,
    insert_pending_approval,
    insert_risk_aware_pending_approval,
    load_approval_record,
    load_approval_reviews,
    load_risk_aware_approval_record,
)


class ApprovalBridgeError(Exception):
    """Raised for any failure at this bridge's own boundary -- an
    unsupported or malformed operation request, a preparation-phase
    internal-consistency failure, a descriptor mismatch between a
    prepared and a regenerated descriptor, or a malformed
    executor-response envelope during verification.

    Messages are always one of a small, fixed set of generic phrases --
    never a record, a transition plan, an `action_payload`, an identity
    value, an approval ID, an expected binding, an executor response, a
    descriptor, a raw exception, or a traceback. `ApprovalPersistenceError`
    subclasses raised by the wrapped persistence functions themselves
    (`ApprovalNotFoundError`, `ApprovalResponseError`,
    `ApprovalTransportError`, `ApprovalConflictError`, or the base class
    itself for pre-executor input failures) are never converted into this
    exception -- they propagate exactly as those functions already raise
    them.
    """


_INVALID_REQUEST_MESSAGE = "Invalid approval bridge request."
_PREPARE_FAILURE_MESSAGE = "Approval bridge preparation failed."
_DESCRIPTOR_MISMATCH_MESSAGE = "Approval bridge descriptor mismatch."
_VERIFY_FAILURE_MESSAGE = "Approval bridge verification failed."

_SUPPORTED_OPERATIONS = (
    "insert_pending_approval",
    "load_approval_record",
    "apply_approval_review_transition",
    "apply_approval_consumption",
    "insert_risk_aware_pending_approval",
    "load_risk_aware_approval_record",
    "load_approval_reviews",
    "apply_multi_review_transition",
)
_SUPPORTED_OPERATIONS_SET = frozenset(_SUPPORTED_OPERATIONS)

_OPERATION_INPUT_FIELDS: dict[str, tuple[str, ...]] = {
    "insert_pending_approval": ("validated_request", "expires_at"),
    "load_approval_record": ("approval_id",),
    "apply_approval_review_transition": ("current_record", "transition_plan"),
    "apply_approval_consumption": ("current_record", "transition_plan"),
    "insert_risk_aware_pending_approval": ("request", "current_investigation", "expires_at"),
    "load_risk_aware_approval_record": ("approval_id",),
    "load_approval_reviews": ("approval_id",),
    "apply_multi_review_transition": ("current_record", "existing_reviews", "transition_plan"),
}

_EXPECTED_POST_CAPTURE_EXCEPTIONS: dict[str, type[ApprovalPersistenceError]] = {
    "insert_pending_approval": ApprovalResponseError,
    "load_approval_record": ApprovalNotFoundError,
    "apply_approval_review_transition": ApprovalConflictError,
    "apply_approval_consumption": ApprovalConflictError,
    "insert_risk_aware_pending_approval": ApprovalResponseError,
    "load_risk_aware_approval_record": ApprovalNotFoundError,
    "load_approval_reviews": ApprovalResponseError,
    "apply_multi_review_transition": ApprovalConflictError,
}

# Every operation's descriptor-capture executor returns an empty list by
# default -- driving the wrapped persistence function to its own already-
# known "zero rows" branch (see _DescriptorCaptureExecutor below), exactly
# as it always has for the four Block 5 operations. load_approval_reviews
# is the sole exception: an empty list is that operation's own legitimate
# success (a not-yet-reviewed approval has zero reviews), so an empty-list
# capture response would let it return successfully instead of raising --
# defeating the whole capture mechanism, which requires a deterministic
# exception to confirm exactly one descriptor was built. One deliberately
# malformed placeholder row (missing every required field) is used
# instead, which validate_approval_review_record always rejects, still
# driving that operation to a deterministic ApprovalResponseError without
# ever performing real I/O or depending on any real database state.
_CAPTURE_FAKE_RESPONSES: dict[str, list[Any]] = {
    "load_approval_reviews": [{}],
}

_ROWS_ENVELOPE_FIELDS = ("kind", "rows")
_TRANSPORT_ENVELOPE_FIELDS = ("kind",)


def _validate_operation_name(operation: Any) -> str:
    if operation not in _SUPPORTED_OPERATIONS_SET:
        raise ApprovalBridgeError(_INVALID_REQUEST_MESSAGE)
    return operation


def _validate_operation_input(operation: str, operation_input: Any) -> dict[str, Any]:
    if not isinstance(operation_input, Mapping):
        raise ApprovalBridgeError(_INVALID_REQUEST_MESSAGE)

    expected_fields = _OPERATION_INPUT_FIELDS[operation]
    if tuple(operation_input) != expected_fields:
        raise ApprovalBridgeError(_INVALID_REQUEST_MESSAGE)

    return dict(operation_input)


def _dispatch_persistence(operation: str, executor: Any, normalized_input: Mapping[str, Any]) -> Any:
    if operation == "insert_pending_approval":
        return insert_pending_approval(
            executor,
            normalized_input["validated_request"],
            expires_at=normalized_input["expires_at"],
        )
    if operation == "load_approval_record":
        return load_approval_record(executor, normalized_input["approval_id"])
    if operation == "apply_approval_review_transition":
        return apply_approval_review_transition(
            executor, normalized_input["current_record"], normalized_input["transition_plan"]
        )
    if operation == "apply_approval_consumption":
        return apply_approval_consumption(
            executor, normalized_input["current_record"], normalized_input["transition_plan"]
        )
    if operation == "insert_risk_aware_pending_approval":
        return insert_risk_aware_pending_approval(
            executor,
            normalized_input["request"],
            normalized_input["current_investigation"],
            expires_at=normalized_input["expires_at"],
        )
    if operation == "load_risk_aware_approval_record":
        return load_risk_aware_approval_record(executor, normalized_input["approval_id"])
    if operation == "load_approval_reviews":
        return load_approval_reviews(executor, normalized_input["approval_id"])
    return apply_multi_review_transition(
        executor,
        normalized_input["current_record"],
        normalized_input["existing_reviews"],
        normalized_input["transition_plan"],
    )


def _deep_ordered_equal(left: Any, right: Any) -> bool:
    """Recursively compare two values for equality, requiring list
    elements to appear in the same order at every level (list order is
    semantically meaningful -- e.g. `returning`/`columns` column order --
    so a shuffled list is a genuine mismatch), while treating mapping key
    order as insignificant, exactly like this project's own
    `sort_keys=True` JSON convention already does: a descriptor that
    round-trips through this project's own CLI (which always serializes
    with `sort_keys=True`) must still compare equal to a freshly
    regenerated descriptor built with ordinary Python dict-literal
    construction order. A missing, added, or changed field at any depth
    -- in a mapping or a list -- still makes two descriptors unequal."""
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        if set(left.keys()) != set(right.keys()):
            return False
        return all(_deep_ordered_equal(left[key], right[key]) for key in left)
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return False
        return all(_deep_ordered_equal(a, b) for a, b in zip(left, right))
    return left == right


class _DescriptorCaptureExecutor:
    """Prepare-phase executor: captures exactly one operation descriptor
    as an independently-owned deep copy and performs no I/O of any kind,
    always returning a fixed, operation-specific fake response (an empty
    list for every Block 5 operation and for every Block 6 operation
    except `load_approval_reviews`; see `_CAPTURE_FAKE_RESPONSES`). That
    fixed response drives the wrapped persistence function to its own
    already-defined, already-tested deterministic-failure branch -- never
    a guessed or synthetic success."""

    def __init__(self, fake_response: list[Any]) -> None:
        self.captured: list[dict[str, Any]] = []
        self._fake_response = fake_response

    def __call__(self, operation: Mapping[str, Any]) -> list[Any]:
        self.captured.append(copy.deepcopy(dict(operation)))
        return self._fake_response


class _VerifyExecutor:
    """Verify-phase executor: confirms the operation the wrapped
    persistence function regenerates internally still exactly matches the
    independently-verified descriptor, is invoked at most once, and
    either returns an independently-owned deep copy of the normalized
    rows or raises a plain internal exception for a transport-error
    envelope -- which the wrapped persistence function's own existing
    executor-invocation boundary already converts into a redacted
    `ApprovalTransportError`, exactly as it does for any other executor
    failure."""

    def __init__(self, expected_descriptor: Mapping[str, Any], kind: str, rows: list[Any] | None) -> None:
        self._expected_descriptor = expected_descriptor
        self._kind = kind
        self._rows = rows
        self._call_count = 0

    def __call__(self, operation: Mapping[str, Any]) -> list[Any]:
        self._call_count += 1
        if self._call_count > 1:
            raise ApprovalBridgeError(_VERIFY_FAILURE_MESSAGE)
        if not _deep_ordered_equal(dict(operation), self._expected_descriptor):
            raise ApprovalBridgeError(_VERIFY_FAILURE_MESSAGE)
        if self._kind == "transport_error":
            raise RuntimeError("approval bridge transport error envelope")
        return copy.deepcopy(self._rows)


def _normalize_executor_response(executor_response: Any) -> tuple[str, list[Any] | None]:
    if not isinstance(executor_response, Mapping):
        raise ApprovalBridgeError(_VERIFY_FAILURE_MESSAGE)

    kind = executor_response.get("kind")

    if kind == "rows":
        if tuple(executor_response) != _ROWS_ENVELOPE_FIELDS:
            raise ApprovalBridgeError(_VERIFY_FAILURE_MESSAGE)
        rows = executor_response["rows"]
        if not isinstance(rows, list):
            raise ApprovalBridgeError(_VERIFY_FAILURE_MESSAGE)
        return "rows", copy.deepcopy(rows)

    if kind == "transport_error":
        if tuple(executor_response) != _TRANSPORT_ENVELOPE_FIELDS:
            raise ApprovalBridgeError(_VERIFY_FAILURE_MESSAGE)
        return "transport_error", None

    raise ApprovalBridgeError(_VERIFY_FAILURE_MESSAGE)


def prepare_approval_operation(
    operation: str,
    operation_input: Mapping[str, Any],
) -> dict[str, Any]:
    """Run one approval persistence function's complete pre-executor
    validation and capture the exact operation descriptor it would hand
    to its executor -- performing no database or network operation of
    any kind.

    `operation` must be exactly one of `insert_pending_approval`,
    `load_approval_record`, `apply_approval_review_transition`, or
    `apply_approval_consumption` -- no alias, and no arbitrary function
    name. `operation_input` must be a mapping containing exactly that
    operation's own input fields, in the exact committed order (never
    reordered, never a field belonging to a different operation).

    This never reimplements descriptor construction: it invokes the
    genuine, committed persistence function with a private
    descriptor-capturing executor that performs no I/O and always
    returns an empty list, driving that function to its own already-known
    "zero rows" branch (`ApprovalResponseError` for
    `insert_pending_approval`, `ApprovalNotFoundError` for
    `load_approval_record`, `ApprovalConflictError` for the two
    transition functions) -- proving every one of its pre-executor
    validation rules already ran successfully.

    Returns exactly:

        {
            "phase": "prepare",
            "operation": "<the supported operation name>",
            "descriptor": {...},
        }

    Raises `ApprovalBridgeError` for an unsupported operation name, a
    malformed or wrongly-shaped `operation_input`, or an internal
    inconsistency (no descriptor captured together with a non-persistence
    exception, more than one descriptor captured, an unexpected
    post-capture exception type, or an unexpected successful return).
    Propagates the underlying `ApprovalPersistenceError` subclass
    unchanged whenever pre-executor validation itself fails -- never
    converting it to `ApprovalBridgeError`. Never mutates
    `operation_input` or any nested value within it.
    """
    _validate_operation_name(operation)
    normalized_input = _validate_operation_input(operation, operation_input)

    capture = _DescriptorCaptureExecutor(_CAPTURE_FAKE_RESPONSES.get(operation, []))
    expected_exception_type = _EXPECTED_POST_CAPTURE_EXCEPTIONS[operation]

    caught_exception: Exception | None = None
    succeeded_unexpectedly = False
    try:
        _dispatch_persistence(operation, capture, normalized_input)
        succeeded_unexpectedly = True
    except Exception as exc:
        caught_exception = exc

    if not capture.captured:
        if isinstance(caught_exception, ApprovalPersistenceError):
            raise caught_exception
        raise ApprovalBridgeError(_PREPARE_FAILURE_MESSAGE) from None

    if len(capture.captured) > 1:
        raise ApprovalBridgeError(_PREPARE_FAILURE_MESSAGE) from None

    if succeeded_unexpectedly or not isinstance(caught_exception, expected_exception_type):
        raise ApprovalBridgeError(_PREPARE_FAILURE_MESSAGE) from None

    return {
        "phase": "prepare",
        "operation": operation,
        "descriptor": copy.deepcopy(capture.captured[0]),
    }


def verify_approval_operation(
    operation: str,
    operation_input: Mapping[str, Any],
    prepared_descriptor: Mapping[str, Any],
    executor_response: Mapping[str, Any],
) -> dict[str, Any]:
    """Independently regenerate and verify a previously prepared
    operation descriptor, then complete the same approval persistence
    function using a canonical, already-normalized executor-response
    envelope -- reusing every one of that function's own existing
    response-validation rules unchanged.

    `operation` and `operation_input` must be exactly the same values
    originally passed to `prepare_approval_operation`. This function
    calls `prepare_approval_operation` again itself, from scratch, and
    requires `prepared_descriptor` to equal the freshly regenerated
    descriptor exactly (every field, in the same order, at every nesting
    level) -- a descriptor is never trusted merely because it names a
    known operation.

    `executor_response` must be exactly one of two canonical shapes:

        {"kind": "rows", "rows": [...]}
        {"kind": "transport_error"}

    No other shape, and no guessed-at MCP wrapper key (`data`, `result`,
    `content`, `records`, `response`, `tool_result`, or similar) is ever
    accepted -- converting a real Supabase MCP tool response into one of
    these two canonical shapes remains an explicitly unresolved, later
    concern, entirely out of this module's scope.

    Returns exactly:

        {
            "phase": "verify",
            "operation": "<the supported operation name>",
            "result": {...},
        }

    where `result` is exactly what the wrapped persistence function
    itself returns, unwrapped and unaltered -- a dict for every operation
    except `load_approval_reviews`, which returns a list of review-summary
    dicts instead.

    Raises `ApprovalBridgeError` for an unsupported operation, a
    malformed `operation_input`, a non-mapping or mismatched
    `prepared_descriptor`, or a malformed `executor_response` envelope.
    Otherwise propagates whatever the wrapped persistence function itself
    raises (`ApprovalConflictError` for zero rows, `ApprovalResponseError`
    for a malformed or mismatched response, `ApprovalTransportError` for
    the canonical transport-error envelope) unchanged. Never mutates
    `operation_input`, `prepared_descriptor`, `executor_response`, or any
    nested value within any of them.
    """
    regenerated = prepare_approval_operation(operation, operation_input)
    regenerated_descriptor = regenerated["descriptor"]

    if not isinstance(prepared_descriptor, Mapping):
        raise ApprovalBridgeError(_DESCRIPTOR_MISMATCH_MESSAGE)
    if not _deep_ordered_equal(prepared_descriptor, regenerated_descriptor):
        raise ApprovalBridgeError(_DESCRIPTOR_MISMATCH_MESSAGE)

    kind, rows = _normalize_executor_response(executor_response)

    normalized_input = _validate_operation_input(operation, operation_input)
    verify_executor = _VerifyExecutor(regenerated_descriptor, kind, rows)

    result = _dispatch_persistence(operation, verify_executor, normalized_input)

    # Every Block 5 operation, and every Block 6 operation except
    # load_approval_reviews, returns a dict. load_approval_reviews returns
    # a list of review-summary dicts instead -- dict(result) would raise
    # for a list, so the packaging is type-aware, while remaining exactly
    # copy.deepcopy(dict(result)) for every dict-returning operation,
    # unchanged from before.
    if isinstance(result, Mapping):
        packaged_result: Any = copy.deepcopy(dict(result))
    else:
        packaged_result = copy.deepcopy(result)

    return {
        "phase": "verify",
        "operation": operation,
        "result": packaged_result,
    }
