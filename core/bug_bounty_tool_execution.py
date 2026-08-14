"""Bug Bounty tool execution boundary (Block 15G-B).

This is the **only** place in the entire ThreatTrace codebase where a
Bug Bounty tool_request can ever result in a real external process being
started. Every path into external execution runs through
`execute_bug_bounty_tool`; nothing upstream (the LLM planner, the
deterministic plan validator, `core.bug_bounty_tool_policy` itself) ever
invokes an adapter directly.

## Flow (see docs/block15g-nmap-nuclei-adapters.md for the full picture)

    validated tool_request
            v
    permission_result   (re-derived here, never trusted from the caller)
            v
    require execution_permitted == True
            v
    require a supplied Governor result with execution_allowed == True
            v
    adapter selected from a CLOSED, hardcoded registry
            v
    adapter builds its own fixed argument vector, shell=False
            v
    structured, sanitized tool result

## The permission decision is never trusted from the caller

This module calls the real, unmodified
`core.bug_bounty_tool_policy.evaluate_tool_permission` itself, exactly
once, over the caller's own `permissions`/`tool_request`. It never
accepts a caller-supplied boolean claiming a tool is permitted, and never
reimplements or second-guesses what that function returns.

## The Governor result is required, never synthesized

This module has no `core.security_governor` event to build on its own --
it does not know the actor role, workflow stage, approval state, or any
of the other fields a real Governor evaluation needs. A genuinely
computed `core.security_governor.evaluate_security_governor_event`
result (or an exact-shape equivalent) must be supplied by the caller.
This module never fabricates one, never defaults it to "allow", and
never proceeds without it. Execution is permitted only when the supplied
result's `execution_allowed` is `True` and its `decision` is not one of
`"block"`, `"freeze"`, or `"require_review"` -- which, under
`core.security_governor`'s own real semantics, is equivalent to
`decision == "allow"` (`execution_allowed` is `True` only in that case).

## Closed adapter registry -- never a caller-supplied binary name

`_ADAPTER_REGISTRY` is a hardcoded, two-entry mapping from `tool_id` to
one specific adapter callable (`adapters.bug_bounty_nmap.run_nmap_scan`,
`adapters.bug_bounty_nuclei.run_nuclei_scan`). There is no code path by
which a `tool_id` string chooses an arbitrary binary -- the mapping is a
fixed Python literal, never constructed from caller input.
`http_assessor` is deliberately not registered here: its own existing
orchestration path (`core.bug_bounty_assessment` +
`adapters.bug_bounty_http`) is untouched by this checkpoint, and nothing
about it requires re-routing through this newer execution boundary.

## No raw command surface, anywhere in this module

Nothing in `execute_bug_bounty_tool`'s parameters, in the `tool_request`
contract it forwards to `evaluate_tool_permission`, or in
`execution_config`, has any field for a shell/raw/terminal command or
arbitrary arguments. `execution_config` is a closed three-field contract
(`execution_config_version`, `process_timeout_seconds`,
`max_output_bytes`); ceiling enforcement for those two numeric fields
lives in each adapter itself (see `adapters.bug_bounty_nmap`/
`adapters.bug_bounty_nuclei`), so a caller may lower either value, never
raise it above the adapter's own hardcoded safety ceiling.

## Tool result is not a finding

Exactly like each adapter's own docstring states, nothing this module
returns is a canonical ThreatTrace finding -- `tool_result` is a raw,
sanitized tool observation only. Correlation into findings is out of
scope for this block.

`BugBountyToolExecutionError` and `execute_bug_bounty_tool` are this
module's public symbols.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from adapters.bug_bounty_nmap import BugBountyNmapAdapterError, run_nmap_scan
from adapters.bug_bounty_nuclei import BugBountyNucleiAdapterError, run_nuclei_scan
from core.bug_bounty_tool_policy import BugBountyToolPolicyError, evaluate_tool_permission

TOOL_EXECUTION_VERSION = "1"

_EXECUTION_CONFIG_REQUIRED_FIELDS = ("execution_config_version", "process_timeout_seconds", "max_output_bytes")

# A private, local copy of core.security_governor's own fixed result
# shape/vocabulary -- deliberately never imported from that module (this
# project's established convention; compare core.bug_bounty_tool_policy's
# own private scope helpers). This module does not call the Governor
# itself; it only validates the *shape* of a result the caller must
# already have obtained from a real Governor evaluation.
_GOVERNOR_RESULT_REQUIRED_FIELDS = (
    "governor_version",
    "decision",
    "reason_codes",
    "actor_role",
    "action_class",
    "human_review_required",
    "mutation_freeze_recommended",
    "execution_allowed",
    "observable_only",
    "execution_performed",
)
_GOVERNOR_DECISIONS = frozenset({"allow", "warn", "require_review", "block", "freeze"})
_GOVERNOR_BLOCKING_DECISIONS = frozenset({"block", "freeze", "require_review"})

_EXECUTION_BLOCKED_REASONS = frozenset({
    "POLICY_DENIED",
    "GOVERNOR_DENIED",
    "NO_ADAPTER_REGISTERED",
    "ADAPTER_REJECTED_REQUEST",
})


class BugBountyToolExecutionError(ValueError):
    """Raised when a supplied `governor_result`/`execution_config` is
    structurally invalid, or when `permissions`/`tool_request` fail the
    real `core.bug_bounty_tool_policy` structural validation (wrapping
    the underlying `BugBountyToolPolicyError`).

    Never raised because a tool is policy-denied, Governor-denied, has no
    registered adapter, or was rejected by an adapter's own additional
    scope check -- every one of those is a normal, successfully evaluated
    result represented through `execution_blocked_reason`, not an error.
    """


def _raise(detail: str) -> None:
    raise BugBountyToolExecutionError(f"INVALID_GOVERNOR_RESULT: {detail}")


def _validate_governor_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_GOVERNOR_RESULT_REQUIRED_FIELDS):
        _raise("governor_result must contain exactly the ten fields core.security_governor produces")
    if value.get("decision") not in _GOVERNOR_DECISIONS:
        _raise("decision must be a recognized Governor decision")
    if value.get("execution_allowed") not in (True, False):
        _raise("execution_allowed must be a bool")
    return dict(value)


def _validate_execution_config_shape(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_EXECUTION_CONFIG_REQUIRED_FIELDS):
        raise BugBountyToolExecutionError(
            "INVALID_EXECUTION_CONFIG: execution_config must contain exactly the three required fields",
        )
    return value


# ---------------------------------------------------------------------------
# Closed adapter registry. Hardcoded Python literal only -- never built
# from a tool_id string or any other caller-supplied value.
# ---------------------------------------------------------------------------


def _run_nmap_adapter(*, tool_request: Mapping[str, Any], execution_config: Mapping[str, Any]) -> dict[str, Any]:
    return run_nmap_scan(
        target=tool_request["target"],
        ports=tool_request["ports"],
        request_id=tool_request["request_id"],
        execution_config=execution_config,
    )


def _run_nuclei_adapter(*, tool_request: Mapping[str, Any], execution_config: Mapping[str, Any]) -> dict[str, Any]:
    return run_nuclei_scan(
        target=tool_request["target"],
        request_id=tool_request["request_id"],
        execution_config=execution_config,
    )


_ADAPTER_REGISTRY: Mapping[str, Any] = MappingProxyType({
    "nmap": _run_nmap_adapter,
    "nuclei": _run_nuclei_adapter,
})

_ADAPTER_ERRORS = (BugBountyNmapAdapterError, BugBountyNucleiAdapterError)


def _blocked_result(
    *, request_id: str, tool_id: str, reason: str, permission_result: Mapping[str, Any], governor_result: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "tool_execution_version": TOOL_EXECUTION_VERSION,
        "request_id": request_id,
        "tool_id": tool_id,
        "execution_permitted": False,
        "execution_blocked_reason": reason,
        "permission_result": permission_result,
        "governor_decision": governor_result["decision"],
        "tool_result": None,
        "execution_performed": False,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def execute_bug_bounty_tool(
    *, permissions: Any, tool_request: Any, governor_result: Any, execution_config: Any,
) -> dict[str, Any]:
    """The single execution boundary for the Bug Bounty Nmap/Nuclei
    adapters. Re-evaluates the real tool permission policy itself, then
    requires an already-computed, genuinely `allow`ing Security Governor
    result, before ever selecting an adapter from the closed registry.

    All four parameters are required and keyword-only. `permissions` and
    `tool_request` are passed through, unmodified, to
    `core.bug_bounty_tool_policy.evaluate_tool_permission` -- this
    function never trusts a caller-supplied boolean claiming permission.
    `governor_result` must be a mapping shaped exactly like
    `core.security_governor.evaluate_security_governor_event`'s own
    return value; this function never synthesizes one. `execution_config`
    must be a mapping containing exactly `execution_config_version`,
    `process_timeout_seconds`, `max_output_bytes` -- deep ceiling
    enforcement for the latter two happens inside whichever adapter is
    ultimately selected.

    Returns a new dict containing exactly `tool_execution_version`,
    `request_id`, `tool_id`, `execution_permitted`,
    `execution_blocked_reason` (`None` when `execution_permitted` is
    `True`, else one of `"POLICY_DENIED"`, `"GOVERNOR_DENIED"`,
    `"NO_ADAPTER_REGISTERED"`, `"ADAPTER_REJECTED_REQUEST"`),
    `permission_result` (the full result from `evaluate_tool_permission`),
    `governor_decision` (echoed from the supplied `governor_result`),
    `tool_result` (`None` unless a real adapter call was made, in which
    case the adapter's own structured result), `execution_performed`
    (`True` only when the selected adapter itself reports it started a
    real process -- see each adapter's own `execution_performed`
    semantics).

    An unregistered/unimplemented `tool_id` (including `http_assessor`,
    which is deliberately not registered here -- see module docstring)
    always resolves to `POLICY_DENIED` first when the policy layer's own
    `ADAPTER_UNAVAILABLE`/`TOOL_NOT_ALLOWED`/etc. reasons already deny
    execution; `NO_ADAPTER_REGISTERED` is reserved for the structurally
    unreachable case of a policy-permitted tool_id this registry still
    does not carry an entry for.

    Raises `BugBountyToolExecutionError` for a structurally invalid
    `governor_result`/`execution_config`, or for a structurally invalid
    `permissions`/`tool_request` (wrapping the real
    `BugBountyToolPolicyError`). Never raises because execution was
    policy-denied, Governor-denied, or adapter-rejected -- every one of
    those is a normal, successfully returned result.
    """
    validated_governor = _validate_governor_result(governor_result)
    validated_config = _validate_execution_config_shape(execution_config)

    try:
        permission_result = evaluate_tool_permission(permissions=permissions, tool_request=tool_request)
    except BugBountyToolPolicyError as exc:
        raise BugBountyToolExecutionError(f"INVALID_TOOL_REQUEST_OR_PERMISSIONS: {exc}") from None

    tool_id = permission_result["tool_id"]
    request_id = permission_result["request_id"]

    governor_allows = (
        validated_governor["execution_allowed"] is True
        and validated_governor["decision"] not in _GOVERNOR_BLOCKING_DECISIONS
    )

    if not permission_result["execution_permitted"]:
        return _blocked_result(
            request_id=request_id, tool_id=tool_id, reason="POLICY_DENIED",
            permission_result=permission_result, governor_result=validated_governor,
        )

    if not governor_allows:
        return _blocked_result(
            request_id=request_id, tool_id=tool_id, reason="GOVERNOR_DENIED",
            permission_result=permission_result, governor_result=validated_governor,
        )

    adapter_callable = _ADAPTER_REGISTRY.get(tool_id)
    if adapter_callable is None:
        return _blocked_result(
            request_id=request_id, tool_id=tool_id, reason="NO_ADAPTER_REGISTERED",
            permission_result=permission_result, governor_result=validated_governor,
        )

    try:
        tool_result = adapter_callable(tool_request=tool_request, execution_config=validated_config)
    except _ADAPTER_ERRORS:
        return _blocked_result(
            request_id=request_id, tool_id=tool_id, reason="ADAPTER_REJECTED_REQUEST",
            permission_result=permission_result, governor_result=validated_governor,
        )

    return {
        "tool_execution_version": TOOL_EXECUTION_VERSION,
        "request_id": request_id,
        "tool_id": tool_id,
        "execution_permitted": True,
        "execution_blocked_reason": None,
        "permission_result": permission_result,
        "governor_decision": validated_governor["decision"],
        "tool_result": tool_result,
        "execution_performed": tool_result["execution_performed"],
    }
