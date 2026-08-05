"""Pure, deterministic, claim-based identity and least-privilege policy
engine for Agent Identity and Least Privilege (Block 9).

This module answers one question only: *does this specific claimed agent
identity have the least-privilege capability to even make this proposed
tool call at all?* It never answers whether the tool call is generally
safe to consider -- that remains `core.agent_gateway.evaluate_tool_call`'s
own concern, reused here unchanged -- and it never makes the tool call
happen.

This module does not:

- authenticate, verify, or cryptographically prove the caller's identity.
  `agent_id` is always a claimed identifier only, matched against a
  fixed, in-code registry by exact, case-sensitive, trimmed-only
  comparison -- never casefolded, never aliased, never fuzzy-matched.
  A successful registry match proves only that the caller typed a
  string equal to a known registry key, nothing more;
- accept a caller-supplied role, capability list, tool allowlist,
  operation-class permission, enabled state, or any other policy-outcome
  field -- every one of those is always derived from the fixed registry
  alone;
- execute the proposed tool, call MCP, construct SQL, or perform any I/O
  of any kind;
- read the system clock, an environment variable, or the filesystem;
- generate a random value of any kind;
- create, approve, reject, review, or consume an approval, and never
  invokes `/request-case-update`, `/review-approval`, or
  `/apply-case-update`;
- reclassify a tool, duplicate the Block 8 tool registry, duplicate
  Block 8 argument validation, duplicate Block 8 policy rules, or
  duplicate Block 8 decision calculation -- `canonical_tool_name`,
  `operation_class`, and the gateway `decision` are always read verbatim
  from `evaluate_tool_call`'s own return value;
- ever promote a Block 8 decision: `deny` can never become
  `require_approval` or `allow`, and `require_approval` can never become
  `allow`. This module can only narrow what Block 8 already permits,
  never widen it;
- call an AI/LLM model to decide anything. Every rule this module can
  ever emit comes from one small, fixed, closed vocabulary, evaluated by
  plain deterministic comparisons -- never generated, ranked, or worded
  dynamically from arbitrary input, exactly like
  `core.agent_gateway.evaluate_tool_call`'s own fixed `RULE_ORDER`.

`evaluate_agent_tool_call` is this module's only public function. Its
result is a strict, self-contained mapping -- never a caller-supplied raw
unknown agent ID, a complete tool allowlist, raw argument values, secret
material, SQL, paths, descriptors, or any other transport metadata -- and
always carries `identity_authenticated: false` and
`execution_performed: false`, so a caller can never mistake a registry
match for real authentication or a policy report for evidence that the
proposed tool actually ran.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from core.agent_gateway import AgentGatewayError, evaluate_tool_call

IDENTITY_POLICY_VERSION = "1"

_MAX_AGENT_ID_LENGTH = 4096

# ---------------------------------------------------------------------------
# Fixed role vocabulary and per-role operation-class ceilings. No role may
# ever permit schema_mutation, external_side_effect, or prohibited, and no
# role may ever override a Block 8 deny -- both are enforced structurally
# by evaluate_agent_tool_call below, never by anything in this table.
# ---------------------------------------------------------------------------

ROLES = (
    "observer",
    "analyst",
    "investigation_coordinator",
    "approval_reviewer",
    "disabled",
)
_ROLES_SET = frozenset(ROLES)

_ROLE_OPERATION_CLASS_CEILING: Mapping[str, frozenset[str]] = MappingProxyType({
    "observer": frozenset({"read_only"}),
    "analyst": frozenset({"read_only", "state_mutation", "approval_mutation"}),
    "investigation_coordinator": frozenset({"read_only", "state_mutation", "approval_mutation"}),
    "approval_reviewer": frozenset({"read_only"}),
    "disabled": frozenset(),
})

# ---------------------------------------------------------------------------
# Fixed decision and required-next-action vocabularies -- reused verbatim
# from Block 8's own three-value shape, never a fourth value.
# ---------------------------------------------------------------------------

_REQUIRED_NEXT_ACTION_BY_DECISION = MappingProxyType({
    "allow": "proceed_to_separate_execution_boundary",
    "require_approval": "submit_to_approval_workflow",
    "deny": "do_not_execute",
})

# ---------------------------------------------------------------------------
# Fixed, closed identity-policy rule vocabulary -- one fixed severity, one
# fixed deterministic message, and one fixed decision-effect flag per code.
# Nothing here is ever generated dynamically from caller input.
# ---------------------------------------------------------------------------

RULE_ORDER = (
    "UNKNOWN_AGENT",
    "AGENT_DISABLED",
    "GATEWAY_DENIED",
    "OPERATION_CLASS_NOT_PERMITTED",
    "TOOL_NOT_IN_AGENT_ALLOWLIST",
    "MUTATION_REQUEST_NOT_PERMITTED",
    "GATEWAY_APPROVAL_REQUIRED",
    "IDENTITY_POLICY_ALLOWED",
    "CLAIMED_IDENTITY_NOT_AUTHENTICATED",
    "EXECUTION_NOT_PERFORMED",
)

_RULE_SEVERITY = MappingProxyType({
    "UNKNOWN_AGENT": "blocking",
    "AGENT_DISABLED": "blocking",
    "GATEWAY_DENIED": "blocking",
    "OPERATION_CLASS_NOT_PERMITTED": "blocking",
    "TOOL_NOT_IN_AGENT_ALLOWLIST": "blocking",
    "MUTATION_REQUEST_NOT_PERMITTED": "blocking",
    "GATEWAY_APPROVAL_REQUIRED": "caution",
    "IDENTITY_POLICY_ALLOWED": "informational",
    "CLAIMED_IDENTITY_NOT_AUTHENTICATED": "informational",
    "EXECUTION_NOT_PERFORMED": "informational",
})

_RULE_AFFECTS_DECISION = MappingProxyType({
    "UNKNOWN_AGENT": True,
    "AGENT_DISABLED": True,
    "GATEWAY_DENIED": True,
    "OPERATION_CLASS_NOT_PERMITTED": True,
    "TOOL_NOT_IN_AGENT_ALLOWLIST": True,
    "MUTATION_REQUEST_NOT_PERMITTED": True,
    "GATEWAY_APPROVAL_REQUIRED": True,
    "IDENTITY_POLICY_ALLOWED": True,
    "CLAIMED_IDENTITY_NOT_AUTHENTICATED": False,
    "EXECUTION_NOT_PERFORMED": False,
})

_RULE_MESSAGE = MappingProxyType({
    "UNKNOWN_AGENT": "The claimed agent ID is not a recognized entry in the identity policy's fixed registry.",
    "AGENT_DISABLED": "The claimed agent is recognized but currently disabled in the identity policy's fixed registry.",
    "GATEWAY_DENIED": "The AI Agent Gateway denied this tool call; identity policy can never override a gateway denial.",
    "OPERATION_CLASS_NOT_PERMITTED": "The tool's operation class is outside the operation classes permitted for this agent's role.",
    "TOOL_NOT_IN_AGENT_ALLOWLIST": "The requested tool is not included in this agent's fixed tool allowlist.",
    "MUTATION_REQUEST_NOT_PERMITTED": (
        "This agent is not permitted to submit mutation requests, even though the tool and "
        "operation class are otherwise permitted."
    ),
    "GATEWAY_APPROVAL_REQUIRED": (
        "The gateway requires approval for this mutation, and this agent is permitted to submit "
        "mutation requests."
    ),
    "IDENTITY_POLICY_ALLOWED": "This agent's role and tool allowlist permit this request.",
    "CLAIMED_IDENTITY_NOT_AUTHENTICATED": (
        "canonical_agent_id and agent_role were resolved from a claimed identifier against a fixed "
        "registry. This is not authentication, verification, or cryptographic proof of identity."
    ),
    "EXECUTION_NOT_PERFORMED": "The identity policy only evaluated this request. No tool was executed and no agent was authenticated.",
})

# ---------------------------------------------------------------------------
# Structurally prohibited claimed-agent-ID syntax. A syntactically safe but
# unregistered identifier is never rejected here -- it is a normal
# UNKNOWN_AGENT deny report produced by evaluate_agent_tool_call instead.
# ---------------------------------------------------------------------------

_PROHIBITED_AGENT_ID_SUBSTRINGS = (
    ";", "|", "`", "$(", "://", "..", "/", "\\", "--", "/*", "*/",
)


class AgentIdentityPolicyError(ValueError):
    """Raised when a supplied identity-evaluation input is structurally invalid.

    This is only raised for malformed input: a non-string, blank,
    oversized, or syntactically unsafe `agent_id`; a non-string or blank
    `tool_name`; a non-mapping `arguments`; a malformed or
    timezone-naive `evaluated_at`; or a structural `AgentGatewayError`
    raised by `core.agent_gateway.evaluate_tool_call` after identity
    resolution.

    It is never raised because an agent happens to be unknown, disabled,
    or lacks the least-privilege capability for a requested tool --
    every one of those is a fully valid input this module represents
    through a normal `deny` decision report, not an exception. This
    module never exposes a database, SQL, MCP, or transport concept in
    any exception message, and never echoes a supplied `agent_id` in an
    exception message.
    """


# ---------------------------------------------------------------------------
# Fixed, immutable agent registry -- policy metadata only. No password,
# token, key, secret, authorization phrase, certificate, callable, module,
# import path, SQL, or RPC name is ever stored here.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _AgentRegistryEntry:
    canonical_agent_id: str
    role: str
    enabled: bool
    allowed_tools: frozenset[str]
    allowed_operation_classes: frozenset[str]
    mutation_request_allowed: bool
    description: str


_REGISTRY: Mapping[str, _AgentRegistryEntry] = MappingProxyType({
    "observer_agent": _AgentRegistryEntry(
        canonical_agent_id="observer_agent",
        role="observer",
        enabled=True,
        allowed_tools=frozenset({"load_investigation_approval_context"}),
        allowed_operation_classes=frozenset({"read_only"}),
        mutation_request_allowed=False,
        description="Narrowly scoped, read-only monitoring agent.",
    ),
    "analyst_agent": _AgentRegistryEntry(
        canonical_agent_id="analyst_agent",
        role="analyst",
        enabled=True,
        allowed_tools=frozenset({
            "load_risk_aware_approval_record",
            "load_investigation_approval_context",
            "apply_approval_consumption",
        }),
        allowed_operation_classes=frozenset({"read_only", "state_mutation", "approval_mutation"}),
        mutation_request_allowed=False,
        description=(
            "Day-to-day investigation analyst. The mutation tool is intentionally allowlisted so "
            "the independent mutation-request restriction can be demonstrated."
        ),
    ),
    "coordinator_agent": _AgentRegistryEntry(
        canonical_agent_id="coordinator_agent",
        role="investigation_coordinator",
        enabled=True,
        allowed_tools=frozenset({
            "load_risk_aware_approval_record",
            "load_investigation_approval_context",
            "apply_approval_consumption",
        }),
        allowed_operation_classes=frozenset({"read_only", "state_mutation", "approval_mutation"}),
        mutation_request_allowed=True,
        description="Leads case-update mutation requests through the separate approval workflow.",
    ),
    "reviewer_agent": _AgentRegistryEntry(
        canonical_agent_id="reviewer_agent",
        role="approval_reviewer",
        enabled=True,
        allowed_tools=frozenset({
            "load_risk_aware_approval_record",
            "apply_approval_consumption",
        }),
        allowed_operation_classes=frozenset({"read_only"}),
        mutation_request_allowed=False,
        description=(
            "Reviews approvals. The mutation tool is intentionally allowlisted so the role "
            "operation-class ceiling can independently deny it."
        ),
    ),
    "disabled_agent": _AgentRegistryEntry(
        canonical_agent_id="disabled_agent",
        role="disabled",
        enabled=False,
        allowed_tools=frozenset(),
        allowed_operation_classes=frozenset(),
        mutation_request_allowed=False,
        description="Explicitly deactivated identity, kept only to demonstrate deny-when-disabled.",
    ),
})

for _entry in _REGISTRY.values():
    assert _entry.allowed_operation_classes <= _ROLE_OPERATION_CLASS_CEILING[_entry.role]
del _entry


# ---------------------------------------------------------------------------
# Narrow, private input validators -- each module in this project owns its
# own copy of this exact validation shape rather than sharing one; no
# public UUID or timestamp validator exists anywhere in this project to
# import instead.
# ---------------------------------------------------------------------------


def _validate_agent_id(value: Any) -> str:
    if not isinstance(value, str):
        raise AgentIdentityPolicyError("agent_id must be a string")
    stripped = value.strip()
    if not stripped:
        raise AgentIdentityPolicyError("agent_id must not be blank")
    if len(stripped) > _MAX_AGENT_ID_LENGTH:
        raise AgentIdentityPolicyError(f"agent_id must not exceed {_MAX_AGENT_ID_LENGTH} characters")
    for character in stripped:
        if ord(character) < 0x20 or ord(character) == 0x7F:
            raise AgentIdentityPolicyError("agent_id must not contain control characters")
    for fragment in _PROHIBITED_AGENT_ID_SUBSTRINGS:
        if fragment in stripped:
            raise AgentIdentityPolicyError("agent_id contains prohibited syntax")
    return stripped


def _validate_tool_name_shape(value: Any) -> str:
    if not isinstance(value, str):
        raise AgentIdentityPolicyError("tool_name must be a string")
    stripped = value.strip()
    if not stripped:
        raise AgentIdentityPolicyError("tool_name must not be blank")
    return stripped


def _normalize_timestamp(value: Any, field_name: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise AgentIdentityPolicyError(f"{field_name} must not be blank")
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError as exc:
            raise AgentIdentityPolicyError(
                f"{field_name} must be an aware datetime or an aware ISO-8601 string"
            ) from exc
    else:
        raise AgentIdentityPolicyError(f"{field_name} must be an aware datetime or an aware ISO-8601 string")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AgentIdentityPolicyError(f"{field_name} must include timezone information")

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _unknown_or_disabled_capability_summary() -> dict[str, Any]:
    return {
        "role": None,
        "requested_tool_allowed": False,
        "requested_operation_class_permitted": False,
        "mutation_request_allowed": None,
        "allowed_tool_count": None,
    }


def _build_result(
    *,
    canonical_agent_id: str | None,
    agent_role: str | None,
    canonical_tool_name: str | None,
    operation_class: str | None,
    gateway_decision: str | None,
    final_decision: str,
    matched_identity_rules: list[dict[str, Any]],
    safe_capability_summary: dict[str, Any],
    evaluated_at: str,
) -> dict[str, Any]:
    return {
        "identity_policy_version": IDENTITY_POLICY_VERSION,
        "canonical_agent_id": canonical_agent_id,
        "agent_role": agent_role,
        "identity_authenticated": False,
        "canonical_tool_name": canonical_tool_name,
        "operation_class": operation_class,
        "gateway_decision": gateway_decision,
        "final_decision": final_decision,
        "eligible_for_execution": final_decision == "allow",
        "requires_approval": final_decision == "require_approval",
        "matched_identity_rules": matched_identity_rules,
        "safe_capability_summary": safe_capability_summary,
        "required_next_action": _REQUIRED_NEXT_ACTION_BY_DECISION[final_decision],
        "evaluated_at": evaluated_at,
        "execution_performed": False,
    }


def evaluate_agent_tool_call(
    *,
    agent_id: Any,
    tool_name: Any,
    arguments: Any,
    evaluated_at: Any,
) -> dict[str, Any]:
    """Deterministically evaluate one proposed AI-agent tool call against a
    fixed, claim-based agent registry and least-privilege policy-rule
    vocabulary, layered on top of an unmodified Block 8 gateway
    evaluation, without ever executing anything or authenticating anyone.

    All four parameters are required and keyword-only, and none has a
    hidden default. `agent_id` is a claimed identifier only, matched
    against the fixed registry's exact, case-sensitive canonical keys --
    trimmed of surrounding whitespace, never case-folded, never
    fuzzy-matched, never resolved through an alias. `tool_name` and
    `arguments` are passed to `core.agent_gateway.evaluate_tool_call`
    unchanged for a known, enabled agent; this module never reclassifies
    a tool, never duplicates the Block 8 registry, and never duplicates
    Block 8's argument validation or policy rules. `evaluated_at` must be
    an aware `datetime` or aware ISO-8601 string; this function never
    reads the system clock itself.

    Neither `arguments` (nor any nested value within it) is ever
    mutated, and no mutable object from it is retained by reference in
    the result -- the returned mapping and every nested list/mapping
    within it are newly constructed.

    Returns a new dict containing exactly fifteen fields:
    `identity_policy_version`, `canonical_agent_id`, `agent_role`,
    `identity_authenticated`, `canonical_tool_name`, `operation_class`,
    `gateway_decision`, `final_decision`, `eligible_for_execution`,
    `requires_approval`, `matched_identity_rules`,
    `safe_capability_summary`, `required_next_action`, `evaluated_at`,
    `execution_performed`. `identity_authenticated` and
    `execution_performed` are always `False` -- a registry match is
    never authentication, and this function never executes the named
    tool, never calls MCP, never constructs SQL, never creates or
    consumes an approval, and never updates an investigation.

    `final_decision` can only narrow a Block 8 decision: a Block 8
    `deny` can never become `require_approval` or `allow`, and a Block 8
    `require_approval` can never become `allow`.

    Raises `AgentIdentityPolicyError` for any structurally invalid
    input. Never raises because an agent is unknown, disabled, or lacks
    the least-privilege capability for the requested tool -- every one
    of those is represented in the returned result through
    `final_decision` and `matched_identity_rules` instead.
    """
    canonical_agent_id_input = _validate_agent_id(agent_id)
    canonical_tool_name_input = _validate_tool_name_shape(tool_name)

    if not isinstance(arguments, Mapping):
        raise AgentIdentityPolicyError("arguments must be a mapping")

    canonical_evaluated_at = _normalize_timestamp(evaluated_at, "evaluated_at")

    matched_identity_rules: list[dict[str, Any]] = []

    def _emit(code: str) -> None:
        matched_identity_rules.append({
            "code": code,
            "severity": _RULE_SEVERITY[code],
            "message": _RULE_MESSAGE[code],
            "affects_decision": _RULE_AFFECTS_DECISION[code],
        })

    entry = _REGISTRY.get(canonical_agent_id_input)

    if entry is None:
        _emit("UNKNOWN_AGENT")
        _emit("EXECUTION_NOT_PERFORMED")
        return _build_result(
            canonical_agent_id=None,
            agent_role=None,
            canonical_tool_name=None,
            operation_class=None,
            gateway_decision=None,
            final_decision="deny",
            matched_identity_rules=matched_identity_rules,
            safe_capability_summary=_unknown_or_disabled_capability_summary(),
            evaluated_at=canonical_evaluated_at,
        )

    if not entry.enabled:
        _emit("AGENT_DISABLED")
        _emit("EXECUTION_NOT_PERFORMED")
        return _build_result(
            canonical_agent_id=entry.canonical_agent_id,
            agent_role=None,
            canonical_tool_name=None,
            operation_class=None,
            gateway_decision=None,
            final_decision="deny",
            matched_identity_rules=matched_identity_rules,
            safe_capability_summary=_unknown_or_disabled_capability_summary(),
            evaluated_at=canonical_evaluated_at,
        )

    try:
        gateway_result = evaluate_tool_call(
            tool_name=canonical_tool_name_input,
            arguments=arguments,
            evaluated_at=canonical_evaluated_at,
        )
    except AgentGatewayError as exc:
        raise AgentIdentityPolicyError("tool call evaluation failed") from exc

    canonical_tool_name = gateway_result["canonical_tool_name"]
    operation_class = gateway_result["operation_class"]
    gateway_decision = gateway_result["decision"]

    requested_tool_allowed = canonical_tool_name is not None and canonical_tool_name in entry.allowed_tools
    requested_operation_class_permitted = (
        operation_class is not None and operation_class in entry.allowed_operation_classes
    )
    mutation_request_allowed_field: bool | None = None

    if gateway_decision == "deny":
        _emit("GATEWAY_DENIED")
        final_decision = "deny"
    elif not requested_operation_class_permitted or not requested_tool_allowed:
        if not requested_operation_class_permitted:
            _emit("OPERATION_CLASS_NOT_PERMITTED")
        if not requested_tool_allowed:
            _emit("TOOL_NOT_IN_AGENT_ALLOWLIST")
        final_decision = "deny"
    elif gateway_decision == "require_approval":
        mutation_request_allowed_field = entry.mutation_request_allowed
        if entry.mutation_request_allowed:
            _emit("GATEWAY_APPROVAL_REQUIRED")
            final_decision = "require_approval"
        else:
            _emit("MUTATION_REQUEST_NOT_PERMITTED")
            final_decision = "deny"
    else:
        _emit("IDENTITY_POLICY_ALLOWED")
        final_decision = "allow"

    _emit("CLAIMED_IDENTITY_NOT_AUTHENTICATED")
    _emit("EXECUTION_NOT_PERFORMED")

    safe_capability_summary = {
        "role": entry.role,
        "requested_tool_allowed": requested_tool_allowed,
        "requested_operation_class_permitted": requested_operation_class_permitted,
        "mutation_request_allowed": mutation_request_allowed_field,
        "allowed_tool_count": len(entry.allowed_tools),
    }

    return _build_result(
        canonical_agent_id=entry.canonical_agent_id,
        agent_role=entry.role,
        canonical_tool_name=canonical_tool_name,
        operation_class=operation_class,
        gateway_decision=gateway_decision,
        final_decision=final_decision,
        matched_identity_rules=matched_identity_rules,
        safe_capability_summary=safe_capability_summary,
        evaluated_at=canonical_evaluated_at,
    )
