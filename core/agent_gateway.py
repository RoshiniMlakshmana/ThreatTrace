"""Pure, deterministic, default-deny runtime policy engine for the AI
Agent Gateway / Runtime Firewall (Block 8).

This module answers exactly one question: *may an AI agent's proposed
tool call proceed?* It never answers that question by executing
anything -- it is a pure decision function over a fixed, in-code tool
registry and a fixed, closed policy-rule vocabulary, evaluated
identically to `core.source_trust_policy.assess_source_trust`'s own
fixed `_REASON_CODE_ORDER`-filtered-by-`set` pattern.

This module does not:

- execute the proposed tool, call MCP, construct SQL, or perform any
  I/O of any kind;
- import, `getattr`, or otherwise select a callable, module, or function
  from caller-supplied `tool_name` or `arguments` -- the registry never
  stores a callable, module path, or import name, only descriptive
  policy metadata;
- read the system clock, an environment variable, or the filesystem;
- generate a random value of any kind;
- create, approve, reject, review, or consume an approval, and never
  updates an investigation -- a `require_approval` decision only names
  the existing, separate Block 6 workflow as the required next action,
  never invokes it;
- perform a schema change of any kind;
- call an AI/LLM model to decide anything. Every rule this module can
  ever emit comes from one small, fixed, closed vocabulary, evaluated by
  plain deterministic comparisons against a fixed, immutable registry --
  never generated, ranked, or worded dynamically from arbitrary input;
- accept a caller-supplied decision, operation class, risk level, or any
  other policy-outcome field -- every one of those is always derived
  from the fixed registry alone, and a caller who supplies one of those
  field names inside `arguments` is rejected outright
  (`PROHIBITED_ARGUMENT`), never silently accepted or overridden.

`evaluate_tool_call` is this module's only public function. Its result
is a strict, self-contained mapping -- never raw argument values, secret
material, SQL, paths, descriptors, or any other transport metadata --
and always carries `execution_performed: false`, so a caller can never
mistake a gateway decision for evidence that the proposed tool actually
ran.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

GATEWAY_VERSION = "1"

_MAX_ARGUMENT_STRING_LENGTH = 4096

# ---------------------------------------------------------------------------
# Fixed decision and operation-class vocabularies
# ---------------------------------------------------------------------------

DECISIONS = ("allow", "require_approval", "deny")
_DECISIONS_SET = frozenset(DECISIONS)

OPERATION_CLASSES = (
    "read_only",
    "state_mutation",
    "approval_mutation",
    "schema_mutation",
    "external_side_effect",
    "prohibited",
)
_OPERATION_CLASSES_SET = frozenset(OPERATION_CLASSES)

_REQUIRED_NEXT_ACTION_BY_DECISION = MappingProxyType({
    "allow": "proceed_to_separate_execution_boundary",
    "require_approval": "submit_to_approval_workflow",
    "deny": "do_not_execute",
})

# ---------------------------------------------------------------------------
# Fixed, closed policy-rule vocabulary -- one fixed severity, one fixed
# deterministic message, and one fixed decision-effect flag per code.
# Nothing here is ever generated dynamically from caller input.
# ---------------------------------------------------------------------------

RULE_ORDER = (
    "UNKNOWN_TOOL",
    "TOOL_DISABLED",
    "MALFORMED_ARGUMENTS",
    "MISSING_ARGUMENT",
    "UNKNOWN_ARGUMENT",
    "PROHIBITED_ARGUMENT",
    "SCHEMA_MUTATION_DENIED",
    "GENERIC_SQL_TOOL_DENIED",
    "EXTERNAL_SIDE_EFFECT_DENIED",
    "MUTATION_REQUIRES_APPROVAL",
    "APPROVAL_MUTATION_RESTRICTED",
    "READ_ONLY_TOOL_ALLOWED",
    "SENSITIVE_ARGUMENT_SUPPRESSED",
    "EXECUTION_NOT_PERFORMED",
)

_RULE_SEVERITY = MappingProxyType({
    "UNKNOWN_TOOL": "blocking",
    "TOOL_DISABLED": "blocking",
    "MALFORMED_ARGUMENTS": "blocking",
    "MISSING_ARGUMENT": "blocking",
    "UNKNOWN_ARGUMENT": "blocking",
    "PROHIBITED_ARGUMENT": "blocking",
    "SCHEMA_MUTATION_DENIED": "blocking",
    "GENERIC_SQL_TOOL_DENIED": "blocking",
    "EXTERNAL_SIDE_EFFECT_DENIED": "blocking",
    "MUTATION_REQUIRES_APPROVAL": "caution",
    "APPROVAL_MUTATION_RESTRICTED": "informational",
    "READ_ONLY_TOOL_ALLOWED": "informational",
    "SENSITIVE_ARGUMENT_SUPPRESSED": "informational",
    "EXECUTION_NOT_PERFORMED": "informational",
})

_RULE_AFFECTS_DECISION = MappingProxyType({
    "UNKNOWN_TOOL": True,
    "TOOL_DISABLED": True,
    "MALFORMED_ARGUMENTS": True,
    "MISSING_ARGUMENT": True,
    "UNKNOWN_ARGUMENT": True,
    "PROHIBITED_ARGUMENT": True,
    "SCHEMA_MUTATION_DENIED": True,
    "GENERIC_SQL_TOOL_DENIED": True,
    "EXTERNAL_SIDE_EFFECT_DENIED": True,
    "MUTATION_REQUIRES_APPROVAL": True,
    "APPROVAL_MUTATION_RESTRICTED": False,
    "READ_ONLY_TOOL_ALLOWED": False,
    "SENSITIVE_ARGUMENT_SUPPRESSED": False,
    "EXECUTION_NOT_PERFORMED": False,
})

_RULE_MESSAGE = MappingProxyType({
    "UNKNOWN_TOOL": "The requested tool is not a recognized entry in the gateway's fixed registry.",
    "TOOL_DISABLED": "The requested tool is recognized but currently disabled in the gateway's fixed registry.",
    "MALFORMED_ARGUMENTS": "One or more supplied arguments are structurally malformed.",
    "MISSING_ARGUMENT": "One or more arguments required by this tool are missing.",
    "UNKNOWN_ARGUMENT": "One or more supplied arguments are not recognized by this tool.",
    "PROHIBITED_ARGUMENT": "One or more supplied arguments are globally prohibited policy-control fields.",
    "SCHEMA_MUTATION_DENIED": "This tool performs a schema mutation, which the gateway always denies.",
    "GENERIC_SQL_TOOL_DENIED": "This tool is a generic or prohibited execution path, which the gateway always denies.",
    "EXTERNAL_SIDE_EFFECT_DENIED": "This tool performs an external side effect, which the gateway always denies in the MVP.",
    "MUTATION_REQUIRES_APPROVAL": "This tool mutates state and must go through the separate approval workflow before execution.",
    "APPROVAL_MUTATION_RESTRICTED": "This tool mutates approval lifecycle state, which is always gated by the approval workflow.",
    "READ_ONLY_TOOL_ALLOWED": "This tool is a recognized, enabled, read-only operation.",
    "SENSITIVE_ARGUMENT_SUPPRESSED": "One or more supplied arguments are sensitive and have been redacted from this report.",
    "EXECUTION_NOT_PERFORMED": "The gateway only evaluated this request. No tool was executed.",
})

# ---------------------------------------------------------------------------
# Global, fixed, closed set of caller-controlled policy/control field names
# that can never appear in a caller-supplied `arguments` mapping, regardless
# of which tool is named -- every one of these names a value this module
# only ever derives itself, never accepts as input.
# ---------------------------------------------------------------------------

_GLOBALLY_PROHIBITED_ARGUMENT_FIELDS = frozenset({
    "decision",
    "policy_outcome",
    "operation_class",
    "mutability_class",
    "risk_level",
    "required_approvals",
    "matched_rules",
    "eligible_for_execution",
    "requires_approval",
    "execution_performed",
    "canonical_tool_name",
    "required_next_action",
    "rpc_name",
    "descriptor",
    "mcp_arguments",
})

_UNKNOWN_ARGUMENT_MARKER = "<unknown>"


class AgentGatewayError(ValueError):
    """Raised when a supplied gateway-evaluation input is structurally
    invalid.

    This is only raised for malformed input: a non-string or blank
    `tool_name`, a non-mapping `arguments`, or a malformed/timezone-naive
    `evaluated_at`.

    It is never raised because a tool happens to be unknown, disabled,
    supplied with malformed or prohibited tool-specific arguments, or
    otherwise denied by policy -- every one of those is a fully valid
    input this module represents through a normal `deny` decision
    report, not an exception. This module never exposes a database, SQL,
    MCP, or transport concept in any exception message.
    """


# ---------------------------------------------------------------------------
# Fixed, immutable tool registry -- policy metadata only. No callable, no
# module path, no import name, no SQL template, and no RPC function is
# ever stored here.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ToolRegistryEntry:
    canonical_name: str
    operation_class: str
    decision_policy: str
    required_argument_fields: tuple[str, ...]
    allowed_argument_fields: tuple[str, ...]
    sensitive_argument_fields: frozenset[str]
    uuid_argument_fields: frozenset[str]
    enabled: bool
    description: str


def _entry(
    *,
    canonical_name: str,
    operation_class: str,
    decision_policy: str,
    required_argument_fields: tuple[str, ...],
    allowed_argument_fields: tuple[str, ...],
    sensitive_argument_fields: frozenset[str] = frozenset(),
    uuid_argument_fields: frozenset[str] = frozenset(),
    enabled: bool,
    description: str,
) -> _ToolRegistryEntry:
    return _ToolRegistryEntry(
        canonical_name=canonical_name,
        operation_class=operation_class,
        decision_policy=decision_policy,
        required_argument_fields=required_argument_fields,
        allowed_argument_fields=allowed_argument_fields,
        sensitive_argument_fields=sensitive_argument_fields,
        uuid_argument_fields=uuid_argument_fields,
        enabled=enabled,
        description=description,
    )


_REGISTRY: Mapping[str, _ToolRegistryEntry] = MappingProxyType({
    "load_risk_aware_approval_record": _entry(
        canonical_name="load_risk_aware_approval_record",
        operation_class="read_only",
        decision_policy="allow",
        required_argument_fields=("approval_id",),
        allowed_argument_fields=("approval_id",),
        uuid_argument_fields=frozenset({"approval_id"}),
        enabled=True,
        description="Trusted, read-only lookup of one risk-aware approval record by ID.",
    ),
    "load_investigation_approval_context": _entry(
        canonical_name="load_investigation_approval_context",
        operation_class="read_only",
        decision_policy="allow",
        required_argument_fields=("investigation_id",),
        allowed_argument_fields=("investigation_id",),
        uuid_argument_fields=frozenset({"investigation_id"}),
        enabled=True,
        description="Trusted, read-only lookup of one investigation's current status/confidence.",
    ),
    "apply_approval_consumption": _entry(
        canonical_name="apply_approval_consumption",
        operation_class="approval_mutation",
        decision_policy="require_approval",
        required_argument_fields=("approval_id",),
        allowed_argument_fields=("approval_id",),
        uuid_argument_fields=frozenset({"approval_id"}),
        enabled=True,
        description=(
            "Gateway classification only, for the existing Block 6 atomic consumption operation. "
            "Not a replacement for the real descriptor or execution contract."
        ),
    ),
    "load_approval_record": _entry(
        canonical_name="load_approval_record",
        operation_class="read_only",
        decision_policy="deny",
        required_argument_fields=("approval_id",),
        allowed_argument_fields=("approval_id",),
        uuid_argument_fields=frozenset({"approval_id"}),
        enabled=False,
        description="Legacy Block 5 lookup, disabled in the Block 8 registry.",
    ),
    "apply_migration": _entry(
        canonical_name="apply_migration",
        operation_class="schema_mutation",
        decision_policy="deny",
        required_argument_fields=("name", "query"),
        allowed_argument_fields=("name", "query"),
        sensitive_argument_fields=frozenset({"query"}),
        enabled=True,
        description="Schema mutation. Always denied; its query is never inspected to decide safety.",
    ),
    "execute_sql": _entry(
        canonical_name="execute_sql",
        operation_class="prohibited",
        decision_policy="deny",
        required_argument_fields=("query",),
        allowed_argument_fields=("query",),
        sensitive_argument_fields=frozenset({"query"}),
        enabled=True,
        description="Generic SQL execution. Always denied regardless of the query's own content.",
    ),
    "run_evtx_analysis": _entry(
        canonical_name="run_evtx_analysis",
        operation_class="external_side_effect",
        decision_policy="deny",
        required_argument_fields=("evtx_file", "analysis_type", "output_name", "authorization_phrase"),
        allowed_argument_fields=("evtx_file", "analysis_type", "output_name", "authorization_phrase"),
        sensitive_argument_fields=frozenset({"evtx_file", "analysis_type", "output_name", "authorization_phrase"}),
        enabled=True,
        description="External Hayabusa execution side effect. Always denied in the Block 8 MVP.",
    ),
    "run_bug_bounty_assessment": _entry(
        canonical_name="run_bug_bounty_assessment",
        operation_class="external_side_effect",
        decision_policy="deny",
        required_argument_fields=("target", "testing_profile"),
        allowed_argument_fields=("target", "testing_profile"),
        enabled=True,
        description=(
            "Bounded, scope-checked GET/HEAD/OPTIONS web-application security assessment via the "
            "Block 15A Bug Bounty assessment engine (core.bug_bounty_assessment). This gateway "
            "entry governs only whether an AI agent may request the tool by name; the actual real "
            "execution surface is the separate, human-invoked core.bug_bounty_cli boundary. Always "
            "denied by the gateway's fixed external_side_effect policy in this MVP -- never "
            "exploitation, never a comprehensive penetration test, never a production mutation."
        ),
    ),
})


# ---------------------------------------------------------------------------
# Narrow, private input validators -- each module in this project owns its
# own copy of this exact validation shape rather than sharing one; no
# public UUID or timestamp validator exists anywhere in this project to
# import instead.
# ---------------------------------------------------------------------------


def _validate_tool_name(value: Any) -> str:
    if not isinstance(value, str):
        raise AgentGatewayError("tool_name must be a string")
    stripped = value.strip()
    if not stripped:
        raise AgentGatewayError("tool_name must not be blank")
    return stripped


def _normalize_timestamp(value: Any, field_name: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise AgentGatewayError(f"{field_name} must not be blank")
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError as exc:
            raise AgentGatewayError(f"{field_name} must be an aware datetime or an aware ISO-8601 string") from exc
    else:
        raise AgentGatewayError(f"{field_name} must be an aware datetime or an aware ISO-8601 string")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AgentGatewayError(f"{field_name} must include timezone information")

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_valid_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped:
        return False
    try:
        uuid.UUID(stripped)
    except ValueError:
        return False
    return True


def _contains_nested_structure(value: Any) -> bool:
    return isinstance(value, (Mapping, list, tuple, set))


def evaluate_tool_call(
    *,
    tool_name: Any,
    arguments: Any,
    evaluated_at: Any,
) -> dict[str, Any]:
    """Deterministically evaluate one proposed AI-agent tool call against
    the fixed Block 8 tool registry and policy-rule vocabulary, without
    ever executing anything.

    All three parameters are required and keyword-only, and none has a
    hidden default. `tool_name` is matched against the registry's exact,
    case-sensitive canonical keys only -- trimmed of surrounding
    whitespace, never case-folded, never fuzzy-matched, never resolved
    through an alias. `arguments` is validated against the matched
    registry entry's own fixed field lists; every value is inspected
    only enough to classify it (missing/unknown/prohibited/malformed) --
    no value is ever echoed back in the result. `evaluated_at` must be
    an aware `datetime` or aware ISO-8601 string; this function never
    reads the system clock itself, so the caller alone controls what
    moment is evaluated -- a future command boundary is expected to pin
    it once, exactly like `core.shadow_execution.simulate_case_update`'s
    own `simulated_at` parameter.

    Neither `arguments` (nor any nested value within it) is ever
    mutated, and no mutable object from it is retained by reference in
    the result -- the returned mapping and every nested list/mapping
    within it are newly constructed.

    Returns a new dict containing exactly twelve fields:
    `gateway_version`, `canonical_tool_name`, `operation_class`,
    `decision`, `eligible_for_execution`, `requires_approval`,
    `matched_rules`, `safe_argument_summary`, `blocked_argument_fields`,
    `required_next_action`, `evaluated_at`, `execution_performed`.
    `execution_performed` is always `False` -- this function never
    executes the named tool, never calls MCP, never constructs SQL,
    never creates or consumes an approval, and never updates an
    investigation.

    Raises `AgentGatewayError` for any structurally invalid input.
    Never raises because a tool is unknown, disabled, or its arguments
    are invalid -- every one of those is represented in the returned
    result through `decision` and `matched_rules` instead.
    """
    canonical_input_tool_name = _validate_tool_name(tool_name)

    if not isinstance(arguments, Mapping):
        raise AgentGatewayError("arguments must be a mapping")

    canonical_evaluated_at = _normalize_timestamp(evaluated_at, "evaluated_at")

    matched_rules: list[dict[str, Any]] = []

    def _emit(code: str) -> None:
        matched_rules.append({
            "code": code,
            "severity": _RULE_SEVERITY[code],
            "message": _RULE_MESSAGE[code],
            "affects_decision": _RULE_AFFECTS_DECISION[code],
        })

    entry = _REGISTRY.get(canonical_input_tool_name)

    if entry is None:
        _emit("UNKNOWN_TOOL")
        _emit("EXECUTION_NOT_PERFORMED")
        return {
            "gateway_version": GATEWAY_VERSION,
            "canonical_tool_name": None,
            "operation_class": None,
            "decision": "deny",
            "eligible_for_execution": False,
            "requires_approval": False,
            "matched_rules": matched_rules,
            "safe_argument_summary": {},
            "blocked_argument_fields": [],
            "required_next_action": _REQUIRED_NEXT_ACTION_BY_DECISION["deny"],
            "evaluated_at": canonical_evaluated_at,
            "execution_performed": False,
        }

    if not entry.enabled:
        _emit("TOOL_DISABLED")
        _emit("EXECUTION_NOT_PERFORMED")
        return {
            "gateway_version": GATEWAY_VERSION,
            "canonical_tool_name": entry.canonical_name,
            "operation_class": entry.operation_class,
            "decision": "deny",
            "eligible_for_execution": False,
            "requires_approval": False,
            "matched_rules": matched_rules,
            "safe_argument_summary": {},
            "blocked_argument_fields": [],
            "required_next_action": _REQUIRED_NEXT_ACTION_BY_DECISION["deny"],
            "evaluated_at": canonical_evaluated_at,
            "execution_performed": False,
        }

    allowed_fields = frozenset(entry.allowed_argument_fields)
    supplied_fields = set(arguments)

    blocked_argument_fields: list[str] = []

    is_malformed = False
    for key, value in arguments.items():
        if not isinstance(key, str) or not key.strip():
            is_malformed = True
            continue
        if _contains_nested_structure(value):
            is_malformed = True
        if isinstance(value, str) and len(value) > _MAX_ARGUMENT_STRING_LENGTH:
            is_malformed = True
    for uuid_field in entry.uuid_argument_fields:
        if uuid_field in arguments and not _is_valid_uuid(arguments[uuid_field]):
            is_malformed = True

    is_missing = any(field not in supplied_fields for field in entry.required_argument_fields)

    unknown_fields = [
        key for key in supplied_fields
        if isinstance(key, str) and key not in allowed_fields and key not in _GLOBALLY_PROHIBITED_ARGUMENT_FIELDS
    ]
    is_unknown = len(unknown_fields) > 0

    prohibited_fields = sorted(
        key for key in supplied_fields
        if isinstance(key, str) and key in _GLOBALLY_PROHIBITED_ARGUMENT_FIELDS
    )
    is_prohibited = len(prohibited_fields) > 0

    argument_validation_failed = is_malformed or is_missing or is_unknown or is_prohibited

    if is_malformed:
        _emit("MALFORMED_ARGUMENTS")
    if is_missing:
        _emit("MISSING_ARGUMENT")
    if is_unknown:
        _emit("UNKNOWN_ARGUMENT")
        blocked_argument_fields.extend(_UNKNOWN_ARGUMENT_MARKER for _ in unknown_fields)
    if is_prohibited:
        _emit("PROHIBITED_ARGUMENT")
        blocked_argument_fields.extend(prohibited_fields)

    safe_argument_summary: dict[str, str] = {}
    for field in sorted(allowed_fields):
        if field not in supplied_fields:
            safe_argument_summary[field] = "absent"
        elif field in entry.sensitive_argument_fields:
            safe_argument_summary[field] = "redacted"
        else:
            safe_argument_summary[field] = "present"

    sensitive_supplied = any(field in supplied_fields for field in entry.sensitive_argument_fields)

    if argument_validation_failed:
        decision = "deny"
    elif entry.operation_class == "schema_mutation":
        _emit("SCHEMA_MUTATION_DENIED")
        decision = "deny"
    elif entry.operation_class == "prohibited":
        _emit("GENERIC_SQL_TOOL_DENIED")
        decision = "deny"
    elif entry.operation_class == "external_side_effect":
        _emit("EXTERNAL_SIDE_EFFECT_DENIED")
        decision = "deny"
    elif entry.operation_class in ("state_mutation", "approval_mutation"):
        _emit("MUTATION_REQUIRES_APPROVAL")
        if entry.operation_class == "approval_mutation":
            _emit("APPROVAL_MUTATION_RESTRICTED")
        decision = "require_approval"
    else:
        _emit("READ_ONLY_TOOL_ALLOWED")
        decision = "allow"

    if sensitive_supplied:
        _emit("SENSITIVE_ARGUMENT_SUPPRESSED")

    _emit("EXECUTION_NOT_PERFORMED")

    return {
        "gateway_version": GATEWAY_VERSION,
        "canonical_tool_name": entry.canonical_name,
        "operation_class": entry.operation_class,
        "decision": decision,
        "eligible_for_execution": decision == "allow",
        "requires_approval": decision == "require_approval",
        "matched_rules": matched_rules,
        "safe_argument_summary": safe_argument_summary,
        "blocked_argument_fields": blocked_argument_fields,
        "required_next_action": _REQUIRED_NEXT_ACTION_BY_DECISION[decision],
        "evaluated_at": canonical_evaluated_at,
        "execution_performed": False,
    }
