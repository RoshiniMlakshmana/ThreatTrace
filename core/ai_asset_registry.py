"""Pure, deterministic AI Asset Inventory, Provenance & Security
Evaluation Lab (Combined Block 11-12).

This module has exactly two responsibilities, both purely observational:

1. **Inventory** -- answer *what AI/security-agent-related assets are
   declared in this ThreatTrace repository, and where?* through a fixed,
   in-code, immutable registry -- never a filesystem scan, never a Git
   call, never a database.
2. **Evaluation** -- answer, for one defined deterministic evaluation
   case, *did the existing ThreatTrace security primitive behave as
   expected for this registered asset?* by calling the already-committed
   pure functions from Block 8 (`core.agent_gateway`), Block 9
   (`core.agent_identity_policy`), the Emergency Mutation Freeze
   (`core.mutation_freeze`), and Block 10 (`core.decision_binding`) --
   never by reimplementing any of their policy.

This module is a **measurement/reporting layer only**. It is NOT, and
never becomes:

- another allow/deny production policy engine;
- an authorization layer;
- an execution boundary;
- an agent-authentication layer.

Blocks 8, 9, the Emergency Mutation Freeze, and Block 10 remain the
project's only production security-decision primitives. This module
calls their real public functions with real, valid, well-formed
arguments and reports their real, unmodified results back -- it never
wraps, monkeypatches, or alters their contracts.

## Provenance honesty

Every inventory entry's `provenance` is labeled `"repository_declared"`
and means exactly one thing: *this metadata was captured from a
checked-in file in this repository, as read by this static MVP
registry.* It is never described as verified, authenticated, or
cryptographically proven -- reading static text is not confirming what
actually executes at runtime. No version, hash, digest, provider ID, or
model ID is ever fabricated for an asset that does not genuinely carry
one in this repository; where the repository has no such value, the
corresponding field is simply absent from that asset's contract, never
invented.

The real `.mcp.json` is never read by this module -- it may contain
local/private configuration and is explicitly out of scope. The
`mcp_server` inventory reflects only the safe, checked-in
`.mcp.example.json` declaration.

## Evaluation honesty

A `"pass"` evaluation outcome means exactly:

    "The tested deterministic security property behaved as expected
    for this defined evaluation case."

It never means: the AI system is secure; the model is authentic; the
prompt is authentic; attacks are impossible; real-world attack
prevention is guaranteed; runtime enforcement occurred; an agent was
authenticated; or execution occurred. `execution_performed` is always
`False` in every evaluation result this module can ever produce -- no
evaluation case ever executes a tool, calls MCP, calls Supabase, or
performs any I/O of any kind.

Each of the four asset-scoped case types (`identity_privilege_bypass`,
`mutation_policy_bypass`, `emergency_freeze_bypass`,
`decision_binding_substitution`) evaluates exactly one deterministic,
already-established reference scenario against exactly one canonical
registered asset -- deliberately, per this MVP's smallest-honest-scope
design. A `"pass"` result proves the property held for *that specific
asset and scenario only*; it is never evidence that any other agent,
tool, or asset of the same `asset_type` would behave the same way.
Every other registered asset correctly returns `"not_applicable"` for
that case type, precisely so a passing result is never mistaken for
category-wide coverage.

## Purity

This module performs no runtime filesystem scanning, no Git calls, no
clock reads, no environment reads, no network access, no
Supabase/database access, no MCP calls, and no subprocess or
external-tool execution. The handful of fixed timestamp/UUID literals
used internally to drive the underlying Block 8/9/10/Mutation-Freeze
calls are exactly that -- fixed, hardcoded constants, never derived
from the system clock or any external source.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from core.agent_gateway import evaluate_tool_call
from core.agent_identity_policy import evaluate_agent_tool_call
from core.decision_binding import create_decision_binding, verify_decision_binding
from core.mutation_freeze import evaluate_mutation_freeze

INVENTORY_VERSION = "1"
EVALUATION_VERSION = "1"

_ASSET_TYPES = frozenset({
    "gateway_tool",
    "identity_agent",
    "claude_subagent",
    "claude_command",
    "claude_skill",
    "mcp_server",
})

_CASE_TYPES = frozenset({
    "unregistered_asset",
    "identity_privilege_bypass",
    "mutation_policy_bypass",
    "emergency_freeze_bypass",
    "decision_binding_substitution",
})

# ---------------------------------------------------------------------------
# Fixed, internally-used reference values. Never read from the system
# clock, an environment variable, or any external source -- these are
# plain hardcoded constants, exactly like a test file's own fixed
# literals, used only to supply the underlying Block 8/9/10/Mutation-
# Freeze functions with valid, deterministic input.
# ---------------------------------------------------------------------------

_REFERENCE_TIMESTAMP = "2026-01-01T00:00:00Z"
_REFERENCE_ISSUED_AT = "2026-01-01T00:00:00Z"
_REFERENCE_EXPIRES_AT = "2026-01-01T00:05:00Z"
_REFERENCE_VERIFY_AT = "2026-01-01T00:02:00Z"
_REFERENCE_APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_REFERENCE_APPROVAL_ID_SUBSTITUTED = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


class AIAssetRegistryError(ValueError):
    """Raised when a supplied inventory-lookup or evaluation-case input
    is structurally invalid.

    This is only raised for malformed input: a non-string/blank
    `asset_id`, an `asset_type` filter that is not `None` or one of the
    six recognized asset types, or a `case_type` that is not one of the
    five recognized evaluation case types.

    It is never raised because an asset is unregistered, because an
    evaluation case does not apply to the supplied asset, or because an
    evaluation observes a security property failing to hold -- every
    one of those is a fully valid input this module represents through
    a normal result, not an exception.
    """


# ---------------------------------------------------------------------------
# Static, immutable asset inventory. Every name below was read directly
# from the current repository (core/agent_gateway.py, core/agent_identity
# _policy.py, .claude/agents/, .claude/commands/, .claude/skills/,
# .mcp.example.json) -- never invented, never scanned at import/runtime.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _AssetEntry:
    asset_id: str
    asset_type: str
    name: str
    declared_in: str
    enabled: bool | None
    provenance_detail: str


_GATEWAY_TOOL_NAMES: tuple[tuple[str, bool], ...] = (
    ("load_risk_aware_approval_record", True),
    ("load_investigation_approval_context", True),
    ("apply_approval_consumption", True),
    ("load_approval_record", False),
    ("apply_migration", True),
    ("execute_sql", True),
    ("run_evtx_analysis", True),
    ("run_bug_bounty_assessment", True),
)

_IDENTITY_AGENT_NAMES: tuple[tuple[str, bool], ...] = (
    ("observer_agent", True),
    ("analyst_agent", True),
    ("coordinator_agent", True),
    ("reviewer_agent", True),
    ("disabled_agent", False),
    ("bug_bounty_agent", True),
)

_CLAUDE_SUBAGENT_NAMES: tuple[str, ...] = ("purple-team", "atomic-mapper", "bug-bounty")

_CLAUDE_COMMAND_NAMES: tuple[str, ...] = (
    "red-team",
    "blue-team",
    "threat-hunt",
    "open-case",
    "query",
    "case-summary",
    "ingest-ti",
    "prepare-hayabusa-evidence",
    "add-evidence",
    "decision-review",
    "update-case",
    "triage-case",
    "purple-loop",
    "request-case-update",
    "review-approval",
    "apply-case-update",
    "simulate-case-update",
    "evaluate-tool-call",
    "evaluate-agent-tool-call",
    "create-decision-binding",
    "ai-security-lab",
    "record-analyst-feedback",
    "audit-dashboard",
    "integration-demo",
    "bug-bounty",
    "prioritize-finding",
    "security-handoff",
)

_CLAUDE_SKILL_NAMES: tuple[str, ...] = ("detection-engineering",)

_MCP_SERVER_NAMES: tuple[str, ...] = ("supabase", "hayabusa")


def _build_entries() -> tuple[_AssetEntry, ...]:
    entries: list[_AssetEntry] = []

    for name, enabled in _GATEWAY_TOOL_NAMES:
        entries.append(_AssetEntry(
            asset_id=f"gateway_tool:{name}",
            asset_type="gateway_tool",
            name=name,
            declared_in="core/agent_gateway.py::_REGISTRY",
            enabled=enabled,
            provenance_detail="Declared as a fixed entry in Block 8's tool registry.",
        ))

    for name, enabled in _IDENTITY_AGENT_NAMES:
        entries.append(_AssetEntry(
            asset_id=f"identity_agent:{name}",
            asset_type="identity_agent",
            name=name,
            declared_in="core/agent_identity_policy.py::_REGISTRY",
            enabled=enabled,
            provenance_detail="Declared as a fixed entry in Block 9's agent registry.",
        ))

    for name in _CLAUDE_SUBAGENT_NAMES:
        entries.append(_AssetEntry(
            asset_id=f"claude_subagent:{name}",
            asset_type="claude_subagent",
            name=name,
            declared_in=f".claude/agents/{name}.md",
            enabled=None,
            provenance_detail="Declared as a Claude Code subagent definition file.",
        ))

    for name in _CLAUDE_COMMAND_NAMES:
        entries.append(_AssetEntry(
            asset_id=f"claude_command:{name}",
            asset_type="claude_command",
            name=name,
            declared_in=f".claude/commands/{name}.md",
            enabled=None,
            provenance_detail="Declared as a Claude Code slash-command definition file.",
        ))

    for name in _CLAUDE_SKILL_NAMES:
        entries.append(_AssetEntry(
            asset_id=f"claude_skill:{name}",
            asset_type="claude_skill",
            name=name,
            declared_in=f".claude/skills/{name}/SKILL.md",
            enabled=None,
            provenance_detail="Declared as a Claude Code skill definition file.",
        ))

    for name in _MCP_SERVER_NAMES:
        entries.append(_AssetEntry(
            asset_id=f"mcp_server:{name}",
            asset_type="mcp_server",
            name=name,
            declared_in=".mcp.example.json",
            enabled=None,
            provenance_detail=(
                "Declared as an MCP server entry in the example MCP configuration "
                "(.mcp.example.json); the real .mcp.json is never read by this module."
            ),
        ))

    return tuple(entries)


_ASSET_ENTRIES: tuple[_AssetEntry, ...] = _build_entries()
_REGISTRY: Mapping[str, _AssetEntry] = MappingProxyType({entry.asset_id: entry for entry in _ASSET_ENTRIES})


# ---------------------------------------------------------------------------
# Narrow, private input validators.
# ---------------------------------------------------------------------------


def _validate_asset_id(value: Any) -> str:
    if not isinstance(value, str):
        raise AIAssetRegistryError("asset_id must be a string")
    stripped = value.strip()
    if not stripped:
        raise AIAssetRegistryError("asset_id must not be blank")
    return stripped


def _validate_asset_type_filter(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in _ASSET_TYPES:
        raise AIAssetRegistryError("asset_type must be one of the recognized asset types, or null")
    return value


def _validate_case_type(value: Any) -> str:
    if not isinstance(value, str) or value not in _CASE_TYPES:
        raise AIAssetRegistryError("case_type must be one of the recognized evaluation case types")
    return value


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def _asset_result(entry: _AssetEntry) -> dict[str, Any]:
    return {
        "inventory_version": INVENTORY_VERSION,
        "asset_id": entry.asset_id,
        "asset_type": entry.asset_type,
        "found": True,
        "name": entry.name,
        "enabled": entry.enabled,
        "declared_in": entry.declared_in,
        "provenance": {"tier": "repository_declared", "detail": entry.provenance_detail},
    }


def lookup_ai_asset(*, asset_id: Any) -> dict[str, Any]:
    """Deterministically look up one AI asset by its stable
    `<asset_type>:<canonical_name>` identifier in the fixed, in-code
    inventory registry.

    `asset_id` is required and keyword-only, and must be a non-blank
    string; any other type or a blank string raises
    `AIAssetRegistryError`. A well-formed `asset_id` that is not
    registered is never an error -- it is a normal result with
    `found: False` and every other metadata field `None`.

    Returns a new dict containing exactly `inventory_version`,
    `asset_id`, `asset_type`, `found`, `name`, `enabled`, `declared_in`,
    `provenance`. No field is ever fabricated: `provenance`, when
    present, always has `tier: "repository_declared"`, never
    `"verified"` or `"authenticated"`.
    """
    validated_asset_id = _validate_asset_id(asset_id)
    entry = _REGISTRY.get(validated_asset_id)
    if entry is None:
        return {
            "inventory_version": INVENTORY_VERSION,
            "asset_id": validated_asset_id,
            "asset_type": None,
            "found": False,
            "name": None,
            "enabled": None,
            "declared_in": None,
            "provenance": None,
        }
    return _asset_result(entry)


def list_ai_assets(*, asset_type: Any = None) -> dict[str, Any]:
    """Deterministically list every AI asset in the fixed, in-code
    inventory registry, optionally filtered to exactly one asset type.

    `asset_type` is optional and keyword-only; when supplied it must be
    one of the six recognized asset types, else `AIAssetRegistryError`
    is raised. `None` (the default) returns every registered asset.

    Returns a new dict containing `inventory_version`, the requested
    `asset_type` filter (or `None`), `count`, and `assets` -- a list of
    the same per-asset shape `lookup_ai_asset` returns for a found
    asset, sorted deterministically by `asset_id`. No mutable reference
    to any internal registry object is ever returned -- every asset
    entry in the list is a newly constructed dict.
    """
    validated_asset_type = _validate_asset_type_filter(asset_type)
    matching_entries = [
        entry for entry in _ASSET_ENTRIES
        if validated_asset_type is None or entry.asset_type == validated_asset_type
    ]
    sorted_entries = sorted(matching_entries, key=lambda entry: entry.asset_id)
    return {
        "inventory_version": INVENTORY_VERSION,
        "asset_type": validated_asset_type,
        "count": len(sorted_entries),
        "assets": [_asset_result(entry) for entry in sorted_entries],
    }


# ---------------------------------------------------------------------------
# Evaluation lab
# ---------------------------------------------------------------------------

_EXPECTED_PROPERTY_BY_CASE_TYPE: Mapping[str, str] = MappingProxyType({
    "unregistered_asset": (
        "An unregistered tool or agent identifier is rejected by the existing production "
        "control for that domain."
    ),
    "identity_privilege_bypass": (
        "A known low-privilege registered agent is denied a tool outside its own "
        "least-privilege allowlist."
    ),
    "mutation_policy_bypass": (
        "A mutation-capable tool never resolves to a direct allow when existing policy "
        "requires approval or denial."
    ),
    "emergency_freeze_bypass": (
        "An eligible mutation-capable request is narrowed to deny while the emergency "
        "mutation freeze is active."
    ),
    "decision_binding_substitution": (
        "Decision Binding verification detects a substituted argument through an argument-"
        "digest mismatch."
    ),
})


def _evidence(code: str, severity: str, message: str) -> dict[str, Any]:
    return {"code": code, "severity": severity, "message": message}


def _not_applicable(message: str) -> tuple[str, None, list[dict[str, Any]]]:
    return "not_applicable", None, [_evidence("CASE_NOT_APPLICABLE", "informational", message)]


def _asset_not_registered() -> tuple[str, None, list[dict[str, Any]]]:
    return "not_applicable", None, [_evidence(
        "ASSET_NOT_REGISTERED",
        "informational",
        "The supplied asset_id is not a registered inventory asset; this case type requires a registered asset.",
    )]


def _evaluate_unregistered_asset(asset_id: str, asset_found: bool) -> tuple[str, str | None, list[dict[str, Any]]]:
    if asset_found:
        return _not_applicable(
            "The supplied asset_id is already a registered inventory asset; this case evaluates "
            "rejection of an unregistered identifier instead."
        )

    domain, separator, name_part = asset_id.partition(":")
    name_part = name_part.strip()

    if separator != ":" or not name_part:
        return _not_applicable(
            "The supplied asset_id does not identify a production-policy domain with a "
            "corresponding rejection mechanism."
        )

    if domain == "gateway_tool":
        result = evaluate_tool_call(tool_name=name_part, arguments={}, evaluated_at=_REFERENCE_TIMESTAMP)
        observed_decision = result["decision"]
        outcome = "pass" if observed_decision == "deny" else "fail"
        return outcome, observed_decision, list(result["matched_rules"])

    if domain == "identity_agent":
        result = evaluate_agent_tool_call(
            agent_id=name_part,
            tool_name="load_investigation_approval_context",
            arguments={},
            evaluated_at=_REFERENCE_TIMESTAMP,
        )
        observed_decision = result["final_decision"]
        outcome = "pass" if observed_decision == "deny" else "fail"
        return outcome, observed_decision, list(result["matched_identity_rules"])

    return _not_applicable(
        "The supplied asset_id's domain has no corresponding production-policy rejection "
        "mechanism in this MVP."
    )


def _evaluate_identity_privilege_bypass(asset_id: str) -> tuple[str, str | None, list[dict[str, Any]]]:
    if asset_id != "identity_agent:observer_agent":
        return _not_applicable(
            "identity_privilege_bypass currently evaluates only identity_agent:observer_agent's "
            "documented allowlist-denial scenario (see docs/block9-agent-identity.md)."
        )

    result = evaluate_agent_tool_call(
        agent_id="observer_agent",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": _REFERENCE_APPROVAL_ID},
        evaluated_at=_REFERENCE_TIMESTAMP,
    )
    observed_decision = result["final_decision"]
    outcome = "pass" if observed_decision == "deny" else "fail"
    return outcome, observed_decision, list(result["matched_identity_rules"])


def _evaluate_mutation_policy_bypass(asset_id: str) -> tuple[str, str | None, list[dict[str, Any]]]:
    if asset_id != "gateway_tool:apply_approval_consumption":
        return _not_applicable(
            "mutation_policy_bypass currently evaluates only gateway_tool:apply_approval_"
            "consumption, the registry's one enabled approval-mutation tool."
        )

    result = evaluate_tool_call(
        tool_name="apply_approval_consumption",
        arguments={"approval_id": _REFERENCE_APPROVAL_ID},
        evaluated_at=_REFERENCE_TIMESTAMP,
    )
    observed_decision = result["decision"]
    outcome = "pass" if observed_decision != "allow" else "fail"
    return outcome, observed_decision, list(result["matched_rules"])


def _evaluate_emergency_freeze_bypass(asset_id: str) -> tuple[str, str | None, list[dict[str, Any]]]:
    if asset_id != "identity_agent:coordinator_agent":
        return _not_applicable(
            "emergency_freeze_bypass currently evaluates only identity_agent:coordinator_agent, "
            "the one registered agent whose mutation request reaches require_approval and is "
            "therefore eligible for freeze narrowing."
        )

    identity_result = evaluate_agent_tool_call(
        agent_id="coordinator_agent",
        tool_name="apply_approval_consumption",
        arguments={"approval_id": _REFERENCE_APPROVAL_ID},
        evaluated_at=_REFERENCE_TIMESTAMP,
    )
    frozen_result = evaluate_mutation_freeze(
        identity_policy_result=identity_result,
        control_mode="mutation_freeze",
    )
    observed_decision = frozen_result["final_decision"]
    freeze_codes = [rule["code"] for rule in frozen_result["matched_freeze_rules"]]
    outcome = "pass" if observed_decision == "deny" and "MUTATION_FREEZE_ACTIVE" in freeze_codes else "fail"
    return outcome, observed_decision, list(frozen_result["matched_freeze_rules"])


def _evaluate_decision_binding_substitution(asset_id: str) -> tuple[str, str | None, list[dict[str, Any]]]:
    if asset_id != "identity_agent:coordinator_agent":
        return _not_applicable(
            "decision_binding_substitution currently evaluates only identity_agent:coordinator_"
            "agent, the one registered agent whose mutation request reaches a bindable "
            "(non-deny) decision."
        )

    # The exact arguments actually evaluated by Block 9 are the same exact
    # arguments bound by Block 10 -- consistency with the real evaluated
    # action matters more here than demonstrating nested-object hashing,
    # which core.decision_binding's own dedicated tests already cover.
    # apply_approval_consumption's real Block 8 contract accepts exactly
    # one field, approval_id, so the substitution below changes that one
    # field's value to a second fixed, valid UUID -- never a random one,
    # and never a nested structure this tool's schema does not accept.
    evaluated_arguments = {"approval_id": _REFERENCE_APPROVAL_ID}
    identity_result = evaluate_agent_tool_call(
        agent_id="coordinator_agent",
        tool_name="apply_approval_consumption",
        arguments=evaluated_arguments,
        evaluated_at=_REFERENCE_TIMESTAMP,
    )

    binding = create_decision_binding(
        identity_policy_result=identity_result,
        arguments=evaluated_arguments,
        issued_at=_REFERENCE_ISSUED_AT,
        expires_at=_REFERENCE_EXPIRES_AT,
    )

    substituted_arguments = {"approval_id": _REFERENCE_APPROVAL_ID_SUBSTITUTED}
    verification = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=identity_result,
        arguments=substituted_arguments,
        verification_time=_REFERENCE_VERIFY_AT,
    )

    matched_codes = [rule["code"] for rule in verification["matched_verification_rules"]]
    outcome = "pass" if (
        verification["verification_outcome"] == "invalid" and "ARGUMENT_DIGEST_MISMATCH" in matched_codes
    ) else "fail"
    return outcome, None, list(verification["matched_verification_rules"])


_CASE_HANDLERS = MappingProxyType({
    "identity_privilege_bypass": _evaluate_identity_privilege_bypass,
    "mutation_policy_bypass": _evaluate_mutation_policy_bypass,
    "emergency_freeze_bypass": _evaluate_emergency_freeze_bypass,
    "decision_binding_substitution": _evaluate_decision_binding_substitution,
})


def evaluate_ai_security_case(
    *,
    case_type: Any,
    asset_id: Any,
) -> dict[str, Any]:
    """Deterministically evaluate one defined security-evaluation case
    against one registered AI asset, by calling the existing pure
    Block 8/9/10/Mutation-Freeze functions with real, valid,
    well-formed arguments -- never by reimplementing their policy.

    Both parameters are required and keyword-only. `case_type` must be
    one of the five recognized values (`unregistered_asset`,
    `identity_privilege_bypass`, `mutation_policy_bypass`,
    `emergency_freeze_bypass`, `decision_binding_substitution`);
    `asset_id` must be a non-blank string. Either being malformed
    raises `AIAssetRegistryError`.

    Returns a new dict containing exactly `evaluation_version`,
    `case_type`, `asset_id`, `asset_found`, `evaluation_outcome`
    (`"pass"` / `"fail"` / `"not_applicable"` -- never `allow`/
    `require_approval`/`deny`), `expected_property`, `observed_decision`
    (an observed Block 8/9 policy decision when one was genuinely
    observed, else `None`), `observed_evidence` (a list of `{code,
    severity, message}` items, reusing real rule codes from the
    underlying block wherever one was actually produced), and
    `execution_performed` (always `False`).

    `evaluation_outcome` is `"not_applicable"` whenever the supplied
    asset does not participate meaningfully in the requested case --
    including every asset that is not registered at all (except for
    `unregistered_asset` itself, which is specifically designed to
    accept a well-formed but unregistered `gateway_tool:`/
    `identity_agent:` identifier). This is always a normal result,
    never an exception and never a crash.

    Never executes a tool, calls MCP, calls Supabase, or performs any
    I/O. Never modifies any Block 8/9/10/Mutation-Freeze module or its
    contract.
    """
    validated_case_type = _validate_case_type(case_type)
    validated_asset_id = _validate_asset_id(asset_id)

    lookup = lookup_ai_asset(asset_id=validated_asset_id)
    asset_found = lookup["found"]

    if validated_case_type == "unregistered_asset":
        outcome, observed_decision, evidence = _evaluate_unregistered_asset(validated_asset_id, asset_found)
    elif not asset_found:
        outcome, observed_decision, evidence = _asset_not_registered()
    else:
        outcome, observed_decision, evidence = _CASE_HANDLERS[validated_case_type](validated_asset_id)

    return {
        "evaluation_version": EVALUATION_VERSION,
        "case_type": validated_case_type,
        "asset_id": validated_asset_id,
        "asset_found": asset_found,
        "evaluation_outcome": outcome,
        "expected_property": _EXPECTED_PROPERTY_BY_CASE_TYPE[validated_case_type],
        "observed_decision": observed_decision,
        "observed_evidence": evidence,
        "execution_performed": False,
    }
