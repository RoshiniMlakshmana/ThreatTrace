"""Pure, deterministic Emergency Mutation Freeze narrowing layer (Block 11).

This module answers exactly one question: *given an already-produced
Block 9 identity-policy result and an explicit, caller-supplied
administrative control mode, should this otherwise-permitted
mutation-capable request be denied right now?* It never answers whether
a proposed tool call is generally safe (`core.agent_gateway`'s concern)
or whether a specific claimed agent has the least-privilege capability
to make it (`core.agent_identity_policy`'s concern) -- both remain
entirely those modules' own, consumed here strictly as an
already-produced result, never recomputed.

This is a **policy-evaluation-time control only**. It is NOT, and this
module never claims it to be:

- OS process termination;
- cancellation of already-running or already-executed work;
- network isolation or shutdown;
- credential or token revocation;
- agent or caller authentication;
- database-level enforcement;
- cryptographic revocation.

`control_mode` is a **caller-supplied policy input representing claimed
current administrative state** -- it is never proof that the caller
supplying it was authorized to set that state, exactly like a claimed
`agent_id` is never proof of identity anywhere else in this project.

This module does not:

- call `core.agent_gateway.evaluate_tool_call` or
  `core.agent_identity_policy.evaluate_agent_tool_call`, and never
  imports either module;
- classify a tool, look up an agent, evaluate a role, evaluate an
  allowlist, or evaluate a capability -- every one of those remains
  Block 8's and Block 9's own concern;
- independently re-derive `operation_class` -- it is read verbatim from
  the supplied Block 9 result, which itself already copied it verbatim
  from Block 8;
- execute the proposed tool, call MCP, construct SQL, or perform any
  I/O of any kind;
- read the system clock, an environment variable, or the filesystem;
- generate a random value of any kind;
- retain any state between calls -- `evaluate_mutation_freeze` is a
  single pure computation over its own arguments alone, and has no
  memory of a previous call.

`evaluate_mutation_freeze` may only **preserve or narrow** the supplied
Block 9 `final_decision` -- it can never widen `deny` to
`require_approval` or `allow`, and can never widen `require_approval` to
`allow`. When `control_mode` is `"normal"`, the result preserves every
existing Block 9 field unchanged (aside from the new, always-present
`matched_freeze_rules` field). `identity_authenticated` and
`execution_performed` are always `False` in every result this module can
ever produce.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

MUTATION_FREEZE_VERSION = "1"

_FINAL_DECISIONS = frozenset({"allow", "require_approval", "deny"})

_OPERATION_CLASSES = frozenset({
    "read_only",
    "state_mutation",
    "approval_mutation",
    "schema_mutation",
    "external_side_effect",
    "prohibited",
})

# Only these two operation classes are ever narrowed by an active freeze.
# schema_mutation, external_side_effect, and prohibited are already
# unconditionally denied by Block 8's own fixed policy -- an active freeze
# never claims credit for a denial it did not cause. read_only is never
# narrowed by design: the freeze targets mutation-capable requests only.
_FREEZE_NARROWED_OPERATION_CLASSES = frozenset({"state_mutation", "approval_mutation"})

_CONTROL_MODES = frozenset({"normal", "mutation_freeze"})

_REQUIRED_NEXT_ACTION_BY_DECISION = MappingProxyType({
    "allow": "proceed_to_separate_execution_boundary",
    "require_approval": "submit_to_approval_workflow",
    "deny": "do_not_execute",
})

# ---------------------------------------------------------------------------
# The exact fifteen fields `core.agent_identity_policy.evaluate_agent_tool_call`
# always returns. This module never reimplements Block 9 policy -- it only
# confirms the supplied mapping has this shape before reading the two fields
# (`final_decision`, `operation_class`) its own narrowing decision needs.
# ---------------------------------------------------------------------------

_REQUIRED_IDENTITY_RESULT_FIELDS = (
    "identity_policy_version",
    "canonical_agent_id",
    "agent_role",
    "identity_authenticated",
    "canonical_tool_name",
    "operation_class",
    "gateway_decision",
    "final_decision",
    "eligible_for_execution",
    "requires_approval",
    "matched_identity_rules",
    "safe_capability_summary",
    "required_next_action",
    "evaluated_at",
    "execution_performed",
)

_NULLABLE_STRING_FIELDS = (
    "canonical_agent_id",
    "agent_role",
    "canonical_tool_name",
    "gateway_decision",
)

# ---------------------------------------------------------------------------
# Fixed, closed, single-code freeze-rule vocabulary. Emitted only when the
# freeze actually narrows a decision -- never merely because control_mode is
# "mutation_freeze", and never for a class the freeze had no effect on.
# ---------------------------------------------------------------------------

_MUTATION_FREEZE_ACTIVE_RULE = MappingProxyType({
    "code": "MUTATION_FREEZE_ACTIVE",
    "severity": "blocking",
    "message": (
        "This request's operation class is mutation-capable, and an active emergency mutation "
        "freeze denies it regardless of the otherwise-applicable Block 8/9 decision."
    ),
    "affects_decision": True,
})


class MutationFreezeError(ValueError):
    """Raised when a supplied mutation-freeze-evaluation input is
    structurally invalid.

    This is only raised for malformed input: a non-mapping
    `identity_policy_result`, one missing a required Block 9 result
    field, one whose `final_decision` or `operation_class` is not a
    recognized value, or a `control_mode` that is not exactly
    `"normal"` or `"mutation_freeze"`.

    It is never raised because a freeze is currently active, or because
    an active freeze narrows a decision to `deny` -- every one of those
    is a fully valid input this module represents through a normal
    result, not an exception.
    """


def _validate_identity_policy_result(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise MutationFreezeError("identity_policy_result must be a mapping")

    for field in _REQUIRED_IDENTITY_RESULT_FIELDS:
        if field not in value:
            raise MutationFreezeError(f"identity_policy_result is missing required field: {field!r}")

    final_decision = value["final_decision"]
    if not isinstance(final_decision, str) or final_decision not in _FINAL_DECISIONS:
        raise MutationFreezeError("identity_policy_result['final_decision'] is not a recognized decision value")

    operation_class = value["operation_class"]
    if operation_class is not None and operation_class not in _OPERATION_CLASSES:
        raise MutationFreezeError("identity_policy_result['operation_class'] is not a recognized operation class")

    for field in _NULLABLE_STRING_FIELDS:
        field_value = value[field]
        if field_value is not None and not isinstance(field_value, str):
            raise MutationFreezeError(f"identity_policy_result[{field!r}] must be a string or null")

    if value["identity_authenticated"] is not False:
        raise MutationFreezeError("identity_policy_result['identity_authenticated'] must be false")
    if value["execution_performed"] is not False:
        raise MutationFreezeError("identity_policy_result['execution_performed'] must be false")

    if not isinstance(value["matched_identity_rules"], list):
        raise MutationFreezeError("identity_policy_result['matched_identity_rules'] must be a list")
    if not isinstance(value["safe_capability_summary"], Mapping):
        raise MutationFreezeError("identity_policy_result['safe_capability_summary'] must be a mapping")


def _validate_control_mode(value: Any) -> str:
    if not isinstance(value, str) or value not in _CONTROL_MODES:
        raise MutationFreezeError("control_mode must be exactly 'normal' or 'mutation_freeze'")
    return value


def evaluate_mutation_freeze(
    *,
    identity_policy_result: Any,
    control_mode: Any,
) -> dict[str, Any]:
    """Deterministically narrow one already-produced Block 9
    identity-policy result according to an explicit, caller-supplied
    emergency mutation-freeze control mode, without ever executing
    anything or re-evaluating Block 8/9 policy.

    Both parameters are required and keyword-only, and neither has a
    hidden default. `identity_policy_result` must be a mapping shaped
    like `core.agent_identity_policy.evaluate_agent_tool_call`'s own
    return value; this function never calls that function itself, never
    looks up an agent, and never reclassifies a tool -- every field is
    read verbatim from it and, except for the decision-derived fields
    described below, returned unchanged. `control_mode` must be exactly
    `"normal"` or `"mutation_freeze"`; it is never inferred, defaulted,
    case-folded, trimmed-and-reinterpreted, or read from an environment
    variable, file, or database -- the caller alone supplies it, and it
    represents only a *claimed* current administrative state, never
    proof that the caller was authorized to set it.

    Returns a new dict containing every field
    `evaluate_agent_tool_call` returns, plus one additional field,
    `matched_freeze_rules`: `identity_policy_version`,
    `canonical_agent_id`, `agent_role`, `identity_authenticated`
    (always `False`), `canonical_tool_name`, `operation_class`,
    `gateway_decision`, `final_decision`, `eligible_for_execution`,
    `requires_approval`, `matched_identity_rules`,
    `safe_capability_summary`, `required_next_action`, `evaluated_at`,
    `execution_performed` (always `False`), `matched_freeze_rules`.
    `gateway_decision` is always preserved unchanged -- this function
    narrows only the effective final decision, never Block 8's own
    decision. `matched_identity_rules` and `safe_capability_summary` are
    always preserved unchanged (freshly copied, never the caller's own
    objects) -- a freeze rule is never appended to `matched_identity_rules`,
    which remains exclusively Block 9's own identity-policy reasoning.

    When `control_mode` is `"normal"`, every field is preserved exactly
    as supplied and `matched_freeze_rules` is always `[]`.

    When `control_mode` is `"mutation_freeze"`: a `final_decision` of
    `"require_approval"` or `"allow"` on a `state_mutation` or
    `approval_mutation` `operation_class` is narrowed to `"deny"`, with
    `eligible_for_execution`, `requires_approval`, and
    `required_next_action` recomputed to match, and
    `matched_freeze_rules` containing exactly one `MUTATION_FREEZE_ACTIVE`
    entry. Every other case is left unchanged and `matched_freeze_rules`
    is `[]` -- in particular, `read_only` is never narrowed, an already-
    `deny` result is never rewritten, and `schema_mutation`/
    `external_side_effect`/`prohibited` are never claimed as freeze-caused
    denials, since Block 8 already denies them unconditionally regardless
    of the freeze.

    This function is strictly narrowing: it can never turn `deny` into
    `require_approval` or `allow`, and can never turn `require_approval`
    into `allow`.

    Neither `identity_policy_result` (nor any nested list/mapping within
    it) is ever mutated, and no mutable object from it is retained by
    reference in the result -- the returned mapping and every nested
    list/mapping within it are newly constructed.

    Raises `MutationFreezeError` for any structurally invalid input.
    Never raises because a freeze is active or because it narrows a
    decision to `deny` -- that is represented in the returned result
    through `final_decision` and `matched_freeze_rules` instead.
    """
    _validate_identity_policy_result(identity_policy_result)
    validated_control_mode = _validate_control_mode(control_mode)

    final_decision = identity_policy_result["final_decision"]
    operation_class = identity_policy_result["operation_class"]

    narrows = (
        validated_control_mode == "mutation_freeze"
        and operation_class in _FREEZE_NARROWED_OPERATION_CLASSES
        and final_decision != "deny"
    )

    matched_freeze_rules: list[dict[str, Any]] = []
    if narrows:
        new_final_decision = "deny"
        matched_freeze_rules.append(dict(_MUTATION_FREEZE_ACTIVE_RULE))
    else:
        new_final_decision = final_decision

    return {
        "identity_policy_version": identity_policy_result["identity_policy_version"],
        "canonical_agent_id": identity_policy_result["canonical_agent_id"],
        "agent_role": identity_policy_result["agent_role"],
        "identity_authenticated": False,
        "canonical_tool_name": identity_policy_result["canonical_tool_name"],
        "operation_class": operation_class,
        "gateway_decision": identity_policy_result["gateway_decision"],
        "final_decision": new_final_decision,
        "eligible_for_execution": new_final_decision == "allow",
        "requires_approval": new_final_decision == "require_approval",
        "matched_identity_rules": copy.deepcopy(identity_policy_result["matched_identity_rules"]),
        "safe_capability_summary": copy.deepcopy(identity_policy_result["safe_capability_summary"]),
        "required_next_action": _REQUIRED_NEXT_ACTION_BY_DECISION[new_final_decision],
        "evaluated_at": identity_policy_result["evaluated_at"],
        "execution_performed": False,
        "matched_freeze_rules": matched_freeze_rules,
    }
