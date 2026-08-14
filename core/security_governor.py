"""Pure, deterministic Security Governor (Block 15C.5).

This module answers exactly one question: *given a caller-supplied,
structured description of one observable role/agent action, does it
cross a ThreatTrace policy/workflow boundary, and if so how severely?*

## Observable state only -- never intent or private reasoning

The Governor never inspects free-text reasoning, a chain-of-thought
transcript, or anything resembling "intent." It evaluates only the
fixed, closed-vocabulary `event` fields documented below -- the same
kind of externally/caller-supplied structured state every other module
in this project consumes (compare `core.security_handoff`'s stage
results, `core.mutation_freeze`'s `control_mode`). Every result this
module returns carries `observable_only: True` to make that boundary
explicit in the data itself, not merely in prose.

## What a Governor decision is, and is not

`allow`/`warn`/`require_review`/`block`/`freeze` are **evaluation
outcomes describing a proposed or already-observed action**. They are
never: OS process termination, network isolation, credential
revocation, an execution permit, or proof that any enforcement actually
happened downstream. `freeze` is a deterministic recommendation/state
this module returns -- never a daemon, never something this module
enacts. `execution_performed` is always `False`; this module never
executes a tool, calls MCP, contacts Supabase, or performs any I/O.

## Governor operational stage vs. Security Handoff stage (Block 15G-B.2)

`core.security_governor.STAGES` and `core.security_handoff.STAGES` are
two **deliberately separate** closed vocabularies -- this module never
imports the other's, exactly as documented above. They represent two
different abstractions, and this checkpoint's one new stage,
`"bug_bounty_assessment"`, makes that distinction load-bearing for the
first time:

- A **Security Handoff stage** (`core.security_handoff.STAGES`) is a
  narrower, six-stage *defensive workflow state machine* a finding case
  advances through: threat-intel review, threat hunt, detection
  engineering, Red validation, Purple remediation, human review. It is
  unchanged by this checkpoint and remains exactly those six stages --
  `"bug_bounty_assessment"` is never added there.
- A **Governor operational stage** (`core.security_governor.STAGES`) is
  the broader set of situations the Governor can evaluate an observable
  action against. It is not required to mirror the Handoff's workflow.
  `"bug_bounty_assessment"` is a Governor operational stage the Handoff
  has no equivalent of: bounded, analyst-approved Bug Bounty tool
  execution (`core.bug_bounty_tool_execution`) happens **before** any
  Handoff case necessarily exists -- a Bug Bounty run is often exactly
  what produces the Block 15A finding a Handoff case would later be
  created from. The Governor supervises this pre-Handoff activity using
  its own stage, without pretending the Handoff has such a stage, and
  without forcing Bug Bounty execution to masquerade as `red_validation`
  or any other Handoff-owned stage/role it does not actually belong to.

`"bug_bounty_assessment"` maps to `required_role: "bug_bounty"` in
`REQUIRED_ROLE_BY_STAGE` below -- the same `"bug_bounty"` value `ROLES`
already declared since this module's original checkpoint, but which no
stage previously mapped to. Before this checkpoint, that meant no
honestly-constructed event with `actor_role: "bug_bounty"` could ever
avoid `STAGE_BYPASS_ATTEMPT`/`ROLE_SCOPE_VIOLATION` at *any* stage --
not a deliberate policy (Bug Bounty execution was never meant to be
permanently ungovernable), but a real gap this checkpoint closes. Every
other rule -- gateway/identity denial, mutation freeze, scope expansion,
source-truth protection, the untrusted-remote-content boundary, audit
requirements, Decision Binding, approval requirements, repeated-denial
escalation -- applies to a `bug_bounty_assessment` event exactly as it
does to every other stage. Nothing about Bug Bounty is exempted from any
existing rule; the only thing that changed is that a legitimate stage
now exists for it to be evaluated *under*.

## Remote content and role-generated text are untrusted data

`remote_content_state` describes only a caller-asserted classification
of externally-sourced content. A value of `"adopted_as_instruction"`
means some upstream process *attempted* to let untrusted content steer
a workflow decision -- this module never re-derives that classification
from free text itself, and no string value anywhere in `event` can ever
change a computed decision except through this one closed-vocabulary
field. This mirrors the prompt-injection boundary documented throughout
`core.security_handoff` and the Block 15A Bug Bounty engine.

## No external capabilities

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access; no Supabase/database,
MCP, or LLM/model calls; and imports no other `core.*` module. It keeps
no state between calls -- `evaluate_security_governor_event` is a single
pure computation over its own argument alone.

`SecurityGovernorError` and `evaluate_security_governor_event` are this
module's only public symbols (plus its fixed vocabulary constants).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

GOVERNOR_VERSION = "1"

# ---------------------------------------------------------------------------
# Closed vocabularies.
# ---------------------------------------------------------------------------

ROLES = frozenset({
    "bug_bounty",
    "context_engine",
    "threat_intelligence",
    "threat_hunting",
    "blue_team",
    "red_team",
    "purple_ir",
    "human_analyst",
})

ACTION_CLASSES = frozenset({
    "stage_contribution",
    "approval_decision",
    "execution_request",
    "source_truth_edit",
    "audit_action",
    "content_adoption",
})

# A Governor's own private copy of the Block 15C stage graph -- deliberately
# never imported from core.security_handoff, exactly like every other
# closely-related pair of modules in this project owns its own copy of a
# shared shape rather than sharing one. "bug_bounty_assessment" (Block
# 15G-B.2) is a Governor-only operational stage with no Security Handoff
# equivalent -- see the module docstring's "Governor operational stage
# vs. Security Handoff stage" section.
STAGES = frozenset({
    "threat_intel_review",
    "threat_hunt",
    "detection_engineering",
    "red_validation",
    "purple_remediation",
    "human_review",
    "bug_bounty_assessment",
})

REQUIRED_ROLE_BY_STAGE: Mapping[str, str] = MappingProxyType({
    "threat_intel_review": "threat_intelligence",
    "threat_hunt": "threat_hunting",
    "detection_engineering": "blue_team",
    "bug_bounty_assessment": "bug_bounty",
    "red_validation": "red_team",
    "purple_remediation": "purple_ir",
    "human_review": "human_analyst",
})

GATEWAY_DECISIONS = frozenset({"allow", "require_approval", "deny"})
IDENTITY_DECISIONS = frozenset({"allow", "require_approval", "deny"})
APPROVAL_STATES = frozenset({"not_required", "pending", "approved", "rejected"})
DECISION_BINDING_STATES = frozenset({"not_required", "valid", "invalid", "missing"})
SCOPE_STATES = frozenset({"within_scope", "expansion_attempt"})
SOURCE_TRUTH_STATES = frozenset({"unchanged", "modification_attempted"})
REMOTE_CONTENT_STATES = frozenset({"not_present", "untrusted_data_only", "adopted_as_instruction"})
AUDIT_STATES = frozenset({"recorded", "bypass_attempted"})

# Governor decisions -- exactly five, in fixed ascending severity order.
DECISIONS = ("allow", "warn", "require_review", "block", "freeze")
_SEVERITY = {decision: index for index, decision in enumerate(DECISIONS)}

# Action classes that constitute an actual mutation attempt (as opposed to
# a read-only/observational or advisory action) for freeze-narrowing purposes.
_MUTATING_ACTION_CLASSES = frozenset({"execution_request", "source_truth_edit", "approval_decision"})

_EVENT_REQUIRED_FIELDS = (
    "event_version",
    "actor_role",
    "action_class",
    "current_stage",
    "required_role",
    "gateway_decision",
    "identity_decision",
    "mutation_freeze_active",
    "approval_state",
    "decision_binding_state",
    "scope_state",
    "source_truth_state",
    "remote_content_state",
    "audit_state",
    "prior_policy_denials",
    "execution_requested",
)

# Fixed, closed, twelve-code reason vocabulary, evaluated in this exact
# order. Each code is emitted at most once per call.
REASON_CODES = (
    "TOOL_OR_GATEWAY_DENIED",
    "IDENTITY_POLICY_DENIED",
    "STAGE_BYPASS_ATTEMPT",
    "ROLE_SCOPE_VIOLATION",
    "MUTATION_FREEZE_ACTIVE",
    "SCOPE_EXPANSION_ATTEMPT",
    "SOURCE_TRUTH_MODIFICATION",
    "UNTRUSTED_CONTENT_INSTRUCTION_ATTEMPT",
    "AUDIT_BYPASS_ATTEMPT",
    "DECISION_BINDING_REQUIRED",
    "APPROVAL_REQUIRED",
    "REPEATED_POLICY_DENIAL",
)


class SecurityGovernorError(ValueError):
    """Raised when a supplied `event` is structurally invalid: not a
    mapping, missing a required field, carrying a value outside its
    fixed closed vocabulary, or carrying a `prior_policy_denials` that
    is not a non-negative int.

    Never raised because an event describes a policy violation, a
    freeze-worthy condition, or repeated prior denials -- every one of
    those is a normal, successfully evaluated result represented
    through `decision`/`reason_codes`, not an error condition.
    """


def _raise(detail: str) -> None:
    raise SecurityGovernorError(f"INVALID_EVENT: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _validate_event(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("event must be a mapping")
    if set(value) != set(_EVENT_REQUIRED_FIELDS):
        _raise("event must contain exactly the sixteen required fields")

    if value.get("event_version") != "1":
        _raise("event_version must be '1'")

    if not _in_vocab(value.get("actor_role"), ROLES):
        _raise("actor_role must be a recognized functional role")
    if not _in_vocab(value.get("action_class"), ACTION_CLASSES):
        _raise("action_class must be a recognized value")
    if not _in_vocab(value.get("current_stage"), STAGES):
        _raise("current_stage must be a recognized stage")
    if not _in_vocab(value.get("required_role"), ROLES):
        _raise("required_role must be a recognized functional role")

    if not _in_vocab(value.get("gateway_decision"), GATEWAY_DECISIONS):
        _raise("gateway_decision must be a recognized value")
    if not _in_vocab(value.get("identity_decision"), IDENTITY_DECISIONS):
        _raise("identity_decision must be a recognized value")

    if value.get("mutation_freeze_active") not in (True, False):
        _raise("mutation_freeze_active must be a bool")

    if not _in_vocab(value.get("approval_state"), APPROVAL_STATES):
        _raise("approval_state must be a recognized value")
    if not _in_vocab(value.get("decision_binding_state"), DECISION_BINDING_STATES):
        _raise("decision_binding_state must be a recognized value")
    if not _in_vocab(value.get("scope_state"), SCOPE_STATES):
        _raise("scope_state must be a recognized value")
    if not _in_vocab(value.get("source_truth_state"), SOURCE_TRUTH_STATES):
        _raise("source_truth_state must be a recognized value")
    if not _in_vocab(value.get("remote_content_state"), REMOTE_CONTENT_STATES):
        _raise("remote_content_state must be a recognized value")
    if not _in_vocab(value.get("audit_state"), AUDIT_STATES):
        _raise("audit_state must be a recognized value")

    prior_policy_denials = value.get("prior_policy_denials")
    if isinstance(prior_policy_denials, bool) or not isinstance(prior_policy_denials, int):
        _raise("prior_policy_denials must be an int")
    if prior_policy_denials < 0:
        _raise("prior_policy_denials must be a non-negative int")

    if value.get("execution_requested") not in (True, False):
        _raise("execution_requested must be a bool")

    return {
        "event_version": "1",
        "actor_role": value["actor_role"],
        "action_class": value["action_class"],
        "current_stage": value["current_stage"],
        "required_role": value["required_role"],
        "gateway_decision": value["gateway_decision"],
        "identity_decision": value["identity_decision"],
        "mutation_freeze_active": value["mutation_freeze_active"],
        "approval_state": value["approval_state"],
        "decision_binding_state": value["decision_binding_state"],
        "scope_state": value["scope_state"],
        "source_truth_state": value["source_truth_state"],
        "remote_content_state": value["remote_content_state"],
        "audit_state": value["audit_state"],
        "prior_policy_denials": prior_policy_denials,
        "execution_requested": value["execution_requested"],
    }


# ---------------------------------------------------------------------------
# Deterministic rule evaluation. Each triggered reason code carries a
# "floor" -- the minimum decision severity it independently requires. The
# final decision is the maximum floor across every triggered code (or
# "allow" if none triggered).
# ---------------------------------------------------------------------------


def _evaluate_reasons(event: Mapping[str, Any]) -> tuple[list[str], dict[str, str]]:
    triggered: list[str] = []
    floor_by_code: dict[str, str] = {}

    def _trigger(code: str, floor: str) -> None:
        triggered.append(code)
        floor_by_code[code] = floor

    if event["gateway_decision"] == "deny":
        _trigger("TOOL_OR_GATEWAY_DENIED", "block")

    if event["identity_decision"] == "deny":
        _trigger("IDENTITY_POLICY_DENIED", "block")

    fixed_required_role = REQUIRED_ROLE_BY_STAGE[event["current_stage"]]

    if event["required_role"] != fixed_required_role:
        _trigger("STAGE_BYPASS_ATTEMPT", "block")

    if event["actor_role"] != fixed_required_role:
        _trigger("ROLE_SCOPE_VIOLATION", "block")

    if event["mutation_freeze_active"] is True:
        floor = "block" if event["action_class"] in _MUTATING_ACTION_CLASSES else "warn"
        _trigger("MUTATION_FREEZE_ACTIVE", floor)

    if event["scope_state"] == "expansion_attempt":
        _trigger("SCOPE_EXPANSION_ATTEMPT", "block")

    if event["source_truth_state"] == "modification_attempted" or event["action_class"] == "source_truth_edit":
        _trigger("SOURCE_TRUTH_MODIFICATION", "freeze")

    if event["remote_content_state"] == "adopted_as_instruction":
        _trigger("UNTRUSTED_CONTENT_INSTRUCTION_ATTEMPT", "block")

    if event["audit_state"] == "bypass_attempted":
        _trigger("AUDIT_BYPASS_ATTEMPT", "freeze")

    if event["execution_requested"] is True and event["decision_binding_state"] != "valid":
        _trigger("DECISION_BINDING_REQUIRED", "block")

    approval_needed = (
        (event["execution_requested"] is True and event["approval_state"] != "approved")
        or event["gateway_decision"] == "require_approval"
        or event["identity_decision"] == "require_approval"
    )
    if approval_needed:
        floor = "block" if event["execution_requested"] is True else "require_review"
        _trigger("APPROVAL_REQUIRED", floor)

    prior_policy_denials = event["prior_policy_denials"]
    if prior_policy_denials >= 3 and len(triggered) > 0:
        _trigger("REPEATED_POLICY_DENIAL", "freeze")
    elif prior_policy_denials == 2:
        _trigger("REPEATED_POLICY_DENIAL", "require_review")

    return triggered, floor_by_code


def evaluate_security_governor_event(*, event: Any) -> dict[str, Any]:
    """Deterministically evaluate one caller-supplied, structured
    observable event against ThreatTrace's fixed policy/workflow
    boundaries. Performs no I/O of any kind, executes nothing, and
    inspects only the sixteen fixed `event` fields documented in the
    module docstring -- never any private reasoning or free text.

    `event` is required and keyword-only, and must be a mapping
    containing exactly the sixteen required fields, each drawn from its
    own fixed closed vocabulary (see the module-level `ROLES`,
    `ACTION_CLASSES`, `STAGES`, `GATEWAY_DECISIONS`,
    `IDENTITY_DECISIONS`, `APPROVAL_STATES`, `DECISION_BINDING_STATES`,
    `SCOPE_STATES`, `SOURCE_TRUTH_STATES`, `REMOTE_CONTENT_STATES`,
    `AUDIT_STATES` constants), plus a boolean `mutation_freeze_active`,
    a non-negative int `prior_policy_denials`, and a boolean
    `execution_requested`.

    Returns a new dict containing exactly `governor_version`,
    `decision` (one of `DECISIONS`), `reason_codes` (a fixed-order,
    deduplicated list drawn from `REASON_CODES`), `actor_role`,
    `action_class`, `human_review_required`, `mutation_freeze_recommended`,
    `execution_allowed` (`True` only when `decision == "allow"`),
    `observable_only` (always `True`), `execution_performed` (always
    `False`).

    `event` is never mutated, and no mutable object from it is retained
    by reference in the result.

    Raises `SecurityGovernorError` for a structurally invalid `event`.
    Never raises because the evaluated event represents a policy
    violation, a freeze-worthy condition, or repeated prior denials --
    every one of those is represented through the returned `decision`
    and `reason_codes` instead.
    """
    validated_event = _validate_event(event)

    reason_codes, floor_by_code = _evaluate_reasons(validated_event)

    if reason_codes:
        decision = max(reason_codes, key=lambda code: _SEVERITY[floor_by_code[code]])
        decision = floor_by_code[decision]
    else:
        decision = "allow"

    human_review_required = decision in ("require_review", "block", "freeze")
    mutation_freeze_recommended = decision == "freeze" or (
        validated_event["mutation_freeze_active"] is True
        and decision == "block"
        and "MUTATION_FREEZE_ACTIVE" in reason_codes
    )
    execution_allowed = decision == "allow"

    return {
        "governor_version": GOVERNOR_VERSION,
        "decision": decision,
        "reason_codes": reason_codes,
        "actor_role": validated_event["actor_role"],
        "action_class": validated_event["action_class"],
        "human_review_required": human_review_required,
        "mutation_freeze_recommended": mutation_freeze_recommended,
        "execution_allowed": execution_allowed,
        "observable_only": True,
        "execution_performed": False,
    }
