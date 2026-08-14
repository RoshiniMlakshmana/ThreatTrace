"""Pure, deterministic LLM-generated Bug Bounty test-plan validator
(Block 15G-A, checkpoint 2 of 2).

This module answers exactly one question: *given an LLM-proposed,
already-structured Bug Bounty test plan and an analyst's own permission
contract, which of the plan's proposed steps are actually permitted,
and which are blocked, awaiting review, or waiting on an adapter that
does not exist yet?*

## This module never calls an LLM, and never plans anything itself

`validate_bug_bounty_plan` is a pure validator/normalizer only. The
actual reasoning -- what the target appears to be, which analyst-
approved tools are relevant, what order to run them in, when existing
evidence is already sufficient -- is entirely `.claude/agents/
bug-bounty-planner.md`'s job, a Claude custom agent this module never
invokes and has no dependency on. This module only checks whether the
LLM's own proposal is structurally well-formed and, for every step,
what `core.bug_bounty_tool_policy.evaluate_tool_permission` (the real,
unmodified deterministic policy -- never reimplemented here) says about
it.

## The LLM proposes; deterministic policy decides

Every step's `policy_status` (`"PERMITTED"`/`"REVIEW_REQUIRED"`/
`"BLOCKED"`/`"ADAPTER_UNAVAILABLE"`) is derived exclusively from a real
call to `core.bug_bounty_tool_policy.evaluate_tool_permission` -- this
module never grants, denies, or second-guesses that decision, and never
promotes a step past what the policy result actually says. A plan that
proposes five redundant tool calls is validated exactly as proposed --
this module never deduplicates, reorders, or drops a step to "improve"
the LLM's plan; it only reports each step's real policy outcome
honestly, so redundancy (or the lack of analyst permission for it)
stays visible rather than silently hidden.

## Remote-derived target observations are untrusted evidence, never
## instructions

Every field on `target_profile` (`observed_technologies`, `known_paths`,
`previous_findings`, and so on) is treated as inert, caller-supplied
observational data -- exactly like a Bug Bounty finding's own
`observation` text is treated elsewhere in this project. This module
never parses any of it as an instruction, never lets its content change
scope/tools/profile/approval, and never infers authorization from it.
Only the analyst's own structured `permissions` object (validated by
`core.bug_bounty_tool_policy`) ever grants anything.

## No raw command surface

There is no field anywhere in the plan/step/tool-request contract this
module accepts for a shell command, a raw command, a terminal command,
or arbitrary arguments -- `core.bug_bounty_tool_policy`'s own
tool-request contract (reused here unmodified) already excludes them
structurally, and this module adds no field of its own that could
reintroduce one.

## No execution, ever

This module executes nothing -- not even the one currently-implemented
`http_assessor` adapter. `execution_performed` is always `False` in
every result it can ever produce. It performs no network, filesystem,
environment-variable, subprocess, system-clock, or randomness access.

`BugBountyPlannerError` and `validate_bug_bounty_plan` are this
module's two primary public symbols (plus its fixed vocabulary
constants).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from core.bug_bounty_tool_policy import BugBountyToolPolicyError, evaluate_tool_permission

PLAN_VALIDATION_VERSION = "1"
PLAN_VERSION = "1"

EXPECTED_EVIDENCE_CATEGORIES = frozenset({
    "host_exposure",
    "service",
    "web_configuration",
    "known_pattern_match",
    "dast_observation",
    "authenticated_observation",
    "controlled_validation_evidence",
})

POLICY_STATUSES = ("PERMITTED", "REVIEW_REQUIRED", "BLOCKED", "ADAPTER_UNAVAILABLE")

_TARGET_PROFILE_REQUIRED_FIELDS = (
    "target_type",
    "observed_ports",
    "observed_protocols",
    "observed_technologies",
    "authentication_present",
    "known_paths",
    "previous_findings",
)

_STEP_REQUIRED_FIELDS = (
    "step_id",
    "sequence",
    "tool_request",
    "rationale",
    "depends_on",
    "expected_evidence",
    "stop_if_sufficient_evidence",
)

_PLAN_REQUIRED_FIELDS = (
    "plan_version",
    "plan_id",
    "target_profile",
    "planning_goal",
    "steps",
    "stop_conditions",
)


class BugBountyPlannerError(ValueError):
    """Raised when a supplied `plan` is structurally invalid, including
    a malformed nested `tool_request`/`permissions` (wrapping the real
    `core.bug_bounty_tool_policy.BugBountyToolPolicyError` this module
    never hides).

    Every message begins with one of a fixed set of stable codes:
    `INVALID_PLAN`, `INVALID_TARGET_PROFILE`, `INVALID_STEP`,
    `DUPLICATE_STEP_ID`, `INVALID_SEQUENCE`, `INVALID_DEPENDS_ON`,
    `INVALID_EXPECTED_EVIDENCE`, `INVALID_TOOL_REQUEST_OR_PERMISSIONS`.

    Never raised because a step's `policy_status` is
    `"BLOCKED"`/`"REVIEW_REQUIRED"`/`"ADAPTER_UNAVAILABLE"`, or because
    a plan proposes a redundant or ultimately-denied step -- every one
    of those is a normal, successfully validated result, not an error
    condition.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyPlannerError(f"{code}: {detail}")


def _require_nonblank_string(value: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be a non-blank string")
    return value


def _require_bool(value: Any, code: str, field_name: str) -> bool:
    if value is not True and value is not False:
        _raise(code, f"{field_name!r} must be a bool")
    return value


def _require_string_list(value: Any, code: str, field_name: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list):
        _raise(code, f"{field_name!r} must be a list")
    if not allow_empty and len(value) == 0:
        _raise(code, f"{field_name!r} must be a non-empty list")
    return [_require_nonblank_string(item, code, f"{field_name} entry") for item in value]


# ---------------------------------------------------------------------------
# target_profile validation -- every field here is untrusted,
# caller-supplied observational evidence, never an instruction.
# ---------------------------------------------------------------------------


def _validate_target_profile(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_TARGET_PROFILE_REQUIRED_FIELDS):
        _raise("INVALID_TARGET_PROFILE", "target_profile must contain exactly the seven required fields")

    target_type = _require_nonblank_string(value.get("target_type"), "INVALID_TARGET_PROFILE", "target_type")

    raw_ports = value.get("observed_ports")
    if not isinstance(raw_ports, list):
        _raise("INVALID_TARGET_PROFILE", "observed_ports must be a list")
    observed_ports: list[int] = []
    for item in raw_ports:
        if isinstance(item, bool) or not isinstance(item, int) or item < 1 or item > 65535:
            _raise("INVALID_TARGET_PROFILE", "observed_ports entries must be ints between 1 and 65535")
        observed_ports.append(item)

    observed_protocols = _require_string_list(value.get("observed_protocols"), "INVALID_TARGET_PROFILE", "observed_protocols")
    observed_technologies = _require_string_list(
        value.get("observed_technologies"), "INVALID_TARGET_PROFILE", "observed_technologies",
    )

    authentication_present = _require_bool(
        value.get("authentication_present"), "INVALID_TARGET_PROFILE", "authentication_present",
    )

    raw_known_paths = value.get("known_paths")
    if not isinstance(raw_known_paths, list):
        _raise("INVALID_TARGET_PROFILE", "known_paths must be a list")
    known_paths: list[str] = []
    for item in raw_known_paths:
        path = _require_nonblank_string(item, "INVALID_TARGET_PROFILE", "known_paths entry")
        if not path.startswith("/"):
            _raise("INVALID_TARGET_PROFILE", "known_paths entries must begin with '/'")
        known_paths.append(path)

    previous_findings = _require_string_list(value.get("previous_findings"), "INVALID_TARGET_PROFILE", "previous_findings")

    return {
        "target_type": target_type,
        "observed_ports": observed_ports,
        "observed_protocols": observed_protocols,
        "observed_technologies": observed_technologies,
        "authentication_present": authentication_present,
        "known_paths": known_paths,
        "previous_findings": previous_findings,
    }


# ---------------------------------------------------------------------------
# Step validation + real policy evaluation.
# ---------------------------------------------------------------------------


def _derive_policy_status(permission_result: Mapping[str, Any]) -> str:
    if permission_result["execution_permitted"]:
        return "PERMITTED"
    codes = set(permission_result["reason_codes"])
    if "ADAPTER_UNAVAILABLE" in codes:
        return "ADAPTER_UNAVAILABLE"
    if codes == {"HUMAN_APPROVAL_REQUIRED"}:
        return "REVIEW_REQUIRED"
    return "BLOCKED"


def _validate_step(
    value: Any, *, expected_sequence: int, known_step_ids: set[str], permissions: Any,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_STEP_REQUIRED_FIELDS):
        _raise("INVALID_STEP", "each step must contain exactly the seven required fields")

    step_id = _require_nonblank_string(value.get("step_id"), "INVALID_STEP", "step_id")
    if step_id in known_step_ids:
        _raise("DUPLICATE_STEP_ID", f"duplicate step_id: {step_id!r}")

    sequence = value.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        _raise("INVALID_SEQUENCE", "sequence must be an int")
    if sequence != expected_sequence:
        _raise("INVALID_SEQUENCE", "steps must be sequenced 1..N with no gaps, matching list order")

    rationale = _require_nonblank_string(value.get("rationale"), "INVALID_STEP", "rationale")

    raw_depends_on = value.get("depends_on")
    if not isinstance(raw_depends_on, list):
        _raise("INVALID_DEPENDS_ON", "depends_on must be a list")
    depends_on: list[str] = []
    seen_deps: set[str] = set()
    for item in raw_depends_on:
        dep = _require_nonblank_string(item, "INVALID_DEPENDS_ON", "depends_on entry")
        if dep == step_id:
            _raise("INVALID_DEPENDS_ON", "a step must not depend on itself")
        if dep not in known_step_ids:
            _raise("INVALID_DEPENDS_ON", f"depends_on references an unknown or later step: {dep!r}")
        if dep in seen_deps:
            _raise("INVALID_DEPENDS_ON", "depends_on must not contain duplicates")
        seen_deps.add(dep)
        depends_on.append(dep)

    raw_evidence = value.get("expected_evidence")
    if not isinstance(raw_evidence, list) or len(raw_evidence) == 0:
        _raise("INVALID_EXPECTED_EVIDENCE", "expected_evidence must be a non-empty list")
    expected_evidence: list[str] = []
    seen_evidence: set[str] = set()
    for item in raw_evidence:
        if item not in EXPECTED_EVIDENCE_CATEGORIES:
            _raise("INVALID_EXPECTED_EVIDENCE", "expected_evidence entries must be recognized categories")
        if item in seen_evidence:
            _raise("INVALID_EXPECTED_EVIDENCE", "expected_evidence must not contain duplicates")
        seen_evidence.add(item)
        expected_evidence.append(item)

    stop_if_sufficient_evidence = _require_bool(
        value.get("stop_if_sufficient_evidence"), "INVALID_STEP", "stop_if_sufficient_evidence",
    )

    try:
        permission_result = evaluate_tool_permission(permissions=permissions, tool_request=value.get("tool_request"))
    except BugBountyToolPolicyError as exc:
        _raise("INVALID_TOOL_REQUEST_OR_PERMISSIONS", str(exc))

    policy_status = _derive_policy_status(permission_result)

    return {
        "step_id": step_id,
        "sequence": sequence,
        "tool_id": permission_result["tool_id"],
        "rationale": rationale,
        "depends_on": depends_on,
        "expected_evidence": expected_evidence,
        "stop_if_sufficient_evidence": stop_if_sufficient_evidence,
        "policy_status": policy_status,
        "execution_permitted": permission_result["execution_permitted"],
        "reason_codes": permission_result["reason_codes"],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_bug_bounty_plan(*, plan: Any, permissions: Any) -> dict[str, Any]:
    """Deterministically validate and normalize one LLM-proposed Bug
    Bounty test plan against an analyst's own permission contract.
    Performs no I/O of any kind, calls no LLM, and executes no tool --
    not even the currently-implemented `http_assessor` adapter.

    Both parameters are required and keyword-only. `plan` must be a
    mapping containing exactly the six fields documented in the module
    docstring's plan contract: `plan_version` (must be `"1"`), `plan_id`
    (non-blank string), `target_profile` (the seven-field, untrusted-
    observation contract), `planning_goal` (non-blank string), `steps`
    (a non-empty list, each a seven-field step -- `step_id` unique,
    `sequence` exactly `1..N` matching list order, `tool_request`
    evaluated via the real, unmodified `core.bug_bounty_tool_policy.
    evaluate_tool_permission`, `rationale`, `depends_on` referencing
    only strictly-earlier `step_id`s, `expected_evidence` a non-empty
    list drawn from `EXPECTED_EVIDENCE_CATEGORIES`,
    `stop_if_sufficient_evidence`), `stop_conditions` (a list of
    non-blank strings, may be empty). `permissions` must be shaped like
    `core.bug_bounty_tool_policy`'s own permission contract -- it is
    never modified, and this function never grants anything beyond what
    it already permits.

    Every step's `policy_status` is one of `POLICY_STATUSES`
    (`"PERMITTED"`, `"REVIEW_REQUIRED"`, `"BLOCKED"`,
    `"ADAPTER_UNAVAILABLE"`), derived exclusively from the real
    `evaluate_tool_permission` result for that step -- this function
    never overrides, softens, or second-guesses it. A plan proposing a
    redundant or ultimately-denied step is validated and returned
    exactly as proposed; this function never drops, reorders, or merges
    a step to "clean up" the LLM's own plan.

    Returns a new dict containing exactly `plan_validation_version`
    (always `"1"`), `plan_id`, `planning_goal`, `target_profile`
    (validated, newly constructed), `step_count`, `steps` (each with
    `step_id`, `sequence`, `tool_id`, `rationale`, `depends_on`,
    `expected_evidence`, `stop_if_sufficient_evidence`,
    `policy_status`, `execution_permitted`, `reason_codes`),
    `stop_conditions`, `overall_execution_ready` (`True` only when
    every step's `policy_status` is `"PERMITTED"`),
    `human_review_required` (`True` when any step's `policy_status` is
    `"REVIEW_REQUIRED"`), `execution_performed` (always `False`).

    Neither `plan` nor `permissions` (nor any nested value within
    either) is ever mutated.

    Raises `BugBountyPlannerError` for any structurally invalid `plan`,
    including a duplicate `step_id`, a sequence gap, a `depends_on`
    referencing an unknown or later step, or a malformed nested
    `tool_request`/`permissions` (wrapping the real
    `BugBountyToolPolicyError`). Never raises because a step's
    `policy_status` is `"BLOCKED"`/`"REVIEW_REQUIRED"`/
    `"ADAPTER_UNAVAILABLE"` -- every one of those is a normal,
    successfully validated result.
    """
    if not isinstance(plan, Mapping) or set(plan) != set(_PLAN_REQUIRED_FIELDS):
        _raise("INVALID_PLAN", "plan must contain exactly the six required fields")

    if plan.get("plan_version") != PLAN_VERSION:
        _raise("INVALID_PLAN", "plan_version must be '1'")

    plan_id = _require_nonblank_string(plan.get("plan_id"), "INVALID_PLAN", "plan_id")
    target_profile = _validate_target_profile(plan.get("target_profile"))
    planning_goal = _require_nonblank_string(plan.get("planning_goal"), "INVALID_PLAN", "planning_goal")

    raw_steps = plan.get("steps")
    if not isinstance(raw_steps, list) or len(raw_steps) == 0:
        _raise("INVALID_PLAN", "steps must be a non-empty list")

    stop_conditions = _require_string_list(plan.get("stop_conditions"), "INVALID_PLAN", "stop_conditions")

    known_step_ids: set[str] = set()
    validated_steps: list[dict[str, Any]] = []
    for index, raw_step in enumerate(raw_steps):
        step = _validate_step(
            raw_step, expected_sequence=index + 1, known_step_ids=known_step_ids, permissions=permissions,
        )
        known_step_ids.add(step["step_id"])
        validated_steps.append(step)

    overall_execution_ready = all(step["policy_status"] == "PERMITTED" for step in validated_steps)
    human_review_required = any(step["policy_status"] == "REVIEW_REQUIRED" for step in validated_steps)

    return {
        "plan_validation_version": PLAN_VALIDATION_VERSION,
        "plan_id": plan_id,
        "planning_goal": planning_goal,
        "target_profile": target_profile,
        "step_count": len(validated_steps),
        "steps": validated_steps,
        "stop_conditions": stop_conditions,
        "overall_execution_ready": overall_execution_ready,
        "human_review_required": human_review_required,
        "execution_performed": False,
    }
