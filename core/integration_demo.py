"""Pure, deterministic integration/demonstration layer (Block 15,
checkpoint A).

This module answers one question only: *when several already-implemented
ThreatTrace components are exercised together, through their own real
public APIs, in a fixed local scenario, what happened at each step and
what was the end result?* It creates no new security primitive and
duplicates no existing policy, hashing, evaluation, or aggregation
logic -- every decision surfaced here is computed by the real Block
8/9/10/11/11-12/13/14 function that already owns it.

## What "full integration" honestly means here

    Multiple already-implemented ThreatTrace components are exercised
    together through their real public APIs, in deterministic, local,
    fixed-fixture demonstration scenarios.

It does NOT mean, and this module never claims:

- every ThreatTrace feature runs in one runtime path;
- any database-backed workflow executed;
- any workflow was persisted;
- any real tool or action executed;
- any agent was authenticated;
- any provenance was cryptographically verified;
- the audit history assembled by a scenario is immutable;
- analyst feedback is ground truth or overrides the result it comments
  on;
- automatic learning occurred;
- dashboard metrics are live.

Every scenario's result carries `execution_performed: False`. This
module never executes a tool, calls MCP, calls Supabase, reads the
system clock, generates a random value, or performs any I/O of any
kind. All fixture data (agent/tool identifiers, arguments, timestamps,
asset/case selections) is a fixed, hardcoded, in-code constant, exactly
like `core.ai_asset_registry`'s own reference constants -- never derived
from the system clock, an environment variable, or any external source.

## Scenarios

Exactly four fixed scenario IDs are supported, each composing real
public functions from existing Blocks only:

- `identity_narrowing_deny` -- Block 8 + Block 9. A registered agent
  (`reviewer_agent`) is permitted a mutation-capable tool by the
  gateway (`require_approval`, never `deny`) but is denied at the
  identity/least-privilege layer because that tool's operation class
  exceeds the agent's role ceiling.
- `emergency_mutation_freeze` -- Block 9 + the Emergency Mutation
  Freeze. A registered agent (`coordinator_agent`) reaches a non-deny
  Block 9 decision (`require_approval`) for a mutation-capable tool;
  an active freeze narrows it to `deny`.
- `evaluation_feedback_audit` -- Blocks 11-12 + 13 + 14. A deterministic
  security-evaluation case is run and passes; an analyst records
  disagreement with it; both are captured as linked audit records; the
  chain is verified; the dashboard summarizes it.
- `decision_binding_argument_drift` -- Block 9 + Block 10. A Decision
  Binding is created for a real Block 9 result and a fixed argument set,
  then verified twice: once against the same arguments (valid), and
  once against a single changed argument value (invalid, with an
  `ARGUMENT_DIGEST_MISMATCH` finding).

A denial, a freeze narrowing, or an invalid verification is always a
*successful* demonstration of the underlying security property -- never
a scenario failure. `IntegrationDemoError` is raised only for a
malformed or unrecognized `scenario` selection; a genuine mismatch
between this module's fixed fixtures and a real underlying block's
current contract is never caught here -- the real block's own typed
exception is left to propagate unchanged, since that represents an
actual integration regression, not a normal scenario outcome.

`run_integration_scenario` is this module's only public function.
"""

from __future__ import annotations

from typing import Any

from core.agent_gateway import evaluate_tool_call
from core.agent_identity_policy import evaluate_agent_tool_call
from core.ai_asset_registry import evaluate_ai_security_case
from core.analyst_feedback import create_analyst_feedback
from core.decision_binding import create_decision_binding, verify_decision_binding
from core.evaluation_dashboard import summarize_audit_dashboard
from core.mutation_freeze import evaluate_mutation_freeze
from core.tamper_evident_audit import create_audit_record, verify_audit_chain

INTEGRATION_VERSION = "1"

_SCENARIO_IDS = frozenset({
    "identity_narrowing_deny",
    "emergency_mutation_freeze",
    "evaluation_feedback_audit",
    "decision_binding_argument_drift",
})

_FINAL_OUTCOME_BY_SCENARIO = {
    "identity_narrowing_deny": "identity_scope_denied",
    "emergency_mutation_freeze": "mutation_freeze_denied",
    "evaluation_feedback_audit": "evaluation_feedback_audited",
    "decision_binding_argument_drift": "argument_drift_detected",
}

# ---------------------------------------------------------------------------
# Fixed, deterministic in-code demo fixtures. Never derived from the
# system clock, an environment variable, randomness, or any external
# source. Every agent/tool identifier and asset/case pair below is a
# real, already-registered entry in the relevant Block's own fixed
# registry -- never invented.
# ---------------------------------------------------------------------------

_DEMO_TIMESTAMP_SCENARIO_1 = "2026-03-01T00:00:00Z"
_DEMO_APPROVAL_ID_SCENARIO_1 = "10000000-0000-4000-8000-000000000001"

_DEMO_TIMESTAMP_SCENARIO_2 = "2026-03-15T00:00:00Z"
_DEMO_APPROVAL_ID_SCENARIO_2 = "20000000-0000-4000-8000-000000000002"

_DEMO_EVALUATION_CASE_TYPE = "mutation_policy_bypass"
_DEMO_EVALUATION_ASSET_ID = "gateway_tool:apply_approval_consumption"
_DEMO_AUDIT_RECORD_1_OCCURRED_AT = "2026-05-01T00:00:00Z"
_DEMO_AUDIT_RECORD_2_OCCURRED_AT = "2026-05-01T00:05:00Z"
_DEMO_FEEDBACK_SUBMITTED_AT = "2026-05-01T00:05:00Z"
_DEMO_EVALUATION_EVENT_REFERENCE = (
    "demo:security_evaluation_result:mutation_policy_bypass:gateway_tool:apply_approval_consumption"
)
_DEMO_FEEDBACK_EVENT_REFERENCE = "demo:analyst_feedback:mutation_policy_bypass_disagreement"
_DEMO_FEEDBACK_TARGET_REFERENCE = "demo:security_evaluation_result:mutation_policy_bypass:001"
_DEMO_FEEDBACK_RATIONALE = (
    "Demonstration rationale: the analyst disagrees that this evaluation case's pass outcome "
    "fully reflects the intended security expectation for this scenario."
)

_DEMO_TIMESTAMP_SCENARIO_4 = "2026-04-01T00:00:00Z"
_DEMO_ISSUED_AT_SCENARIO_4 = "2026-04-01T00:00:00Z"
_DEMO_EXPIRES_AT_SCENARIO_4 = "2026-04-01T00:04:00Z"
_DEMO_VERIFY_AT_SCENARIO_4_UNCHANGED = "2026-04-01T00:01:00Z"
_DEMO_VERIFY_AT_SCENARIO_4_DRIFTED = "2026-04-01T00:02:00Z"
_DEMO_APPROVAL_ID_SCENARIO_4_ORIGINAL = "30000000-0000-4000-8000-000000000003"
_DEMO_APPROVAL_ID_SCENARIO_4_DRIFTED = "40000000-0000-4000-8000-000000000004"


class IntegrationDemoError(ValueError):
    """Raised when a supplied scenario selection is structurally invalid.

    This is only raised for malformed input: a non-string, blank, or
    unrecognized `scenario`. It is never raised because an underlying
    scenario step results in a security denial, a freeze narrowing, or
    an invalid verification -- every one of those is a normal,
    successfully demonstrated scenario outcome, not an error condition.
    """


def _step(*, step: str, block: str, function: str, outcome_field: str, outcome_value: Any) -> dict[str, Any]:
    return {
        "step": step,
        "block": block,
        "function": function,
        "outcome_field": outcome_field,
        "outcome_value": outcome_value,
    }


def _dedup_codes(codes: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for code in codes:
        if code not in seen:
            seen.add(code)
            deduped.append(code)
    return deduped


def _run_identity_narrowing_deny() -> tuple[list[dict[str, Any]], list[str]]:
    tool_name = "apply_approval_consumption"
    arguments = {"approval_id": _DEMO_APPROVAL_ID_SCENARIO_1}

    gateway_result = evaluate_tool_call(
        tool_name=tool_name,
        arguments=arguments,
        evaluated_at=_DEMO_TIMESTAMP_SCENARIO_1,
    )
    identity_result = evaluate_agent_tool_call(
        agent_id="reviewer_agent",
        tool_name=tool_name,
        arguments=arguments,
        evaluated_at=_DEMO_TIMESTAMP_SCENARIO_1,
    )

    steps = [
        _step(
            step="gateway_evaluation",
            block="block_8_agent_gateway",
            function="core.agent_gateway.evaluate_tool_call",
            outcome_field="decision",
            outcome_value=gateway_result["decision"],
        ),
        _step(
            step="identity_evaluation",
            block="block_9_agent_identity_policy",
            function="core.agent_identity_policy.evaluate_agent_tool_call",
            outcome_field="final_decision",
            outcome_value=identity_result["final_decision"],
        ),
    ]

    narrowing_codes = [
        rule["code"] for rule in identity_result["matched_identity_rules"] if rule["affects_decision"]
    ]
    return steps, _dedup_codes(narrowing_codes)


def _run_emergency_mutation_freeze() -> tuple[list[dict[str, Any]], list[str]]:
    tool_name = "apply_approval_consumption"
    arguments = {"approval_id": _DEMO_APPROVAL_ID_SCENARIO_2}

    identity_result = evaluate_agent_tool_call(
        agent_id="coordinator_agent",
        tool_name=tool_name,
        arguments=arguments,
        evaluated_at=_DEMO_TIMESTAMP_SCENARIO_2,
    )
    frozen_result = evaluate_mutation_freeze(
        identity_policy_result=identity_result,
        control_mode="mutation_freeze",
    )

    steps = [
        _step(
            step="identity_evaluation_pre_freeze",
            block="block_9_agent_identity_policy",
            function="core.agent_identity_policy.evaluate_agent_tool_call",
            outcome_field="final_decision",
            outcome_value=identity_result["final_decision"],
        ),
        _step(
            step="mutation_freeze_evaluation",
            block="block_11_mutation_freeze",
            function="core.mutation_freeze.evaluate_mutation_freeze",
            outcome_field="final_decision",
            outcome_value=frozen_result["final_decision"],
        ),
    ]

    freeze_codes = [rule["code"] for rule in frozen_result["matched_freeze_rules"]]
    return steps, _dedup_codes(freeze_codes)


def _run_evaluation_feedback_audit() -> tuple[list[dict[str, Any]], list[str]]:
    evaluation_result = evaluate_ai_security_case(
        case_type=_DEMO_EVALUATION_CASE_TYPE,
        asset_id=_DEMO_EVALUATION_ASSET_ID,
    )

    feedback_result = create_analyst_feedback(
        target_type="evaluation_result",
        target_reference=_DEMO_FEEDBACK_TARGET_REFERENCE,
        analyst_decision="disagree",
        error_category="evaluation_expectation_mismatch",
        rationale=_DEMO_FEEDBACK_RATIONALE,
        evidence_reference=None,
        corrected_value="fail",
        submitted_at=_DEMO_FEEDBACK_SUBMITTED_AT,
    )

    record_1 = create_audit_record(
        sequence=1,
        event_type="security_evaluation_result",
        event_reference=_DEMO_EVALUATION_EVENT_REFERENCE,
        event_summary={
            "outcome": evaluation_result["evaluation_outcome"],
            "case_type": evaluation_result["case_type"],
        },
        occurred_at=_DEMO_AUDIT_RECORD_1_OCCURRED_AT,
        previous_record_digest=None,
    )
    record_2 = create_audit_record(
        sequence=2,
        event_type="analyst_feedback",
        event_reference=_DEMO_FEEDBACK_EVENT_REFERENCE,
        event_summary={
            "outcome": feedback_result["analyst_decision"],
            "error_category": feedback_result["error_category"],
        },
        occurred_at=_DEMO_AUDIT_RECORD_2_OCCURRED_AT,
        previous_record_digest=record_1["record_digest"],
    )

    records = [record_1, record_2]
    verification = verify_audit_chain(records=records, expected_head_digest=None)
    dashboard = summarize_audit_dashboard(records=records, expected_head_digest=None)

    steps = [
        _step(
            step="security_evaluation",
            block="block_11_12_ai_asset_registry",
            function="core.ai_asset_registry.evaluate_ai_security_case",
            outcome_field="evaluation_outcome",
            outcome_value=evaluation_result["evaluation_outcome"],
        ),
        _step(
            step="analyst_feedback",
            block="block_13_analyst_feedback",
            function="core.analyst_feedback.create_analyst_feedback",
            outcome_field="analyst_decision",
            outcome_value=feedback_result["analyst_decision"],
        ),
        _step(
            step="audit_record_evaluation",
            block="block_14_tamper_evident_audit",
            function="core.tamper_evident_audit.create_audit_record",
            outcome_field="event_type",
            outcome_value=record_1["event_type"],
        ),
        _step(
            step="audit_record_feedback",
            block="block_14_tamper_evident_audit",
            function="core.tamper_evident_audit.create_audit_record",
            outcome_field="event_type",
            outcome_value=record_2["event_type"],
        ),
        _step(
            step="chain_verification",
            block="block_14_tamper_evident_audit",
            function="core.tamper_evident_audit.verify_audit_chain",
            outcome_field="verification_outcome",
            outcome_value=verification["verification_outcome"],
        ),
        _step(
            step="dashboard_summary",
            block="block_14_evaluation_dashboard",
            function="core.evaluation_dashboard.summarize_audit_dashboard",
            outcome_field="audit_verification_outcome",
            outcome_value=dashboard["audit"]["verification_outcome"],
        ),
    ]

    evidence_codes = [item["code"] for item in evaluation_result["observed_evidence"]]
    return steps, _dedup_codes(evidence_codes)


def _run_decision_binding_argument_drift() -> tuple[list[dict[str, Any]], list[str]]:
    tool_name = "apply_approval_consumption"
    original_arguments = {"approval_id": _DEMO_APPROVAL_ID_SCENARIO_4_ORIGINAL}
    drifted_arguments = {"approval_id": _DEMO_APPROVAL_ID_SCENARIO_4_DRIFTED}

    identity_result = evaluate_agent_tool_call(
        agent_id="coordinator_agent",
        tool_name=tool_name,
        arguments=original_arguments,
        evaluated_at=_DEMO_TIMESTAMP_SCENARIO_4,
    )

    binding = create_decision_binding(
        identity_policy_result=identity_result,
        arguments=original_arguments,
        issued_at=_DEMO_ISSUED_AT_SCENARIO_4,
        expires_at=_DEMO_EXPIRES_AT_SCENARIO_4,
    )

    unchanged_verification = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=identity_result,
        arguments=original_arguments,
        verification_time=_DEMO_VERIFY_AT_SCENARIO_4_UNCHANGED,
    )
    drifted_verification = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=identity_result,
        arguments=drifted_arguments,
        verification_time=_DEMO_VERIFY_AT_SCENARIO_4_DRIFTED,
    )

    steps = [
        _step(
            step="identity_evaluation",
            block="block_9_agent_identity_policy",
            function="core.agent_identity_policy.evaluate_agent_tool_call",
            outcome_field="final_decision",
            outcome_value=identity_result["final_decision"],
        ),
        _step(
            step="binding_creation",
            block="block_10_decision_binding",
            function="core.decision_binding.create_decision_binding",
            outcome_field="binding_outcome",
            outcome_value=binding["binding_outcome"],
        ),
        _step(
            step="binding_verification_unchanged",
            block="block_10_decision_binding",
            function="core.decision_binding.verify_decision_binding",
            outcome_field="verification_outcome",
            outcome_value=unchanged_verification["verification_outcome"],
        ),
        _step(
            step="binding_verification_drifted",
            block="block_10_decision_binding",
            function="core.decision_binding.verify_decision_binding",
            outcome_field="verification_outcome",
            outcome_value=drifted_verification["verification_outcome"],
        ),
    ]

    drift_codes = [
        rule["code"] for rule in drifted_verification["matched_verification_rules"] if rule["affects_decision"]
    ]
    return steps, _dedup_codes(drift_codes)


_SCENARIO_HANDLERS = {
    "identity_narrowing_deny": _run_identity_narrowing_deny,
    "emergency_mutation_freeze": _run_emergency_mutation_freeze,
    "evaluation_feedback_audit": _run_evaluation_feedback_audit,
    "decision_binding_argument_drift": _run_decision_binding_argument_drift,
}


def _validate_scenario(value: Any) -> str:
    if not isinstance(value, str):
        raise IntegrationDemoError("scenario must be a string")
    stripped = value.strip()
    if not stripped:
        raise IntegrationDemoError("scenario must not be blank")
    if stripped not in _SCENARIO_IDS:
        raise IntegrationDemoError("scenario must be one of the recognized integration scenario ids")
    return stripped


def run_integration_scenario(*, scenario: Any) -> dict[str, Any]:
    """Deterministically run one fixed integration/demonstration
    scenario by composing real, already-implemented ThreatTrace public
    functions, without executing anything or reimplementing any policy,
    evaluation, hashing, or aggregation logic.

    `scenario` is required and keyword-only, and must be a non-blank
    string, trimmed of surrounding whitespace, matching exactly one of
    the four recognized scenario ids: `identity_narrowing_deny`,
    `emergency_mutation_freeze`, `evaluation_feedback_audit`,
    `decision_binding_argument_drift`. Any other value raises
    `IntegrationDemoError`.

    Returns a new dict containing exactly `integration_version` (always
    `"1"`), `scenario` (the canonical scenario id), `steps` (a list of
    per-step dicts, each containing exactly `step`, `block`, `function`,
    `outcome_field`, `outcome_value`), `final_outcome` (a fixed,
    scenario-specific label -- an integration-demo label only, never a
    replacement for the underlying block's own decision/outcome
    vocabulary), `observed_evidence` (a deduplicated, order-preserving
    list of real evidence-code strings actually emitted by the
    underlying blocks -- never invented), and `execution_performed`
    (always `False`).

    A security denial, a freeze narrowing, or an invalid verification
    within a scenario is always a normal, successfully demonstrated
    result -- never raised as an error. `IntegrationDemoError` is raised
    only for a malformed or unrecognized `scenario` selection; any
    typed exception raised by an underlying block's own real function is
    never caught here and propagates unchanged.
    """
    validated_scenario = _validate_scenario(scenario)
    steps, observed_evidence = _SCENARIO_HANDLERS[validated_scenario]()

    return {
        "integration_version": INTEGRATION_VERSION,
        "scenario": validated_scenario,
        "steps": steps,
        "final_outcome": _FINAL_OUTCOME_BY_SCENARIO[validated_scenario],
        "observed_evidence": observed_evidence,
        "execution_performed": False,
    }
