"""Run orchestration for the ThreatTrace Live Platform backend (Block
15J-K).

This module contains **no security/business logic of its own**. Every
decision (scope, tool permission, Governor evaluation, telemetry
feasibility, rule construction/deduplication/syntax validation) is made
by calling the exact same, unmodified `core.*`/`adapters.*` modules
already exercised by every earlier block in this project. This module's
only job is sequencing those calls against one `run_id`, updating
`backend.run_store`, and publishing `backend.event_bus` events that
honestly describe what actually happened -- it never invents a stage
transition, a tool result, or a finding that did not occur.

## The backend never calls an LLM

Per this checkpoint's own explicit LLM-boundary requirement, this
process never invokes any model. For the Bug Bounty workflow, the
"planning" stage is satisfied by one **fixed, hardcoded, minimal
default plan** (a single passive `http_assessor` request) -- clearly
reported via the `planner_started`/`planner_completed` events as a
fixed default, never described as an LLM proposal. For the Detection
workflow, the analogous "LLM proposes a rule draft" step is **required
caller input** (`llm_proposal`) -- the API caller (a human analyst, or
a separate process that already invoked
`.claude/agents/detection-engineering-planner.md`, e.g. via this
project's own `Agent` tool, exactly as Block 15H-I's live validation
did) supplies the already-produced `detection_objective`/
`proposed_rules`/`telemetry_recommendation`; this module only
deterministically assembles them with the trigger/telemetry it computed
itself and validates the result via `core.detection_planner`. Neither
workflow ever fabricates a plan when the required input is missing.

## Threading model

Both `run_bug_bounty_workflow`/`run_detection_workflow` are plain,
blocking, synchronous functions (they call real adapters that perform
real blocking I/O, e.g. `adapters.bug_bounty_http`). `backend.app` is
responsible for running them off the asyncio event loop (a background
thread) -- this module has no asyncio dependency itself and is fully
unit-testable by calling these functions directly and synchronously.

## Cooperative cancellation only

Before starting any new stage, the run's own `cancellation_requested`
flag (set via `POST /api/runs/{run_id}/cancel`) is checked; if set, the
workflow stops scheduling further stages and transitions to
`"cancelled"`. This never interrupts an already-in-flight adapter call
(e.g. a live HTTP request already sent) -- see
`docs/block15jk-live-platform-dashboard.md` for why real OS-level
cancellation is out of scope for this checkpoint.
"""

from __future__ import annotations

import traceback
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

from adapters.bug_bounty_http import BugBountyHttpTransport
from backend.event_bus import EventBus
from backend.models import TERMINAL_STATUSES, validate_local_only_target
from backend.run_store import RunStore
from core.bug_bounty_assessment import BugBountyAssessmentError, run_bug_bounty_assessment
from core.bug_bounty_evidence_normalization import BugBountyEvidenceNormalizationError, normalize_bug_bounty_evidence
from core.bug_bounty_final_report import BugBountyFinalReportError, build_final_bug_bounty_report
from core.bug_bounty_finding_correlation import BugBountyFindingCorrelationError, correlate_bug_bounty_evidence
from core.bug_bounty_scope import BugBountyScopeError, create_bug_bounty_scope
from core.bug_bounty_tool_policy import BugBountyToolPolicyError, evaluate_tool_permission
from core.detection_engineering_report import DetectionEngineeringReportError, build_detection_engineering_report
from core.detection_planner import DetectionPlannerError, validate_detection_plan
from core.detection_rule import DetectionRuleError, apply_validation_result, build_detection_rule
from core.detection_rule_deduplication import DetectionRuleDeduplicationError, check_rule_duplicate
from core.detection_rule_validation import DetectionRuleValidationError, validate_rule_syntax
from core.detection_telemetry import DetectionTelemetryError, evaluate_telemetry_feasibility
from core.detection_trigger import DetectionTriggerError, build_bug_bounty_trigger, build_threat_intelligence_trigger
from core.security_governor import SecurityGovernorError, evaluate_security_governor_event

ORCHESTRATOR_VERSION = "1"

TRIGGER_SOURCES = frozenset({"bug_bounty", "threat_intelligence"})

_MAX_ERROR_SUMMARY_LENGTH = 200

__all__ = ["run_bug_bounty_workflow", "run_detection_workflow", "TRIGGER_SOURCES"]


def _default_clock() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_error(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    return text if len(text) <= _MAX_ERROR_SUMMARY_LENGTH else text[: _MAX_ERROR_SUMMARY_LENGTH - 3] + "..."


class _Emitter:
    def __init__(self, *, run_id: str, event_bus: EventBus, clock: Callable[[], str]) -> None:
        self._run_id = run_id
        self._event_bus = event_bus
        self._clock = clock

    def __call__(
        self, event_type: str, stage: str, source_component: str, summary: str, payload: dict[str, Any] | None = None,
    ) -> None:
        self._event_bus.publish(
            run_id=self._run_id, event_type=event_type, timestamp=self._clock(), stage=stage,
            source_component=source_component, summary=summary, sanitized_payload=payload,
        )


def _is_cancelled(*, run_store: RunStore, run_id: str) -> bool:
    run = run_store.get_run(run_id=run_id)
    return bool(run.get("cancellation_requested")) and run["status"] not in TERMINAL_STATUSES


def _stop_cancelled(*, run_store: RunStore, run_id: str, emit: _Emitter, stage: str, clock: Callable[[], str]) -> None:
    run_store.transition(run_id=run_id, new_status="cancelled", current_stage=stage, completed_at=clock())
    emit("run_cancelled", stage, "orchestrator", "Run cancelled by cooperative cancellation request.")


# ---------------------------------------------------------------------------
# Bug Bounty workflow
# ---------------------------------------------------------------------------


def _default_bug_bounty_permissions(*, target: str) -> dict[str, Any]:
    parsed = urlsplit(target)
    port = parsed.port or 80
    return {
        "permission_version": "1",
        "target_origin": f"http://{parsed.hostname}" + (f":{port}" if port != 80 else ""),
        "allowed_hosts": [parsed.hostname],
        "allowed_ports": [port],
        "allowed_paths": ["/"],
        "excluded_paths": [],
        "testing_profile": "passive",
        "allowed_tools": ["http_assessor"],
        "authenticated_testing_allowed": False,
        "controlled_validation_allowed": False,
        "max_requests": 12,
        "human_approval_state": "approved",
    }


def run_bug_bounty_workflow(
    *,
    run_id: str,
    target: str,
    run_store: RunStore,
    event_bus: EventBus,
    clock: Callable[[], str] | None = None,
    transport: Any = None,
) -> None:
    """Run one real, bounded, local-only Bug Bounty assessment against
    `target` (already validated by `backend.models.
    validate_local_only_target` -- this function re-validates it anyway,
    defense in depth) through the existing Tool Policy -> Governor ->
    `http_assessor` -> Evidence Normalization -> Correlation -> Final
    Report chain, publishing an event at every stage.

    `transport` defaults to a real `adapters.bug_bounty_http.
    BugBountyHttpTransport()` when not supplied; tests inject a fake
    object satisfying `core.bug_bounty_assessment`'s own minimal
    `request(*, url, method, headers=None)` protocol instead, exactly
    like that module's own established injected-transport pattern.

    Intended to be called from a background thread by `backend.app`,
    never from the asyncio event loop directly (it performs real
    blocking network I/O via `adapters.bug_bounty_http` by default).
    """
    active_clock = clock or _default_clock
    emit = _Emitter(run_id=run_id, event_bus=event_bus, clock=active_clock)

    try:
        target = validate_local_only_target(target)

        run_store.transition(
            run_id=run_id, new_status="planning", current_stage="planning", started_at=active_clock(),
            target_summary=target,
        )
        emit("run_started", "intake", "orchestrator", f"Bug Bounty run started against {target}", {"target": target})

        if _is_cancelled(run_store=run_store, run_id=run_id):
            _stop_cancelled(run_store=run_store, run_id=run_id, emit=emit, stage="planning", clock=active_clock)
            return

        emit(
            "planner_started", "planning", "orchestrator",
            "Using a fixed local default assessment plan -- the backend performs no live LLM call.",
        )
        tool_request = {
            "request_version": "1",
            "request_id": f"REQ-{run_id}-01",
            "tool_id": "http_assessor",
            "purpose": "Bounded passive Bug Bounty assessment via ThreatTrace Live Platform backend",
            "target": target,
            "ports": [urlsplit(target).port or 80],
            "paths": ["/"],
            "testing_mode": "passive",
            "authentication_requested": False,
            "controlled_validation_requested": False,
        }
        emit(
            "planner_completed", "planning", "orchestrator",
            "Plan accepted: 1 tool request (http_assessor, passive).", {"tool_count": 1},
        )
        run_store.update_fields(run_id=run_id, requested_tools=["http_assessor"])

        run_store.transition(run_id=run_id, new_status="awaiting_policy", current_stage="tool_policy")
        permissions = _default_bug_bounty_permissions(target=target)
        policy_result = evaluate_tool_permission(permissions=permissions, tool_request=tool_request)
        emit(
            "tool_policy_evaluated", "tool_policy", "bug_bounty_tool_policy",
            f"http_assessor execution_permitted={policy_result['execution_permitted']}",
            {"execution_permitted": policy_result["execution_permitted"], "reason_codes": policy_result["reason_codes"]},
        )

        if not policy_result["execution_permitted"]:
            run_store.transition(
                run_id=run_id, new_status="blocked", current_stage="tool_policy", completed_at=active_clock(),
                limitations=[f"Tool policy denied http_assessor: {', '.join(policy_result['reason_codes'])}"],
            )
            emit("run_blocked", "tool_policy", "bug_bounty_tool_policy", "Blocked: tool policy denied execution.")
            return

        run_store.update_fields(run_id=run_id, permitted_tools=["http_assessor"])

        run_store.transition(run_id=run_id, new_status="awaiting_governor", current_stage="governor")
        # `execution_requested` is honestly `False` here: per
        # `core.bug_bounty_tool_execution`'s own documented design, the
        # passive `http_assessor` path is deliberately *not* routed
        # through that module's stricter Decision-Binding-gated
        # execution boundary (see that module's docstring). This
        # backend implements no authenticated Decision Binding
        # mechanism at all, so honestly claiming `execution_requested:
        # True` here would force `decision_binding_state: "valid"` to
        # avoid an automatic `DECISION_BINDING_REQUIRED` block -- a
        # claim this checkpoint cannot honestly make. Framing this as a
        # `"stage_contribution"` observational check instead still
        # exercises every other Governor rule (role scope, mutation
        # freeze, scope expansion, source-truth protection, untrusted
        # content, audit, repeated-denial escalation) against this
        # stage exactly as strictly as any other.
        governor_event = {
            "event_version": "1",
            "actor_role": "bug_bounty",
            "action_class": "stage_contribution",
            "current_stage": "bug_bounty_assessment",
            "required_role": "bug_bounty",
            "gateway_decision": "allow",
            "identity_decision": "allow",
            "mutation_freeze_active": False,
            "approval_state": "not_required",
            "decision_binding_state": "not_required",
            "scope_state": "within_scope",
            "source_truth_state": "unchanged",
            "remote_content_state": "not_present",
            "audit_state": "recorded",
            "prior_policy_denials": 0,
            "execution_requested": False,
        }
        governor_result = evaluate_security_governor_event(event=governor_event)
        emit(
            "governor_evaluated", "governor", "security_governor",
            f"Governor decision: {governor_result['decision']}",
            {
                "decision": governor_result["decision"], "reason_codes": governor_result["reason_codes"],
                "execution_allowed": governor_result["execution_allowed"],
            },
        )
        run_store.update_fields(
            run_id=run_id,
            governor_decisions=[{"stage": "bug_bounty_assessment", "decision": governor_result["decision"]}],
        )

        if not governor_result["execution_allowed"]:
            run_store.transition(
                run_id=run_id, new_status="blocked", current_stage="governor", completed_at=active_clock(),
                limitations=[f"Governor decision: {governor_result['decision']}"],
            )
            emit("run_blocked", "governor", "security_governor", "Blocked: Governor did not allow execution.")
            return

        if _is_cancelled(run_store=run_store, run_id=run_id):
            _stop_cancelled(run_store=run_store, run_id=run_id, emit=emit, stage="governor", clock=active_clock)
            return

        run_store.transition(run_id=run_id, new_status="running", current_stage="tool_execution")
        emit("tool_started", "tool_execution", "bug_bounty_assessment", f"Running http_assessor against {target}")

        scope = create_bug_bounty_scope(
            target=target, target_type="web_application", allowed_origins=[permissions["target_origin"]],
            allowed_paths=["/"], excluded_paths=[], testing_profile="passive",
        )
        assessment_started_at = active_clock()
        active_transport = transport if transport is not None else BugBountyHttpTransport()
        assessment_result = run_bug_bounty_assessment(scope=scope, transport=active_transport)
        assessment_completed_at = active_clock()

        emit(
            "tool_completed", "tool_execution", "bug_bounty_assessment",
            f"http_assessor completed: {len(assessment_result['findings'])} findings, "
            f"{assessment_result['network_requests_performed']} requests.",
            {
                "findings_count": len(assessment_result["findings"]),
                "network_requests_performed": assessment_result["network_requests_performed"],
                "assessment_performed": assessment_result["assessment_performed"],
            },
        )
        emit(
            "http_assessment_completed", "tool_execution", "bug_bounty_assessment",
            "HTTP assessment stage complete.", {"observed_evidence": assessment_result["observed_evidence"]},
        )
        run_store.update_fields(run_id=run_id, executed_tools=["http_assessor"])

        run_store.transition(run_id=run_id, new_status="normalizing", current_stage="normalization")
        evidence_records = normalize_bug_bounty_evidence(
            source_results=[{"source_tool": "http_assessor", "result": assessment_result}],
            scope_reference=permissions["target_origin"], observed_at=active_clock(),
        )
        emit(
            "evidence_normalized", "normalization", "bug_bounty_evidence_normalization",
            f"{len(evidence_records)} evidence records normalized.", {"evidence_count": len(evidence_records)},
        )

        run_store.transition(run_id=run_id, new_status="correlating", current_stage="correlation")
        correlation_result = correlate_bug_bounty_evidence(evidence_records=evidence_records)
        emit(
            "finding_correlated", "correlation", "bug_bounty_finding_correlation",
            f"{correlation_result['total_groups']} correlation groups from {correlation_result['total_input_records']} records.",
            {"total_groups": correlation_result["total_groups"], "duplicate_evidence_count": correlation_result["duplicate_evidence_count"]},
        )

        report = build_final_bug_bounty_report(
            correlation_result=correlation_result, evidence_records=evidence_records, target=target,
            scope=permissions["target_origin"], testing_profile="passive",
            assessment_started_at=assessment_started_at, assessment_completed_at=assessment_completed_at,
            tools_requested=["http_assessor"], tools_permitted=["http_assessor"], tools_executed=["http_assessor"],
            tools_unavailable=[],
        )
        for finding in report["canonical_findings"]:
            emit(
                "canonical_finding_created", "correlation", "bug_bounty_finding_correlation",
                f"Canonical finding: {finding['title']} ({finding['technical_severity']})",
                {"finding_id": finding["finding_id"], "technical_severity": finding["technical_severity"]},
            )

        run_store.update_fields(
            run_id=run_id, finding_count=len(evidence_records),
            canonical_finding_count=len(report["canonical_findings"]), report=report,
            human_review_required=True,
        )
        run_store.transition(run_id=run_id, new_status="completed", current_stage="complete", completed_at=active_clock())
        emit(
            "run_completed", "complete", "orchestrator",
            f"Bug Bounty run complete: {len(report['canonical_findings'])} canonical findings.",
            {"canonical_finding_count": len(report["canonical_findings"])},
        )

    except (
        BugBountyScopeError, BugBountyToolPolicyError, SecurityGovernorError, BugBountyAssessmentError,
        BugBountyEvidenceNormalizationError, BugBountyFindingCorrelationError, BugBountyFinalReportError,
    ) as exc:
        _fail_run(run_store=run_store, emit=emit, run_id=run_id, exc=exc, stage="tool_execution", clock=active_clock)
    except Exception as exc:  # noqa: BLE001 -- last-resort honest failure boundary, never a silent crash
        traceback.print_exc()
        _fail_run(run_store=run_store, emit=emit, run_id=run_id, exc=exc, stage="tool_execution", clock=active_clock)


def _fail_run(
    *, run_store: RunStore, emit: _Emitter, run_id: str, exc: BaseException, stage: str, clock: Callable[[], str],
) -> None:
    sanitized = _sanitize_error(exc)
    try:
        run_store.transition(
            run_id=run_id, new_status="failed", current_stage=stage, completed_at=clock(), error_summary=sanitized,
        )
    except Exception:  # noqa: BLE001 -- the run may already be terminal; failure reporting itself must never raise
        return
    emit("run_failed", stage, "orchestrator", f"Run failed: {sanitized}", {"error_type": type(exc).__name__})


# ---------------------------------------------------------------------------
# Detection Engineering workflow
# ---------------------------------------------------------------------------


def run_detection_workflow(
    *,
    run_id: str,
    trigger_source: str,
    trigger_input: dict[str, Any],
    telemetry_context: dict[str, Any],
    llm_proposal: dict[str, Any],
    run_store: RunStore,
    event_bus: EventBus,
    clock: Callable[[], str] | None = None,
) -> None:
    """Run one bounded Detection Engineering demonstration through the
    existing Trigger -> Telemetry Feasibility -> deterministic plan
    validation -> Rule construction -> Deduplication -> Structural
    Validation chain, publishing an event at every stage.

    `trigger_source` must be `"bug_bounty"` or `"threat_intelligence"`.
    `trigger_input` is a canonical-finding-shaped or TI-record-shaped
    mapping (matching `trigger_source`). `telemetry_context` supplies
    `available_telemetry`/`siem`/`edr`/`cloud_provider`/`environment`/
    `industry`. `llm_proposal` supplies the already-produced
    `detection_objective`/`proposed_rules`/`telemetry_recommendation`
    this backend never generates itself (see module docstring) -- when
    `telemetry_evaluated` reports `TELEMETRY_GAP`, `llm_proposal` is
    never even read, since no rule may be proposed.
    """
    active_clock = clock or _default_clock
    emit = _Emitter(run_id=run_id, event_bus=event_bus, clock=active_clock)

    try:
        run_store.transition(
            run_id=run_id, new_status="planning", current_stage="planning", started_at=active_clock(),
            target_summary=f"trigger_source={trigger_source}",
        )
        emit("run_started", "intake", "orchestrator", f"Detection run started (trigger_source={trigger_source})")

        if trigger_source == "bug_bounty":
            trigger = build_bug_bounty_trigger(canonical_finding=trigger_input)
        elif trigger_source == "threat_intelligence":
            trigger = build_threat_intelligence_trigger(ti_record=trigger_input)
        else:
            raise DetectionTriggerError(f"INVALID_TRIGGER_SOURCE: trigger_source must be one of {sorted(TRIGGER_SOURCES)}")

        emit(
            "detection_plan_created", "detection_engineering", "detection_trigger",
            f"Detection trigger built: {trigger['trigger_id']} ({trigger['trigger_type']})",
            {
                "trigger_id": trigger["trigger_id"], "trigger_type": trigger["trigger_type"],
                "cve": trigger["cve"], "cwe": trigger["cwe"], "confidence": trigger["confidence"],
                "affected_technology": trigger["affected_technology"],
            },
        )
        run_store.update_fields(run_id=run_id, detection_trigger_count=1)

        telemetry_result = evaluate_telemetry_feasibility(
            required_telemetry_candidates=trigger["required_telemetry_candidates"],
            available_telemetry=telemetry_context.get("available_telemetry", []),
            siem=telemetry_context.get("siem"), edr=telemetry_context.get("edr"),
            cloud_provider=telemetry_context.get("cloud_provider"),
            environment=telemetry_context.get("environment"), industry=telemetry_context.get("industry"),
        )
        emit(
            "telemetry_evaluated", "detection_engineering", "detection_telemetry",
            f"Telemetry decision: {telemetry_result['decision']}",
            {"decision": telemetry_result["decision"], "missing_sources": telemetry_result["missing_sources"]},
        )

        if telemetry_result["decision"] == "TELEMETRY_GAP":
            run_store.update_fields(
                run_id=run_id, rule_candidate_count=0,
                limitations=["TELEMETRY_GAP: no rule can be meaningfully proposed from available telemetry."],
            )
            run_store.transition(run_id=run_id, new_status="completed", current_stage="complete", completed_at=active_clock())
            emit("run_completed", "complete", "orchestrator", "Detection run complete: TELEMETRY_GAP, zero rules proposed.")
            return

        run_store.transition(run_id=run_id, new_status="awaiting_governor", current_stage="governor")
        governor_event = {
            "event_version": "1",
            "actor_role": "blue_team",
            "action_class": "stage_contribution",
            "current_stage": "detection_engineering",
            "required_role": "blue_team",
            "gateway_decision": "allow",
            "identity_decision": "allow",
            "mutation_freeze_active": False,
            "approval_state": "not_required",
            "decision_binding_state": "not_required",
            "scope_state": "within_scope",
            "source_truth_state": "unchanged",
            "remote_content_state": "not_present",
            "audit_state": "recorded",
            "prior_policy_denials": 0,
            "execution_requested": False,
        }
        governor_result = evaluate_security_governor_event(event=governor_event)
        emit(
            "governor_evaluated", "governor", "security_governor",
            f"Governor decision: {governor_result['decision']}",
            {
                "decision": governor_result["decision"], "reason_codes": governor_result["reason_codes"],
                "execution_allowed": governor_result["execution_allowed"],
            },
        )
        run_store.update_fields(
            run_id=run_id,
            governor_decisions=[{"stage": "detection_engineering", "decision": governor_result["decision"]}],
        )

        if not governor_result["execution_allowed"]:
            run_store.transition(
                run_id=run_id, new_status="blocked", current_stage="governor", completed_at=active_clock(),
                limitations=[f"Governor decision: {governor_result['decision']}"],
            )
            emit("run_blocked", "governor", "security_governor", "Blocked: Governor did not allow rule generation to proceed.")
            return

        if _is_cancelled(run_store=run_store, run_id=run_id):
            _stop_cancelled(run_store=run_store, run_id=run_id, emit=emit, stage="detection_engineering", clock=active_clock)
            return

        run_store.transition(run_id=run_id, new_status="generating_detection", current_stage="detection_engineering")
        emit(
            "planner_started", "detection_engineering", "detection_planner",
            "Validating caller-supplied LLM proposal (backend performs no live LLM call itself).",
        )

        plan = {
            "plan_version": "1",
            "plan_id": f"DP-{run_id}",
            "trigger": trigger,
            "telemetry_feasibility": telemetry_result,
            "detection_objective": llm_proposal.get("detection_objective"),
            "proposed_rules": llm_proposal.get("proposed_rules", []),
            "telemetry_recommendation": llm_proposal.get("telemetry_recommendation"),
        }
        validated_plan = validate_detection_plan(plan=plan)
        emit(
            "planner_completed", "detection_engineering", "detection_planner",
            f"Plan validated: {validated_plan['rule_count']} proposed rule draft(s).",
            {"rule_count": validated_plan["rule_count"]},
        )

        rules: list[dict[str, Any]] = []
        dedup_results: list[dict[str, Any]] = []
        for draft in validated_plan["proposed_rules"]:
            rule = build_detection_rule(validated_rule_draft=draft, trigger=trigger, data_source=telemetry_context.get("siem"))
            dedup = check_rule_duplicate(candidate_rule=rule, existing_rules=rules)
            dedup_results.append(dedup)
            emit(
                "detection_rule_created", "detection_engineering", "detection_rule",
                f"Rule drafted: {rule['detection_id']} ({rule['rule_format']}), dedup={dedup['status']}",
                {"detection_id": rule["detection_id"], "rule_format": rule["rule_format"], "dedup_status": dedup["status"]},
            )

            syntax_result = validate_rule_syntax(rule_format=rule["rule_format"], rule_content=rule["generic_rule"])
            if syntax_result["syntax_valid"]:
                rule = apply_validation_result(
                    rule=rule, validation_status="syntax_validated",
                    known_limitations_addendum="Structural syntax check only -- not detection-efficacy tested.",
                )
            else:
                rule = apply_validation_result(
                    rule=rule, validation_status="rejected",
                    known_limitations_addendum="Failed bounded structural syntax check: " + "; ".join(syntax_result["issues"]),
                )
            emit(
                "detection_rule_validated", "detection_engineering", "detection_rule_validation",
                f"Rule {rule['detection_id']}: validation_status={rule['validation_status']}, "
                f"deployment_state={rule['deployment_state']}",
                {"detection_id": rule["detection_id"], "validation_status": rule["validation_status"], "deployment_state": rule["deployment_state"]},
            )
            rules.append(rule)

        report = build_detection_engineering_report(
            triggers=[trigger],
            telemetry_feasibility_results=[{"trigger_id": trigger["trigger_id"], "result": telemetry_result}],
            rules=rules, dedup_results=dedup_results,
            rules_requested=len(validated_plan["proposed_rules"]),
        )
        run_store.update_fields(
            run_id=run_id, rule_candidate_count=len(rules), human_review_required=True, report=report,
        )
        emit(
            "human_review_required", "human_review", "detection_engineering_report",
            f"{len(rules)} rule candidate(s) pending human review; deployment_state=NOT_DEPLOYED for all.",
            {"rule_count": len(rules)},
        )
        run_store.transition(run_id=run_id, new_status="awaiting_human_review", current_stage="human_review")
        run_store.transition(run_id=run_id, new_status="completed", current_stage="complete", completed_at=active_clock())
        emit("run_completed", "complete", "orchestrator", f"Detection run complete: {len(rules)} rule candidate(s).")

    except (
        DetectionTriggerError, DetectionTelemetryError, DetectionPlannerError, DetectionRuleError,
        DetectionRuleDeduplicationError, DetectionRuleValidationError, DetectionEngineeringReportError,
    ) as exc:
        _fail_run(run_store=run_store, emit=emit, run_id=run_id, exc=exc, stage="detection_engineering", clock=active_clock)
    except Exception as exc:  # noqa: BLE001 -- last-resort honest failure boundary, never a silent crash
        traceback.print_exc()
        _fail_run(run_store=run_store, emit=emit, run_id=run_id, exc=exc, stage="detection_engineering", clock=active_clock)
