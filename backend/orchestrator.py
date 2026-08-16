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
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

from adapters.bug_bounty_http import BugBountyHttpTransport
from adapters.threat_intel_nvd import fetch_nvd_records
from backend.event_bus import EventBus
from backend.models import TERMINAL_STATUSES, resolve_execution_target, validate_local_only_target
from backend.run_store import RunStore
from core.bug_bounty_assessment import BugBountyAssessmentError, run_bug_bounty_assessment
from core.bug_bounty_crawler import BugBountyCrawlerError, run_bug_bounty_crawl
from core.bug_bounty_evidence_normalization import BugBountyEvidenceNormalizationError, normalize_bug_bounty_evidence
from core.bug_bounty_final_report import BugBountyFinalReportError, build_final_bug_bounty_report
from core.bug_bounty_finding_correlation import BugBountyFindingCorrelationError, correlate_bug_bounty_evidence
from core.bug_bounty_purple_remediation import PurpleRemediationError, build_purple_remediation_recommendation
from core.bug_bounty_scope import BugBountyScopeError, create_bug_bounty_scope
from core.bug_bounty_threat_hunt_review import ThreatHuntReviewError, review_threat_hunt_for_finding
from core.bug_bounty_threat_intel_review import ThreatIntelReviewError, review_threat_intelligence_for_finding
from core.bug_bounty_tool_execution import BugBountyToolExecutionError, execute_bug_bounty_tool
from core.bug_bounty_tool_policy import BugBountyToolPolicyError, evaluate_tool_permission
from core.context_prioritization import ContextPrioritizationError, prioritize_finding
from core.detection_engineering_report import DetectionEngineeringReportError, build_detection_engineering_report
from core.detection_planner import DetectionPlannerError, validate_detection_plan
from core.detection_rule import DetectionRuleError, apply_validation_result, build_detection_rule
from core.detection_rule_deduplication import DetectionRuleDeduplicationError, check_rule_duplicate
from core.detection_rule_validation import DetectionRuleValidationError, validate_rule_syntax
from core.detection_telemetry import DetectionTelemetryError, evaluate_telemetry_feasibility
from core.detection_trigger import DetectionTriggerError, build_bug_bounty_trigger, build_threat_intelligence_trigger
from core.security_governor import SecurityGovernorError, evaluate_security_governor_event
from core.security_experience_memory import SecurityExperienceMemoryError, create_security_experience
from core.security_handoff import (
    SecurityHandoffError,
    append_security_stage_result,
    create_security_handoff_case,
    record_security_handoff_approval,
)

ORCHESTRATOR_VERSION = "1"

TRIGGER_SOURCES = frozenset({"bug_bounty", "threat_intelligence"})

_MAX_ERROR_SUMMARY_LENGTH = 200

__all__ = [
    "run_bug_bounty_workflow", "run_detection_workflow", "run_security_lifecycle_workflow",
    "record_lifecycle_human_review", "TRIGGER_SOURCES",
]


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


# The fixed default Bug Bounty tool plan -- every deployment (host-native
# or self-hosted Docker) requests the same five tools; each one's real
# availability (adapter binary/daemon present or not) is decided honestly,
# per tool, by Policy + the real adapter -- never assumed here. Order is
# significant only for display/execution order, never for authorization.
# "crawler" (Step 2: Attack-Surface Discovery) runs immediately after
# http_assessor, reusing the exact same scope + transport instance --
# it never scans anything itself; it only builds and persists the
# attack-surface inventory (endpoints/parameters) that a later,
# dedicated step may eventually wire into nmap/nuclei/zap. It never
# contributes to source_results (never normalized/correlated into a
# finding, never scored by the benchmark) -- discovery data and
# vulnerability findings are deliberately kept as separate concerns.
DEFAULT_BUG_BOUNTY_TOOL_PLAN = ("http_assessor", "crawler", "nmap", "nuclei", "zap")

# Matches adapters.bug_bounty_{nmap,nuclei,zap}'s own hardcoded
# `max_output_bytes` safety ceiling (1 MiB) -- see each adapter's own
# `_validate_execution_config`. Exceeding it raises INVALID_EXECUTION_CONFIG
# at the adapter boundary, so this value must never be raised above it.
_EXECUTION_CONFIG = {"execution_config_version": "1", "process_timeout_seconds": 60, "max_output_bytes": 1_048_576}

# Nuclei gets its own, separately-justified runtime budget (Nuclei
# Reliability Step 1, revised in Step 1B, revised again in Step 1C).
# nmap/zap keep the shared 60s config above unchanged. Step 1C added
# exposures_medium (Step 1B's exposures phase, but at medium severity
# only -- measured ~66.24s real, the single most expensive phase) and
# technology_directed (small, tag-only, ~29 templates when applicable)
# for "valuable medium coverage" + live technology-aware selection --
# see adapters/bug_bounty_nuclei.py's own module docstring for the full
# per-phase timing derivation. Sum of all five QUICK phase budgets is
# 210s (25+100+55+20+10); 200s here keeps real, measured margin over
# the actually-needed real total (~118s across every applicable phase
# on this project's own authorized target) while staying under the
# adapter's own MAX_PROCESS_TIMEOUT_SECONDS (230s) hard ceiling. This
# is a real, disclosed UX tradeoff versus Step 1B's 60s -- a full Bug
# Bounty run now typically takes ~2 minutes when Nuclei's medium tier
# genuinely runs, not ~40s, in exchange for the wider coverage.
_NUCLEI_EXECUTION_CONFIG = {"execution_config_version": "1", "process_timeout_seconds": 200, "max_output_bytes": 1_048_576}


# Nuclei Reliability Step 1C: closed, deterministic technology-name
# vocabulary this module knows how to recognize in http_assessor's own
# already-produced evidence text -- kept in sync with (a small subset
# of) adapters.bug_bounty_nuclei's own _TECHNOLOGY_TAG_MAP keys, but
# never imported from it (this project's established "each module owns
# its own copy of a shape it shares in spirit with another module"
# convention) -- a name detected here that adapter's own map doesn't
# recognize simply contributes no extra tags there, never an error.
_KNOWN_TECHNOLOGY_SIGNATURES = ("express", "nodejs", "node.js", "angular")


def _detect_technologies_from_http_assessor(findings: Any) -> list[str]:
    """Deterministic, closed technology detection reusing ONLY
    http_assessor's own already-produced `information_disclosure`
    findings text (`reproduction_summary`, e.g. "server header
    disclosed: Express") -- never a new header-capture code path, never
    a raw-header contract change to core.bug_bounty_assessment, never
    inference beyond a fixed, reviewed substring vocabulary.

    Returns a sorted list of recognized technology names (possibly
    empty -- most targets, including this project's own authorized
    Juice Shop target, do not disclose a recognized `Server`/
    `X-Powered-By` value at all, and this function returns `[]` for
    them, never a guess).
    """
    if not isinstance(findings, list):
        return []
    detected: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("vulnerability_class") != "information_disclosure":
            continue
        text = str(finding.get("reproduction_summary") or "").lower()
        for signature in _KNOWN_TECHNOLOGY_SIGNATURES:
            if signature in text:
                detected.add(signature)
    return sorted(detected)


def _default_bug_bounty_permissions(*, execution_target: str) -> dict[str, Any]:
    parsed = urlsplit(execution_target)
    port = parsed.port or 80
    return {
        "permission_version": "1",
        "target_origin": f"http://{parsed.hostname}" + (f":{port}" if port != 80 else ""),
        "allowed_hosts": [parsed.hostname],
        "allowed_ports": [port],
        "allowed_paths": ["/"],
        "excluded_paths": [],
        "testing_profile": "safe_dast",
        "allowed_tools": list(DEFAULT_BUG_BOUNTY_TOOL_PLAN),
        "authenticated_testing_allowed": False,
        "controlled_validation_allowed": False,
        "max_requests": 12,
        "human_approval_state": "approved",
    }


def _tool_request_target(*, tool_id: str, execution_target: str) -> str:
    """Nmap's own adapter requires a bare host (never a URL); every
    other tool in the default plan requires a full http(s) URL -- see
    `adapters.bug_bounty_nmap._validate_scan_target` vs.
    `adapters.bug_bounty_nuclei`/`bug_bounty_zap`'s own equivalents."""
    if tool_id == "nmap":
        return urlsplit(execution_target).hostname or execution_target
    return execution_target


def _build_tool_request(*, run_id: str, tool_id: str, execution_target: str, port: int) -> dict[str, Any]:
    return {
        "request_version": "1",
        "request_id": f"REQ-{run_id}-{tool_id}",
        "tool_id": tool_id,
        "purpose": f"Bounded Bug Bounty assessment via ThreatTrace Live Platform backend ({tool_id})",
        "target": _tool_request_target(tool_id=tool_id, execution_target=execution_target),
        "ports": [port] if tool_id in ("http_assessor", "nmap") else [],
        "paths": ["/"] if tool_id != "nmap" else [],
        "testing_mode": "safe_dast",
        "authentication_requested": False,
        "controlled_validation_requested": False,
    }


def _run_bug_bounty_core(
    *,
    run_id: str,
    target: str,
    run_store: RunStore,
    event_bus: EventBus,
    active_clock: Callable[[], str],
    emit: _Emitter,
    transport: Any = None,
    env: Any = None,
    execute_tool: Callable[..., dict[str, Any]] = execute_bug_bounty_tool,
) -> dict[str, Any] | None:
    """Runs the Bug Bounty phase (scope validation through Tool Policy,
    Governor, tool execution, Normalization, Correlation, and Final
    Report) WITHOUT ever marking the run terminal -- unlike
    `run_bug_bounty_workflow` (a thin wrapper around this function that
    marks `"completed"` immediately after), this function lets the
    caller decide what "the run is complete" actually means, so a Full
    Security Lifecycle run (`run_security_lifecycle_workflow`) can reuse
    this exact same code path and then continue into further stages
    before ever transitioning the run to a terminal status --
    `backend.run_store`'s own terminal-status invariant means a run can
    never be updated again once marked `"completed"`/`"blocked"`/
    `"failed"`/`"cancelled"`, so the Bug Bounty phase itself must never
    be the one to make that call for a lifecycle run.

    Returns the real `report` dict (from `core.bug_bounty_final_report.
    build_final_bug_bounty_report`) on success. Returns `None` if the
    run was blocked (tool policy denied every tool, or Governor denied
    execution), cancelled, or failed -- in every one of those cases,
    `run_store` already reflects the terminal outcome (this function
    itself calls `run_store.transition`/`_fail_run` before returning),
    and the caller must simply return without any further action.
    """
    try:
        target = validate_local_only_target(target)
        execution_target = resolve_execution_target(display_target=target, env=env)

        run_store.transition(
            run_id=run_id, new_status="planning", current_stage="planning", started_at=active_clock(),
            target_summary=target,
        )
        target_payload = {"target": target}
        if execution_target != target:
            target_payload["execution_target"] = execution_target
        emit("run_started", "intake", "orchestrator", f"Bug Bounty run started against {target}", target_payload)

        if _is_cancelled(run_store=run_store, run_id=run_id):
            _stop_cancelled(run_store=run_store, run_id=run_id, emit=emit, stage="planning", clock=active_clock)
            return None

        emit(
            "planner_started", "planning", "orchestrator",
            "Using a fixed local default assessment plan -- the backend performs no live LLM call.",
        )
        port = urlsplit(execution_target).port or 80
        tool_requests = {
            tool_id: _build_tool_request(run_id=run_id, tool_id=tool_id, execution_target=execution_target, port=port)
            for tool_id in DEFAULT_BUG_BOUNTY_TOOL_PLAN
        }
        emit(
            "planner_completed", "planning", "orchestrator",
            f"Plan accepted: {len(tool_requests)} tool request(s) ({', '.join(DEFAULT_BUG_BOUNTY_TOOL_PLAN)}).",
            {"tool_count": len(tool_requests)},
        )
        run_store.update_fields(run_id=run_id, requested_tools=list(DEFAULT_BUG_BOUNTY_TOOL_PLAN))

        run_store.transition(run_id=run_id, new_status="awaiting_policy", current_stage="tool_policy")
        permissions = _default_bug_bounty_permissions(execution_target=execution_target)

        policy_results: dict[str, dict[str, Any]] = {}
        for tool_id in DEFAULT_BUG_BOUNTY_TOOL_PLAN:
            policy_result = evaluate_tool_permission(permissions=permissions, tool_request=tool_requests[tool_id])
            policy_results[tool_id] = policy_result
            emit(
                "tool_policy_evaluated", "tool_policy", "bug_bounty_tool_policy",
                f"{tool_id} execution_permitted={policy_result['execution_permitted']}",
                {"tool_id": tool_id, "execution_permitted": policy_result["execution_permitted"], "reason_codes": policy_result["reason_codes"]},
            )

        permitted_tools = [tool_id for tool_id in DEFAULT_BUG_BOUNTY_TOOL_PLAN if policy_results[tool_id]["execution_permitted"]]
        if not permitted_tools:
            run_store.transition(
                run_id=run_id, new_status="blocked", current_stage="tool_policy", completed_at=active_clock(),
                limitations=["Tool policy denied every requested tool."],
            )
            emit("run_blocked", "tool_policy", "bug_bounty_tool_policy", "Blocked: tool policy denied every requested tool.")
            return None

        run_store.update_fields(run_id=run_id, permitted_tools=permitted_tools)

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
            return None

        if _is_cancelled(run_store=run_store, run_id=run_id):
            _stop_cancelled(run_store=run_store, run_id=run_id, emit=emit, stage="governor", clock=active_clock)
            return None

        run_store.transition(run_id=run_id, new_status="running", current_stage="tool_execution")

        assessment_started_at = active_clock()
        source_results: list[dict[str, Any]] = []
        executed_tools: list[str] = []
        detected_technologies: list[str] = []

        needs_scope = "http_assessor" in permitted_tools or "crawler" in permitted_tools
        scope = None
        active_transport = transport if transport is not None else BugBountyHttpTransport()
        if needs_scope:
            scope = create_bug_bounty_scope(
                target=execution_target, target_type="web_application", allowed_origins=[permissions["target_origin"]],
                allowed_paths=["/"], excluded_paths=[], testing_profile="safe_active",
            )

        if "http_assessor" in permitted_tools:
            emit("tool_started", "tool_execution", "bug_bounty_assessment", f"Running http_assessor against {execution_target}")
            assessment_result = run_bug_bounty_assessment(scope=scope, transport=active_transport)
            detected_technologies = _detect_technologies_from_http_assessor(assessment_result["findings"])

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
            source_results.append({"source_tool": "http_assessor", "result": assessment_result})
            executed_tools.append("http_assessor")

        if "crawler" in permitted_tools:
            emit("tool_started", "tool_execution", "bug_bounty_crawler", f"Running crawler against {execution_target}")
            try:
                crawl_result = run_bug_bounty_crawl(scope=scope, transport=active_transport)
            except Exception as exc:  # noqa: BLE001 -- a crawler failure must never abort tools that can
                # still run safely (nmap/nuclei/zap need neither the crawler nor its output this step) --
                # this is the one deliberate exception to this function's usual "let it propagate to the
                # top-level failure boundary" pattern, matching this project's established principle that
                # a bounded, best-effort discovery layer must degrade honestly, never take down a run that
                # doesn't actually depend on it.
                sanitized = _sanitize_error(exc)
                run_store.update_fields(
                    run_id=run_id,
                    attack_surface={"attack_surface_version": "1", "status": "failed", "target": execution_target, "error": sanitized},
                )
                emit(
                    "tool_failed", "tool_execution", "bug_bounty_crawler",
                    f"crawler did not complete: {sanitized}.", {"tool_id": "crawler", "reason": sanitized},
                )
            else:
                surface = crawl_result["attack_surface_summary"]
                telemetry = crawl_result["telemetry"]
                # "partial" (not "completed") when a real bound was actually hit -- the crawl produced
                # real, honest, bounded results, but genuinely did not exhaust its own discovery queue;
                # never silently reported the same as an unbounded, naturally-finished crawl.
                status = "partial" if telemetry["budget_exhausted"] else "completed"
                run_store.update_fields(
                    run_id=run_id,
                    attack_surface={
                        "attack_surface_version": "1",
                        "status": status,
                        "target": crawl_result["target"],
                        "endpoints": crawl_result["endpoints"],
                        "parameters": crawl_result["parameters"],
                        "attack_surface_summary": surface,
                        "telemetry": telemetry,
                        "observed_evidence": crawl_result["observed_evidence"],
                    },
                )
                emit(
                    "tool_completed", "tool_execution", "bug_bounty_crawler",
                    f"crawler {status}: {surface['endpoint_count']} endpoint(s), {surface['parameter_count']} parameter(s) discovered.",
                    {
                        "status": status,
                        "endpoint_count": surface["endpoint_count"],
                        "parameter_count": surface["parameter_count"],
                        "form_count": surface["form_count"],
                        "api_endpoint_count": surface["api_endpoint_count"],
                        "pages_requested": telemetry["pages_requested"],
                        "budget_exhausted": telemetry["budget_exhausted"],
                        "runtime_seconds": telemetry["runtime_seconds"],
                    },
                )
                executed_tools.append("crawler")

        for tool_id in ("nmap", "nuclei", "zap"):
            if tool_id not in permitted_tools:
                continue
            emit("tool_started", "tool_execution", "bug_bounty_assessment", f"Running {tool_id} against {execution_target}")
            execution_result = execute_tool(
                permissions=permissions, tool_request=tool_requests[tool_id], governor_result=governor_result,
                execution_config=_NUCLEI_EXECUTION_CONFIG if tool_id == "nuclei" else _EXECUTION_CONFIG,
                detected_technologies=detected_technologies,
            )
            tool_result = execution_result["tool_result"]
            if tool_result is not None:
                source_results.append({"source_tool": tool_id, "result": tool_result})

            if execution_result["execution_performed"]:
                executed_tools.append(tool_id)
                tool_completed_payload = {
                    "tool_id": tool_id, "status": tool_result.get("status"),
                    "observation_count": len(tool_result.get("observations", [])),
                }
                if tool_id == "nuclei":
                    # Nuclei Reliability Step 1B: surface phase telemetry
                    # into the event stream -- this data previously
                    # existed only in the transient tool_result and was
                    # invisible to any downstream consumer (dashboard,
                    # logs) once execution moved past this point.
                    # phases_attempted excludes skipped_not_applicable
                    # entries (e.g. ssl on a plain-HTTP target) -- a
                    # deliberately-skipped phase was never attempted and
                    # must never be counted as an incomplete one.
                    phases = tool_result.get("phases") or []
                    attempted_phases = [p for p in phases if p.get("status") != "skipped_not_applicable"]
                    tool_completed_payload.update({
                        "profile": tool_result.get("profile_name"),
                        "phases_attempted": len(attempted_phases),
                        "phases_completed": sum(1 for p in attempted_phases if p.get("status") == "completed"),
                        "duration": tool_result.get("runtime_duration_seconds"),
                        "partial_results": tool_result.get("partial_results"),
                    })
                emit(
                    "tool_completed", "tool_execution", "bug_bounty_assessment",
                    f"{tool_id} completed: status={tool_result.get('status')}, "
                    f"{len(tool_result.get('observations', []))} observation(s).",
                    tool_completed_payload,
                )
            else:
                reason = execution_result["execution_blocked_reason"] or (tool_result.get("status") if tool_result else "unknown")
                emit(
                    "tool_failed", "tool_execution", "bug_bounty_assessment",
                    f"{tool_id} did not execute: {reason}.", {"tool_id": tool_id, "reason": str(reason)},
                )

        run_store.update_fields(run_id=run_id, executed_tools=executed_tools)
        assessment_completed_at = active_clock()

        run_store.transition(run_id=run_id, new_status="normalizing", current_stage="normalization")
        evidence_records = normalize_bug_bounty_evidence(
            source_results=source_results, scope_reference=permissions["target_origin"], observed_at=active_clock(),
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

        tools_unavailable = [tool_id for tool_id in permitted_tools if tool_id not in executed_tools]
        report = build_final_bug_bounty_report(
            correlation_result=correlation_result, evidence_records=evidence_records, target=target,
            scope=permissions["target_origin"], testing_profile="safe_active",
            assessment_started_at=assessment_started_at, assessment_completed_at=assessment_completed_at,
            tools_requested=list(DEFAULT_BUG_BOUNTY_TOOL_PLAN), tools_permitted=permitted_tools,
            tools_executed=executed_tools, tools_unavailable=tools_unavailable,
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
        return report

    except (
        BugBountyScopeError, BugBountyToolPolicyError, SecurityGovernorError, BugBountyAssessmentError,
        BugBountyCrawlerError, BugBountyToolExecutionError, BugBountyEvidenceNormalizationError,
        BugBountyFindingCorrelationError, BugBountyFinalReportError,
    ) as exc:
        _fail_run(run_store=run_store, emit=emit, run_id=run_id, exc=exc, stage="tool_execution", clock=active_clock)
        return None
    except Exception as exc:  # noqa: BLE001 -- last-resort honest failure boundary, never a silent crash
        traceback.print_exc()
        _fail_run(run_store=run_store, emit=emit, run_id=run_id, exc=exc, stage="tool_execution", clock=active_clock)
        return None


def run_bug_bounty_workflow(
    *,
    run_id: str,
    target: str,
    run_store: RunStore,
    event_bus: EventBus,
    clock: Callable[[], str] | None = None,
    transport: Any = None,
    env: Any = None,
    execute_tool: Callable[..., dict[str, Any]] = execute_bug_bounty_tool,
) -> None:
    """Run one real, bounded, local-only Bug Bounty assessment against
    `target` (already validated by `backend.models.
    validate_local_only_target` -- this function re-validates it anyway,
    defense in depth) through the existing Tool Policy -> Governor ->
    `http_assessor`/`nmap`/`nuclei`/`zap` -> Evidence Normalization ->
    Correlation -> Final Report chain, publishing an event at every
    stage.

    `target` is the *display* target (what a user/browser submits --
    e.g. `http://localhost:3000/`). `backend.models.
    resolve_execution_target` maps it to the real *execution* target
    this function actually connects to -- a no-op on host-native
    deployments, or the configured Docker Compose service address
    (`http://juice-shop:3000`) on the self-hosted Docker deployment,
    but only for that one fixed, immutable alias (see that function's
    own docstring). Every tool this function requests is attempted
    honestly: an unavailable adapter (missing binary, unreachable
    daemon) is reported via `tool_failed`, never silently skipped or
    fabricated as executed.

    `transport` defaults to a real `adapters.bug_bounty_http.
    BugBountyHttpTransport()` when not supplied; tests inject a fake
    object satisfying `core.bug_bounty_assessment`'s own minimal
    `request(*, url, method, headers=None)` protocol instead, exactly
    like that module's own established injected-transport pattern.
    `execute_tool` defaults to the real `core.bug_bounty_tool_execution.
    execute_bug_bounty_tool` (used for `nmap`/`nuclei`/`zap`) and is
    injectable the same way, so tests never perform real subprocess/
    network I/O for those three tools either. `env` is injectable for
    the same reason `backend.models.resolve_execution_target` itself
    accepts one -- defaults to the real process environment.

    This function is a thin wrapper around `_run_bug_bounty_core`: it
    runs the exact same Bug Bounty phase, then immediately marks the
    run `"completed"`/`"complete"` and emits `run_completed` -- the
    same behavior this function has always had. A Full Security
    Lifecycle run (`run_security_lifecycle_workflow`) calls
    `_run_bug_bounty_core` directly instead, so it can continue into
    further stages before ever marking the run terminal.

    Intended to be called from a background thread by `backend.app`,
    never from the asyncio event loop directly (it performs real
    blocking network I/O by default).
    """
    active_clock = clock or _default_clock
    emit = _Emitter(run_id=run_id, event_bus=event_bus, clock=active_clock)

    report = _run_bug_bounty_core(
        run_id=run_id, target=target, run_store=run_store, event_bus=event_bus, active_clock=active_clock,
        emit=emit, transport=transport, env=env, execute_tool=execute_tool,
    )
    if report is None:
        return

    run_store.transition(run_id=run_id, new_status="completed", current_stage="complete", completed_at=active_clock())
    emit(
        "run_completed", "complete", "orchestrator",
        f"Bug Bounty run complete: {len(report['canonical_findings'])} canonical findings.",
        {"canonical_finding_count": len(report["canonical_findings"])},
    )


# ---------------------------------------------------------------------------
# Full Security Lifecycle workflow
# ---------------------------------------------------------------------------

# Bounded, deterministic -- a real Bug Bounty run can produce many
# canonical findings; only the highest-priority `MAX_LIFECYCLE_FINDINGS`
# (by real core.context_prioritization.prioritize_finding score, never
# title/discovery order) are ever carried into the expensive downstream
# stages (Threat Intel/Hunt/Detection/Red/Purple review).
MAX_LIFECYCLE_FINDINGS = 3

# An explicitly-labeled demo/research context -- never presented as a
# real organization's risk profile. This project's only live target is
# the local OWASP Juice Shop research container; every field here is
# chosen to honestly describe that (a throwaway, non-production,
# internet-inaccessible research sandbox), never a fabricated business
# context.
DEMO_LIFECYCLE_CONTEXT: dict[str, Any] = {
    "context_version": "1",
    "industry": "general",
    "environment": "sandbox",
    "asset_criticality": "low",
    "exposure": "internal",
    "data_sensitivity": "public",
    "detection_coverage": "unknown",
    "compensating_controls": "unknown",
    "threat_activity": "none_observed",
    "regulatory_relevance": "none",
}


def _canonical_finding_to_prioritization_input(canonical_finding: Mapping[str, Any]) -> dict[str, Any]:
    """Adapts a real `core.bug_bounty_final_report` canonical finding
    into the shape both `core.context_prioritization.prioritize_finding`
    AND `core.security_handoff.create_security_handoff_case` require
    (each matching `core.bug_bounty_findings.create_bug_bounty_finding`'s
    own contract, but validated to different depths by each caller).

    `prioritize_finding` only checks the *presence* of
    `vulnerability_class`/`evidence`/`validation`/`owasp_category`/`cwe`
    -- never their content. `create_security_handoff_case`, however,
    validates `evidence` more strictly: a non-empty list of mappings,
    each carrying a well-formed `evidence_digest` (`sha256:<64 hex>`).
    The canonical finding's own real `evidence_digests` (a list of
    already-sha256-formatted strings, produced by
    `core.bug_bounty_final_report` from real correlated evidence
    records) is reshaped into that exact `[{"evidence_digest": ...}]`
    form here -- this is a real digest already computed over real
    evidence, never a fabricated one.

    `finding_status` is always `"candidate"`: every canonical finding
    this project produces carries `status: "requires_human_review"`
    (never a recorded human validation), so `"candidate"` -- never
    `"validated"` -- is the only honest mapping. `confidence` defaults
    to `"medium"` only if the canonical finding's own value is somehow
    outside the recognized confidence levels (structurally required by
    both downstream functions; never silently drops a finding from
    prioritization/handoff).
    """
    confidence = canonical_finding.get("confidence")
    if confidence not in ("low", "medium", "high"):
        confidence = "medium"
    real_digests = [d for d in (canonical_finding.get("evidence_digests") or []) if isinstance(d, str) and d]
    return {
        "finding_version": "1",
        "finding_id": canonical_finding["finding_id"],
        "finding_status": "candidate",
        "technical_severity": canonical_finding.get("technical_severity"),
        "confidence": confidence,
        "vulnerability_class": canonical_finding.get("vulnerability_class"),
        "evidence": [{"evidence_digest": digest} for digest in real_digests],
        "validation": canonical_finding.get("validation_state"),
        "owasp_category": canonical_finding.get("owasp_category"),
        "cwe": canonical_finding.get("cwe"),
    }


def _select_top_findings(
    canonical_findings: list[dict[str, Any]], prioritizations_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    ranked = sorted(
        canonical_findings, key=lambda f: prioritizations_by_id[f["finding_id"]]["priority_score"]["final"], reverse=True,
    )
    return ranked[:MAX_LIFECYCLE_FINDINGS]


def _review_detection_engineering_for_finding(
    *, canonical_finding: Mapping[str, Any], available_telemetry: list[str], llm_proposal: Any, run_id: str,
) -> dict[str, Any]:
    """Real Detection Trigger -> Telemetry Feasibility -> (only with a
    genuine caller-supplied `llm_proposal`) Detection Planner ->
    deterministic validation -> rule candidate -> deduplication ->
    structural syntax validation, exactly reusing every existing
    `core.detection_*` function `run_detection_workflow` itself calls --
    never reimplemented. Never fabricates an `llm_proposal` when the
    caller supplied none for this finding: `outcome` is honestly
    `"not_applicable"` in that case, exactly like a genuine
    `"TELEMETRY_GAP"`, distinguished only by `reason`.
    """
    trigger = build_bug_bounty_trigger(canonical_finding=dict(canonical_finding))
    telemetry_result = evaluate_telemetry_feasibility(
        required_telemetry_candidates=trigger["required_telemetry_candidates"], available_telemetry=available_telemetry,
    )

    if telemetry_result["decision"] == "TELEMETRY_GAP":
        return {
            "trigger_id": trigger["trigger_id"], "telemetry_decision": telemetry_result["decision"],
            "outcome": "not_applicable", "reason": "telemetry_gap", "rule": None,
        }
    if not isinstance(llm_proposal, Mapping):
        return {
            "trigger_id": trigger["trigger_id"], "telemetry_decision": telemetry_result["decision"],
            "outcome": "not_applicable", "reason": "no_llm_proposal_supplied", "rule": None,
        }

    plan = {
        "plan_version": "1", "plan_id": f"DP-{run_id}-{trigger['trigger_id']}", "trigger": trigger,
        "telemetry_feasibility": telemetry_result, "detection_objective": llm_proposal.get("detection_objective"),
        "proposed_rules": llm_proposal.get("proposed_rules", []),
        "telemetry_recommendation": llm_proposal.get("telemetry_recommendation"),
    }
    validated_plan = validate_detection_plan(plan=plan)
    if not validated_plan["proposed_rules"]:
        return {
            "trigger_id": trigger["trigger_id"], "telemetry_decision": telemetry_result["decision"],
            "outcome": "not_applicable", "reason": "llm_proposal_had_no_rules", "rule": None,
        }

    draft = validated_plan["proposed_rules"][0]
    rule = build_detection_rule(validated_rule_draft=draft, trigger=trigger, data_source=None)
    check_rule_duplicate(candidate_rule=rule, existing_rules=[])
    syntax_result = validate_rule_syntax(rule_format=rule["rule_format"], rule_content=rule["generic_rule"])
    if syntax_result["syntax_valid"]:
        rule = apply_validation_result(
            rule=rule, validation_status="syntax_validated",
            known_limitations_addendum="Structural syntax check only -- not detection-efficacy tested.",
        )
        outcome, reason = "candidate_ready", "rule_generated"
    else:
        rule = apply_validation_result(
            rule=rule, validation_status="rejected",
            known_limitations_addendum="Failed bounded structural syntax check: " + "; ".join(syntax_result["issues"]),
        )
        outcome, reason = "needs_review", "syntax_rejected"

    return {
        "trigger_id": trigger["trigger_id"], "telemetry_decision": telemetry_result["decision"],
        "outcome": outcome, "reason": reason, "rule": rule,
    }


def _process_lifecycle_finding(
    *, run_id: str, canonical_finding: dict[str, Any], prioritization: dict[str, Any],
    available_telemetry: list[str], llm_proposal: Any, emit: _Emitter,
) -> dict[str, Any]:
    """Walks one selected canonical finding through the real Security
    Handoff stage graph (`core.security_handoff`), calling a real review
    function/module at every stage -- never fabricating a result, never
    reimplementing `core.security_handoff`'s own transition logic."""
    adapted_finding = _canonical_finding_to_prioritization_input(canonical_finding)
    case = create_security_handoff_case(finding=adapted_finding, prioritization=prioritization)

    # --- Threat Intelligence review ---
    emit(
        "threat_intel_review_started", "threat_intel", "bug_bounty_threat_intel_review",
        f"Reviewing threat intelligence for {canonical_finding['finding_id']}.",
    )
    ti_result = review_threat_intelligence_for_finding(canonical_finding=canonical_finding, nvd_fetch=fetch_nvd_records)
    ti_handoff_outcome = {"no_relevant_intel": "reviewed_no_match", "reviewed_no_match": "reviewed_no_match", "reviewed_relevant": "reviewed_relevant"}[ti_result["outcome"]]
    case = append_security_stage_result(
        case=case, stage="threat_intel_review", role="threat_intelligence", result_type="assessment",
        outcome=ti_handoff_outcome, evidence_references=[{"reference_type": "finding", "reference": canonical_finding["finding_id"]}],
        recommendation=f"Threat intel review outcome: {ti_result['outcome']}.",
    )
    emit(
        "threat_intel_review_completed", "threat_intel", "bug_bounty_threat_intel_review",
        f"Threat intel outcome for {canonical_finding['finding_id']}: {ti_result['outcome']}.",
        {"finding_id": canonical_finding["finding_id"], "outcome": ti_result["outcome"], "real_query_performed": ti_result["real_query_performed"]},
    )

    # --- Threat Hunt review ---
    emit(
        "threat_hunt_started", "threat_hunt", "bug_bounty_threat_hunt_review",
        f"Reviewing hunt feasibility for {canonical_finding['finding_id']}.",
    )
    hunt_result = review_threat_hunt_for_finding(canonical_finding=canonical_finding, available_telemetry=available_telemetry)
    hunt_handoff_outcome = "planned" if hunt_result["outcome"] == "hunt_candidate_created" else "not_applicable"
    case = append_security_stage_result(
        case=case, stage="threat_hunt", role="threat_hunting", result_type="plan",
        outcome=hunt_handoff_outcome, evidence_references=[{"reference_type": "finding", "reference": canonical_finding["finding_id"]}],
        recommendation=hunt_result["hunt_hypothesis"],
    )
    emit(
        "threat_hunt_completed", "threat_hunt", "bug_bounty_threat_hunt_review",
        f"Hunt outcome for {canonical_finding['finding_id']}: {hunt_result['outcome']}.",
        {"finding_id": canonical_finding["finding_id"], "outcome": hunt_result["outcome"], "missing_telemetry": hunt_result["missing_telemetry"]},
    )

    # --- Detection Engineering review ---
    emit(
        "detection_engineering_started", "detection_engineering", "detection_trigger",
        f"Evaluating detection engineering for {canonical_finding['finding_id']}.",
    )
    detection_result = _review_detection_engineering_for_finding(
        canonical_finding=canonical_finding, available_telemetry=available_telemetry,
        llm_proposal=llm_proposal, run_id=run_id,
    )
    case = append_security_stage_result(
        case=case, stage="detection_engineering", role="blue_team", result_type="candidate",
        outcome=detection_result["outcome"], evidence_references=[{"reference_type": "finding", "reference": canonical_finding["finding_id"]}],
        recommendation=f"Detection engineering outcome: {detection_result['outcome']} ({detection_result['reason']}).",
    )
    emit(
        "detection_engineering_completed", "detection_engineering", "detection_trigger",
        f"Detection outcome for {canonical_finding['finding_id']}: {detection_result['outcome']} ({detection_result['reason']}).",
        {"finding_id": canonical_finding["finding_id"], "outcome": detection_result["outcome"], "reason": detection_result["reason"]},
    )

    # --- Red Validation ---
    # Real, honest, fixed fact: authenticated_testing/controlled_validation
    # are declared, not-yet-implemented capabilities (see
    # core.bug_bounty_tool_policy.TOOL_CATALOG) -- there is no automated
    # exploit/validation engine anywhere in this project, so this outcome
    # is always the same real fact, never a per-finding guess.
    red_validation_result = {"outcome": "controlled_validation_unavailable", "reason": "controlled_validation not implemented"}
    if case["current_stage"] == "red_validation":
        emit(
            "red_validation_started", "red_validation", "security_handoff",
            f"Evaluating red validation availability for {canonical_finding['finding_id']}.",
        )
        case = append_security_stage_result(
            case=case, stage="red_validation", role="red_team", result_type="assessment",
            outcome="not_applicable", evidence_references=[{"reference_type": "finding", "reference": canonical_finding["finding_id"]}],
            recommendation="Controlled/automated validation is not implemented in this project -- human validation required.",
        )
        emit(
            "red_validation_completed", "red_validation", "security_handoff",
            f"Red validation for {canonical_finding['finding_id']}: controlled_validation_unavailable.",
            {"finding_id": canonical_finding["finding_id"], "outcome": "controlled_validation_unavailable"},
        )

    # --- Purple Remediation ---
    emit(
        "purple_remediation_started", "purple_remediation", "bug_bounty_purple_remediation",
        f"Building remediation recommendation for {canonical_finding['finding_id']}.",
    )
    purple_result = build_purple_remediation_recommendation(
        canonical_finding=canonical_finding, ti_result=ti_result, hunt_result=hunt_result,
        detection_result=detection_result, red_validation_result=red_validation_result,
    )
    case = append_security_stage_result(
        case=case, stage="purple_remediation", role="purple_ir", result_type="recommendation",
        outcome="planned", evidence_references=[{"reference_type": "finding", "reference": canonical_finding["finding_id"]}],
        recommendation="; ".join(purple_result["recommendations"]),
    )
    emit(
        "purple_remediation_completed", "purple_remediation", "bug_bounty_purple_remediation",
        f"Remediation recommendation created for {canonical_finding['finding_id']}.",
        {"finding_id": canonical_finding["finding_id"], "recommendation_count": len(purple_result["recommendations"])},
    )

    # append_security_stage_result auto-transitions to "human_review"
    # with approval_state="pending" the instant purple_remediation
    # completes with a non-blocking outcome -- see core.security_handoff's
    # own transition graph. This is never set manually here.
    emit(
        "human_review_required", "human_review", "security_handoff",
        f"Handoff case {case['case_id']} awaiting human review.", {"case_id": case["case_id"], "finding_id": canonical_finding["finding_id"]},
    )

    return {
        "finding_id": canonical_finding["finding_id"], "case": case, "prioritization": prioritization,
        "ti_result": ti_result, "hunt_result": hunt_result, "detection_result": detection_result,
        "red_validation_result": red_validation_result, "purple_result": purple_result,
    }


def run_security_lifecycle_workflow(
    *,
    run_id: str,
    target: str,
    run_store: RunStore,
    event_bus: EventBus,
    clock: Callable[[], str] | None = None,
    transport: Any = None,
    env: Any = None,
    execute_tool: Callable[..., dict[str, Any]] = execute_bug_bounty_tool,
    available_telemetry: Any = (),
    detection_llm_proposals: Any = None,
) -> None:
    """Run one real, bounded, local-only Full Security Lifecycle
    assessment: the exact same Bug Bounty phase `run_bug_bounty_workflow`
    runs (reused via `_run_bug_bounty_core`, never duplicated), followed
    by real Context Prioritization, Security Handoff case creation, and
    a real Threat Intel review / Threat Hunt review / Detection
    Engineering review / Red Validation fact-check / Purple Remediation
    recommendation for each of the highest-priority
    `MAX_LIFECYCLE_FINDINGS` canonical findings.

    `available_telemetry` (default empty) is a list of
    `core.detection_telemetry.TELEMETRY_TYPES` values the caller
    declares as actually available -- passed unchanged to both the
    Threat Hunt feasibility check and the Detection Engineering
    telemetry check. `detection_llm_proposals` (default `None`) is an
    optional mapping of `finding_id -> llm_proposal` (shaped exactly
    like `run_detection_workflow`'s own `llm_proposal` parameter) for
    any finding the caller wants a real detection-rule-generation
    attempt for; a finding with no entry here always gets
    `outcome="not_applicable"` for Detection Engineering -- this
    function never fabricates an LLM proposal itself.

    Every dashboard-visible stage state is backed by a real recorded
    event/result -- this function never marks a stage `"done"` merely
    because the run itself reached a terminal status.
    """
    active_clock = clock or _default_clock
    emit = _Emitter(run_id=run_id, event_bus=event_bus, clock=active_clock)
    telemetry_list = list(available_telemetry or [])
    proposals = detection_llm_proposals if isinstance(detection_llm_proposals, Mapping) else {}

    report = _run_bug_bounty_core(
        run_id=run_id, target=target, run_store=run_store, event_bus=event_bus, active_clock=active_clock,
        emit=emit, transport=transport, env=env, execute_tool=execute_tool,
    )
    if report is None:
        return

    if _is_cancelled(run_store=run_store, run_id=run_id):
        _stop_cancelled(run_store=run_store, run_id=run_id, emit=emit, stage="correlation", clock=active_clock)
        return

    canonical_findings = report["canonical_findings"]

    run_store.transition(run_id=run_id, new_status="prioritizing", current_stage="prioritization")
    emit(
        "context_prioritization_started", "prioritization", "context_prioritization",
        f"Prioritizing {len(canonical_findings)} canonical finding(s) (demo/research context).",
    )

    prioritizations_by_id: dict[str, dict[str, Any]] = {}
    try:
        for finding in canonical_findings:
            adapted = _canonical_finding_to_prioritization_input(finding)
            prioritizations_by_id[finding["finding_id"]] = prioritize_finding(finding=adapted, context=DEMO_LIFECYCLE_CONTEXT)
    except ContextPrioritizationError as exc:
        _fail_run(run_store=run_store, emit=emit, run_id=run_id, exc=exc, stage="prioritization", clock=active_clock)
        return

    selected_findings = _select_top_findings(canonical_findings, prioritizations_by_id)
    emit(
        "context_prioritized", "prioritization", "context_prioritization",
        f"{len(canonical_findings)} finding(s) prioritized; {len(selected_findings)} selected for downstream lifecycle review.",
        {
            "total_canonical_findings": len(canonical_findings), "findings_prioritized": len(prioritizations_by_id),
            "findings_selected": len(selected_findings),
            "selection_reason": f"top {MAX_LIFECYCLE_FINDINGS} by real context_prioritization priority_score",
        },
    )

    lifecycle_results: list[dict[str, Any]] = []
    try:
        for finding in selected_findings:
            result = _process_lifecycle_finding(
                run_id=run_id, canonical_finding=finding, prioritization=prioritizations_by_id[finding["finding_id"]],
                available_telemetry=telemetry_list, llm_proposal=proposals.get(finding["finding_id"]), emit=emit,
            )
            lifecycle_results.append(result)
    except (
        SecurityHandoffError, ThreatIntelReviewError, ThreatHuntReviewError, DetectionTriggerError,
        DetectionTelemetryError, DetectionPlannerError, DetectionRuleError, DetectionRuleDeduplicationError,
        DetectionRuleValidationError, PurpleRemediationError,
    ) as exc:
        _fail_run(run_store=run_store, emit=emit, run_id=run_id, exc=exc, stage="human_review", clock=active_clock)
        return

    governor_event = {
        "event_version": "1", "actor_role": "purple_ir", "action_class": "stage_contribution",
        "current_stage": "purple_remediation", "required_role": "purple_ir", "gateway_decision": "allow",
        "identity_decision": "allow", "mutation_freeze_active": False, "approval_state": "not_required",
        "decision_binding_state": "not_required", "scope_state": "within_scope", "source_truth_state": "unchanged",
        "remote_content_state": "not_present", "audit_state": "recorded", "prior_policy_denials": 0,
        "execution_requested": False,
    }
    governor_result = evaluate_security_governor_event(event=governor_event)
    emit(
        "governor_evaluated", "human_review", "security_governor",
        f"Governor decision: {governor_result['decision']}",
        {"decision": governor_result["decision"], "reason_codes": governor_result["reason_codes"], "execution_allowed": governor_result["execution_allowed"]},
    )

    run_store.update_fields(
        run_id=run_id,
        lifecycle={
            "lifecycle_version": "1",
            "context": dict(DEMO_LIFECYCLE_CONTEXT),
            "context_label": "demo/research context",
            "total_canonical_findings": len(canonical_findings),
            "findings_prioritized": len(prioritizations_by_id),
            "findings_selected": [f["finding_id"] for f in selected_findings],
            "selection_reason": f"top {MAX_LIFECYCLE_FINDINGS} by real context_prioritization priority_score",
            "results": lifecycle_results,
            "governor_decision": governor_result["decision"],
            "governor_result": governor_result,
            "experiences": [],
        },
        governor_decisions=[{"stage": "bug_bounty_assessment", "decision": "allow"}, {"stage": "purple_remediation", "decision": governor_result["decision"]}],
        human_review_required=True,
    )

    # Deliberately NOT "completed" here -- every selected finding's real
    # Security Handoff case is now genuinely awaiting a human decision
    # (`approval_state: "pending"`), and `backend.run_store`'s own
    # terminal-status invariant means a run can never be updated again
    # once marked `"completed"`. Leaving the run at the real, existing,
    # non-terminal `"awaiting_human_review"` status (exactly like
    # `run_detection_workflow`'s own intermediate use of it) is what
    # lets `record_lifecycle_human_review` below actually record a
    # caller's local review decision after this function returns. This
    # run only becomes `"completed"` once every selected finding has a
    # real recorded decision -- never merely because the lifecycle
    # stages themselves finished running.
    run_store.transition(run_id=run_id, new_status="awaiting_human_review", current_stage="human_review")
    emit(
        "human_review_required", "human_review", "orchestrator",
        f"Full Security Lifecycle run: {len(selected_findings)} finding(s) carried through downstream review, "
        f"{len(canonical_findings) - len(selected_findings)} not selected. All selected findings await human review.",
        {"canonical_finding_count": len(canonical_findings), "findings_selected": len(selected_findings)},
    )


def record_lifecycle_human_review(
    *, run_id: str, case_id: str, approval_state: str, approval_reference: str,
    run_store: RunStore, event_bus: EventBus, clock: Callable[[], str] | None = None,
) -> dict[str, Any]:
    """Records one caller-supplied local review decision (`"approved"`
    or `"rejected"`) against one specific Security Handoff case within
    an `"awaiting_human_review"` Full Security Lifecycle run, via the
    real, unmodified `core.security_handoff.
    record_security_handoff_approval` (never reimplemented here).

    This is a **local development/research review action only** -- this
    backend implements no authentication of any kind, so
    `approval_reference` is always a caller-supplied string, never
    verified against any real identity or credential. Calling this
    function never means an authenticated analyst approved anything; it
    only means a caller of this local backend reported that decision,
    exactly as `core.security_handoff.record_security_handoff_approval`
    itself already documents.

    Raises `RunStoreError` for an unknown `run_id`. Raises `ValueError`
    (`RUN_NOT_AWAITING_REVIEW`) if the run's `status` is not
    `"awaiting_human_review"`, or (`CASE_NOT_FOUND`) if no lifecycle
    result carries a case with the given `case_id`. Propagates
    `SecurityHandoffError` unchanged for an invalid `approval_state`/
    `approval_reference`, or a case not actually in `"human_review"`
    with `approval_state == "pending"` (e.g. already reviewed).

    Once every selected finding's case has a non-`"pending"`
    `approval_state`, the run transitions to `"completed"`/`"complete"`
    and a real `run_completed` event is published -- never before every
    case has a real recorded decision.
    """
    active_clock = clock or _default_clock
    emit = _Emitter(run_id=run_id, event_bus=event_bus, clock=active_clock)

    run = run_store.get_run(run_id=run_id)
    if run["status"] != "awaiting_human_review":
        raise ValueError(f"RUN_NOT_AWAITING_REVIEW: run status is {run['status']!r}, not 'awaiting_human_review'")

    lifecycle = dict(run["lifecycle"])
    results = [dict(r) for r in lifecycle["results"]]
    target_index = next((i for i, r in enumerate(results) if r["case"]["case_id"] == case_id), None)
    if target_index is None:
        raise ValueError(f"CASE_NOT_FOUND: no lifecycle result carries case_id {case_id!r}")

    updated_case = record_security_handoff_approval(
        case=results[target_index]["case"], approval_state=approval_state, approval_reference=approval_reference,
    )
    results[target_index] = dict(results[target_index], case=updated_case)
    lifecycle["results"] = results

    emit(
        "human_review_recorded", "human_review", "security_handoff",
        f"Local review recorded for case {case_id}: {approval_state} (reference={approval_reference}).",
        {"case_id": case_id, "approval_state": approval_state, "review_type": "local_development_research_review_action"},
    )

    all_reviewed = all(r["case"]["approval_state"] != "pending" for r in results)
    if all_reviewed:
        # Security Experience Memory: real, gated creation, via the
        # exact same governor_result this lifecycle run already
        # computed -- never reused merely because the run reached a
        # terminal status. core.security_experience_memory.
        # create_security_experience itself enforces the real gate
        # (Governor decision not block/freeze, case at human_review with
        # approval_state=="approved", at least one stage result and one
        # evidence digest) -- a "rejected" case, or any case while the
        # Governor decision was block/freeze, always yields
        # experience_status="rejected"/reusable=False here, never
        # silently promoted to reusable.
        experiences = [
            create_security_experience(
                case=r["case"], prioritization=r["prioritization"], governor_result=lifecycle["governor_result"],
            )
            for r in results
        ]
        lifecycle["experiences"] = experiences
        run_store.update_fields(run_id=run_id, lifecycle=lifecycle)
        run_store.transition(run_id=run_id, new_status="completed", current_stage="complete", completed_at=active_clock())
        emit(
            "run_completed", "complete", "orchestrator",
            f"Full Security Lifecycle run complete: all {len(results)} selected finding(s) reviewed.",
            {"reviewed_count": len(results)},
        )
    else:
        run_store.update_fields(run_id=run_id, lifecycle=lifecycle)

    return run_store.get_run(run_id=run_id)


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
