"""Focused tests for backend.orchestrator -- sequencing of existing
`core.*` calls with mocked/fixture inputs (Block 15J-K). These tests
never perform real network I/O; the Bug Bounty workflow is always
exercised with a fake injected transport.
"""

from __future__ import annotations

import pytest

import backend.orchestrator as orchestrator
from backend.event_bus import EventBus
from backend.run_store import RunStore


def _clock_factory():
    counter = {"n": 0}

    def clock():
        counter["n"] += 1
        return f"t{counter['n']}"

    return clock


class _FakeTransport:
    def __init__(self, *, status_code=200, headers=None, body="<html></html>"):
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/html"}
        self.body = body
        self.calls = []

    def request(self, *, url, method, headers=None):
        self.calls.append((url, method))
        return {
            "url": url, "status_code": self.status_code, "headers": self.headers,
            "body_excerpt": self.body, "redirect_location": None, "request_performed": True,
        }


def _ti_record(**overrides):
    record = {
        "ti_record_version": "1", "intel_id": "TI-1", "source_type": "cisa_kev", "source_name": "CISA KEV",
        "source_reference": "https://example.test/kev", "title": "Test SQLi", "summary": "Test summary",
        "published_at": "2026-01-01T00:00:00Z", "modified_at": None, "observed_at": "2026-01-01T00:00:00Z",
        "cve": ["CVE-2026-1"], "cwe": [], "owasp": [], "affected_products": ["TestApp"], "affected_versions": [],
        "ioc": {"ip": [], "domain": [], "url": [], "file_hash": []}, "actor": None, "campaign": None,
        "attack": {"tactic": [], "technique": [], "subtechnique": []}, "behavioral_indicators": [],
        "exploitation_status": "exploited_in_wild", "known_exploited": True, "epss_score": None, "confidence": "high",
        "corroboration_state": "single_source", "evidence_references": ["https://example.test/kev#1"],
        "source_reliability": "high", "information_credibility": "high", "limitations": [],
    }
    record.update(overrides)
    return record


def _llm_proposal():
    return {
        "detection_objective": "Detect exploitation behavior.",
        "proposed_rules": [{
            "rule_draft_id": "RD-1-sigma", "rule_format": "sigma", "title": "Test rule",
            "description": "Test description of detection logic and rationale for this rule.",
            "generic_rule_content": (
                "title: Test rule\nid: test-rule\nstatus: experimental\ndescription: test\n"
                "logsource:\n  category: process_creation\ndetection:\n  selection:\n    EventID: 1\n"
                "  condition: selection\nlevel: high\n"
            ),
            "context_tuned_rule_content": None,
            "false_positive_considerations": ["Some benign admin activity may match."],
            "required_telemetry": ["process_creation"],
        }],
        "telemetry_recommendation": None,
    }


class TestBugBountyWorkflowOrdering:
    def test_001_happy_path_event_order(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(),
        )
        events = [e["event_type"] for e in bus.get_events(run_id=run["run_id"])]
        assert events == [
            "run_started", "planner_started", "planner_completed", "tool_policy_evaluated",
            "governor_evaluated", "tool_started", "tool_completed", "http_assessment_completed",
            "evidence_normalized", "finding_correlated", "canonical_finding_created", "run_completed",
        ]
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "completed"
        assert final["report"] is not None

    def test_002_slot_released_after_completion(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.try_acquire_bug_bounty_slot(run_id=run["run_id"])
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(),
        )
        assert store.active_bug_bounty_run_id() is None


class TestBugBountyGovernorBlocking:
    def test_003_blocked_governor_never_executes_tool(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        transport = _FakeTransport()

        def _blocked(*, event):
            return {
                "governor_version": "1", "decision": "block", "reason_codes": ["ROLE_SCOPE_VIOLATION"],
                "actor_role": event["actor_role"], "action_class": event["action_class"],
                "human_review_required": True, "mutation_freeze_recommended": False,
                "execution_allowed": False, "observable_only": True, "execution_performed": False,
            }

        monkeypatch.setattr(orchestrator, "evaluate_security_governor_event", _blocked)
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=transport,
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "blocked"
        assert transport.calls == []

    def test_004_denied_tool_policy_never_reaches_governor(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        transport = _FakeTransport()
        governor_calls = []

        def _denied(*, permissions, tool_request):
            return {
                "policy_version": "1", "request_id": tool_request["request_id"], "tool_id": tool_request["tool_id"],
                "analyst_permitted": False, "profile_permitted": True, "adapter_available": True,
                "human_approval_required": False, "approval_satisfied": True, "execution_permitted": False,
                "reason_codes": ["TOOL_NOT_ALLOWED"], "execution_performed": False,
            }

        def _tracking_governor(*, event):
            governor_calls.append(event)
            return orchestrator.evaluate_security_governor_event(event=event)

        monkeypatch.setattr(orchestrator, "evaluate_tool_permission", _denied)
        monkeypatch.setattr(orchestrator, "evaluate_security_governor_event", _tracking_governor)
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=transport,
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "blocked"
        assert governor_calls == []
        assert transport.calls == []


class TestBugBountyCancellation:
    def test_005_cooperative_cancellation_before_execution(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.update_fields(run_id=run["run_id"], cancellation_requested=True)
        transport = _FakeTransport()
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=transport,
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "cancelled"
        assert transport.calls == []


class TestBugBountyFailureHandling:
    def test_006_invalid_target_fails_before_any_stage(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://example.com/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(),
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "failed"
        assert "INVALID_TARGET" in final["error_summary"]

    def test_007_unexpected_exception_never_crashes_caller(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")

        def _boom(*, permissions, tool_request):
            raise RuntimeError("unexpected failure detail that must never leak")

        monkeypatch.setattr(orchestrator, "evaluate_tool_permission", _boom)
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(),
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "failed"
        assert "RuntimeError" in final["error_summary"]

    def test_008_error_summary_is_bounded(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")

        def _boom(*, permissions, tool_request):
            raise RuntimeError("x" * 5000)

        monkeypatch.setattr(orchestrator, "evaluate_tool_permission", _boom)
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(),
        )
        final = store.get_run(run_id=run["run_id"])
        assert len(final["error_summary"]) <= 200


class TestDetectionWorkflowOrdering:
    def test_009_generate_rule_event_order(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="detection", created_at="t0")
        orchestrator.run_detection_workflow(
            run_id=run["run_id"], trigger_source="threat_intelligence", trigger_input=_ti_record(),
            telemetry_context={"available_telemetry": ["process_creation"], "siem": "Splunk"},
            llm_proposal=_llm_proposal(), run_store=store, event_bus=bus, clock=_clock_factory(),
        )
        events = [e["event_type"] for e in bus.get_events(run_id=run["run_id"])]
        assert events == [
            "run_started", "detection_plan_created", "telemetry_evaluated", "governor_evaluated",
            "planner_started", "planner_completed", "detection_rule_created", "detection_rule_validated",
            "human_review_required", "run_completed",
        ]
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "completed"
        assert final["rule_candidate_count"] == 1
        assert final["human_review_required"] is True

    def test_010_telemetry_gap_proposes_zero_rules(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="detection", created_at="t0")
        orchestrator.run_detection_workflow(
            run_id=run["run_id"], trigger_source="threat_intelligence", trigger_input=_ti_record(),
            telemetry_context={"available_telemetry": []}, llm_proposal={}, run_store=store, event_bus=bus,
            clock=_clock_factory(),
        )
        events = [e["event_type"] for e in bus.get_events(run_id=run["run_id"])]
        assert events == ["run_started", "detection_plan_created", "telemetry_evaluated", "run_completed"]
        final = store.get_run(run_id=run["run_id"])
        assert final["rule_candidate_count"] == 0
        assert "planner_started" not in events

    def test_011_deployment_state_always_not_deployed(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="detection", created_at="t0")
        orchestrator.run_detection_workflow(
            run_id=run["run_id"], trigger_source="threat_intelligence", trigger_input=_ti_record(),
            telemetry_context={"available_telemetry": ["process_creation"]}, llm_proposal=_llm_proposal(),
            run_store=store, event_bus=bus, clock=_clock_factory(),
        )
        rule_events = [
            e for e in bus.get_events(run_id=run["run_id"]) if e["event_type"] == "detection_rule_validated"
        ]
        assert len(rule_events) == 1
        assert rule_events[0]["sanitized_payload"]["deployment_state"] == "NOT_DEPLOYED"

    def test_012_bug_bounty_trigger_source(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="detection", created_at="t0")
        canonical_finding = {
            "finding_id": "BB-1", "title": "Missing CSP header", "vulnerability_class": "security_header_misconfiguration",
            "cwe": ["CWE-693"], "owasp_category": None, "cve": [], "tools_used": ["http_assessor"],
            "confidence": "high", "evidence_digests": ["sha256:" + "a" * 64], "limitations": [],
        }
        orchestrator.run_detection_workflow(
            run_id=run["run_id"], trigger_source="bug_bounty", trigger_input=canonical_finding,
            telemetry_context={"available_telemetry": []}, llm_proposal={}, run_store=store, event_bus=bus,
            clock=_clock_factory(),
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "completed"
        assert final["detection_trigger_count"] == 1

    def test_013_invalid_trigger_source_fails_cleanly(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="detection", created_at="t0")
        orchestrator.run_detection_workflow(
            run_id=run["run_id"], trigger_source="nonsense", trigger_input={},
            telemetry_context={}, llm_proposal={}, run_store=store, event_bus=bus, clock=_clock_factory(),
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "failed"


class TestDetectionGovernorBlocking:
    def test_014_blocked_governor_stops_before_rule_generation(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="detection", created_at="t0")

        def _blocked(*, event):
            return {
                "governor_version": "1", "decision": "block", "reason_codes": ["MUTATION_FREEZE_ACTIVE"],
                "actor_role": event["actor_role"], "action_class": event["action_class"],
                "human_review_required": True, "mutation_freeze_recommended": True,
                "execution_allowed": False, "observable_only": True, "execution_performed": False,
            }

        monkeypatch.setattr(orchestrator, "evaluate_security_governor_event", _blocked)
        orchestrator.run_detection_workflow(
            run_id=run["run_id"], trigger_source="threat_intelligence", trigger_input=_ti_record(),
            telemetry_context={"available_telemetry": ["process_creation"]}, llm_proposal=_llm_proposal(),
            run_store=store, event_bus=bus, clock=_clock_factory(),
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "blocked"
        assert final["rule_candidate_count"] == 0
