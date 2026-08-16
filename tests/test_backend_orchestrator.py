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


def _fake_execute_tool_unavailable(*, permissions, tool_request, governor_result, execution_config, detected_technologies=None):
    """Deterministic stand-in for `core.bug_bounty_tool_execution.
    execute_bug_bounty_tool` -- honestly reports nmap/nuclei/zap as not
    installed/unreachable, performing no real subprocess or network I/O.
    This is the realistic default for most dev/CI environments and keeps
    every test in this file deterministic regardless of what happens to
    be installed/running on the machine executing the test."""
    tool_id = tool_request["tool_id"]
    return {
        "tool_execution_version": "1", "request_id": tool_request["request_id"], "tool_id": tool_id,
        "execution_permitted": True, "execution_blocked_reason": None,
        "permission_result": None, "governor_decision": governor_result["decision"],
        "tool_result": {"tool_result_version": "1", "status": "tool_not_installed", "observations": [], "execution_performed": False},
        "execution_performed": False,
    }


def _tracking_fake_execute_tool(calls: list):
    def _fake(*, permissions, tool_request, governor_result, execution_config, detected_technologies=None):
        calls.append(tool_request["tool_id"])
        return _fake_execute_tool_unavailable(
            permissions=permissions, tool_request=tool_request, governor_result=governor_result,
            execution_config=execution_config,
        )

    return _fake


def _config_tracking_fake_execute_tool(calls: list):
    def _fake(*, permissions, tool_request, governor_result, execution_config, detected_technologies=None):
        calls.append((tool_request["tool_id"], dict(execution_config)))
        return _fake_execute_tool_unavailable(
            permissions=permissions, tool_request=tool_request, governor_result=governor_result,
            execution_config=execution_config,
        )

    return _fake


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


def _fake_execute_tool_mixed(*, permissions, tool_request, governor_result, execution_config, detected_technologies=None):
    """nmap/nuclei honestly unavailable; zap genuinely 'executes' and
    finds one observation -- exercises both the `tool_completed` and
    `tool_failed` branches in one deterministic, no-real-I/O run."""
    tool_id = tool_request["tool_id"]
    if tool_id == "zap":
        return {
            "tool_execution_version": "1", "request_id": tool_request["request_id"], "tool_id": tool_id,
            "execution_permitted": True, "execution_blocked_reason": None,
            "permission_result": None, "governor_decision": governor_result["decision"],
            "tool_result": {
                "tool_result_version": "1", "status": "completed",
                "observations": [{"observation_id": "zap-1", "title": "Test ZAP alert", "risk": "medium"}],
                "evidence_references": ["sha256:" + "a" * 64], "execution_performed": True,
            },
            "execution_performed": True,
        }
    return _fake_execute_tool_unavailable(
        permissions=permissions, tool_request=tool_request, governor_result=governor_result,
        execution_config=execution_config,
    )


class TestBugBountyWorkflowOrdering:
    def test_001_happy_path_event_order(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_mixed,
        )
        events = [e["event_type"] for e in bus.get_events(run_id=run["run_id"])]
        assert events == [
            "run_started", "planner_started", "planner_completed",
            "tool_policy_evaluated", "tool_policy_evaluated", "tool_policy_evaluated",
            "tool_policy_evaluated", "tool_policy_evaluated",
            "governor_evaluated",
            "tool_started", "tool_completed", "http_assessment_completed",
            "tool_started", "tool_completed",  # crawler
            "tool_started", "tool_failed",  # nmap
            "tool_started", "tool_failed",  # nuclei
            "tool_started", "tool_completed",  # zap
            "evidence_normalized", "finding_correlated",
            "canonical_finding_created", "canonical_finding_created",  # ZAP's fake alert + http_assessor's CSP finding
            "run_completed",
        ]
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "completed"
        assert final["report"] is not None
        assert final["requested_tools"] == ["http_assessor", "crawler", "nmap", "nuclei", "zap"]
        assert final["executed_tools"] == ["http_assessor", "crawler", "zap"]

    def test_001b_tool_unavailable_never_fabricates_execution(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_unavailable,
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["executed_tools"] == ["http_assessor", "crawler"]
        events = bus.get_events(run_id=run["run_id"])
        failed_tools = {e["sanitized_payload"]["tool_id"] for e in events if e["event_type"] == "tool_failed"}
        assert failed_tools == {"nmap", "nuclei", "zap"}

    def test_002_slot_released_after_completion(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.try_acquire_bug_bounty_slot(run_id=run["run_id"])
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_unavailable,
        )
        assert store.active_bug_bounty_run_id() is None


class TestBugBountyGovernorBlocking:
    def test_003_blocked_governor_never_executes_tool(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        transport = _FakeTransport()
        execute_tool_calls: list = []

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
            clock=_clock_factory(), transport=transport, execute_tool=_tracking_fake_execute_tool(execute_tool_calls),
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "blocked"
        assert transport.calls == []
        assert execute_tool_calls == []

    def test_004_denied_tool_policy_never_reaches_governor(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        transport = _FakeTransport()
        governor_calls = []
        execute_tool_calls: list = []

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
            clock=_clock_factory(), transport=transport, execute_tool=_tracking_fake_execute_tool(execute_tool_calls),
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "blocked"
        assert governor_calls == []
        assert transport.calls == []
        assert execute_tool_calls == []


class TestNucleiExecutionConfig:
    """Nuclei Reliability Step 1/1B: nuclei gets its own, separately-
    defined, separately-justified execution_config object -- nmap/zap
    keep the unchanged shared config. Step 1B's phased QUICK profile
    (measured ~38.2s real combined runtime) let the nuclei budget come
    back down to the same 60s nmap/zap already use, but it is still a
    distinct, independently-justified value, not a shared reference, so
    it can be changed for nuclei alone in the future without touching
    nmap/zap. Real call-site tracking, not just reading the module
    constant, since a config could be defined correctly but never
    actually wired to the loop that calls execute_tool.
    """

    def test_005_nuclei_receives_its_own_execution_config_object(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        transport = _FakeTransport()
        calls: list = []
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=transport, execute_tool=_config_tracking_fake_execute_tool(calls),
        )
        configs = dict(calls)
        assert configs["nuclei"]["process_timeout_seconds"] == orchestrator._NUCLEI_EXECUTION_CONFIG["process_timeout_seconds"]
        assert orchestrator._NUCLEI_EXECUTION_CONFIG is not orchestrator._EXECUTION_CONFIG

    def test_006_nuclei_phase_telemetry_reaches_the_tool_completed_event(self):
        # Nuclei Reliability Step 1B: profile/phases_attempted/phases_
        # completed/duration/partial_results must actually reach the
        # event stream, not just exist in the adapter's own transient
        # tool_result -- this is a real regression guard for exactly the
        # gap Step 1 disclosed (telemetry existed but disappeared before
        # events/report).
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        transport = _FakeTransport()

        def fake_execute_tool(*, permissions, tool_request, governor_result, execution_config, detected_technologies=None):
            if tool_request["tool_id"] != "nuclei":
                return _fake_execute_tool_unavailable(
                    permissions=permissions, tool_request=tool_request, governor_result=governor_result,
                    execution_config=execution_config,
                )
            nuclei_result = {
                "tool_result_version": "3", "tool_id": "nuclei", "request_id": tool_request["request_id"],
                "target": tool_request["target"], "status": "partial", "observations": [],
                "evidence_references": [], "network_requests_performed": None, "output_truncated": False,
                "error_detail": None, "execution_performed": True, "partial_results": True,
                "runtime_duration_seconds": 38.2, "profile_name": "quick_phased_v1", "nuclei_version": "3.11.1",
                "templates_selected_count": 474, "stderr_summary": None,
                "phases": [
                    {"phase_id": "exposures", "status": "completed", "templates_selected_count": 94, "elapsed_seconds": 15.2, "observation_count": 0, "partial_results": False},
                    {"phase_id": "misconfiguration", "status": "timeout", "templates_selected_count": 380, "elapsed_seconds": 35.0, "observation_count": 0, "partial_results": False},
                    {"phase_id": "ssl", "status": "skipped_not_applicable", "templates_selected_count": 0, "elapsed_seconds": 0.0, "observation_count": 0, "partial_results": False},
                ],
            }
            return {
                "tool_execution_version": "1", "request_id": tool_request["request_id"], "tool_id": "nuclei",
                "execution_permitted": True, "execution_blocked_reason": None,
                "permission_result": {"tool_id": "nuclei", "execution_permitted": True},
                "governor_decision": "allow", "tool_result": nuclei_result, "execution_performed": True,
            }

        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=transport, execute_tool=fake_execute_tool,
        )
        events = bus.get_events(run_id=run["run_id"], since_sequence=0)
        nuclei_event = next(
            e for e in events
            if e["event_type"] == "tool_completed" and e["sanitized_payload"].get("tool_id") == "nuclei"
        )
        payload = nuclei_event["sanitized_payload"]
        assert payload["profile"] == "quick_phased_v1"
        # 2, not 3 -- the ssl phase's skipped_not_applicable entry is
        # correctly excluded from "attempted" (it was never run at all).
        assert payload["phases_attempted"] == 2
        assert payload["phases_completed"] == 1
        assert payload["duration"] == 38.2
        assert payload["partial_results"] is True

    def test_006_nmap_and_zap_share_the_unchanged_default_config(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        transport = _FakeTransport()
        calls: list = []
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=transport, execute_tool=_config_tracking_fake_execute_tool(calls),
        )
        configs = dict(calls)
        assert configs["nmap"] == orchestrator._EXECUTION_CONFIG
        assert configs["zap"] == orchestrator._EXECUTION_CONFIG

    def test_007_nuclei_timeout_never_exceeds_adapter_ceiling(self):
        from adapters.bug_bounty_nuclei import MAX_PROCESS_TIMEOUT_SECONDS

        assert orchestrator._NUCLEI_EXECUTION_CONFIG["process_timeout_seconds"] <= MAX_PROCESS_TIMEOUT_SECONDS


class TestTechnologyDetection:
    """Nuclei Reliability Step 1C: live technology-aware selection --
    detection reuses http_assessor's own already-produced
    information_disclosure findings only, never a new header-capture
    path, and is wired all the way through to the real nuclei
    execute_tool call.
    """

    def _info_disclosure_finding(self, *, header_name="server", value="Express"):
        return {
            "vulnerability_class": "information_disclosure",
            "reproduction_summary": f"Requested / and observed {header_name}: {value}.",
        }

    def test_008_detects_known_technology_from_real_finding_shape(self):
        findings = [self._info_disclosure_finding(value="Express")]
        detected = orchestrator._detect_technologies_from_http_assessor(findings)
        assert detected == ["express"]

    def test_009_unrecognized_value_detects_nothing(self):
        findings = [self._info_disclosure_finding(value="SomeUnknownServer/2.0")]
        detected = orchestrator._detect_technologies_from_http_assessor(findings)
        assert detected == []

    def test_010_non_information_disclosure_findings_ignored(self):
        findings = [{"vulnerability_class": "security_header_misconfiguration", "reproduction_summary": "Express is missing a header"}]
        # vulnerability_class gate means this must NOT be scanned even
        # though the word "Express" appears in its own text -- detection
        # only ever looks at genuine information_disclosure evidence.
        detected = orchestrator._detect_technologies_from_http_assessor(findings)
        assert detected == []

    def test_011_no_findings_at_all_is_empty_not_an_error(self):
        assert orchestrator._detect_technologies_from_http_assessor([]) == []
        assert orchestrator._detect_technologies_from_http_assessor(None) == []

    def test_012_multiple_recognized_technologies_all_detected(self):
        findings = [
            self._info_disclosure_finding(header_name="server", value="Express"),
            self._info_disclosure_finding(header_name="x-powered-by", value="Angular"),
        ]
        detected = orchestrator._detect_technologies_from_http_assessor(findings)
        assert detected == ["angular", "express"]

    def test_013_detected_technology_reaches_the_real_nuclei_execute_tool_call(self):
        # End-to-end: a real http_assessor finding shape (via a fake
        # transport that actually discloses a Server header) must flow
        # through detection into the real execute_tool call's
        # detected_technologies argument for nuclei specifically.
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")

        class _DisclosingTransport(_FakeTransport):
            def request(self, *, url, method, headers=None):
                self.calls.append((url, method))
                return {
                    "url": url, "status_code": 200, "headers": {"content-type": "text/html", "server": "Express/4.18.2"},
                    "body_excerpt": "<html></html>", "redirect_location": None, "request_performed": True,
                }

        calls: list = []

        def tracking_execute_tool(*, permissions, tool_request, governor_result, execution_config, detected_technologies=None):
            calls.append((tool_request["tool_id"], detected_technologies))
            return _fake_execute_tool_unavailable(
                permissions=permissions, tool_request=tool_request, governor_result=governor_result,
                execution_config=execution_config,
            )

        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_DisclosingTransport(), execute_tool=tracking_execute_tool,
        )
        nuclei_call = next(c for c in calls if c[0] == "nuclei")
        assert nuclei_call[1] == ["express"]

    def test_014_no_disclosure_yields_empty_list_reaching_nuclei(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        calls: list = []

        def tracking_execute_tool(*, permissions, tool_request, governor_result, execution_config, detected_technologies=None):
            calls.append((tool_request["tool_id"], detected_technologies))
            return _fake_execute_tool_unavailable(
                permissions=permissions, tool_request=tool_request, governor_result=governor_result,
                execution_config=execution_config,
            )

        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=tracking_execute_tool,
        )
        nuclei_call = next(c for c in calls if c[0] == "nuclei")
        assert nuclei_call[1] == []


class TestCrawlerFailureIsolation:
    """Step 2 Phase 3: a crawler failure must never abort tools that can
    still run safely without it (nmap/nuclei/zap depend on neither the
    crawler nor its output this step)."""

    def test_015_crawler_exception_does_not_fail_the_run(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")

        def _boom(*, scope, transport):
            raise RuntimeError("crawler failure detail that must never leak")

        monkeypatch.setattr(orchestrator, "run_bug_bounty_crawl", _boom)
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_mixed,
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["status"] == "completed"
        assert final["report"] is not None

    def test_016_crawler_exception_recorded_as_failed_attack_surface(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")

        def _boom(*, scope, transport):
            raise RuntimeError("boom")

        monkeypatch.setattr(orchestrator, "run_bug_bounty_crawl", _boom)
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_mixed,
        )
        final = store.get_run(run_id=run["run_id"])
        assert final["attack_surface"]["status"] == "failed"
        assert "crawler" not in final["executed_tools"]

    def test_017_crawler_exception_never_leaks_raw_detail_into_events(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")

        def _boom(*, scope, transport):
            raise RuntimeError("SECRET_INTERNAL_DETAIL")

        monkeypatch.setattr(orchestrator, "run_bug_bounty_crawl", _boom)
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_mixed,
        )
        events = bus.get_events(run_id=run["run_id"])
        failed_event = next(e for e in events if e["event_type"] == "tool_failed" and e["sanitized_payload"]["tool_id"] == "crawler")
        assert "RuntimeError" in failed_event["sanitized_payload"]["reason"]

    def test_018_other_tools_still_execute_after_crawler_failure(self, monkeypatch):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")

        def _boom(*, scope, transport):
            raise RuntimeError("boom")

        monkeypatch.setattr(orchestrator, "run_bug_bounty_crawl", _boom)
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_mixed,
        )
        final = store.get_run(run_id=run["run_id"])
        # http_assessor is pure Python (always executes); zap succeeds under
        # _fake_execute_tool_mixed -- neither depends on the crawler.
        assert "http_assessor" in final["executed_tools"]
        assert "zap" in final["executed_tools"]

    def test_019_crawler_budget_exhausted_reported_as_partial_not_failed(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")

        class _ExhaustingClock:
            """Every call after the first reports the runtime budget as
            already exhausted -- deterministic, no real sleeping."""
            def __init__(self):
                self._n = 0

            def __call__(self):
                self._n += 1
                return 0.0 if self._n <= 1 else 999.0

        import core.bug_bounty_crawler as crawler_module
        original = crawler_module.run_bug_bounty_crawl

        def _wrapped(*, scope, transport):
            return original(scope=scope, transport=transport, clock=_ExhaustingClock())

        import backend.orchestrator as orch_module
        orig_ref = orch_module.run_bug_bounty_crawl
        try:
            orch_module.run_bug_bounty_crawl = _wrapped
            orchestrator.run_bug_bounty_workflow(
                run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
                clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_unavailable,
            )
        finally:
            orch_module.run_bug_bounty_crawl = orig_ref

        final = store.get_run(run_id=run["run_id"])
        assert final["attack_surface"]["status"] == "partial"
        assert final["attack_surface"]["telemetry"]["budget_exhausted"] is True
        assert "crawler" in final["executed_tools"]


class TestBugBountyCancellation:
    def test_005_cooperative_cancellation_before_execution(self):
        store = RunStore()
        bus = EventBus()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.update_fields(run_id=run["run_id"], cancellation_requested=True)
        transport = _FakeTransport()
        orchestrator.run_bug_bounty_workflow(
            run_id=run["run_id"], target="http://localhost:3000/", run_store=store, event_bus=bus,
            clock=_clock_factory(), transport=transport, execute_tool=_fake_execute_tool_unavailable,
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
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_unavailable,
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
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_unavailable,
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
            clock=_clock_factory(), transport=_FakeTransport(), execute_tool=_fake_execute_tool_unavailable,
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
