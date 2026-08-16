"""Focused tests for backend.app -- the HTTP/SSE interface (Block
15J-K). Uses Starlette's TestClient (in-process ASGI, no real socket).
Bug Bounty runs in these tests always execute against the real local
Juice Shop container at http://localhost:3000/ when reachable
(mirroring this project's own established live-validation pattern) --
tests that require it are skipped when the container is not reachable,
never faked into a false pass.
"""

from __future__ import annotations

import time

import pytest
from starlette.testclient import TestClient

import backend.app as backend_app
from backend.app import app


@pytest.fixture()
def client():
    return TestClient(app)


def _juice_shop_reachable() -> bool:
    import http.client

    try:
        conn = http.client.HTTPConnection("localhost", 3000, timeout=1.5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status < 500
    except OSError:
        return False


_JUICE_SHOP_UP = _juice_shop_reachable()
requires_juice_shop = pytest.mark.skipif(not _JUICE_SHOP_UP, reason="local Juice Shop container not reachable")


class TestHealthAndSystem:
    def test_001_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["bind"] == "127.0.0.1:8420"
        assert r.json()["interface_class"] == "local_development_research_interface"

    def test_002_system_reports_tool_readiness(self, client):
        r = client.get("/api/system")
        assert r.status_code == 200
        body = r.json()
        tools = body["tools"]
        assert tools["http_assessor"] == "ready"
        assert tools["burp_dast"] == "not_configured"
        assert tools["zap"] in (
            "ready", "container_available", "runtime_unavailable",
        )  # real, environment-dependent -- never fabricated

    def test_002b_system_categories_present_and_optional_never_shows_as_failed(self, client):
        r = client.get("/api/system")
        categories = {c["category"]: c for c in r.json()["categories"]}
        assert set(categories) == {"core_services", "scanners", "intelligence", "detection", "optional_integrations"}

        optional_ids = {item["id"]: item for item in categories["optional_integrations"]["items"]}
        assert set(optional_ids) == {"burp_dast", "authenticated_testing", "controlled_validation"}
        for item in optional_ids.values():
            assert item["required"] is False
            assert item["state"] != "failed"

        for item in categories["scanners"]["items"]:
            assert item["required"] is True
        for item in categories["core_services"]["items"]:
            assert item["state"] == "ready"

    def test_003_system_never_exposes_env_vars(self, client):
        r = client.get("/api/system")
        assert "environ" not in r.text.lower()
        assert "path=" not in r.text.lower()


class TestCreateRunValidation:
    def test_004_unknown_run(self, client):
        r = client.get("/api/runs/RUN-" + "0" * 32)
        assert r.status_code == 404
        assert r.json()["error_code"] == "RUN_NOT_FOUND"

    @pytest.mark.parametrize("run_id", ["../../etc/passwd", "not-a-run-id", "RUN-short", "RUN-" + "z" * 32])
    def test_005_path_traversal_in_run_id_rejected(self, client, run_id):
        r = client.get(f"/api/runs/{run_id}")
        assert r.status_code in (400, 404)
        if r.status_code == 400:
            assert r.json()["error_code"] == "INVALID_RUN_ID"

    @pytest.mark.parametrize("target", [
        "http://example.com/", "https://example.com/", "http://8.8.8.8/", "http://192.168.1.10/",
        "http://10.0.0.5/", "file:///etc/passwd", "ftp://localhost/", "javascript:alert(1)",
        "http://127.0.0.1:3000/",
    ])
    def test_006_rejects_unsafe_targets(self, client, target):
        r = client.post("/api/runs/bug-bounty", json={"target": target})
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_TARGET"

    def test_007_rejects_oversized_payload(self, client):
        r = client.post("/api/runs/bug-bounty", json={"target": "http://localhost:3000/", "pad": "x" * 200000})
        assert r.status_code == 413

    def test_008_rejects_unsupported_run_type_via_detection_source(self, client):
        r = client.post("/api/runs/detection", json={"trigger_source": "not_a_source", "trigger_input": {}})
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_TRIGGER_SOURCE"

    def test_009_rejects_non_object_trigger_input(self, client):
        r = client.post("/api/runs/detection", json={"trigger_source": "bug_bounty", "trigger_input": "nope"})
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_TRIGGER_INPUT"

    def test_010_rejects_malformed_json(self, client):
        r = client.post(
            "/api/runs/bug-bounty", content=b"{not json", headers={"content-type": "application/json"},
        )
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_JSON"


class TestSecurityLifecycleEndpoint:
    """POST /api/runs/security-lifecycle -- validation only. A real full
    run is exercised at the orchestrator level (fake transport/execute_tool,
    tests/test_backend_orchestrator.py::TestSecurityLifecycleWorkflow) --
    these tests only confirm routing/validation, never wait for a real
    background scan against Juice Shop."""

    @pytest.fixture(autouse=True)
    def _isolated_backend_state(self, monkeypatch):
        from backend.event_bus import EventBus
        from backend.run_store import RunStore

        monkeypatch.setattr(backend_app, "_run_store", RunStore())
        monkeypatch.setattr(backend_app, "_event_bus", EventBus())

    @pytest.mark.parametrize("target", [
        "http://example.com/", "https://example.com/", "http://8.8.8.8/", "file:///etc/passwd",
    ])
    def test_036_rejects_unsafe_targets(self, client, target):
        r = client.post("/api/runs/security-lifecycle", json={"target": target})
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_TARGET"

    def test_037_rejects_non_list_available_telemetry(self, client):
        r = client.post(
            "/api/runs/security-lifecycle",
            json={"target": "http://localhost:3000/", "available_telemetry": "web_server"},
        )
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_AVAILABLE_TELEMETRY"

    def test_038_rejects_non_string_available_telemetry_entries(self, client):
        r = client.post(
            "/api/runs/security-lifecycle",
            json={"target": "http://localhost:3000/", "available_telemetry": [1, 2]},
        )
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_AVAILABLE_TELEMETRY"

    def test_039_rejects_non_object_detection_llm_proposals(self, client):
        r = client.post(
            "/api/runs/security-lifecycle",
            json={"target": "http://localhost:3000/", "detection_llm_proposals": "not an object"},
        )
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_DETECTION_LLM_PROPOSALS"

    def test_040_accepted_response_shape(self, client, monkeypatch):
        # Patch the real workflow so this test never performs real I/O
        # or waits on a background scan -- only the API contract
        # (immediate 202 + run_id) is under test here.
        started = {}

        def _fake_workflow(**kwargs):
            started.update(kwargs)

        monkeypatch.setattr(backend_app, "run_security_lifecycle_workflow", _fake_workflow)
        r = client.post("/api/runs/security-lifecycle", json={"target": "http://localhost:3000/"})
        assert r.status_code == 202
        body = r.json()
        assert body["run_id"].startswith("RUN-")
        assert body["status"] == "created"

    def test_041_concurrent_run_rejected(self, client, monkeypatch):
        def _fake_workflow(**kwargs):
            import time as _time
            _time.sleep(0.05)

        monkeypatch.setattr(backend_app, "run_security_lifecycle_workflow", _fake_workflow)
        r1 = client.post("/api/runs/security-lifecycle", json={"target": "http://localhost:3000/"})
        assert r1.status_code == 202
        r2 = client.post("/api/runs/security-lifecycle", json={"target": "http://localhost:3000/"})
        assert r2.status_code == 409
        assert r2.json()["error_code"] == "CONCURRENT_RUN_ACTIVE"

    def test_042_available_telemetry_and_proposals_forwarded(self, client, monkeypatch):
        captured = {}

        def _fake_workflow(**kwargs):
            captured.update(kwargs)

        monkeypatch.setattr(backend_app, "run_security_lifecycle_workflow", _fake_workflow)
        client.post(
            "/api/runs/security-lifecycle",
            json={
                "target": "http://localhost:3000/", "available_telemetry": ["web_server"],
                "detection_llm_proposals": {"CF-1": {"detection_objective": "x"}},
            },
        )
        assert captured["available_telemetry"] == ["web_server"]
        assert captured["detection_llm_proposals"] == {"CF-1": {"detection_objective": "x"}}


class TestLifecycleReviewEndpoint:
    @pytest.fixture(autouse=True)
    def _isolated_backend_state(self, monkeypatch):
        from backend.event_bus import EventBus
        from backend.run_store import RunStore

        monkeypatch.setattr(backend_app, "_run_store", RunStore())
        monkeypatch.setattr(backend_app, "_event_bus", EventBus())

    @staticmethod
    def _real_finding_and_prioritization():
        # Built via the real core.context_prioritization/core.security_handoff
        # functions (never a hand-rolled dict) so these tests never have
        # to guess either module's own required shape.
        from core.context_prioritization import prioritize_finding

        finding = {
            "finding_version": "1", "finding_id": "CF-1", "finding_status": "candidate",
            "technical_severity": "medium", "confidence": "medium", "vulnerability_class": "security_header_misconfiguration",
            "evidence": [{"evidence_digest": "sha256:" + "a" * 64}], "validation": None,
            "owasp_category": None, "cwe": None,
        }
        import backend.orchestrator as orchestrator

        prioritization = prioritize_finding(finding=finding, context=dict(orchestrator.DEMO_LIFECYCLE_CONTEXT))
        return finding, prioritization

    def _real_case_at_human_review(self):
        from core.security_handoff import append_security_stage_result, create_security_handoff_case

        finding, prioritization = self._real_finding_and_prioritization()
        case = create_security_handoff_case(finding=finding, prioritization=prioritization)
        for stage, role, result_type, outcome in (
            ("threat_intel_review", "threat_intelligence", "assessment", "reviewed_no_match"),
            ("threat_hunt", "threat_hunting", "plan", "not_applicable"),
            # detection_engineering's "not_applicable" outcome advances
            # straight to purple_remediation, skipping red_validation
            # entirely (core.security_handoff's own real transition
            # graph) -- never submitted here unless the case is
            # actually still at that stage.
            ("detection_engineering", "blue_team", "candidate", "not_applicable"),
            ("red_validation", "red_team", "assessment", "not_applicable"),
            ("purple_remediation", "purple_ir", "recommendation", "planned"),
        ):
            if case["current_stage"] != stage:
                continue
            case = append_security_stage_result(
                case=case, stage=stage, role=role, result_type=result_type, outcome=outcome,
                evidence_references=[{"reference_type": "finding", "reference": "CF-1"}], recommendation="test",
            )
        return case

    def _awaiting_review_run(self):
        run = backend_app._run_store.create_run(run_type="bug_bounty", created_at="2026-08-15T00:00:00Z")
        _finding, prioritization = self._real_finding_and_prioritization()
        case = self._real_case_at_human_review()
        governor_result = {
            "governor_version": "1", "decision": "allow", "reason_codes": [],
            "observable_only": True, "execution_performed": False,
        }
        backend_app._run_store.transition(
            run_id=run["run_id"], new_status="awaiting_human_review", current_stage="human_review",
            lifecycle={
                "lifecycle_version": "1",
                "results": [{"finding_id": "CF-1", "case": case, "prioritization": prioritization}],
                "governor_result": governor_result,
            },
        )
        return run["run_id"], case["case_id"]

    def test_043_unknown_run_404(self, client):
        r = client.post(
            f"/api/runs/RUN-{'0' * 32}/lifecycle/review",
            json={"case_id": "SH-1", "approval_state": "approved", "approval_reference": "ref"},
        )
        assert r.status_code == 404

    def test_044_rejects_missing_case_id(self, client):
        run_id, _case_id = self._awaiting_review_run()
        r = client.post(
            f"/api/runs/{run_id}/lifecycle/review",
            json={"approval_state": "approved", "approval_reference": "ref"},
        )
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_CASE_ID"

    def test_045_rejects_invalid_approval_state(self, client):
        run_id, case_id = self._awaiting_review_run()
        r = client.post(
            f"/api/runs/{run_id}/lifecycle/review",
            json={"case_id": case_id, "approval_state": "maybe", "approval_reference": "ref"},
        )
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_APPROVAL_STATE"

    def test_046_rejects_missing_approval_reference(self, client):
        run_id, case_id = self._awaiting_review_run()
        r = client.post(
            f"/api/runs/{run_id}/lifecycle/review",
            json={"case_id": case_id, "approval_state": "approved"},
        )
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_APPROVAL_REFERENCE"

    def test_047_unknown_case_id_400(self, client):
        run_id, _case_id = self._awaiting_review_run()
        r = client.post(
            f"/api/runs/{run_id}/lifecycle/review",
            json={"case_id": "SH-does-not-exist", "approval_state": "approved", "approval_reference": "ref"},
        )
        assert r.status_code == 400
        assert r.json()["error_code"] == "CASE_NOT_FOUND"

    def test_048_real_approval_recorded_via_api(self, client):
        run_id, case_id = self._awaiting_review_run()
        r = client.post(
            f"/api/runs/{run_id}/lifecycle/review",
            json={"case_id": case_id, "approval_state": "approved", "approval_reference": "ref-1"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "completed"
        assert body["lifecycle"]["results"][0]["case"]["approval_state"] == "approved"

    def test_049_run_not_awaiting_review_rejected(self, client):
        run = backend_app._run_store.create_run(run_type="bug_bounty", created_at="2026-08-15T00:00:00Z")
        backend_app._run_store.transition(run_id=run["run_id"], new_status="planning", current_stage="planning")
        r = client.post(
            f"/api/runs/{run['run_id']}/lifecycle/review",
            json={"case_id": "SH-1", "approval_state": "approved", "approval_reference": "ref"},
        )
        assert r.status_code == 400
        assert r.json()["error_code"] == "RUN_NOT_AWAITING_REVIEW"


class TestErrorSanitization:
    def test_011_internal_error_never_leaks_traceback(self, client, monkeypatch):
        def _boom(*, run_id):
            raise RuntimeError("sensitive internal detail")

        monkeypatch.setattr(backend_app._run_store, "get_run", _boom)
        r = client.get("/api/runs/RUN-" + "0" * 32)
        assert r.status_code == 500
        assert r.json()["error_code"] == "INTERNAL_ERROR"
        assert "sensitive internal detail" not in r.text
        assert "Traceback" not in r.text


@requires_juice_shop
class TestBugBountyRunLifecycle:
    @pytest.fixture(autouse=True)
    def _isolated_backend_state(self, monkeypatch):
        # The route handlers close over module-level `_run_store`/`_event_bus`
        # globals (looked up at call time, not bind time) -- reassigning them
        # here gives every test in this class its own isolated in-memory
        # state, so a slow/lingering run in one test can never pollute the
        # concurrency slot or run list seen by the next test.
        from backend.event_bus import EventBus
        from backend.run_store import RunStore

        monkeypatch.setattr(backend_app, "_run_store", RunStore())
        monkeypatch.setattr(backend_app, "_event_bus", EventBus())

    def _wait_for_terminal(self, client, run_id, timeout=30):
        deadline = time.time() + timeout
        status = None
        while time.time() < deadline:
            body = client.get(f"/api/runs/{run_id}").json()
            status = body["status"]
            if status in ("completed", "blocked", "failed", "cancelled"):
                break
            time.sleep(0.3)
        return status

    def _create_and_wait(self, client, timeout=30):
        r = client.post("/api/runs/bug-bounty", json={"target": "http://localhost:3000/"})
        assert r.status_code == 202
        run_id = r.json()["run_id"]
        status = self._wait_for_terminal(client, run_id, timeout=timeout)
        return run_id, status

    def test_012_full_lifecycle_completes(self, client):
        run_id, status = self._create_and_wait(client)
        assert status == "completed"
        run = client.get(f"/api/runs/{run_id}").json()
        assert run["governor_decisions"][0]["decision"] == "allow"
        # http_assessor is pure Python and always executes; nmap/nuclei/zap
        # each honestly execute or not depending on real, environment-specific
        # availability -- this integration test never hardcodes that.
        assert "http_assessor" in run["executed_tools"]
        assert run["requested_tools"] == ["http_assessor", "crawler", "nmap", "nuclei", "zap"]

    def test_013_events_endpoint_returns_ordered_events(self, client):
        run_id, _ = self._create_and_wait(client)
        events = client.get(f"/api/runs/{run_id}/events").json()["events"]
        sequences = [e["sequence"] for e in events]
        assert sequences == sorted(sequences)
        assert events[-1]["event_type"] == "run_completed"

    def test_014_report_available_after_completion(self, client):
        run_id, _ = self._create_and_wait(client)
        r = client.get(f"/api/runs/{run_id}/report")
        assert r.status_code == 200
        assert "canonical_findings" in r.json()["report"]

    def test_015_report_not_available_before_completion(self, client):
        r = client.post("/api/runs/bug-bounty", json={"target": "http://localhost:3000/"})
        run_id = r.json()["run_id"]
        report = client.get(f"/api/runs/{run_id}/report")
        assert report.status_code in (200, 409)
        self._wait_for_terminal(client, run_id, timeout=30)

    def test_016_concurrent_run_rejected(self, client):
        r1 = client.post("/api/runs/bug-bounty", json={"target": "http://localhost:3000/"})
        assert r1.status_code == 202
        r2 = client.post("/api/runs/bug-bounty", json={"target": "http://localhost:3000/"})
        assert r2.status_code == 409
        assert r2.json()["error_code"] == "CONCURRENT_RUN_ACTIVE"
        self._wait_for_terminal(client, r1.json()["run_id"], timeout=30)

    def test_017_cancel_on_active_run_sets_flag(self, client):
        r = client.post("/api/runs/bug-bounty", json={"target": "http://localhost:3000/"})
        run_id = r.json()["run_id"]
        cancel = client.post(f"/api/runs/{run_id}/cancel")
        assert cancel.status_code == 200
        assert cancel.json()["cancellation_requested"] is True
        self._wait_for_terminal(client, run_id, timeout=30)

    def test_018_cancel_on_terminal_run_rejected(self, client):
        run_id, status = self._create_and_wait(client)
        cancel = client.post(f"/api/runs/{run_id}/cancel")
        assert cancel.status_code == 409
        assert cancel.json()["error_code"] == "RUN_ALREADY_TERMINAL"

    def test_019_sse_stream_delivers_events(self, client):
        r = client.post("/api/runs/bug-bounty", json={"target": "http://localhost:3000/"})
        run_id = r.json()["run_id"]
        with client.stream("GET", f"/api/runs/{run_id}/stream") as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            lines = []
            for line in resp.iter_lines():
                lines.append(line)
                if len(lines) >= 3:
                    break
            assert any(line.startswith("event:") for line in lines)
        self._create_and_wait(client, timeout=1)

    def test_020_dashboard_root_serves_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "ThreatTrace Live Platform" in r.text


# ---------------------------------------------------------------------------
# GET /api/runs/{run_id}/evaluation -- Step 7 of the Docker Juice Shop
# accuracy exercise. Every run/report/event fixture below is injected
# directly into an isolated RunStore/EventBus -- no real scan is ever
# triggered to produce test data (matching this file's own established
# _isolated_backend_state pattern for TestBugBountyRunLifecycle).
# ---------------------------------------------------------------------------


def _canonical_finding(**overrides):
    finding = {
        "finding_id": "CF-csp", "title": "Missing Content-Security-Policy header",
        "vulnerability_class": "security_header_misconfiguration", "cwe": "CWE-693",
        "path": "/", "technical_severity": "medium", "tools_used": ["http_assessor"],
        "evidence_digests": ["sha256:" + "1" * 64],
        "tool_observations": [{
            "source_tool": "http_assessor", "title": "Missing Content-Security-Policy header",
            "sanitized_evidence": "Response did not include a Content-Security-Policy header.",
        }],
    }
    finding.update(overrides)
    return finding


def _report(**overrides):
    report = {
        "canonical_findings": [_canonical_finding()],
        "informational_observations": [],
        "tools_requested": ["http_assessor", "nmap", "nuclei", "zap"],
        "tools_permitted": ["http_assessor", "nmap", "nuclei", "zap"],
        "tools_executed": ["http_assessor", "nmap", "nuclei", "zap"],
        "correlation_summary": {"multi_tool_corroborated_count": 0, "duplicate_evidence_count": 0},
    }
    report.update(overrides)
    return report


class TestEvaluationEndpoint:
    @pytest.fixture(autouse=True)
    def _isolated_backend_state(self, monkeypatch):
        from backend.event_bus import EventBus
        from backend.run_store import RunStore

        monkeypatch.setattr(backend_app, "_run_store", RunStore())
        monkeypatch.setattr(backend_app, "_event_bus", EventBus())

    def _create_completed_juice_shop_run(self, *, report=None, target_summary="http://localhost:3000/"):
        run = backend_app._run_store.create_run(run_type="bug_bounty", created_at="2026-08-15T00:00:00Z")
        backend_app._run_store.transition(
            run_id=run["run_id"], new_status="completed", completed_at="2026-08-15T00:05:00Z",
            target_summary=target_summary, report=report if report is not None else _report(),
        )
        backend_app._event_bus.publish(
            run_id=run["run_id"], event_type="tool_completed", timestamp="2026-08-15T00:01:00Z",
            stage="tool_execution", source_component="bug_bounty_assessment",
            summary="http_assessor completed: 5 findings, 6 requests.",
            sanitized_payload={"findings_count": 5, "network_requests_performed": 6, "assessment_performed": True},
        )
        backend_app._event_bus.publish(
            run_id=run["run_id"], event_type="tool_completed", timestamp="2026-08-15T00:02:00Z",
            stage="tool_execution", source_component="bug_bounty_assessment",
            summary="nuclei completed: status=timeout, 0 observation(s).",
            sanitized_payload={"tool_id": "nuclei", "status": "timeout", "observation_count": 0},
        )
        return run["run_id"]

    def test_035_unknown_run_404(self, client):
        r = client.get("/api/runs/RUN-" + "0" * 32 + "/evaluation")
        assert r.status_code == 404
        assert r.json()["error_code"] == "RUN_NOT_FOUND"

    def test_036_completed_juice_shop_run_is_evaluated(self, client):
        run_id = self._create_completed_juice_shop_run()
        r = client.get(f"/api/runs/{run_id}/evaluation")
        assert r.status_code == 200
        body = r.json()
        assert body["evaluation_state"] == "evaluated"
        assert body["run_id"] == run_id

    def test_037_tp_fp_fn_tn_and_metrics_present(self, client):
        run_id = self._create_completed_juice_shop_run()
        body = client.get(f"/api/runs/{run_id}/evaluation").json()
        assert body["true_positive_count"] == 1
        assert body["false_positive_count"] == 0
        assert body["true_negative_count"] == 4
        assert body["precision"] == 1.0
        assert "supported_benchmark_accuracy" in body
        assert "overall_accuracy" not in body

    def test_038_case_results_present(self, client):
        run_id = self._create_completed_juice_shop_run()
        body = client.get(f"/api/runs/{run_id}/evaluation").json()
        assert len(body["case_results"]) == 9

    def test_039_non_juice_shop_target_not_evaluated(self, client):
        run_id = self._create_completed_juice_shop_run(target_summary="http://example.com/")
        r = client.get(f"/api/runs/{run_id}/evaluation")
        assert r.status_code == 200
        assert r.json()["evaluation_state"] == "not_evaluated"

    def test_040_incomplete_run_appropriate_state(self, client):
        run = backend_app._run_store.create_run(run_type="bug_bounty", created_at="2026-08-15T00:00:00Z")
        backend_app._run_store.update_fields(run_id=run["run_id"], target_summary="http://localhost:3000/")
        r = client.get(f"/api/runs/{run['run_id']}/evaluation")
        assert r.status_code == 200
        assert r.json()["evaluation_state"] == "run_incomplete"

    def test_041_detection_run_not_evaluated(self, client):
        run = backend_app._run_store.create_run(run_type="detection", created_at="2026-08-15T00:00:00Z")
        backend_app._run_store.transition(run_id=run["run_id"], new_status="completed", completed_at="2026-08-15T00:05:00Z")
        r = client.get(f"/api/runs/{run['run_id']}/evaluation")
        assert r.json()["evaluation_state"] == "not_evaluated"

    def test_042_no_scanner_or_network_call_evaluation_is_pure(self, client, monkeypatch):
        # The evaluation endpoint must never trigger real tool execution
        # -- patch execute_bug_bounty_tool to explode if ever called from
        # this code path, then confirm the request still succeeds.
        def _explode(*args, **kwargs):
            raise AssertionError("evaluation endpoint must never execute a tool")

        monkeypatch.setattr("core.bug_bounty_tool_execution.execute_bug_bounty_tool", _explode)
        run_id = self._create_completed_juice_shop_run()
        r = client.get(f"/api/runs/{run_id}/evaluation")
        assert r.status_code == 200
        assert r.json()["evaluation_state"] == "evaluated"

    def test_043_nuclei_timeout_shown_as_timeout(self, client):
        run_id = self._create_completed_juice_shop_run()
        body = client.get(f"/api/runs/{run_id}/evaluation").json()
        assert body["tool_execution"]["nuclei"]["status"] == "timeout"

    def test_044_limitations_visible_in_response(self, client):
        run_id = self._create_completed_juice_shop_run()
        body = client.get(f"/api/runs/{run_id}/evaluation").json()
        assert len(body["limitations"]) >= 5


# ---------------------------------------------------------------------------
# Dashboard rendering of the Accuracy & Evaluation section -- static
# content assertions only (no browser/JS execution harness exists in this
# project, matching test_020_dashboard_root_serves_html's own level of
# coverage). These confirm the section exists, the empty/limitations
# text is real markup (not a tooltip-only attribute), and -- critically
# -- that no numeric benchmark result (5/0/0/4/100%) is hardcoded into
# the page's own HTML/JS source, since every displayed value must
# originate from the /api/runs/{id}/evaluation response at render time.
# ---------------------------------------------------------------------------


class TestDashboardEvaluationSection:
    def test_045_evaluation_card_present(self, client):
        r = client.get("/")
        assert "evaluation-body" in r.text
        assert "Accuracy" in r.text and "Evaluation" in r.text

    def test_046_empty_state_text_present_not_zeros(self, client):
        r = client.get("/")
        assert "No benchmark evaluation available for this run." in r.text

    def test_047_qualifier_sentence_present(self, client):
        r = client.get("/")
        assert "This is not overall ThreatTrace accuracy." in r.text

    def test_048_limitations_rendered_as_visible_list_not_tooltip_only(self, client):
        r = client.get("/")
        assert "eval-limitations" in r.text
        assert "<ul" in r.text

    def test_049_renders_values_from_api_response_not_hardcoded(self, client):
        # The page source must reference the real field names it reads
        # from the API response object, never a fixed literal result.
        r = client.get("/")
        for field in ("evaluation.precision", "evaluation.recall", "evaluation.f1", "evaluation.supported_benchmark_accuracy", "evaluation.true_positive_count"):
            assert field in r.text

    def test_050_no_hardcoded_benchmark_result_values_in_page_source(self, client):
        r = client.get("/")
        # These are the real Step 6 numbers -- if any of them appear as a
        # bare literal token near the evaluation script (rather than
        # being read off the `evaluation` object), that's a hardcoded
        # presentation value, which this dashboard must never contain.
        assert "TP 5" not in r.text
        assert "FP 0" not in r.text
        assert "100%</div>" not in r.text
        assert "supported_benchmark_accuracy: 1" not in r.text
        assert "supported_benchmark_accuracy = 1" not in r.text

    def test_051_case_ids_are_data_driven_not_individually_hardcoded_rows(self, client):
        # The 9 case IDs must come from the API's case_results array via
        # a template/map, never nine individually authored <tr> rows.
        r = client.get("/")
        assert "case_results" in r.text
        assert "JS-CSP-MISSING" not in r.text  # never literally typed into the page

    def test_052_tool_status_never_labeled_failed_benchmark(self, client):
        r = client.get("/")
        assert "FAILED BENCHMARK" not in r.text.upper().replace("_", " ")
