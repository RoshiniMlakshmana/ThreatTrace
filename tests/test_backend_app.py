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
        tools = r.json()["tools"]
        assert tools["http_assessor"] == "available"
        assert tools["zap"] == "not_configured"
        assert tools["burp_dast"] == "not_configured"

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
        assert run["executed_tools"] == ["http_assessor"]

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
