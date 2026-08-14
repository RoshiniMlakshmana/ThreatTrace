"""Focused tests for dashboard/live/index.html -- the Block 15J-K
real-time operational dashboard. These are static-content checks only
(no browser automation is available in this environment); they confirm
required sections exist, EventSource/fetch wiring targets the real
backend API, no fake data is hardcoded, and the required honest empty/
blocked/unavailable/NOT_DEPLOYED states are present in the markup.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_DASHBOARD_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "live" / "index.html"


@pytest.fixture(scope="module")
def dashboard_html() -> str:
    assert _DASHBOARD_PATH.is_file(), f"expected {_DASHBOARD_PATH} to exist"
    return _DASHBOARD_PATH.read_text(encoding="utf-8")


class TestLoadsAndStructure:
    def test_001_file_exists_and_is_nonempty(self, dashboard_html):
        assert len(dashboard_html) > 1000

    def test_002_has_title(self, dashboard_html):
        assert "<title>ThreatTrace Live Platform</title>" in dashboard_html

    def test_003_is_valid_html_skeleton(self, dashboard_html):
        assert "<!doctype html>" in dashboard_html.lower()
        assert "<html" in dashboard_html
        assert "</html>" in dashboard_html
        assert "<script>" in dashboard_html and "</script>" in dashboard_html


class TestRequiredSections:
    @pytest.mark.parametrize("heading", [
        "A. System Status", "B. Pipeline", "C. Live Event Feed", "D. Tool Activity",
        "E. Security Governor", "F. Findings", "G. Threat Intelligence Context",
        "H. Detection Engineering", "I. Limitations",
    ])
    def test_004_section_headings_present(self, dashboard_html, heading):
        assert heading in dashboard_html

    def test_005_pipeline_stages_present(self, dashboard_html):
        for label in ["Bug Bounty", "Normalize", "Correlate", "Prioritize", "TI / Hunt", "Detection", "Red / Purple", "Human Review"]:
            assert label in dashboard_html


class TestEventSourceWiring:
    def test_006_uses_eventsource(self, dashboard_html):
        assert "new EventSource(" in dashboard_html

    def test_007_stream_endpoint_targets_real_backend_route(self, dashboard_html):
        assert "/api/runs/${runId}/stream" in dashboard_html

    def test_008_uses_fetch_for_api_calls(self, dashboard_html):
        assert "fetch(" in dashboard_html
        assert "/api/health" in dashboard_html
        assert "/api/runs" in dashboard_html


class TestNoHardcodedFakeData:
    @pytest.mark.parametrize("forbidden", [
        '"canonical_findings": [', "Missing Content-Security-Policy header actually found",
        "fakeFinding", "mockFinding", "demoFinding", "sampleFinding", "Math.random()",
        "setInterval(fakeEvent", "hardcodedGovernor",
    ])
    def test_009_no_fake_data_literals(self, dashboard_html, forbidden):
        assert forbidden not in dashboard_html

    def test_010_findings_rendered_only_from_fetched_report(self, dashboard_html):
        assert "report.canonical_findings.map" in dashboard_html

    def test_011_no_inline_finding_arrays(self, dashboard_html):
        import re
        # A hardcoded finding array would look like: findings = [{title: ..., severity: ...}]
        assert not re.search(r"findings\s*=\s*\[\s*\{", dashboard_html)


class TestHonestStates:
    def test_012_no_active_run_empty_state(self, dashboard_html):
        assert "No active run." in dashboard_html

    def test_013_not_configured_state_for_zap_burp(self, dashboard_html):
        assert "not_configured" in dashboard_html.lower() or "not part of this run" in dashboard_html

    def test_014_zero_observations_not_secure_claim(self, dashboard_html):
        assert "0 canonical findings." in dashboard_html
        assert "Secure" not in dashboard_html
        assert "is secure" not in dashboard_html.lower()

    def test_015_not_deployed_displayed(self, dashboard_html):
        assert "NOT_DEPLOYED" in dashboard_html

    def test_016_local_only_disclosure_present(self, dashboard_html):
        assert "local development/research interface" in dashboard_html
        assert "not a production-authenticated control plane" in dashboard_html

    def test_017_never_claims_authentication(self, dashboard_html):
        lowered = dashboard_html.lower()
        assert "authenticated user" not in lowered
        assert "logged in as" not in lowered
