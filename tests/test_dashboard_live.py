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


class TestAttackSurfaceSection:
    """Step 2: core.bug_bounty_crawler's run.attack_surface data,
    rendered by renderAttackSurface(run) -- values must always come
    from the real API response, never be hardcoded, and honest empty/
    partial/failed states must be present."""

    def test_018_section_heading_present(self, dashboard_html):
        assert "K. Attack Surface Discovery" in dashboard_html

    def test_019_no_active_discovery_empty_state(self, dashboard_html):
        assert "No discovery data for this run." in dashboard_html

    def test_020_render_function_reads_run_attack_surface(self, dashboard_html):
        assert "run.attack_surface" in dashboard_html
        assert "function renderAttackSurface(run)" in dashboard_html

    def test_021_wired_into_refresh_and_reset_paths(self, dashboard_html):
        assert dashboard_html.count("renderAttackSurface(") >= 4

    def test_022_status_states_covered(self, dashboard_html):
        for status in ('"completed"', '"partial"', '"failed"'):
            assert status in dashboard_html

    def test_023_failed_state_never_treated_as_empty_success(self, dashboard_html):
        assert 'surface.status === "failed"' in dashboard_html

    def test_024_metrics_come_from_summary_object_not_literals(self, dashboard_html):
        assert "summary.endpoint_count" in dashboard_html
        assert "summary.parameter_count" in dashboard_html
        assert "summary.form_count" in dashboard_html
        assert "summary.api_endpoint_count" in dashboard_html

    def test_025_no_hardcoded_endpoint_counts(self, dashboard_html):
        import re
        # A hardcoded metric would look like a literal number assigned
        # directly instead of read from the surface/summary object.
        assert not re.search(r"endpoint_count[\"']?\s*:\s*\d", dashboard_html)
        assert not re.search(r"parameter_count[\"']?\s*:\s*\d", dashboard_html)

    def test_026_no_juice_shop_route_hardcoding(self, dashboard_html):
        for forbidden in ("/rest/products/search", "/api/BasketItems", "juice-shop", "juiceShop"):
            assert forbidden not in dashboard_html

    def test_027_display_is_bounded_not_unbounded_dump(self, dashboard_html):
        assert "MAX_SURFACE_ROWS_DISPLAYED" in dashboard_html
        assert "endpoints.slice(0, MAX_SURFACE_ROWS_DISPLAYED)" in dashboard_html
        assert "Showing" in dashboard_html and "discovered endpoints" in dashboard_html

    def test_028_endpoint_and_parameter_tables_use_esc(self, dashboard_html):
        # Every endpoint/parameter table cell must be escaped, exactly
        # like the existing findings/evaluation tables -- untrusted
        # target-derived path/parameter strings must never be injected
        # into the DOM unescaped.
        assert "esc(e.method)" in dashboard_html
        assert "esc(e.path)" in dashboard_html
        assert "esc(p.name)" in dashboard_html
        assert "esc(p.location)" in dashboard_html

    def test_029_parameter_values_never_rendered(self, dashboard_html):
        # Only parameter name/location/source/endpoint are ever shown --
        # never a captured value (which could be a sensitive query
        # value like a search term or session-like token).
        assert "p.value" not in dashboard_html

    def test_030_budget_exhausted_honestly_labeled_partial(self, dashboard_html):
        assert "bounded, partial coverage" in dashboard_html

    def test_031_not_a_complete_coverage_claim(self, dashboard_html):
        assert "not a claim of complete application coverage" in dashboard_html
