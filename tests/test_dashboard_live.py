"""Focused tests for dashboard/live/index.html -- the Block 15J-K
real-time operational dashboard. Most tests are static-content checks
(no browser automation is available in this environment): they confirm
required sections exist, EventSource/fetch wiring targets the real
backend API, no fake data is hardcoded, and the required honest empty/
blocked/unavailable/NOT_DEPLOYED states are present in the markup.

`TestPipelineTruthModel`/`TestFindingsEvidenceDisplay` go further: they
extract the dashboard's real `<script>` content and execute it under
real Node.js (with a minimal DOM/fetch/EventSource/setInterval stub so
the script's own top-level bootstrap calls don't need a real browser),
then call the actual `computeNodeState`/`pillClass`/`renderFindings`-
adjacent logic with real JSON-shaped run/event fixtures -- this verifies
genuine JS behavior, not merely that certain strings appear in the file.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

_DASHBOARD_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "live" / "index.html"

_NODE_STUBS = """
function fakeElement() {
  return { innerHTML: '', textContent: '', className: '', addEventListener: () => {}, disabled: false, value: '', children: [], appendChild: () => {}, prepend: () => {}, removeChild: () => {} };
}
global.document = {
  getElementById: () => fakeElement(),
  querySelector: () => ({ addEventListener: () => {}, open: false }),
  createElement: () => fakeElement(),
};
global.fetch = async () => ({ ok: true, json: async () => ({ runs: [], tools: {}, categories: [] }) });
global.setInterval = () => {};
global.EventSource = function () { this.close = () => {}; };
global.alert = () => {};
// The script's own top-level bootstrap calls (checkHealth/loadSystemInfo/
// refreshRunList) are irrelevant to what these tests actually exercise --
// swallow any rejection from them rather than let it crash the process.
process.on('unhandledRejection', () => {});
"""


@pytest.fixture(scope="module")
def dashboard_html() -> str:
    assert _DASHBOARD_PATH.is_file(), f"expected {_DASHBOARD_PATH} to exist"
    return _DASHBOARD_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dashboard_script(dashboard_html: str) -> str:
    match = re.search(r"<script>(.*)</script>", dashboard_html, re.DOTALL)
    assert match is not None, "expected exactly one <script>...</script> block"
    return match.group(1)


def _run_node(script_body: str) -> str:
    """Runs `_NODE_STUBS` + the real dashboard script + `script_body`
    (which must end by printing a single line of JSON to stdout) under
    real Node.js, returning stdout. Raises with the real stderr on any
    non-zero exit so a genuine JS error is never silently swallowed.
    Written to a temp file rather than passed via `node -e`, since the
    full dashboard script exceeds Windows's command-line length limit.
    """
    import tempfile
    import os

    fd, path = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script_body)
        proc = subprocess.run(["node", path], capture_output=True, text=True, timeout=30)
    finally:
        os.remove(path)
    if proc.returncode != 0:
        raise AssertionError(f"node execution failed:\n{proc.stderr}")
    return proc.stdout.strip().splitlines()[-1]


def _eval_js(dashboard_script: str, expression: str):
    """Evaluates `expression` (a JS expression, not a statement) after
    loading the real dashboard script, and returns the JSON-decoded
    Python value of the result."""
    full = _NODE_STUBS + dashboard_script + f"\nconsole.log(JSON.stringify({expression}));"
    return json.loads(_run_node(full))


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

    def test_009_registers_addEventListener_for_every_named_event_type(self, dashboard_html):
        # Regression test for a real bug: backend.app.stream_events sends
        # every SSE message with a named `event:` field (event_type) --
        # per the SSE spec, EventSource.onmessage alone NEVER fires for a
        # named-type message, so relying on onmessage alone silently
        # drops every live event. addEventListener must be registered
        # for the type, not merely referenced elsewhere in the file.
        assert "eventSource.addEventListener(eventType, onStreamMessage)" in dashboard_html

    def test_010_mirrored_event_types_exactly_match_backend_vocabulary(self, dashboard_html):
        import re
        from backend.models import EVENT_TYPES as BACKEND_EVENT_TYPES

        match = re.search(r"const EVENT_TYPES = \[(.*?)\];", dashboard_html, re.DOTALL)
        assert match is not None, "expected a top-level const EVENT_TYPES = [...] array in the dashboard JS"
        js_types = set(re.findall(r'"([a-z_]+)"', match.group(1)))
        assert js_types == set(BACKEND_EVENT_TYPES)

    def test_011_terminal_event_triggers_authoritative_refresh(self, dashboard_html):
        # run_completed (and the other terminal types) must trigger a
        # fresh GET /api/runs/{id} (via refreshSelectedRun) and, since
        # that call checks TERMINAL.has(run.status), a fresh
        # GET /api/runs/{id}/evaluation (via loadEvaluation) -- never
        # stale client-side state after completion.
        assert '["run_completed","run_blocked","run_failed","run_cancelled"].includes(event.event_type)' in dashboard_html
        assert "refreshSelectedRun();" in dashboard_html
        assert "if (TERMINAL.has(run.status)) loadEvaluation(currentRunId);" in dashboard_html


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


def _completed_run(**overrides):
    run = {
        "run_id": "RUN-test", "run_type": "bug_bounty", "status": "completed",
        "current_stage": "complete", "human_review_required": True,
    }
    run.update(overrides)
    return run


class TestPipelineTruthModel:
    """Real-execution tests (via Node.js) for computeNodeState -- the
    dashboard must never infer an optional/skippable stage ran merely
    because run.status advanced to "completed"; truth must come from
    real observed event types or explicit authoritative run fields."""

    def _state(self, dashboard_script, node, run, events_seen=()):
        expr = f"computeNodeState({json.dumps(node)}, {json.dumps(run)}, new Set({json.dumps(list(events_seen))}))"
        return _eval_js(dashboard_script, expr)

    # A: completed Bug Bounty-only run -> Bug Bounty = done
    def test_A_bug_bounty_stage_done_on_completed_run(self, dashboard_script):
        node = {"key": "bug_bounty", "stages": ["intake", "planning", "tool_policy", "governor", "tool_execution"]}
        assert self._state(dashboard_script, node, _completed_run()) == "done"

    # B: normalization present -> Normalize = done
    def test_B_normalize_done_on_completed_run(self, dashboard_script):
        node = {"key": "normalize", "stages": ["normalization"]}
        assert self._state(dashboard_script, node, _completed_run()) == "done"

    # C: correlation present -> Correlate = done
    def test_C_correlate_done_on_completed_run(self, dashboard_script):
        node = {"key": "correlate", "stages": ["correlation"]}
        assert self._state(dashboard_script, node, _completed_run()) == "done"

    def test_C2_normalize_not_done_if_run_failed_before_reaching_it(self, dashboard_script):
        # A run that failed during tool_execution must NOT show
        # Normalize as done -- proves this isn't still inferring from
        # run.status alone.
        node = {"key": "normalize", "stages": ["normalization"]}
        run = _completed_run(status="failed", current_stage="tool_execution")
        assert self._state(dashboard_script, node, run) != "done"

    # D: no TI data/events -> TI / Hunt = not_run
    def test_D_ti_hunt_not_run_without_real_events(self, dashboard_script):
        node = {"key": "ti_hunt", "stages": ["threat_intel"]}
        assert self._state(dashboard_script, node, _completed_run()) == "not_run"

    def test_D2_ti_hunt_done_when_real_event_observed(self, dashboard_script):
        node = {"key": "ti_hunt", "stages": ["threat_intel"]}
        result = self._state(dashboard_script, node, _completed_run(), events_seen=["threat_intel_ingested"])
        assert result == "done"

    # E: no detection data/events -> Detection = not_run
    def test_E_detection_not_run_without_real_events(self, dashboard_script):
        node = {"key": "detection", "stages": ["detection_engineering"]}
        assert self._state(dashboard_script, node, _completed_run()) == "not_run"

    def test_E2_detection_done_when_real_event_observed(self, dashboard_script):
        node = {"key": "detection", "stages": ["detection_engineering"]}
        result = self._state(dashboard_script, node, _completed_run(), events_seen=["detection_plan_created"])
        assert result == "done"

    # F: no Red/Purple data -> Red / Purple = not_run/not applicable
    def test_F_red_purple_always_neutral_never_failed(self, dashboard_script):
        node = {"key": "red_purple", "stages": []}
        assert self._state(dashboard_script, node, _completed_run()) == "na"

    def test_F2_red_purple_neutral_even_on_a_failed_run(self, dashboard_script):
        node = {"key": "red_purple", "stages": []}
        run = _completed_run(status="failed", current_stage="tool_execution")
        state = self._state(dashboard_script, node, run)
        assert state not in ("failed", "blocked")

    # G: requires_human_review with no review result -> awaiting_review/pending
    def test_G_human_review_awaiting_when_required_and_undecided(self, dashboard_script):
        node = {"key": "human_review", "stages": ["human_review"]}
        run = _completed_run(human_review_required=True)
        assert self._state(dashboard_script, node, run) == "awaiting_review"

    def test_G2_human_review_not_applicable_when_not_required(self, dashboard_script):
        node = {"key": "human_review", "stages": ["human_review"]}
        run = _completed_run(human_review_required=False)
        assert self._state(dashboard_script, node, run) == "not_applicable"

    # H: actual recorded review result -> Human Review = done
    def test_H_human_review_done_when_a_real_decision_field_is_present(self, dashboard_script):
        # No current backend code path ever sets human_review_decision
        # -- this is a forward-compatible-only check. Documented here
        # explicitly so a future reviewer knows this branch is
        # currently unreachable with real production data, not dead
        # code by accident.
        node = {"key": "human_review", "stages": ["human_review"]}
        run = _completed_run(human_review_required=True, human_review_decision="approved")
        assert self._state(dashboard_script, node, run) == "done"

    # I: completed run -> Complete = done
    def test_I_complete_done_on_completed_run(self, dashboard_script):
        node = {"key": "complete", "stages": ["complete"]}
        assert self._state(dashboard_script, node, _completed_run()) == "done"

    def test_I2_complete_not_done_on_a_still_running_run(self, dashboard_script):
        node = {"key": "complete", "stages": ["complete"]}
        run = _completed_run(status="running", current_stage="tool_execution")
        assert self._state(dashboard_script, node, run) != "done"

    def test_no_blanket_completed_override_remains_in_source(self, dashboard_html):
        # Regression guard for the exact root cause: the old code's
        # `currentIndex > nodeMaxIndex || (run.status === "completed")`
        # blanket OR-clause must never return.
        assert '|| (run.status === "completed"' not in dashboard_html
        assert '|| run.status === "completed"' not in dashboard_html


class TestFindingsEvidenceDisplay:
    """Real-execution tests for the Findings table's evidence/source
    columns -- the dashboard previously read a nonexistent `f.evidence`
    field, which always silently evaluated to 0."""

    def _render(self, dashboard_script, run):
        # renderFindings writes into el("findings-body").innerHTML; our
        # document stub returns a fresh fake element per call, so we
        # capture the HTML by overriding getElementById for this one
        # call via a small wrapper appended to the script.
        expr = f"""(function() {{
            const captured = {{ html: null }};
            const real = document.getElementById;
            document.getElementById = (id) => {{
                if (id === 'findings-body') {{
                    const el = {{ set innerHTML(v) {{ captured.html = v; }}, get innerHTML() {{ return captured.html; }} }};
                    return el;
                }}
                return real(id);
            }};
            renderFindings({json.dumps(run)});
            document.getElementById = real;
            return captured.html;
        }})()"""
        return _eval_js(dashboard_script, expr)

    # J: canonical finding with 2 evidence records -> dashboard displays 2, not 0
    def test_J_two_evidence_records_displayed_as_2_not_0(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-1", "title": "CSP Header Not Set", "technical_severity": "medium",
            "confidence": "high", "tools_used": ["http_assessor", "zap"],
            "evidence_sources": [{"source_tool": "http_assessor"}, {"source_tool": "zap"}],
            "status": "requires_human_review",
        }]})
        html = self._render(dashboard_script, run)
        assert "2 records" in html
        assert "0 evidence item(s)" not in html

    # K: canonical finding with http_assessor+zap -> both real sources displayed
    def test_K_both_real_sources_displayed(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-1", "title": "CSP Header Not Set", "technical_severity": "medium",
            "confidence": "high", "tools_used": ["http_assessor", "zap"],
            "evidence_sources": [{"source_tool": "http_assessor"}, {"source_tool": "zap"}],
            "status": "requires_human_review",
        }]})
        html = self._render(dashboard_script, run)
        assert "http_assessor" in html
        assert "zap" in html

    # L: missing evidence data -> show unknown / no evidence metadata, never invent zero
    def test_L_missing_evidence_metadata_not_fabricated_as_zero(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-1", "title": "Some Finding", "technical_severity": "low",
            "confidence": "medium", "tools_used": [], "status": "requires_human_review",
        }]})
        html = self._render(dashboard_script, run)
        assert "no evidence metadata" in html
        assert "0 record" not in html
        assert "0 evidence item(s)" not in html

    def test_review_state_column_shows_awaiting_review_not_raw_status_string(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-1", "title": "Some Finding", "technical_severity": "low",
            "confidence": "medium", "tools_used": ["nuclei"],
            "evidence_sources": [{"source_tool": "nuclei"}], "status": "requires_human_review",
        }]})
        html = self._render(dashboard_script, run)
        assert "Awaiting Review" in html

    def test_no_hardcoded_tool_names_per_vulnerability(self, dashboard_html):
        # The table must render whatever tools_used the real finding
        # carries -- it must never special-case a specific vulnerability
        # title to a fixed tool list.
        assert 'title === "Content Security Policy' not in dashboard_html
        assert "CSP Header Not Set" not in dashboard_html or "tools_used" in dashboard_html


class TestSSEFixPreservation:
    """M: the previous named-SSE-event fix must remain fully intact."""

    def test_M1_event_types_const_present(self, dashboard_html):
        assert "const EVENT_TYPES = [" in dashboard_html

    def test_M2_addEventListener_registration_present(self, dashboard_html):
        assert "eventSource.addEventListener(eventType, onStreamMessage)" in dashboard_html

    def test_M3_event_types_still_matches_backend_exactly(self, dashboard_html):
        from backend.models import EVENT_TYPES as BACKEND_EVENT_TYPES

        match = re.search(r"const EVENT_TYPES = \[(.*?)\];", dashboard_html, re.DOTALL)
        assert match is not None
        js_types = set(re.findall(r'"([a-z_]+)"', match.group(1)))
        assert js_types == set(BACKEND_EVENT_TYPES)

    def test_M4_terminal_refresh_still_wired(self, dashboard_html):
        assert '["run_completed","run_blocked","run_failed","run_cancelled"].includes(event.event_type)' in dashboard_html
        assert "refreshSelectedRun();" in dashboard_html
        assert "if (TERMINAL.has(run.status)) loadEvaluation(currentRunId);" in dashboard_html

    def test_M5_observed_event_types_populated_from_every_event(self, dashboard_html):
        assert "observedEventTypes.add(event.event_type);" in dashboard_html
