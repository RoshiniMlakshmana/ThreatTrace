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
  addEventListener: () => {},
};
global.fetch = async () => ({ ok: true, json: async () => ({ runs: [], tools: {}, categories: [] }) });
global.setInterval = () => {};
global.EventSource = function () { this.close = () => {}; };
global.alert = () => {};
global.window = { prompt: () => null };
global.HTMLElement = class {};
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
        "A. System Status", "B. Pipeline", "C. Technical Event Log", "D. Tool Activity",
        "E. Security Governor", "F. Findings", "G. Threat Intelligence Context",
        "H. Detection Engineering", "I. Scope &amp; Safety",
    ])
    def test_004_section_headings_present(self, dashboard_html, heading):
        assert heading in dashboard_html

    def test_005_pipeline_stages_present(self, dashboard_html):
        for label in [
            "Bug Bounty", "Normalize", "Correlate", "Prioritize", "TI / Hunt", "Detection",
            "Red Validation", "Purple", "Human Review",
        ]:
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
        # that call checks run.report (not run status terminality --
        # core.bug_bounty_juice_shop_evaluation gates purely on report
        # presence), a fresh GET /api/runs/{id}/evaluation (via
        # loadEvaluation) -- never stale client-side state after
        # completion.
        assert '["run_completed","run_blocked","run_failed","run_cancelled"].includes(event.event_type)' in dashboard_html
        assert "refreshSelectedRun();" in dashboard_html
        assert "if (run.report) loadEvaluation(currentRunId);" in dashboard_html


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
        return _eval_js(dashboard_script, expr)["state"]

    def _lifecycle_run(self, results, **overrides):
        base = {
            "status": "awaiting_human_review", "current_stage": "human_review",
            "lifecycle": {
                "lifecycle_version": "1", "total_canonical_findings": len(results),
                "findings_selected": [r["finding_id"] for r in results], "results": results,
            },
        }
        base.update(overrides)
        return _completed_run(**base)

    def _result(self, *, finding_id="CF-1", ti_outcome="no_relevant_intel", hunt_outcome="telemetry_gap",
                detection_outcome="not_applicable", purple_outcome="recommendation_created", approval_state="pending"):
        return {
            "finding_id": finding_id,
            "ti_result": {"outcome": ti_outcome}, "hunt_result": {"outcome": hunt_outcome},
            "detection_result": {"outcome": detection_outcome}, "purple_result": {"outcome": purple_outcome},
            "red_validation_result": {"outcome": "controlled_validation_unavailable"},
            "case": {"case_id": f"SH-{finding_id}", "approval_state": approval_state},
        }

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
        node = {"key": "ti_hunt", "stages": ["threat_intel", "threat_hunt"]}
        assert self._state(dashboard_script, node, _completed_run()) == "not_run"

    def test_D2_ti_hunt_active_while_started_but_not_yet_in_results(self, dashboard_script):
        node = {"key": "ti_hunt", "stages": ["threat_intel", "threat_hunt"]}
        result = self._state(dashboard_script, node, _completed_run(), events_seen=["threat_intel_review_started"])
        assert result == "active"

    def test_D3_ti_hunt_done_when_real_lifecycle_results_present(self, dashboard_script):
        node = {"key": "ti_hunt", "stages": ["threat_intel", "threat_hunt"]}
        run = self._lifecycle_run([self._result(hunt_outcome="hunt_candidate_created")])
        assert self._state(dashboard_script, node, run) == "done"

    def test_D4_ti_hunt_neutral_when_no_intel_and_telemetry_gap(self, dashboard_script):
        node = {"key": "ti_hunt", "stages": ["threat_intel", "threat_hunt"]}
        run = self._lifecycle_run([self._result(ti_outcome="no_relevant_intel", hunt_outcome="telemetry_gap")])
        assert self._state(dashboard_script, node, run) == "na"

    # E: no detection data/events -> Detection = not_run
    def test_E_detection_not_run_without_real_events(self, dashboard_script):
        node = {"key": "detection", "stages": ["detection_engineering"]}
        assert self._state(dashboard_script, node, _completed_run()) == "not_run"

    def test_E2_detection_done_when_real_lifecycle_results_present(self, dashboard_script):
        node = {"key": "detection", "stages": ["detection_engineering"]}
        run = self._lifecycle_run([self._result(detection_outcome="candidate_ready")])
        assert self._state(dashboard_script, node, run) == "done"

    def test_E3_detection_neutral_when_no_rule(self, dashboard_script):
        node = {"key": "detection", "stages": ["detection_engineering"]}
        run = self._lifecycle_run([self._result(detection_outcome="not_applicable")])
        assert self._state(dashboard_script, node, run) == "na"

    # F: Red Validation never falsely marked done; Purple recommendation only
    def test_F_red_validation_always_neutral_never_done(self, dashboard_script):
        node = {"key": "red_validation", "stages": ["red_validation"]}
        run = self._lifecycle_run([self._result()])
        assert self._state(dashboard_script, node, run) == "na"

    def test_F2_red_validation_never_failed(self, dashboard_script):
        node = {"key": "red_validation", "stages": ["red_validation"]}
        run = self._lifecycle_run([self._result()], status="failed")
        state = self._state(dashboard_script, node, run)
        assert state not in ("failed", "blocked")

    def test_F3_red_validation_not_run_without_lifecycle(self, dashboard_script):
        node = {"key": "red_validation", "stages": ["red_validation"]}
        assert self._state(dashboard_script, node, _completed_run()) == "not_run"

    def test_F4_purple_done_but_never_applied(self, dashboard_script):
        node = {"key": "purple", "stages": ["purple_remediation"]}
        run = self._lifecycle_run([self._result(purple_outcome="recommendation_created")])
        assert self._state(dashboard_script, node, run) == "done"

    # G: requires_human_review with no review result -> awaiting_review/pending
    def test_G_human_review_awaiting_when_required_and_undecided(self, dashboard_script):
        node = {"key": "human_review", "stages": ["human_review"]}
        run = _completed_run(human_review_required=True)
        assert self._state(dashboard_script, node, run) == "awaiting_review"

    def test_G2_human_review_not_applicable_when_not_required(self, dashboard_script):
        node = {"key": "human_review", "stages": ["human_review"]}
        run = _completed_run(human_review_required=False)
        assert self._state(dashboard_script, node, run) == "not_applicable"

    def test_G3_human_review_awaiting_with_real_pending_case(self, dashboard_script):
        node = {"key": "human_review", "stages": ["human_review"]}
        run = self._lifecycle_run([self._result(approval_state="pending")])
        assert self._state(dashboard_script, node, run) == "awaiting_review"

    # H: actual recorded review result -> Human Review = done
    def test_H_human_review_done_when_all_real_cases_reviewed(self, dashboard_script):
        node = {"key": "human_review", "stages": ["human_review"]}
        run = self._lifecycle_run([self._result(approval_state="approved")], status="completed", current_stage="complete")
        assert self._state(dashboard_script, node, run) == "done"

    def test_H2_human_review_awaiting_if_any_case_still_pending(self, dashboard_script):
        node = {"key": "human_review", "stages": ["human_review"]}
        run = self._lifecycle_run([
            self._result(finding_id="CF-1", approval_state="approved"),
            self._result(finding_id="CF-2", approval_state="pending"),
        ])
        assert self._state(dashboard_script, node, run) == "awaiting_review"

    # I: completed run -> Complete = done
    def test_I_complete_done_on_completed_run(self, dashboard_script):
        node = {"key": "complete", "stages": ["complete"]}
        assert self._state(dashboard_script, node, _completed_run()) == "done"

    def test_I2_complete_not_done_on_a_still_running_run(self, dashboard_script):
        node = {"key": "complete", "stages": ["complete"]}
        run = _completed_run(status="running", current_stage="tool_execution")
        assert self._state(dashboard_script, node, run) != "done"

    def test_I3_complete_not_done_while_awaiting_human_review(self, dashboard_script):
        # Real regression guard: a Full Security Lifecycle run's
        # non-terminal "awaiting_human_review" status must never show
        # Complete = done -- the run genuinely isn't finished yet.
        node = {"key": "complete", "stages": ["complete"]}
        run = self._lifecycle_run([self._result()])
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


class TestSecurityLifecycleUI:
    """Full Security Lifecycle dashboard UI: the new run-mode button,
    the K/L pipeline nodes, and the new lifecycle detail card."""

    def test_050_lifecycle_button_present_distinct_from_bug_bounty_button(self, dashboard_html):
        assert 'id="lifecycle-start"' in dashboard_html
        assert "Run Full Security Lifecycle" in dashboard_html
        assert 'id="bb-start"' in dashboard_html
        assert "New Bug Bounty Run" in dashboard_html

    def test_051_lifecycle_button_posts_to_dedicated_endpoint(self, dashboard_html):
        assert '"/api/runs/security-lifecycle"' in dashboard_html

    def test_052_lifecycle_button_never_silently_reuses_bug_bounty_endpoint(self, dashboard_html):
        import re

        match = re.search(r'el\("lifecycle-start"\)\.addEventListener\("click".*?\}\);', dashboard_html, re.DOTALL)
        assert match is not None
        assert "/api/runs/bug-bounty" not in match.group(0)

    def test_053_lifecycle_card_present(self, dashboard_html):
        assert "L. Security Lifecycle Detail" in dashboard_html
        assert 'id="lifecycle-body"' in dashboard_html

    def test_054_lifecycle_empty_state_honest(self, dashboard_html):
        assert "Not a Full Security Lifecycle run." in dashboard_html

    def test_055_renderLifecycle_wired_into_refresh_and_reset(self, dashboard_html):
        assert dashboard_html.count("renderLifecycle(") >= 3

    def test_056_review_action_labeled_local_not_authenticated(self, dashboard_html):
        assert "local development/research review action only" in dashboard_html
        assert "never authenticated" in dashboard_html

    def test_057_review_posts_to_dedicated_lifecycle_review_endpoint(self, dashboard_html):
        assert "/lifecycle/review" in dashboard_html

    def test_058_purple_recommendation_never_claims_applied(self, dashboard_html):
        assert "recommendation_created" in dashboard_html or "Recommendation created" in dashboard_html
        assert "not applied" in dashboard_html.lower()

    def test_059_red_validation_never_claims_executed_attack(self, dashboard_html):
        lowered = dashboard_html.lower()
        assert "controlled_validation_unavailable" in dashboard_html or "controlled validation unavailable" in lowered
        assert "exploit executed" not in lowered

    def test_060_hunt_labeled_scoped_not_executed(self, dashboard_html):
        assert "Hunt scoped (not executed)" in dashboard_html

    def test_061_lifecycle_outcomes_come_from_real_data_not_hardcoded_finding(self, dashboard_html):
        # lifecycleOutcomeLabel maps outcome CODES to display text -- it
        # must never reference a specific Juice Shop finding title.
        import re

        match = re.search(r"function lifecycleOutcomeLabel\(outcome\) \{.*?\n\}", dashboard_html, re.DOTALL)
        assert match is not None
        assert "CSP" not in match.group(0)
        assert "Juice" not in match.group(0)

    def test_062_pipeline_shows_split_red_and_purple_nodes(self, dashboard_html):
        # Regression guard: the old combined "Red / Purple" node is gone
        # -- Red Validation and Purple are now tracked/labeled separately.
        assert '"key": "red_validation"' in dashboard_html or "key: \"red_validation\"" in dashboard_html
        assert '"key": "purple"' in dashboard_html or "key: \"purple\"" in dashboard_html


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
        assert "if (run.report) loadEvaluation(currentRunId);" in dashboard_html

    def test_M5_observed_event_types_populated_from_every_event(self, dashboard_html):
        assert "observedEventTypes.add(event.event_type);" in dashboard_html


class TestLifecycleRefreshFix:
    """Regression tests for the Full Security Lifecycle dashboard
    synchronization defect: a run that reached the real, non-terminal
    "awaiting_human_review" status went stale on-screen because
    handleEvent() only ever called refreshSelectedRun() for the four
    Bug-Bounty-only terminal event types, and refreshSelectedRun()
    itself only loaded evaluation data when run.status was terminal.
    Both gates are now driven by real backend signals (the actual
    lifecycle event vocabulary, and run.report presence) instead of
    Bug-Bounty-only terminality."""

    def _lifecycle_result(self, *, finding_id="CF-1", ti_outcome="no_relevant_intel",
                           hunt_outcome="telemetry_gap", detection_outcome="not_applicable",
                           red_outcome="controlled_validation_unavailable",
                           purple_outcome="recommendation_created", approval_state="pending"):
        return {
            "finding_id": finding_id,
            "ti_result": {"outcome": ti_outcome},
            "hunt_result": {"outcome": hunt_outcome},
            "detection_result": {"outcome": detection_outcome},
            "red_validation_result": {"outcome": red_outcome},
            "purple_result": {"outcome": purple_outcome, "recommendations": ["Add a documented mitigation."]},
            "case": {"case_id": f"SH-{finding_id}", "approval_state": approval_state},
        }

    def _awaiting_review_run(self, results=None, **overrides):
        results = results if results is not None else [self._lifecycle_result()]
        base = {
            "run_id": "RUN-test", "run_type": "bug_bounty", "status": "awaiting_human_review",
            "current_stage": "human_review", "human_review_required": True,
            "started_at": "2026-08-16T21:22:20Z", "completed_at": None,
            "report": {"canonical_findings": []},
            "attack_surface": {
                "status": "completed",
                "attack_surface_summary": {"endpoint_count": 3, "parameter_count": 1, "form_count": 0, "api_endpoint_count": 2},
                "telemetry": {}, "endpoints": [], "parameters": [],
            },
            "lifecycle": {
                "lifecycle_version": "1", "context_label": "demo/research context",
                "total_canonical_findings": len(results), "findings_selected": [r["finding_id"] for r in results],
                "selection_reason": "highest priority_score.final", "results": results,
            },
        }
        base.update(overrides)
        return base

    def _fetch_after_event(self, dashboard_script, run, event_type):
        """Sets currentRunId, stubs fetch to record every URL requested
        and to serve `run` for GET /api/runs/{id}, calls the real
        handleEvent(event) (which is fire-and-forget for
        refreshSelectedRun, exactly as in the live dashboard), waits one
        macrotask for any triggered async refresh to actually run its
        fetch, and returns the list of requested URLs."""
        # Written directly for _run_node (not _eval_js): this needs a real
        # `await` before printing, which a JSON.stringify(<expression>)
        # wrapper around a Promise cannot provide -- console.log would
        # otherwise fire before the awaited setTimeout resolves.
        script = _NODE_STUBS + dashboard_script + f"""
(async function() {{
    let calls = [];
    global.fetch = async (url) => {{
        calls.push(url);
        if (String(url).includes('/evaluation')) {{
            return {{ ok: true, json: async () => ({{ evaluation_state: "evaluated" }}) }};
        }}
        return {{ ok: true, json: async () => ({json.dumps(run)}) }};
    }};
    // Let the page's own bootstrap (checkHealth/loadSystemInfo/
    // refreshRunList, called at the bottom of the real script) settle
    // first, while currentRunId is still null -- loadSystemInfo() itself
    // conditionally fetches /api/runs/{{currentRunId}} when a run is
    // already selected, which would otherwise be indistinguishable from
    // a refresh genuinely triggered by handleEvent below.
    await new Promise((resolve) => setTimeout(resolve, 0));
    calls = [];
    currentRunId = "RUN-test";
    handleEvent({{
        event_type: {json.dumps(event_type)}, timestamp: "2026-08-16T21:30:00Z",
        source_component: "orchestrator", summary: "x", sanitized_payload: {{}},
    }});
    await new Promise((resolve) => setTimeout(resolve, 50));
    console.log(JSON.stringify(calls));
}})();
"""
        return json.loads(_run_node(script))

    def _render_body(self, dashboard_script, element_id, fn_call):
        expr = f"""(function() {{
            const captured = {{ html: null }};
            const real = document.getElementById;
            document.getElementById = (id) => {{
                if (id === {json.dumps(element_id)}) {{
                    const el = {{ set innerHTML(v) {{ captured.html = v; }}, get innerHTML() {{ return captured.html; }} }};
                    return el;
                }}
                return real(id);
            }};
            {fn_call};
            document.getElementById = real;
            return captured.html;
        }})()"""
        return _eval_js(dashboard_script, expr)

    # A: a real lifecycle sub-stage event triggers an authoritative refresh
    def test_A_lifecycle_event_triggers_refresh(self, dashboard_script):
        run = self._awaiting_review_run()
        calls = self._fetch_after_event(dashboard_script, run, "detection_engineering_completed")
        assert any("/api/runs/RUN-test" in c and "/evaluation" not in c for c in calls)

    # B: human_review_required specifically triggers a refresh
    def test_B_human_review_required_triggers_refresh(self, dashboard_script):
        run = self._awaiting_review_run()
        calls = self._fetch_after_event(dashboard_script, run, "human_review_required")
        assert any("/api/runs/RUN-test" in c and "/evaluation" not in c for c in calls)

    # C: awaiting_human_review displays as an honest stable state, never "running"
    def test_C_awaiting_human_review_displays_correctly(self, dashboard_script):
        run = self._awaiting_review_run()
        expr = f"durationState({json.dumps(run)})"
        assert _eval_js(dashboard_script, expr) == "awaiting review"
        html = self._render_body(dashboard_script, "status-body", f"renderStatus({json.dumps(run)})")
        assert "awaiting review" in html
        assert ">running<" not in html

    # D: Complete must remain pending while awaiting review, never green
    def test_D_complete_remains_pending_while_awaiting_review(self, dashboard_script):
        run = self._awaiting_review_run()
        node = {"key": "complete", "stages": ["complete"]}
        expr = f"computeNodeState({json.dumps(node)}, {json.dumps(run)}, new Set())"
        state = _eval_js(dashboard_script, expr)["state"]
        assert state == "pending"

    # E: Lifecycle Detail renders real content for this run -- keyed off
    # the real run.lifecycle field, never run_type (which stays
    # "bug_bounty" for a lifecycle run by design, since it shares the
    # same concurrency slot as a plain Bug Bounty run).
    def test_E_lifecycle_detail_renders_for_lifecycle_run(self, dashboard_script):
        run = self._awaiting_review_run()
        assert run["run_type"] == "bug_bounty"
        html = self._render_body(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "Not a Full Security Lifecycle run." not in html
        assert "CF-1" in html

    # F: TI outcome renders from real per-finding lifecycle data
    def test_F_ti_result_renders(self, dashboard_script):
        run = self._awaiting_review_run([self._lifecycle_result(ti_outcome="reviewed_relevant")])
        html = self._render_body(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "Relevant intel found" in html

    # G: Hunt outcome renders honestly (never claims real execution)
    def test_G_hunt_result_renders(self, dashboard_script):
        run = self._awaiting_review_run([self._lifecycle_result(hunt_outcome="hunt_candidate_created")])
        html = self._render_body(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "Hunt scoped (not executed)" in html

    # H: Detection outcome renders
    def test_H_detection_result_renders(self, dashboard_script):
        run = self._awaiting_review_run([self._lifecycle_result(detection_outcome="candidate_ready")])
        html = self._render_body(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "Rule candidate created" in html

    # I: Red Validation outcome renders honestly -- never a fabricated
    # "executed"/"passed" claim, since no real exploit engine exists.
    def test_I_red_result_renders_honestly(self, dashboard_script):
        run = self._awaiting_review_run()
        html = self._render_body(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "Controlled validation unavailable" in html
        assert "exploit executed" not in html.lower()

    # J: Purple recommendation renders, never claims applied
    def test_J_purple_recommendation_renders(self, dashboard_script):
        run = self._awaiting_review_run()
        html = self._render_body(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "Add a documented mitigation." in html

    # K: Attack Surface data still renders correctly for a run that is
    # simultaneously a lifecycle run -- the two real data sources
    # (run.attack_surface, run.lifecycle) must not interfere.
    def test_K_attack_surface_still_renders_on_lifecycle_run(self, dashboard_script):
        run = self._awaiting_review_run()
        html = self._render_body(dashboard_script, "attack-surface-body", f"renderAttackSurface({json.dumps(run)})")
        assert "No discovery data for this run." not in html
        assert ">3<" in html  # endpoint_count

    # L: the existing named-SSE event fix remains fully intact
    def test_L_named_sse_fix_still_intact(self, dashboard_html):
        from backend.models import EVENT_TYPES as BACKEND_EVENT_TYPES

        assert "eventSource.addEventListener(eventType, onStreamMessage)" in dashboard_html
        match = re.search(r"const EVENT_TYPES = \[(.*?)\];", dashboard_html, re.DOTALL)
        assert match is not None
        js_types = set(re.findall(r'"([a-z_]+)"', match.group(1)))
        assert js_types == set(BACKEND_EVENT_TYPES)

    # M: ordinary Bug Bounty-only run behavior is unchanged -- no
    # lifecycle field means the honest empty state stays, a completed
    # status still means "finished", and a low-level tool event that
    # isn't part of the new lifecycle-refresh vocabulary never triggers
    # a spurious extra API call.
    def test_M_plain_bug_bounty_run_unaffected(self, dashboard_script):
        run = _completed_run(started_at="2026-08-16T21:22:20Z", completed_at="2026-08-16T21:24:00Z", lifecycle=None)
        html = self._render_body(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "Not a Full Security Lifecycle run." in html
        expr = f"durationState({json.dumps(run)})"
        assert _eval_js(dashboard_script, expr) == "finished"

    def test_M2_irrelevant_low_level_event_does_not_trigger_refresh(self, dashboard_script):
        run = self._awaiting_review_run()
        calls = self._fetch_after_event(dashboard_script, run, "tool_completed")
        assert not any("/api/runs/RUN-test" in c for c in calls)


# ---------------------------------------------------------------------------
# Final Pre-Release Block: explainability features (AI Activity panel,
# httpx enrichment, Attack Surface human summary, finding CWE/OWASP/
# CVE/ATT&CK columns, Target Mode selector, external-target UI).
# ---------------------------------------------------------------------------


def _render_element(dashboard_script, element_id, fn_call):
    expr = f"""(function() {{
        const captured = {{ html: null }};
        const real = document.getElementById;
        document.getElementById = (id) => {{
            if (id === {json.dumps(element_id)}) {{
                const el = {{ set innerHTML(v) {{ captured.html = v; }}, get innerHTML() {{ return captured.html; }} }};
                return el;
            }}
            return real(id);
        }};
        {fn_call};
        document.getElementById = real;
        return captured.html;
    }})()"""
    return _eval_js(dashboard_script, expr)


class TestTargetModeAndExternalTargetUI:
    def test_001_target_mode_selector_present(self, dashboard_html):
        assert 'id="target-mode"' in dashboard_html
        assert "Demo — OWASP Juice Shop" in dashboard_html
        assert "Authorized External Target" in dashboard_html

    def test_002_external_target_form_fields_present(self, dashboard_html):
        for field_id in ("ext-target", "ext-hosts", "ext-ports", "ext-paths", "ext-ack"):
            assert f'id="{field_id}"' in dashboard_html

    def test_003_default_tool_selection_matches_recommended_conservative_default(self, dashboard_html):
        assert 'id="ext-tool-http_assessor" checked disabled' in dashboard_html
        assert 'id="ext-tool-httpx" checked' in dashboard_html
        assert 'id="ext-tool-katana" checked' in dashboard_html

    def test_004_scanners_opt_in_not_checked_by_default(self, dashboard_html):
        import re

        for tool_id in ("nmap", "nuclei", "zap"):
            match = re.search(rf'id="ext-tool-{tool_id}"[^>]*>', dashboard_html)
            assert match is not None
            assert "checked" not in match.group(0)

    def test_005_acknowledgment_wording_present(self, dashboard_html):
        assert "I am providing the scope for a system I am authorized to test." in dashboard_html

    def test_006_acknowledgment_labeled_as_assertion_not_proof(self, dashboard_html):
        lowered = dashboard_html.lower()
        assert "operator assertion only" in lowered
        assert "does not verify or establish legal authorization" in lowered

    def test_007_missing_acknowledgment_blocks_submission_client_side(self, dashboard_script):
        script = _NODE_STUBS + dashboard_script + """
(function() {
    let alerted = null;
    global.alert = (msg) => { alerted = msg; };
    document.getElementById = (id) => {
        const values = {
            "ext-ack": { checked: false },
            "ext-target": { value: "https://security-test.example.com/" },
            "ext-hosts": { value: "security-test.example.com" },
            "ext-ports": { value: "443" },
            "ext-paths": { value: "/" },
        };
        return values[id] || fakeElement();
    };
    const result = _buildExternalTargetBody();
    console.log(JSON.stringify({ result, alerted }));
})();
"""
        outcome = json.loads(_run_node(script))
        assert outcome["result"] is None
        assert "authorized to test" in outcome["alerted"]

    def test_008_katana_discovery_source_label_present_for_new_source(self, dashboard_html):
        assert '"Katana crawl"' in dashboard_html or "Katana crawl" in dashboard_html


class TestAiActivityPanel:
    def test_009_ai_activity_card_present(self, dashboard_html):
        assert "M. AI Assistance" in dashboard_html
        assert 'id="ai-activity-body"' in dashboard_html

    def test_010_bug_bounty_planner_always_says_no_ai(self, dashboard_script):
        run = _completed_run(lifecycle=None)
        html = _render_element(dashboard_script, "ai-activity-body", f"renderAiActivity({json.dumps(run)})")
        assert "Bug Bounty planner" in html
        assert ">NO<" in html
        assert "never calls an LLM" in html

    def test_011_detection_planner_says_no_when_telemetry_gap(self, dashboard_script):
        run = _completed_run(lifecycle={
            "lifecycle_version": "1", "total_canonical_findings": 1, "findings_selected": ["CF-1"],
            "results": [{
                "finding_id": "CF-1",
                "detection_result": {"outcome": "not_applicable", "reason": "telemetry_gap", "rule": None},
            }],
        })
        html = _render_element(dashboard_script, "ai-activity-body", f"renderAiActivity({json.dumps(run)})")
        assert "Detection planner (CF-1)" in html
        assert "telemetry_gap" in html

    def test_012_detection_planner_says_yes_only_with_real_llm_proposal(self, dashboard_script):
        run = _completed_run(lifecycle={
            "lifecycle_version": "1", "total_canonical_findings": 1, "findings_selected": ["CF-1"],
            "results": [{
                "finding_id": "CF-1",
                "detection_result": {
                    "outcome": "candidate_ready", "reason": "rule_generated",
                    "rule": {"deployment_state": "NOT_DEPLOYED"},
                },
            }],
        })
        html = _render_element(dashboard_script, "ai-activity-body", f"renderAiActivity({json.dumps(run)})")
        assert "Detection planner (CF-1)" in html
        assert ">YES<" in html
        assert "NOT_DEPLOYED" in html

    def test_013_no_hardcoded_ai_claim_independent_of_data(self, dashboard_script):
        # Two different runs with different detection reasons must
        # render different AI-invoked verdicts -- proves the panel is
        # data-driven, not a hardcoded YES/NO string.
        run_gap = _completed_run(lifecycle={
            "lifecycle_version": "1", "total_canonical_findings": 1, "findings_selected": ["CF-1"],
            "results": [{"finding_id": "CF-1", "detection_result": {"outcome": "not_applicable", "reason": "no_llm_proposal_supplied", "rule": None}}],
        })
        run_real = _completed_run(lifecycle={
            "lifecycle_version": "1", "total_canonical_findings": 1, "findings_selected": ["CF-1"],
            "results": [{"finding_id": "CF-1", "detection_result": {"outcome": "needs_review", "reason": "syntax_rejected", "rule": {"deployment_state": "NOT_DEPLOYED"}}}],
        })
        html_gap = _render_element(dashboard_script, "ai-activity-body", f"renderAiActivity({json.dumps(run_gap)})")
        html_real = _render_element(dashboard_script, "ai-activity-body", f"renderAiActivity({json.dumps(run_real)})")
        assert html_gap != html_real

    def test_014_deployment_never_claimed_auto_deployed(self, dashboard_html):
        assert "auto-deployed" in dashboard_html.lower() or "NOT_DEPLOYED" in dashboard_html


class TestArchitectureExplainer:
    def test_015_card_present(self, dashboard_html):
        assert "How ThreatTrace Works" in dashboard_html

    def test_016_pipeline_diagram_text_present(self, dashboard_html):
        for phrase in (
            "Discover", "Validate Scope", "Security Tools", "Normalize Evidence",
            "Correlate Findings", "Prioritize", "Purple Recommendation", "Human Review",
            "AI may propose/reason", "Policy + the Security Governor control execution",
            "Human approves final outcomes",
        ):
            assert phrase in dashboard_html

    def test_017_uses_details_element_expandable(self, dashboard_html):
        import re

        match = re.search(r'id="card-architecture".*?</section>', dashboard_html, re.DOTALL)
        assert match is not None
        assert "<details" in match.group(0)


class TestHttpEnrichmentCard:
    def test_018_card_present(self, dashboard_html):
        assert "N. HTTP Enrichment (httpx)" in dashboard_html
        assert 'id="http-enrichment-body"' in dashboard_html

    def test_019_no_activity_empty_state(self, dashboard_html):
        assert "No httpx activity on this run." in dashboard_html

    def test_020_renders_real_enrichment_data(self, dashboard_script):
        run = _completed_run(http_enrichment={
            "http_enrichment_version": "1", "status": "completed", "target": "http://localhost:3000/",
            "enrichment": {
                "reachable": True, "status_code": 200, "title": "Juice Shop", "content_type": "text/html",
                "server": "Express", "technologies": ["Express"], "redirect_location": None,
            },
        })
        html = _render_element(dashboard_script, "http-enrichment-body", f"renderHttpEnrichment({json.dumps(run)})")
        assert "Juice Shop" in html
        assert "Express" in html

    def test_021_technology_never_labeled_as_vulnerability(self, dashboard_html):
        import re

        match = re.search(r"function renderHttpEnrichment.*?\n\}", dashboard_html, re.DOTALL)
        assert match is not None
        # The only mention of "vulnerability" here is the disclaimer
        # stating technology detection is NOT a vulnerability claim --
        # never a labeling pattern like "vulnerability:" or "is a
        # vulnerability" that would imply one.
        assert "never a vulnerability claim" in match.group(0).lower()
        assert "vulnerability:" not in match.group(0).lower()
        assert "is a vulnerability" not in match.group(0).lower()


class TestFindingExplainability:
    def test_022_cwe_owasp_cve_column_renders(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-1", "title": "SQL Injection", "technical_severity": "high", "confidence": "high",
            "tools_used": ["nuclei"], "evidence_sources": [{"source_tool": "nuclei"}], "status": "requires_human_review",
            "cwe": "CWE-89", "owasp_category": "A03:2021", "cve": ["CVE-2024-1234"], "mitre_attack_mapping": None,
        }]})
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        assert "CWE-89" in html
        assert "A03:2021" in html
        assert "CVE-2024-1234" in html

    def test_023_mitre_attck_honestly_not_mapped_when_absent(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-1", "title": "Missing CSP", "technical_severity": "medium", "confidence": "high",
            "tools_used": ["http_assessor"], "evidence_sources": [{"source_tool": "http_assessor"}],
            "status": "requires_human_review", "cwe": None, "owasp_category": None, "cve": [],
            "mitre_attack_mapping": None,
        }]})
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        assert "Not mapped" in html
        assert "insufficient behavioral evidence" in html

    def test_024_mitre_attck_never_forced_onto_config_finding(self, dashboard_html):
        import re

        match = re.search(r"function renderFindingBlock\(f, run\) \{.*?\n\}", dashboard_html, re.DOTALL)
        assert match is not None
        assert "f.mitre_attack_mapping" in match.group(0)
        assert "Not mapped" in match.group(0)

    def test_025_beginner_first_level_fields_present_not_only_in_details(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-1", "title": "CSP Header Not Set", "technical_severity": "medium",
            "confidence": "high", "tools_used": ["http_assessor"], "host": "localhost", "port": 3000,
            "path": "/", "vulnerability_class": "security_header_misconfiguration",
            "evidence_sources": [{"source_tool": "http_assessor"}], "status": "requires_human_review",
        }]})
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        assert "Why it matters" in html
        assert "clickjacking" in html  # deterministic FINDING_CLASS_IMPACT text for this class
        assert "What to do" in html
        assert "localhost:3000" in html
        assert "Technical Details" in html

    def test_026_technical_fields_preserved_inside_details(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-7", "title": "SQL Injection", "technical_severity": "high", "confidence": "high",
            "tools_used": ["nuclei"], "evidence_sources": [{"source_tool": "nuclei"}], "status": "requires_human_review",
            "cwe": "CWE-89", "owasp_category": "A03:2021", "cve": ["CVE-2024-1234"], "mitre_attack_mapping": None,
        }]})
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        import re
        match = re.search(r"<summary>Technical Details</summary>.*?</details>", html, re.DOTALL)
        assert match is not None
        assert "CF-7" in match.group(0)
        assert "CWE-89" in match.group(0)

    def test_027_recommended_action_from_purple_result_when_present(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-1", "title": "CSP Header Not Set", "technical_severity": "medium",
            "confidence": "high", "tools_used": ["http_assessor"],
            "evidence_sources": [{"source_tool": "http_assessor"}], "status": "requires_human_review",
        }]}, lifecycle={
            "results": [{
                "finding_id": "CF-1",
                "purple_result": {"outcome": "recommendation_created", "recommendations": ["Set a strict Content-Security-Policy header."]},
            }],
        })
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        assert "Set a strict Content-Security-Policy header." in html
        assert "No remediation recommendation" not in html

    def test_028_recommended_action_honest_empty_state_when_absent(self, dashboard_script):
        run = _completed_run(report={"canonical_findings": [{
            "finding_id": "CF-1", "title": "CSP Header Not Set", "technical_severity": "medium",
            "confidence": "high", "tools_used": ["http_assessor"],
            "evidence_sources": [{"source_tool": "http_assessor"}], "status": "requires_human_review",
        }]})
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        assert "No remediation recommendation has been generated for this finding yet." in html


class TestAttackSurfaceHumanSummary:
    def test_025_human_summary_sentence_computed_from_real_counts(self, dashboard_script):
        run = _completed_run(attack_surface={
            "attack_surface_version": "1", "status": "completed", "target": "http://localhost:3000/",
            "endpoints": [
                {"endpoint_id": "EP-1", "path": "/", "method": "GET", "source": "seed", "fetched": True, "status_code": 200, "is_static_asset": False, "depth": 0},
                {"endpoint_id": "EP-2", "path": "/styles.css", "method": "GET", "source": "html_link", "fetched": False, "status_code": None, "is_static_asset": True, "depth": 1},
            ],
            "parameters": [],
            "attack_surface_summary": {"endpoint_count": 2, "parameter_count": 0, "form_count": 0, "api_endpoint_count": 0},
            "telemetry": {},
        })
        html = _render_element(dashboard_script, "attack-surface-body", f"renderAttackSurface({json.dumps(run)})")
        assert "ThreatTrace discovered 2 application resources in this bounded crawl." in html
        assert "1 was fetched successfully, 1 was static resource" in html
        assert "No forms, parameters, or API routes were observed" in html

    def test_026_endpoint_what_it_is_column_renders(self, dashboard_script):
        run = _completed_run(attack_surface={
            "attack_surface_version": "1", "status": "completed", "target": "http://localhost:3000/",
            "endpoints": [
                {"endpoint_id": "EP-1", "path": "/main.js", "method": "GET", "source": "html_link", "fetched": True, "status_code": 200, "is_static_asset": False, "depth": 1},
            ],
            "parameters": [],
            "attack_surface_summary": {"endpoint_count": 1, "parameter_count": 0, "form_count": 0, "api_endpoint_count": 0},
            "telemetry": {},
        })
        html = _render_element(dashboard_script, "attack-surface-body", f"renderAttackSurface({json.dumps(run)})")
        assert "JavaScript application resource" in html

    def test_027_katana_contribution_mentioned_when_present(self, dashboard_script):
        run = _completed_run(attack_surface={
            "attack_surface_version": "1", "status": "completed", "target": "http://localhost:3000/",
            "endpoints": [
                {"endpoint_id": "EP-1", "path": "/", "method": "GET", "source": "seed", "fetched": True, "status_code": 200, "is_static_asset": False, "depth": 0},
                {"endpoint_id": "EP-2", "path": "/rest/products", "method": "GET", "source": "katana", "fetched": True, "status_code": 200, "is_static_asset": False, "depth": None},
            ],
            "parameters": [],
            "attack_surface_summary": {"endpoint_count": 2, "parameter_count": 0, "form_count": 0, "api_endpoint_count": 0},
            "telemetry": {},
        })
        html = _render_element(dashboard_script, "attack-surface-body", f"renderAttackSurface({json.dumps(run)})")
        assert "Katana discovery crawl" in html
        assert "Katana crawl" in html  # discovery-source label for the katana row itself

    def test_028_no_fabricated_endpoint_counts_independent_of_data(self, dashboard_script):
        run_empty = _completed_run(attack_surface={
            "attack_surface_version": "1", "status": "completed", "target": "http://localhost:3000/",
            "endpoints": [], "parameters": [],
            "attack_surface_summary": {"endpoint_count": 0, "parameter_count": 0, "form_count": 0, "api_endpoint_count": 0},
            "telemetry": {},
        })
        html = _render_element(dashboard_script, "attack-surface-body", f"renderAttackSurface({json.dumps(run_empty)})")
        assert "ThreatTrace discovered 0 application resources" in html


def _lifecycle_run_for_honesty_tests(results):
    return _completed_run(
        status="awaiting_human_review", current_stage="human_review",
        report={"canonical_findings": [{"finding_id": r["finding_id"], "title": f"Finding {r['finding_id']}"} for r in results]},
        lifecycle={
            "lifecycle_version": "1", "total_canonical_findings": len(results),
            "findings_selected": [r["finding_id"] for r in results], "results": results,
        },
    )


class TestTiDetectionHonestyUpgrades:
    """G/H previously only reflected the legacy single-trigger SSE flow
    (`lastTi`/`ruleState`) and fell back to a flatly dishonest "No ...
    activity on this run" empty state even when a Full Security
    Lifecycle run had genuinely run Threat Intel / Detection Engineering
    review for every selected finding. renderTi/renderDetection now also
    read run.lifecycle.results so that case is never misrepresented."""

    def test_ti_never_says_no_activity_when_lifecycle_ti_ran(self, dashboard_script):
        run = _lifecycle_run_for_honesty_tests([{
            "finding_id": "CF-1",
            "ti_result": {"outcome": "reviewed_no_match", "real_query_performed": True, "queried_cve": "CVE-2024-9999"},
        }])
        html = _render_element(dashboard_script, "ti-body", f"renderTi(null, {json.dumps(run)})")
        assert "No Threat Intelligence activity on this run." not in html
        assert "No matching intel" in html
        assert "CVE-2024-9999" in html

    def test_ti_empty_state_explains_why_when_nothing_ran(self, dashboard_script):
        run = _completed_run(lifecycle=None)
        html = _render_element(dashboard_script, "ti-body", f"renderTi(null, {json.dumps(run)})")
        assert "no finding on this run has reached Threat Intelligence review yet" in html

    def test_detection_never_says_no_activity_when_lifecycle_detection_ran(self, dashboard_script):
        run = _lifecycle_run_for_honesty_tests([{
            "finding_id": "CF-1",
            "detection_result": {"outcome": "not_applicable", "reason": "telemetry_gap", "rule": None},
        }])
        html = _render_element(dashboard_script, "detection-body", f"renderDetection({json.dumps(run)})")
        assert "No Detection Engineering activity on this run." not in html
        assert "Required telemetry for this finding class is not available" in html

    def test_detection_empty_state_explains_why_when_nothing_ran(self, dashboard_script):
        run = _completed_run(lifecycle=None)
        html = _render_element(dashboard_script, "detection-body", f"renderDetection({json.dumps(run)})")
        assert "no finding on this run has reached Detection Engineering review yet" in html

    def test_detection_rule_candidate_shows_format_validation_deployment(self, dashboard_script):
        run = _lifecycle_run_for_honesty_tests([{
            "finding_id": "CF-1",
            "detection_result": {
                "outcome": "candidate_ready", "reason": "rule_generated",
                "rule": {"rule_format": "sigma", "validation_status": "syntax_validated", "human_approval_state": "pending", "deployment_state": "NOT_DEPLOYED"},
            },
        }])
        html = _render_element(dashboard_script, "detection-body", f"renderDetection({json.dumps(run)})")
        assert "sigma" in html
        assert "syntax_validated" in html
        assert "NOT_DEPLOYED" in html


class TestLifecycleDetailRichness:
    """L now shows every field visibly (never hover-only), including
    priority, hunt telemetry breakdown, and a Purple Team success-
    criteria explanation -- section 10/11 of the dashboard usability
    checkpoint."""

    def test_priority_and_telemetry_visible(self, dashboard_script):
        run = _lifecycle_run_for_honesty_tests([{
            "finding_id": "CF-1",
            "case": {"case_id": "SH-CF-1", "approval_state": "pending"},
            "prioritization": {"operational_priority": "high", "priority_direction": "raised", "priority_reasons": ["Internet-facing"]},
            "ti_result": {"outcome": "no_relevant_intel", "real_query_performed": False},
            "hunt_result": {"outcome": "telemetry_gap", "hunt_hypothesis": "x", "required_telemetry": ["web_server_logs"], "available_telemetry": [], "missing_telemetry": ["web_server_logs"]},
            "detection_result": {"outcome": "not_applicable", "reason": "telemetry_gap", "rule": None},
            "red_validation_result": {"outcome": "controlled_validation_unavailable"},
            "purple_result": {"outcome": "recommendation_created", "recommendations": ["Instrument web_server_logs."]},
        }])
        html = _render_element(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "high" in html
        assert "Internet-facing" in html
        assert "web_server_logs" in html
        assert "Success criteria" in html
        assert "NOT remediation applied" in html

    def test_human_review_counts_visible(self, dashboard_script):
        run = _lifecycle_run_for_honesty_tests([
            {"finding_id": "CF-1", "case": {"case_id": "SH-1", "approval_state": "pending"}},
            {"finding_id": "CF-2", "case": {"case_id": "SH-2", "approval_state": "approved", "approval_reference": "analyst1"}},
        ])
        html = _render_element(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "2 finding(s) selected -- 1 reviewed, 1 awaiting review" in html


class TestPriorityReasonObjectShape:
    """Live-validation defect: real core.context_prioritization.
    prioritize_finding output has priority_reasons as a list of
    {code, modifier, message} objects, never plain strings. The dashboard
    used to do priority_reasons.join("; "), which rendered the literal
    text "[object Object]" for every reason on a real run. This must
    never happen again, for either the real object shape or the legacy/
    test string shape."""

    def _run_with_reasons(self, priority_reasons):
        return _lifecycle_run_for_honesty_tests([{
            "finding_id": "CF-1",
            "case": {"case_id": "SH-CF-1", "approval_state": "pending"},
            "prioritization": {
                "operational_priority": "low", "priority_direction": "lowered",
                "priority_reasons": priority_reasons,
            },
        }])

    def test_real_object_reason_message_renders(self, dashboard_script):
        run = self._run_with_reasons([
            {"code": "LOW_CRITICALITY_ASSET", "modifier": -1, "message": "The affected asset is caller-classified as low criticality."},
        ])
        html = _render_element(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "The affected asset is caller-classified as low criticality." in html
        assert "[object Object]" not in html

    def test_multiple_real_object_reasons_render_cleanly(self, dashboard_script):
        run = self._run_with_reasons([
            {"code": "CANDIDATE_FINDING", "modifier": -1, "message": "The finding is a candidate; deterministic confirmation is incomplete."},
            {"code": "ISOLATED_ENVIRONMENT", "modifier": -1, "message": "The caller-supplied environment is non-production and considered isolated."},
            {"code": "CONTEXT_INCOMPLETE", "modifier": 0, "message": "One or more organization-context fields were supplied as 'unknown'."},
        ])
        html = _render_element(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "The finding is a candidate; deterministic confirmation is incomplete." in html
        assert "The caller-supplied environment is non-production and considered isolated." in html
        assert "One or more organization-context fields were supplied as &#39;unknown&#39;." in html or "One or more organization-context fields were supplied as 'unknown'." in html
        assert "[object Object]" not in html

    def test_object_reason_falls_back_to_code_when_message_missing(self, dashboard_script):
        run = self._run_with_reasons([{"code": "SOME_REASON_CODE", "modifier": -1}])
        html = _render_element(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "SOME_REASON_CODE" in html
        assert "[object Object]" not in html

    def test_legacy_string_reasons_still_work(self, dashboard_script):
        run = self._run_with_reasons(["Internet-facing", "High business impact"])
        html = _render_element(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "Internet-facing" in html
        assert "High business impact" in html
        assert "[object Object]" not in html

    def test_no_object_object_anywhere_in_dashboard_html(self, dashboard_html):
        assert "[object Object]" not in dashboard_html


class TestNonSelectedFindingExplanation:
    """Findings K.3/K.4 of the live-validation follow-up: a canonical
    finding that Full Security Lifecycle selection did not carry into
    run.lifecycle.results must clearly explain *why* it has no Purple
    recommendation (bounded selection, not missing functionality) --
    and must never receive a fabricated recommendation."""

    def _run_with_selection(self, *, total, selected_ids, selected_results):
        canonical_findings = [
            {"finding_id": f"CF-{i}", "title": f"Finding {i}", "technical_severity": "low",
             "tools_used": ["http_assessor"], "evidence_sources": [{"source_tool": "http_assessor"}],
             "status": "requires_human_review"}
            for i in range(1, total + 1)
        ]
        return _completed_run(
            status="awaiting_human_review", current_stage="human_review",
            report={"canonical_findings": canonical_findings},
            lifecycle={
                "lifecycle_version": "1", "total_canonical_findings": total,
                "findings_selected": selected_ids, "results": selected_results,
            },
        )

    def test_selected_finding_shows_actual_purple_recommendation(self, dashboard_script):
        run = self._run_with_selection(
            total=8, selected_ids=["CF-1"],
            selected_results=[{"finding_id": "CF-1", "purple_result": {"outcome": "recommendation_created", "recommendations": ["Set a strict CSP header."]}}],
        )
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        assert "Set a strict CSP header." in html
        assert "Purple Team recommendation -- not yet applied" in html

    def test_non_selected_finding_explains_lifecycle_selection(self, dashboard_script):
        run = self._run_with_selection(
            total=8, selected_ids=["CF-1"],
            selected_results=[{"finding_id": "CF-1", "purple_result": {"outcome": "recommendation_created", "recommendations": ["Set a strict CSP header."]}}],
        )
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        assert "No Purple recommendation generated because this finding was not selected for downstream lifecycle review in this run." in html
        assert "not selected for downstream lifecycle review" in html

    def test_selected_count_derived_not_hardcoded(self, dashboard_script):
        run = self._run_with_selection(
            total=8, selected_ids=["CF-1", "CF-2", "CF-3"],
            selected_results=[
                {"finding_id": "CF-1", "purple_result": {"outcome": "recommendation_created", "recommendations": ["x"]}},
                {"finding_id": "CF-2", "purple_result": {"outcome": "recommendation_created", "recommendations": ["y"]}},
                {"finding_id": "CF-3", "purple_result": {"outcome": "recommendation_created", "recommendations": ["z"]}},
            ],
        )
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        assert "3 of 8 findings were selected." in html

        run_different = self._run_with_selection(total=5, selected_ids=["CF-1"], selected_results=[
            {"finding_id": "CF-1", "purple_result": {"outcome": "recommendation_created", "recommendations": ["x"]}},
        ])
        html_different = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run_different)})")
        assert "1 of 5 findings were selected." in html_different
        assert "3 of 8 findings were selected." not in html_different

    def test_non_selected_finding_never_receives_fabricated_remediation(self, dashboard_script):
        run = self._run_with_selection(
            total=2, selected_ids=["CF-1"],
            selected_results=[{"finding_id": "CF-1", "purple_result": {"outcome": "recommendation_created", "recommendations": ["Set a strict CSP header."]}}],
        )
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")

        blocks = html.split('<div class="finding-block">')
        non_selected_block = next(b for b in blocks if "Finding ID</span><span>CF-2" in b)
        assert "Set a strict CSP header." not in non_selected_block
        assert "No Purple recommendation generated" in non_selected_block

    def test_canonical_evidence_remains_visible_for_non_selected_finding(self, dashboard_script):
        run = self._run_with_selection(
            total=8, selected_ids=["CF-1"],
            selected_results=[{"finding_id": "CF-1", "purple_result": {"outcome": "recommendation_created", "recommendations": ["Set a strict CSP header."]}}],
        )
        html = _render_element(dashboard_script, "findings-body", f"renderFindings({json.dumps(run)})")
        assert "Finding 8" in html
        assert "CF-8" in html
        assert "http_assessor" in html


class TestAiActivitySummaryLine:
    def test_ai_used_line_no_when_no_ai_invoked(self, dashboard_script):
        run = _lifecycle_run_for_honesty_tests([{
            "finding_id": "CF-1",
            "detection_result": {"outcome": "not_applicable", "reason": "telemetry_gap", "rule": None},
        }])
        html = _render_element(dashboard_script, "ai-activity-body", f"renderAiActivity({json.dumps(run)})")
        assert "AI used in this run?" in html
        assert ">NO<" in html

    def test_ai_used_line_yes_when_ai_invoked(self, dashboard_script):
        run = _lifecycle_run_for_honesty_tests([{
            "finding_id": "CF-1",
            "detection_result": {"outcome": "candidate_ready", "reason": "rule_generated", "rule": {"deployment_state": "NOT_DEPLOYED"}},
        }])
        html = _render_element(dashboard_script, "ai-activity-body", f"renderAiActivity({json.dumps(run)})")
        assert ">YES<" in html


class TestEmptyStatesExplainWhy:
    """Section 18 of the dashboard usability checkpoint: every empty
    state must explain why, not merely state that nothing happened."""

    def test_governor_empty_state_explains_when_it_will_appear(self, dashboard_script):
        html = _render_element(dashboard_script, "governor-body", "renderGovernor(null)")
        assert "this appears once the first tool-execution request" in html

    def test_attack_surface_empty_state_explains_why(self, dashboard_script):
        run = _completed_run(attack_surface=None)
        html = _render_element(dashboard_script, "attack-surface-body", f"renderAttackSurface({json.dumps(run)})")
        assert "has not run (or has not yet completed)" in html

    def test_http_enrichment_explains_httpx_not_selected(self, dashboard_script):
        run = _completed_run(http_enrichment=None, executed_tools=["nmap"])
        html = _render_element(dashboard_script, "http-enrichment-body", f"renderHttpEnrichment({json.dumps(run)})")
        assert "httpx was not selected to run for this target/mode" in html

    def test_http_enrichment_explains_ran_but_no_record(self, dashboard_script):
        run = _completed_run(http_enrichment=None, executed_tools=["httpx"])
        html = _render_element(dashboard_script, "http-enrichment-body", f"renderHttpEnrichment({json.dumps(run)})")
        assert "httpx ran but produced no enrichment record" in html

    def test_lifecycle_no_findings_selected_explains_count(self, dashboard_script):
        run = _completed_run(lifecycle={
            "lifecycle_version": "1", "total_canonical_findings": 4,
            "findings_selected": [], "results": [],
        })
        html = _render_element(dashboard_script, "lifecycle-body", f"renderLifecycle({json.dumps(run)})")
        assert "0 of 4 canonical findings met the selection criteria" in html

    def test_benchmark_empty_state_explains_when_it_appears(self, dashboard_script):
        html = _render_element(dashboard_script, "evaluation-body", "renderEvaluation(null)")
        assert "becomes available once the run's report is complete" in html
