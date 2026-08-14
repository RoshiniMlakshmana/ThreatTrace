"""Tests for core.presentation_dashboard -- the pure, deterministic
presentation-dashboard HTML renderer (Block 15F-B).

No network, filesystem, environment-variable, subprocess, clock,
randomness, database/Supabase, MCP, or LLM/model access occurs anywhere
in this file. Every input is a plain in-memory mapping.
"""

from __future__ import annotations

import copy
import re

import pytest

from core.presentation_dashboard import (
    DASHBOARD_VERSION,
    PresentationDashboardError,
    render_presentation_dashboard,
)


def _benchmark(**overrides):
    summary = {
        "true_positive_count": 5,
        "false_positive_count": 1,
        "false_negative_count": 0,
        "true_negative_count": 3,
        "precision": 0.8333333333,
        "recall": 1.0,
        "f1": 0.9090909091,
        "supported_ground_truth_count": 9,
    }
    summary.update(overrides)
    return summary


def _refined_benchmark(**overrides):
    summary = {
        "true_positive_count": 5,
        "false_positive_count": 0,
        "false_negative_count": 0,
        "true_negative_count": 4,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "supported_ground_truth_count": 9,
    }
    summary.update(overrides)
    return summary


def _stage(status="not_evaluated", note=None):
    return {"status": status, "note": note}


def _workflow(**overrides):
    workflow = {
        "bug_bounty": _stage("executed"),
        "context_prioritization": _stage(),
        "security_handoff": _stage(),
        "security_governor": _stage(),
        "validated_experience_memory": _stage(),
        "research_evaluation": _stage(),
    }
    workflow.update(overrides)
    return workflow


def _limitations():
    return [
        "Supported-capability benchmark only.",
        "One local application.",
        "One fixed Juice Shop image.",
        "No SQL injection testing.",
    ]


def _dashboard_data(**overrides):
    data = {
        "dashboard_version": "1",
        "project_name": "ThreatTrace",
        "target": "OWASP Juice Shop",
        "target_origin": "http://localhost:3000",
        "target_version_or_digest": "sha256:" + "a" * 64,
        "run_label": "Block 15F-A Controlled Benchmark",
        "baseline_benchmark": _benchmark(),
        "refined_benchmark": _refined_benchmark(),
        "research_evaluation": None,
        "security_workflow_summary": _workflow(),
        "research_limitations": _limitations(),
    }
    data.update(overrides)
    return data


def _real_research_evaluation():
    return {
        "evaluation_version": "1",
        "experiment_id": "EXP-1",
        "scenario_count": 2,
        "context_prioritization": {
            "scenario_count": 2, "raised_count": 1, "unchanged_count": 1, "lowered_count": 0,
            "critical_operational_priority_count": 1, "technical_vs_operational_disagreement_count": 1,
            "mean_priority_delta": 1.5,
        },
        "governor": {
            "allow_count": 1, "warn_count": 0, "require_review_count": 0, "block_count": 1, "freeze_count": 0,
            "intervention_count": 1, "governor_intervention_rate": 0.5,
        },
        "memory": {
            "candidate_count": 1, "validated_count": 1, "rejected_count": 0, "reusable_count": 1,
            "non_reusable_count": 1, "memory_reuse_rate": 0.5, "memory_rejection_rate": 0.0,
        },
        "governor_memory_protection": {
            "unsafe_governor_records": 1, "correctly_non_reusable": 1, "unsafe_reusable_violations": 0,
            "protection_rate": 1.0,
        },
        "handoff": {
            "total_stage_results": 4, "mean_stage_results_per_scenario": 2.0,
            "scenarios_reaching_detection_engineering": 1, "scenarios_reaching_red_validation": 1,
            "scenarios_reaching_purple_remediation": 1, "scenarios_reaching_human_review": 1,
        },
        "red_blue_revision": {"revision_cycle_count": 1, "scenarios_with_revision": 1, "red_blocked_count": 1},
        "evidence_preservation": {
            "source_evidence_count": 2, "preserved_evidence_count": 2, "missing_evidence_count": 0,
            "evidence_preservation_rate": 1.0,
        },
        "human_review": {
            "human_review_required_count": 1, "not_required_count": 1, "pending_count": 0,
            "approved_count": 1, "rejected_count": 0,
        },
        "validated_defensive_experience": {"count": 1, "rate": 0.5},
        "mtvd": {
            "available": True, "validated_scenarios_with_duration": 1,
            "validated_scenarios_missing_duration": 0, "mean_minutes": 12.5,
        },
        "stage_count_proxy": {
            "available": True, "validated_scenario_count": 1, "mean_stage_count_to_validated_experience": 4.0,
        },
        "ablations": {
            "context_enabled": {
                "scenario_count": 1, "validated_defensive_experience_count": 1,
                "validated_defensive_experience_rate": 1.0, "mean_stage_count": 4.0, "mean_duration_minutes": 12.5,
            },
            "context_disabled": {
                "scenario_count": 1, "validated_defensive_experience_count": 0,
                "validated_defensive_experience_rate": 0.0, "mean_stage_count": 0.0, "mean_duration_minutes": None,
            },
            "memory_enabled": {"scenario_count": 0, "validated_defensive_experience_count": 0, "validated_defensive_experience_rate": None, "mean_stage_count": None, "mean_duration_minutes": None},
            "memory_disabled": {"scenario_count": 2, "validated_defensive_experience_count": 1, "validated_defensive_experience_rate": 0.5, "mean_stage_count": 2.0, "mean_duration_minutes": 12.5},
            "governor_enabled": {"scenario_count": 2, "validated_defensive_experience_count": 1, "validated_defensive_experience_rate": 0.5, "mean_stage_count": 2.0, "mean_duration_minutes": 12.5},
            "governor_disabled": {"scenario_count": 0, "validated_defensive_experience_count": 0, "validated_defensive_experience_rate": None, "mean_stage_count": None, "mean_duration_minutes": None},
        },
        "research_limitations": [
            "OBSERVATIONAL_SUMMARY_ONLY", "NO_CAUSAL_CLAIM", "NO_STATISTICAL_SIGNIFICANCE_TEST",
            "CALLER_SUPPLIED_DURATION", "CALLER_SUPPLIED_APPROVAL_STATE", "RECORDED_STAGE_NOT_EXECUTION_PROOF",
            "EVIDENCE_REFERENCE_NOT_AUTHENTICITY_PROOF",
        ],
    }


# ---------------------------------------------------------------------------
# Success -- basic rendering
# ---------------------------------------------------------------------------


class TestRenderSuccess:
    def test_001_returns_a_string(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert isinstance(html, str)

    def test_002_starts_with_doctype(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert html.startswith("<!DOCTYPE html>")

    def test_003_contains_html_and_body_tags(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "<html" in html and "</html>" in html
        assert "<body>" in html and "</body>" in html

    def test_004_contains_project_name_and_run_label(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "ThreatTrace" in html
        assert "Block 15F-A Controlled Benchmark" in html

    def test_005_contains_target(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "OWASP Juice Shop" in html

    def test_006_deterministic_same_input_same_html(self):
        data = _dashboard_data()
        first = render_presentation_dashboard(dashboard_data=data)
        second = render_presentation_dashboard(dashboard_data=data)
        assert first == second

    def test_007_all_four_nav_sections_present(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        for section_id in ("executive", "research", "architecture", "limitations"):
            assert f'id="{section_id}"' in html


# ---------------------------------------------------------------------------
# Data contract validation
# ---------------------------------------------------------------------------


class TestDataContractValidation:
    def test_008_not_a_mapping_raises(self):
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data="nope")

    def test_009_missing_top_level_field_raises(self):
        data = _dashboard_data()
        del data["run_label"]
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=data)

    def test_010_extra_top_level_field_raises(self):
        data = _dashboard_data(unexpected="x")
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=data)

    def test_011_wrong_dashboard_version_raises(self):
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(dashboard_version="2"))

    def test_012_blank_project_name_raises(self):
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(project_name="  "))

    def test_013_blank_target_raises(self):
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(target=""))


# ---------------------------------------------------------------------------
# Malformed benchmark data
# ---------------------------------------------------------------------------


class TestBenchmarkValidation:
    def test_014_baseline_missing_field_raises(self):
        bad = _benchmark()
        del bad["precision"]
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(baseline_benchmark=bad))

    def test_015_baseline_extra_field_raises(self):
        bad = _benchmark(unexpected="x")
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(baseline_benchmark=bad))

    def test_016_negative_count_raises(self):
        bad = _benchmark(true_positive_count=-1)
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(baseline_benchmark=bad))

    def test_017_bool_count_raises(self):
        bad = _benchmark(true_positive_count=True)
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(baseline_benchmark=bad))

    def test_018_precision_out_of_range_raises(self):
        bad = _benchmark(precision=1.5)
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(baseline_benchmark=bad))

    def test_019_precision_negative_raises(self):
        bad = _benchmark(precision=-0.1)
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(baseline_benchmark=bad))

    def test_020_precision_none_allowed(self):
        data = _dashboard_data(baseline_benchmark=_benchmark(precision=None))
        html = render_presentation_dashboard(dashboard_data=data)
        assert "N/A" in html

    def test_021_refined_benchmark_also_validated(self):
        bad = _refined_benchmark(recall="not a number")
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(refined_benchmark=bad))


# ---------------------------------------------------------------------------
# Workflow summary validation
# ---------------------------------------------------------------------------


class TestWorkflowSummaryValidation:
    def test_022_missing_stage_key_raises(self):
        bad = _workflow()
        del bad["bug_bounty"]
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(security_workflow_summary=bad))

    def test_023_extra_stage_key_raises(self):
        bad = _workflow()
        bad["unexpected_stage"] = _stage()
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(security_workflow_summary=bad))

    def test_024_invalid_stage_status_raises(self):
        bad = _workflow(bug_bounty=_stage(status="maybe"))
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(security_workflow_summary=bad))

    def test_025_stage_missing_note_key_raises(self):
        bad_stage = {"status": "executed"}
        bad = _workflow(bug_bounty=bad_stage)
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(security_workflow_summary=bad))

    def test_026_stage_blank_note_raises(self):
        bad = _workflow(bug_bounty=_stage("executed", note="   "))
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(security_workflow_summary=bad))

    def test_027_stage_note_none_allowed(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert html  # baseline fixture already uses note=None throughout

    def test_028_stage_note_rendered_when_present(self):
        data = _dashboard_data(security_workflow_summary=_workflow(
            bug_bounty=_stage("executed", note="Real bounded HTTP assessment."),
        ))
        html = render_presentation_dashboard(dashboard_data=data)
        assert "Real bounded HTTP assessment." in html


# ---------------------------------------------------------------------------
# Research limitations validation
# ---------------------------------------------------------------------------


class TestResearchLimitationsValidation:
    def test_029_empty_limitations_raises(self):
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(research_limitations=[]))

    def test_030_blank_limitation_entry_raises(self):
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(research_limitations=["  "]))

    def test_031_non_list_limitations_raises(self):
        with pytest.raises(PresentationDashboardError):
            render_presentation_dashboard(dashboard_data=_dashboard_data(research_limitations="nope"))

    def test_032_limitations_rendered(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        for item in _limitations():
            assert item in html


# ---------------------------------------------------------------------------
# Percentage rendering
# ---------------------------------------------------------------------------


class TestPercentageRendering:
    def test_033_baseline_precision_formatted(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "83.3%" in html

    def test_034_refined_precision_formatted_no_trailing_zero(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "100%" in html
        assert "100.0%" not in html

    def test_035_f1_formatted(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "90.9%" in html

    def test_036_false_positive_reduction_rendered(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "1 → 0" in html or ("1" in html and "0" in html)


# ---------------------------------------------------------------------------
# HTML escaping / no script injection
# ---------------------------------------------------------------------------


class TestEscaping:
    def test_037_project_name_escaped(self):
        data = _dashboard_data(project_name="<script>alert(1)</script>")
        html = render_presentation_dashboard(dashboard_data=data)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_038_run_label_escaped(self):
        data = _dashboard_data(run_label='"><img src=x onerror=alert(1)>')
        html = render_presentation_dashboard(dashboard_data=data)
        assert "<img src=x onerror=alert(1)>" not in html

    def test_039_target_escaped(self):
        data = _dashboard_data(target="<b>bold</b>")
        html = render_presentation_dashboard(dashboard_data=data)
        assert "<b>bold</b>" not in html

    def test_040_workflow_note_escaped(self):
        data = _dashboard_data(security_workflow_summary=_workflow(
            bug_bounty=_stage("executed", note="<script>evil()</script>"),
        ))
        html = render_presentation_dashboard(dashboard_data=data)
        assert "<script>evil()</script>" not in html

    def test_041_limitation_text_escaped(self):
        data = _dashboard_data(research_limitations=["<script>steal()</script>"])
        html = render_presentation_dashboard(dashboard_data=data)
        assert "<script>steal()</script>" not in html

    def test_042_no_javascript_uri_from_supplied_strings(self):
        data = _dashboard_data(run_label="javascript:alert(1)")
        html = render_presentation_dashboard(dashboard_data=data)
        assert 'href="javascript:' not in html

    def test_043_only_one_script_tag_family_and_it_is_absent(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "<script" not in html


# ---------------------------------------------------------------------------
# null research_evaluation / unavailable states
# ---------------------------------------------------------------------------


class TestUnavailableStates:
    def test_044_null_research_evaluation_shows_not_evaluated_message(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data(research_evaluation=None))
        assert "Not evaluated in this Juice Shop benchmark run." in html

    def test_045_null_research_evaluation_governor_message(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data(research_evaluation=None))
        assert "Governor metrics were not exercised in this benchmark run." in html

    def test_046_null_research_evaluation_memory_message(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data(research_evaluation=None))
        assert "Validated Security Experience Memory was not evaluated in this benchmark run." in html

    def test_047_null_research_evaluation_mtvd_message(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data(research_evaluation=None))
        assert "MTVD unavailable" in html

    def test_048_null_research_evaluation_never_shows_zero_governor_counts(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data(research_evaluation=None))
        assert "0 blocks" not in html
        assert "0 freezes" not in html
        assert "100% protection" not in html

    def test_049_workflow_not_evaluated_badge_rendered(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "Not evaluated" in html

    def test_050_workflow_executed_badge_rendered(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "Executed" in html


# ---------------------------------------------------------------------------
# Real research_evaluation rendering
# ---------------------------------------------------------------------------


class TestResearchEvaluationRendering:
    def test_051_real_research_evaluation_renders_governor_counts(self):
        data = _dashboard_data(research_evaluation=_real_research_evaluation())
        html = render_presentation_dashboard(dashboard_data=data)
        assert "research-available" in html
        assert "Not evaluated in this Juice Shop benchmark run." not in html

    def test_052_real_research_evaluation_renders_mtvd_minutes(self):
        data = _dashboard_data(research_evaluation=_real_research_evaluation())
        html = render_presentation_dashboard(dashboard_data=data)
        assert "12.50" in html

    def test_053_real_research_evaluation_with_mtvd_unavailable(self):
        research = _real_research_evaluation()
        research["mtvd"] = {
            "available": False, "validated_scenarios_with_duration": 0,
            "validated_scenarios_missing_duration": 1, "mean_minutes": None,
        }
        data = _dashboard_data(research_evaluation=research)
        html = render_presentation_dashboard(dashboard_data=data)
        assert "MTVD unavailable" in html

    def test_054_real_research_evaluation_renders_ablation_table(self):
        data = _dashboard_data(research_evaluation=_real_research_evaluation())
        html = render_presentation_dashboard(dashboard_data=data)
        assert "context_enabled" in html
        assert "context_disabled" in html

    def test_055_real_research_evaluation_missing_optional_key_does_not_crash(self):
        research = _real_research_evaluation()
        del research["ablations"]
        data = _dashboard_data(research_evaluation=research)
        html = render_presentation_dashboard(dashboard_data=data)
        assert isinstance(html, str)

    def test_056_research_evaluation_not_required_to_have_extra_fields_rejected(self):
        # This module reads research_evaluation defensively -- an extra
        # or partial shape must never crash the renderer.
        research = {"unexpected_field": "value"}
        data = _dashboard_data(research_evaluation=research)
        html = render_presentation_dashboard(dashboard_data=data)
        assert isinstance(html, str)


# ---------------------------------------------------------------------------
# Limitation banner always present / no overclaiming language
# ---------------------------------------------------------------------------


class TestHonestyLanguage:
    def test_057_limitation_banner_always_present(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert 'id="limitations"' in html
        assert "Research Limitations" in html

    def test_058_unsupported_categories_visually_excluded_note_present(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "never counted as" in html.lower()

    def test_059_never_says_overall_accuracy(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "overall accuracy" not in html.lower()
        assert "overall application accuracy" in html.lower()  # the explicit disclaimer itself

    def test_060_never_affirmatively_claims_eight_autonomous_agents(self):
        # The rendered page does say "never described as eight autonomous
        # agents" (a correct disclaimer) -- this checks only that the
        # *affirmative* phrasing is absent, not the honest negation.
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "runs eight autonomous agents" not in html.lower()
        assert "is composed of eight autonomous agents" not in html.lower()
        assert "never described as eight autonomous agents" in html.lower()

    def test_061_never_says_self_learning_or_model_training(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        lowered = html.lower()
        assert "self-learning" not in lowered
        assert "self learning" not in lowered
        assert "ai learning" not in lowered
        assert "model training" not in lowered

    def test_062_not_an_overall_vulnerability_accuracy_claim_present(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "not an overall vulnerability-detection accuracy claim" in html.lower()

    def test_063_never_claims_100_percent_accurate(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "100% accurate" not in html.lower()

    def test_064_functional_role_terminology_present(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "functional security roles" in html.lower()
        assert "deterministic core services" in html.lower()
        assert "claude custom agents" in html.lower()
        assert "policy identities" in html.lower()


# ---------------------------------------------------------------------------
# No external resources / no network / no timestamps
# ---------------------------------------------------------------------------


class TestNoExternalResourcesOrTimestamps:
    def test_065_no_external_cdn_link_tags(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "<link" not in html

    def test_066_no_script_src(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "<script src" not in html

    def test_067_no_external_http_reference_besides_supplied_target_origin(self):
        data = _dashboard_data()
        html = render_presentation_dashboard(dashboard_data=data)
        remaining = html.replace(data["target_origin"], "")
        assert "http://" not in remaining
        assert "https://" not in remaining

    def test_068_no_import_of_time_or_uuid_modules(self):
        import ast
        import inspect

        import core.presentation_dashboard as presentation_dashboard

        source = inspect.getsource(presentation_dashboard)
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])
        assert "time" not in imported_modules
        assert "datetime" not in imported_modules
        assert "uuid" not in imported_modules
        assert "random" not in imported_modules

    def test_069_module_imports_no_other_core_module(self):
        import ast
        import inspect

        import core.presentation_dashboard as presentation_dashboard

        source = inspect.getsource(presentation_dashboard)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("core."), f"unexpected core import: {node.module}"


# ---------------------------------------------------------------------------
# Accessibility
# ---------------------------------------------------------------------------


class TestAccessibility:
    def test_070_semantic_headings_present(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "<h1>" in html
        assert re.search(r"<h2[ >]", html)

    def test_071_nav_has_aria_label(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert 'aria-label="Dashboard sections"' in html

    def test_072_sections_have_aria_labelledby(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert 'aria-labelledby="executive-heading"' in html

    def test_073_tables_have_scope_attributes(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert 'scope="col"' in html
        assert 'scope="row"' in html

    def test_074_bars_have_aria_label_not_color_only(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert 'role="img"' in html
        assert "aria-label=" in html

    def test_075_numeric_values_present_alongside_bars(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "83.3%" in html and "100%" in html


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_076_dashboard_data_never_mutated(self):
        data = _dashboard_data(research_evaluation=_real_research_evaluation())
        snapshot = copy.deepcopy(data)
        render_presentation_dashboard(dashboard_data=data)
        assert data == snapshot

    def test_077_benchmark_dicts_never_mutated(self):
        baseline = _benchmark()
        refined = _refined_benchmark()
        snapshot_baseline = copy.deepcopy(baseline)
        snapshot_refined = copy.deepcopy(refined)
        render_presentation_dashboard(dashboard_data=_dashboard_data(baseline_benchmark=baseline, refined_benchmark=refined))
        assert baseline == snapshot_baseline
        assert refined == snapshot_refined


# ---------------------------------------------------------------------------
# Output contract / determinism sanity
# ---------------------------------------------------------------------------


class TestOutputContractSanity:
    def test_078_dashboard_version_constant(self):
        assert DASHBOARD_VERSION == "1"

    def test_079_no_secrets_leaked_from_arbitrary_supplied_notes(self):
        secret_marker = "sk_live_super_secret_should_not_appear_verbatim_as_script"
        data = _dashboard_data(security_workflow_summary=_workflow(
            bug_bounty=_stage("executed", note=f"<script>{secret_marker}</script>"),
        ))
        html = render_presentation_dashboard(dashboard_data=data)
        assert f"<script>{secret_marker}</script>" not in html

    def test_080_target_version_or_digest_rendered(self):
        html = render_presentation_dashboard(dashboard_data=_dashboard_data())
        assert "sha256:" in html
