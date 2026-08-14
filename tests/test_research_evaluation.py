"""Tests for core.research_evaluation -- the pure, deterministic
Research Evaluation Harness (Block 15E, checkpoint A).

No network, filesystem, environment-variable, subprocess, clock,
randomness, UUID, database/Supabase, MCP, LLM/model, embedding, or
vector-database access occurs anywhere in this file. Every input is a
plain in-memory mapping. This file targets meaningful contract
coverage, not a test-count quota.
"""

from __future__ import annotations

import copy
import math

import pytest

import core.research_evaluation as research_evaluation
from core.research_evaluation import (
    RESEARCH_LIMITATIONS,
    ResearchEvaluationError,
    evaluate_research_experiment,
)

DIGEST_A = "sha256:" + "a" * 8
DIGEST_B = "sha256:" + "b" * 8

_OUTPUT_FIELDS = {
    "evaluation_version", "experiment_id", "scenario_count", "context_prioritization",
    "governor", "memory", "governor_memory_protection", "handoff", "red_blue_revision",
    "evidence_preservation", "human_review", "validated_defensive_experience", "mtvd",
    "stage_count_proxy", "ablations", "research_limitations",
}


def _stage(stage, outcome):
    return {"stage": stage, "outcome": outcome}


def _scenario(**overrides):
    scenario = {
        "scenario_id": "S-1",
        "technical_severity": "medium",
        "operational_priority": "medium",
        "priority_direction": "unchanged",
        "context_mode": "disabled",
        "memory_mode": "disabled",
        "governor_mode": "disabled",
        "governor_decision": "allow",
        "memory_experience_status": "candidate",
        "memory_reusable": False,
        "handoff_stage_results": [],
        "source_evidence_digests": [DIGEST_A],
        "final_evidence_references": [DIGEST_A],
        "human_review_required": False,
        "approval_state": "not_required",
        "validated_defensive_experience": False,
        "duration_minutes": None,
    }
    scenario.update(overrides)
    return scenario


def _experiment(*scenarios, experiment_id="EXP-1"):
    return {
        "experiment_version": "1",
        "experiment_id": experiment_id,
        "scenario_records": list(scenarios),
    }


# ---------------------------------------------------------------------------
# Experiment-level structural validation
# ---------------------------------------------------------------------------


class TestExperimentValidation:
    def test_001_experiment_not_a_mapping_raises(self):
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment="nope")

    def test_002_missing_top_level_field_raises(self):
        experiment = _experiment(_scenario())
        del experiment["experiment_id"]
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=experiment)

    def test_003_extra_top_level_field_raises(self):
        experiment = _experiment(_scenario())
        experiment["unexpected"] = "x"
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=experiment)

    def test_004_wrong_experiment_version_raises(self):
        experiment = _experiment(_scenario())
        experiment["experiment_version"] = "2"
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=experiment)

    def test_005_blank_experiment_id_raises(self):
        experiment = _experiment(_scenario(), experiment_id="   ")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=experiment)

    def test_006_non_string_experiment_id_raises(self):
        experiment = _experiment(_scenario())
        experiment["experiment_id"] = 123
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=experiment)

    def test_007_empty_scenario_records_raises(self):
        experiment = _experiment()
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=experiment)

    def test_008_scenario_records_not_a_list_raises(self):
        experiment = _experiment(_scenario())
        experiment["scenario_records"] = {"not": "a list"}
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=experiment)

    def test_009_duplicate_scenario_id_raises(self):
        experiment = _experiment(_scenario(scenario_id="S-1"), _scenario(scenario_id="S-1"))
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=experiment)


# ---------------------------------------------------------------------------
# Scenario-level structural validation
# ---------------------------------------------------------------------------


class TestScenarioValidation:
    def test_010_missing_scenario_field_raises(self):
        scenario = _scenario()
        del scenario["approval_state"]
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_011_extra_scenario_field_raises(self):
        scenario = _scenario(unexpected="x")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_012_blank_scenario_id_raises(self):
        scenario = _scenario(scenario_id="")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_013_malformed_technical_severity_raises(self):
        scenario = _scenario(technical_severity="extreme")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_014_malformed_operational_priority_raises(self):
        scenario = _scenario(operational_priority="extreme")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_015_priority_direction_mismatch_raises(self):
        scenario = _scenario(
            technical_severity="medium", operational_priority="high",
            priority_direction="unchanged", context_mode="enabled",
        )
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_016_malformed_priority_direction_raises(self):
        scenario = _scenario(priority_direction="sideways")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_017_malformed_context_mode_raises(self):
        scenario = _scenario(context_mode="maybe")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_018_malformed_memory_mode_raises(self):
        scenario = _scenario(memory_mode="maybe")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_019_malformed_governor_mode_raises(self):
        scenario = _scenario(governor_mode="maybe")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_020_malformed_governor_decision_raises(self):
        scenario = _scenario(governor_decision="maybe")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_021_malformed_memory_status_raises(self):
        scenario = _scenario(memory_experience_status="maybe")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_022_non_bool_memory_reusable_raises(self):
        for bad_value in (1, 0, "true", None):
            scenario = _scenario(memory_reusable=bad_value)
            with pytest.raises(ResearchEvaluationError):
                evaluate_research_experiment(experiment=_experiment(scenario))

    def test_023_non_bool_human_review_required_raises(self):
        scenario = _scenario(human_review_required="yes")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_024_non_bool_validated_defensive_experience_raises(self):
        scenario = _scenario(validated_defensive_experience="yes")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_025_invalid_approval_state_raises(self):
        scenario = _scenario(approval_state="maybe")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))


# ---------------------------------------------------------------------------
# Context baseline rule
# ---------------------------------------------------------------------------


class TestContextBaselineRule:
    def test_026_disabled_context_with_changed_priority_raises(self):
        scenario = _scenario(
            context_mode="disabled", technical_severity="medium",
            operational_priority="high", priority_direction="raised",
        )
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_027_disabled_context_medium_to_medium_baseline_accepted(self):
        scenario = _scenario(
            context_mode="disabled", technical_severity="medium",
            operational_priority="medium", priority_direction="unchanged",
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["scenario_count"] == 1

    def test_028_enabled_context_medium_to_critical_accepted(self):
        scenario = _scenario(
            context_mode="enabled", technical_severity="medium",
            operational_priority="critical", priority_direction="raised",
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["context_prioritization"]["critical_operational_priority_count"] == 1


# ---------------------------------------------------------------------------
# Governor baseline rule
# ---------------------------------------------------------------------------


class TestGovernorBaselineRule:
    def test_029_disabled_governor_with_non_allow_decision_raises(self):
        scenario = _scenario(governor_mode="disabled", governor_decision="warn")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_030_disabled_governor_with_allow_accepted(self):
        scenario = _scenario(governor_mode="disabled", governor_decision="allow")
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["governor"]["allow_count"] == 1

    def test_031_enabled_governor_with_block_accepted(self):
        scenario = _scenario(governor_mode="enabled", governor_decision="block")
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["governor"]["block_count"] == 1


# ---------------------------------------------------------------------------
# Handoff stage validation
# ---------------------------------------------------------------------------


class TestHandoffStageValidation:
    def test_032_handoff_stage_results_not_a_list_raises(self):
        scenario = _scenario(handoff_stage_results="nope")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_033_handoff_stage_result_missing_field_raises(self):
        scenario = _scenario(handoff_stage_results=[{"stage": "threat_hunt"}])
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_034_handoff_stage_result_extra_field_raises(self):
        scenario = _scenario(
            handoff_stage_results=[{"stage": "threat_hunt", "outcome": "planned", "extra": "x"}],
        )
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_035_handoff_stage_result_unknown_stage_raises(self):
        scenario = _scenario(handoff_stage_results=[{"stage": "human_review", "outcome": "x"}])
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_036_handoff_stage_result_blank_outcome_raises(self):
        scenario = _scenario(handoff_stage_results=[{"stage": "threat_hunt", "outcome": "  "}])
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_037_empty_handoff_stage_results_accepted(self):
        scenario = _scenario(handoff_stage_results=[])
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["handoff"]["total_stage_results"] == 0


# ---------------------------------------------------------------------------
# Evidence validation
# ---------------------------------------------------------------------------


class TestEvidenceValidation:
    def test_038_empty_source_evidence_raises(self):
        scenario = _scenario(source_evidence_digests=[])
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_039_duplicate_source_evidence_raises(self):
        scenario = _scenario(source_evidence_digests=[DIGEST_A, DIGEST_A])
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_040_duplicate_final_evidence_references_raises(self):
        scenario = _scenario(final_evidence_references=[DIGEST_A, DIGEST_A])
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_041_blank_evidence_entry_raises(self):
        scenario = _scenario(source_evidence_digests=["  "])
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_042_non_string_evidence_entry_raises(self):
        scenario = _scenario(final_evidence_references=[123])
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_043_empty_final_evidence_references_accepted(self):
        scenario = _scenario(final_evidence_references=[])
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["evidence_preservation"]["preserved_evidence_count"] == 0


# ---------------------------------------------------------------------------
# Duration validation
# ---------------------------------------------------------------------------


class TestDurationValidation:
    def test_044_negative_duration_raises(self):
        scenario = _scenario(duration_minutes=-1)
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_045_nan_duration_raises(self):
        scenario = _scenario(duration_minutes=float("nan"))
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_046_infinite_duration_raises(self):
        scenario = _scenario(duration_minutes=float("inf"))
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_047_bool_duration_raises(self):
        scenario = _scenario(duration_minutes=True)
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_048_string_duration_raises(self):
        scenario = _scenario(duration_minutes="10")
        with pytest.raises(ResearchEvaluationError):
            evaluate_research_experiment(experiment=_experiment(scenario))

    def test_049_zero_duration_accepted(self):
        scenario = _scenario(duration_minutes=0, validated_defensive_experience=True)
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["mtvd"]["mean_minutes"] == 0

    def test_050_null_duration_accepted(self):
        scenario = _scenario(duration_minutes=None)
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["mtvd"]["available"] is False


# ---------------------------------------------------------------------------
# Output contract
# ---------------------------------------------------------------------------


class TestOutputContract:
    def test_051_exact_fifteen_top_level_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result.keys()) == _OUTPUT_FIELDS

    def test_052_evaluation_version_is_one(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert result["evaluation_version"] == "1"

    def test_053_experiment_id_echoed(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario(), experiment_id="EXP-XYZ"))
        assert result["experiment_id"] == "EXP-XYZ"

    def test_054_scenario_count_correct(self):
        result = evaluate_research_experiment(
            experiment=_experiment(_scenario(scenario_id="S-1"), _scenario(scenario_id="S-2")),
        )
        assert result["scenario_count"] == 2

    def test_055_context_prioritization_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["context_prioritization"].keys()) == {
            "scenario_count", "raised_count", "unchanged_count", "lowered_count",
            "critical_operational_priority_count", "technical_vs_operational_disagreement_count",
            "mean_priority_delta",
        }

    def test_056_governor_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["governor"].keys()) == {
            "allow_count", "warn_count", "require_review_count", "block_count", "freeze_count",
            "intervention_count", "governor_intervention_rate",
        }

    def test_057_memory_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["memory"].keys()) == {
            "candidate_count", "validated_count", "rejected_count", "reusable_count",
            "non_reusable_count", "memory_reuse_rate", "memory_rejection_rate",
        }

    def test_058_governor_memory_protection_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["governor_memory_protection"].keys()) == {
            "unsafe_governor_records", "correctly_non_reusable", "unsafe_reusable_violations", "protection_rate",
        }

    def test_059_handoff_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["handoff"].keys()) == {
            "total_stage_results", "mean_stage_results_per_scenario",
            "scenarios_reaching_detection_engineering", "scenarios_reaching_red_validation",
            "scenarios_reaching_purple_remediation", "scenarios_reaching_human_review",
        }

    def test_060_red_blue_revision_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["red_blue_revision"].keys()) == {
            "revision_cycle_count", "scenarios_with_revision", "red_blocked_count",
        }

    def test_061_evidence_preservation_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["evidence_preservation"].keys()) == {
            "source_evidence_count", "preserved_evidence_count", "missing_evidence_count",
            "evidence_preservation_rate",
        }

    def test_062_human_review_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["human_review"].keys()) == {
            "human_review_required_count", "not_required_count", "pending_count",
            "approved_count", "rejected_count",
        }

    def test_063_validated_defensive_experience_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["validated_defensive_experience"].keys()) == {"count", "rate"}

    def test_064_mtvd_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["mtvd"].keys()) == {
            "available", "validated_scenarios_with_duration", "validated_scenarios_missing_duration",
            "mean_minutes",
        }

    def test_065_stage_count_proxy_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["stage_count_proxy"].keys()) == {
            "available", "validated_scenario_count", "mean_stage_count_to_validated_experience",
        }

    def test_066_ablations_exact_groups(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert set(result["ablations"].keys()) == {
            "context_enabled", "context_disabled", "memory_enabled", "memory_disabled",
            "governor_enabled", "governor_disabled",
        }

    def test_067_ablation_group_exact_fields(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        for group in result["ablations"].values():
            assert set(group.keys()) == {
                "scenario_count", "validated_defensive_experience_count",
                "validated_defensive_experience_rate", "mean_stage_count", "mean_duration_minutes",
            }

    def test_068_research_limitations_fixed_order(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert result["research_limitations"] == list(RESEARCH_LIMITATIONS)


# ---------------------------------------------------------------------------
# Context metrics
# ---------------------------------------------------------------------------


class TestContextMetrics:
    def test_070_raised_unchanged_lowered_counts(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", context_mode="enabled", technical_severity="low",
                      operational_priority="high", priority_direction="raised"),
            _scenario(scenario_id="S-2", context_mode="enabled", technical_severity="high",
                      operational_priority="low", priority_direction="lowered"),
            _scenario(scenario_id="S-3"),  # unchanged baseline
        )
        result = evaluate_research_experiment(experiment=experiment)
        ctx = result["context_prioritization"]
        assert ctx["raised_count"] == 1
        assert ctx["lowered_count"] == 1
        assert ctx["unchanged_count"] == 1

    def test_071_mean_priority_delta_computed_correctly(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", context_mode="enabled", technical_severity="low",
                      operational_priority="critical", priority_direction="raised"),  # delta +3
            _scenario(scenario_id="S-2"),  # delta 0
        )
        result = evaluate_research_experiment(experiment=experiment)
        assert result["context_prioritization"]["mean_priority_delta"] == pytest.approx(1.5)

    def test_072_disagreement_count(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", context_mode="enabled", technical_severity="low",
                      operational_priority="critical", priority_direction="raised"),
            _scenario(scenario_id="S-2"),
        )
        result = evaluate_research_experiment(experiment=experiment)
        assert result["context_prioritization"]["technical_vs_operational_disagreement_count"] == 1


# ---------------------------------------------------------------------------
# Governor metrics
# ---------------------------------------------------------------------------


class TestGovernorMetrics:
    def test_073_intervention_count_excludes_warn(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", governor_mode="enabled", governor_decision="warn"),
            _scenario(scenario_id="S-2", governor_mode="enabled", governor_decision="require_review"),
            _scenario(scenario_id="S-3", governor_mode="enabled", governor_decision="block"),
            _scenario(scenario_id="S-4", governor_mode="enabled", governor_decision="freeze"),
        )
        result = evaluate_research_experiment(experiment=experiment)
        gov = result["governor"]
        assert gov["warn_count"] == 1
        assert gov["intervention_count"] == 3

    def test_074_governor_intervention_rate(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", governor_mode="enabled", governor_decision="block"),
            _scenario(scenario_id="S-2"),
        )
        result = evaluate_research_experiment(experiment=experiment)
        assert result["governor"]["governor_intervention_rate"] == pytest.approx(0.5)

    def test_075_governor_allow_only_baseline_zero_intervention(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        assert result["governor"]["intervention_count"] == 0
        assert result["governor"]["governor_intervention_rate"] == 0.0


# ---------------------------------------------------------------------------
# Memory metrics
# ---------------------------------------------------------------------------


class TestMemoryMetrics:
    def test_076_candidate_validated_rejected_counts(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", memory_experience_status="candidate"),
            _scenario(scenario_id="S-2", memory_experience_status="validated", memory_reusable=True),
            _scenario(scenario_id="S-3", memory_experience_status="rejected"),
        )
        result = evaluate_research_experiment(experiment=experiment)
        mem = result["memory"]
        assert mem["candidate_count"] == 1
        assert mem["validated_count"] == 1
        assert mem["rejected_count"] == 1

    def test_077_reuse_and_rejection_rates(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", memory_experience_status="validated", memory_reusable=True),
            _scenario(scenario_id="S-2", memory_experience_status="rejected"),
            _scenario(scenario_id="S-3"),
            _scenario(scenario_id="S-4"),
        )
        result = evaluate_research_experiment(experiment=experiment)
        mem = result["memory"]
        assert mem["memory_reuse_rate"] == pytest.approx(0.25)
        assert mem["memory_rejection_rate"] == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# Governor -> Memory protection
# ---------------------------------------------------------------------------


class TestGovernorMemoryProtection:
    def test_078_governor_allow_validated_reusable(self):
        scenario = _scenario(
            governor_mode="enabled", governor_decision="allow",
            memory_experience_status="validated", memory_reusable=True,
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        protection = result["governor_memory_protection"]
        assert protection["unsafe_governor_records"] == 0
        assert protection["protection_rate"] is None

    def test_079_governor_block_rejected_non_reusable(self):
        scenario = _scenario(
            governor_mode="enabled", governor_decision="block",
            memory_experience_status="rejected", memory_reusable=False,
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        protection = result["governor_memory_protection"]
        assert protection["unsafe_governor_records"] == 1
        assert protection["correctly_non_reusable"] == 1
        assert protection["unsafe_reusable_violations"] == 0
        assert protection["protection_rate"] == pytest.approx(1.0)

    def test_080_governor_freeze_rejected_non_reusable(self):
        scenario = _scenario(
            governor_mode="enabled", governor_decision="freeze",
            memory_experience_status="rejected", memory_reusable=False,
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        protection = result["governor_memory_protection"]
        assert protection["unsafe_governor_records"] == 1
        assert protection["correctly_non_reusable"] == 1
        assert protection["protection_rate"] == pytest.approx(1.0)

    def test_081_unsafe_reusable_violation_increments_but_does_not_raise(self):
        scenario = _scenario(
            governor_mode="enabled", governor_decision="block",
            memory_experience_status="validated", memory_reusable=True,
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        protection = result["governor_memory_protection"]
        assert protection["unsafe_governor_records"] == 1
        assert protection["unsafe_reusable_violations"] == 1
        assert protection["correctly_non_reusable"] == 0
        assert protection["protection_rate"] == pytest.approx(0.0)

    def test_082_mixed_protection_rate(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", governor_mode="enabled", governor_decision="block", memory_reusable=False),
            _scenario(scenario_id="S-2", governor_mode="enabled", governor_decision="freeze", memory_reusable=True),
        )
        result = evaluate_research_experiment(experiment=experiment)
        assert result["governor_memory_protection"]["protection_rate"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Handoff metrics
# ---------------------------------------------------------------------------


class TestHandoffMetrics:
    def test_083_reaching_stages_counted(self):
        scenario = _scenario(handoff_stage_results=[
            _stage("threat_intel_review", "reviewed_relevant"),
            _stage("detection_engineering", "candidate_ready"),
            _stage("red_validation", "validated"),
            _stage("purple_remediation", "planned"),
        ], approval_state="pending", human_review_required=True)
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        handoff = result["handoff"]
        assert handoff["total_stage_results"] == 4
        assert handoff["scenarios_reaching_detection_engineering"] == 1
        assert handoff["scenarios_reaching_red_validation"] == 1
        assert handoff["scenarios_reaching_purple_remediation"] == 1
        assert handoff["scenarios_reaching_human_review"] == 1

    def test_084_human_review_requires_approval_state_not_stage_presence(self):
        scenario = _scenario(
            handoff_stage_results=[_stage("purple_remediation", "planned")],
            approval_state="not_required",
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["handoff"]["scenarios_reaching_human_review"] == 0

    def test_085_mean_stage_results_per_scenario(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", handoff_stage_results=[_stage("threat_hunt", "planned")]),
            _scenario(scenario_id="S-2", handoff_stage_results=[]),
        )
        result = evaluate_research_experiment(experiment=experiment)
        assert result["handoff"]["mean_stage_results_per_scenario"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Red -> Blue revision
# ---------------------------------------------------------------------------


class TestRedBlueRevision:
    def test_086_full_revision_cycle_counted(self):
        scenario = _scenario(handoff_stage_results=[
            _stage("detection_engineering", "candidate_ready"),
            _stage("red_validation", "blocked"),
            _stage("detection_engineering", "candidate_ready"),
            _stage("red_validation", "validated"),
            _stage("purple_remediation", "planned"),
        ], approval_state="approved", human_review_required=True)
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        revision = result["red_blue_revision"]
        assert revision["revision_cycle_count"] == 1
        assert revision["scenarios_with_revision"] == 1
        assert revision["red_blocked_count"] == 1

    def test_087_blocked_without_later_blue_not_counted_as_cycle(self):
        scenario = _scenario(handoff_stage_results=[
            _stage("detection_engineering", "candidate_ready"),
            _stage("red_validation", "blocked"),
        ])
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        revision = result["red_blue_revision"]
        assert revision["red_blocked_count"] == 1
        assert revision["revision_cycle_count"] == 0
        assert revision["scenarios_with_revision"] == 0

    def test_088_blocked_never_called_attack_failure_in_result(self):
        scenario = _scenario(handoff_stage_results=[_stage("red_validation", "blocked")])
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        rendered = str(result)
        assert "attack failure" not in rendered.lower()

    def test_089_multiple_blocked_cycles_in_one_scenario(self):
        scenario = _scenario(handoff_stage_results=[
            _stage("red_validation", "blocked"),
            _stage("detection_engineering", "candidate_ready"),
            _stage("red_validation", "blocked"),
            _stage("detection_engineering", "candidate_ready"),
        ])
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        revision = result["red_blue_revision"]
        assert revision["red_blocked_count"] == 2
        assert revision["revision_cycle_count"] == 2
        assert revision["scenarios_with_revision"] == 1


# ---------------------------------------------------------------------------
# Evidence preservation
# ---------------------------------------------------------------------------


class TestEvidencePreservation:
    def test_090_missing_evidence_preservation(self):
        scenario = _scenario(source_evidence_digests=[DIGEST_A, DIGEST_B], final_evidence_references=[])
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        preservation = result["evidence_preservation"]
        assert preservation["source_evidence_count"] == 2
        assert preservation["preserved_evidence_count"] == 0
        assert preservation["missing_evidence_count"] == 2
        assert preservation["evidence_preservation_rate"] == pytest.approx(0.0)

    def test_091_perfect_evidence_preservation(self):
        scenario = _scenario(
            source_evidence_digests=[DIGEST_A, DIGEST_B], final_evidence_references=[DIGEST_A, DIGEST_B],
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        preservation = result["evidence_preservation"]
        assert preservation["preserved_evidence_count"] == 2
        assert preservation["missing_evidence_count"] == 0
        assert preservation["evidence_preservation_rate"] == pytest.approx(1.0)

    def test_092_partial_evidence_preservation(self):
        scenario = _scenario(
            source_evidence_digests=[DIGEST_A, DIGEST_B], final_evidence_references=[DIGEST_A],
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["evidence_preservation"]["evidence_preservation_rate"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Human review metrics
# ---------------------------------------------------------------------------


class TestHumanReviewMetrics:
    def test_093_approved_pending_rejected_states(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", approval_state="pending", human_review_required=True),
            _scenario(scenario_id="S-2", approval_state="approved", human_review_required=True),
            _scenario(scenario_id="S-3", approval_state="rejected", human_review_required=True),
            _scenario(scenario_id="S-4", approval_state="not_required"),
        )
        result = evaluate_research_experiment(experiment=experiment)
        review = result["human_review"]
        assert review["pending_count"] == 1
        assert review["approved_count"] == 1
        assert review["rejected_count"] == 1
        assert review["not_required_count"] == 1
        assert review["human_review_required_count"] == 3


# ---------------------------------------------------------------------------
# Validated defensive experience
# ---------------------------------------------------------------------------


class TestValidatedDefensiveExperience:
    def test_094_count_and_rate(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", validated_defensive_experience=True),
            _scenario(scenario_id="S-2", validated_defensive_experience=False),
        )
        result = evaluate_research_experiment(experiment=experiment)
        vde = result["validated_defensive_experience"]
        assert vde["count"] == 1
        assert vde["rate"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# MTVD
# ---------------------------------------------------------------------------


class TestMTVD:
    def test_095_validated_with_duration(self):
        scenario = _scenario(validated_defensive_experience=True, duration_minutes=42.0)
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        mtvd = result["mtvd"]
        assert mtvd["available"] is True
        assert mtvd["validated_scenarios_with_duration"] == 1
        assert mtvd["validated_scenarios_missing_duration"] == 0
        assert mtvd["mean_minutes"] == pytest.approx(42.0)

    def test_096_validated_without_duration(self):
        scenario = _scenario(validated_defensive_experience=True, duration_minutes=None)
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        mtvd = result["mtvd"]
        assert mtvd["available"] is False
        assert mtvd["validated_scenarios_with_duration"] == 0
        assert mtvd["validated_scenarios_missing_duration"] == 1
        assert mtvd["mean_minutes"] is None

    def test_097_mixed_duration_uses_only_supplied(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", validated_defensive_experience=True, duration_minutes=10.0),
            _scenario(scenario_id="S-2", validated_defensive_experience=True, duration_minutes=None),
            _scenario(scenario_id="S-3", validated_defensive_experience=True, duration_minutes=30.0),
            _scenario(scenario_id="S-4", validated_defensive_experience=False, duration_minutes=1000.0),
        )
        result = evaluate_research_experiment(experiment=experiment)
        mtvd = result["mtvd"]
        assert mtvd["validated_scenarios_with_duration"] == 2
        assert mtvd["validated_scenarios_missing_duration"] == 1
        assert mtvd["mean_minutes"] == pytest.approx(20.0)

    def test_099_mtvd_never_uses_stage_count_as_time(self):
        scenario = _scenario(
            validated_defensive_experience=True, duration_minutes=None,
            handoff_stage_results=[_stage("threat_hunt", "planned")] * 5,
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["mtvd"]["mean_minutes"] is None


# ---------------------------------------------------------------------------
# Stage-count proxy
# ---------------------------------------------------------------------------


class TestStageCountProxy:
    def test_100_proxy_uses_stage_count_not_duration(self):
        scenario = _scenario(
            validated_defensive_experience=True,
            handoff_stage_results=[_stage("threat_hunt", "planned"), _stage("detection_engineering", "candidate_ready")],
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        proxy = result["stage_count_proxy"]
        assert proxy["available"] is True
        assert proxy["validated_scenario_count"] == 1
        assert proxy["mean_stage_count_to_validated_experience"] == pytest.approx(2.0)

    def test_101_proxy_unavailable_when_no_validated_scenarios(self):
        scenario = _scenario(validated_defensive_experience=False)
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        proxy = result["stage_count_proxy"]
        assert proxy["available"] is False
        assert proxy["mean_stage_count_to_validated_experience"] is None

    def test_102_proxy_independent_of_mtvd(self):
        scenario = _scenario(
            validated_defensive_experience=True, duration_minutes=None,
            handoff_stage_results=[_stage("threat_hunt", "planned")],
        )
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["mtvd"]["available"] is False
        assert result["stage_count_proxy"]["available"] is True


# ---------------------------------------------------------------------------
# Ablations
# ---------------------------------------------------------------------------


class TestAblations:
    def test_103_memory_enabled_vs_disabled(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", memory_mode="enabled", validated_defensive_experience=True),
            _scenario(scenario_id="S-2", memory_mode="disabled", validated_defensive_experience=False),
        )
        result = evaluate_research_experiment(experiment=experiment)
        ablations = result["ablations"]
        assert ablations["memory_enabled"]["scenario_count"] == 1
        assert ablations["memory_enabled"]["validated_defensive_experience_rate"] == pytest.approx(1.0)
        assert ablations["memory_disabled"]["validated_defensive_experience_rate"] == pytest.approx(0.0)

    def test_104_context_enabled_vs_disabled(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", context_mode="enabled", technical_severity="low",
                      operational_priority="high", priority_direction="raised"),
            _scenario(scenario_id="S-2", context_mode="disabled"),
        )
        result = evaluate_research_experiment(experiment=experiment)
        ablations = result["ablations"]
        assert ablations["context_enabled"]["scenario_count"] == 1
        assert ablations["context_disabled"]["scenario_count"] == 1

    def test_105_governor_enabled_vs_disabled(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", governor_mode="enabled", governor_decision="require_review"),
            _scenario(scenario_id="S-2", governor_mode="disabled", governor_decision="allow"),
        )
        result = evaluate_research_experiment(experiment=experiment)
        ablations = result["ablations"]
        assert ablations["governor_enabled"]["scenario_count"] == 1
        assert ablations["governor_disabled"]["scenario_count"] == 1

    def test_106_empty_ablation_group_returns_nulls(self):
        scenario = _scenario(context_mode="disabled")
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        empty_group = result["ablations"]["context_enabled"]
        assert empty_group["scenario_count"] == 0
        assert empty_group["validated_defensive_experience_rate"] is None
        assert empty_group["mean_stage_count"] is None
        assert empty_group["mean_duration_minutes"] is None

    def test_107_ablation_mean_duration_only_from_supplied_durations(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", memory_mode="enabled", duration_minutes=10.0,
                      validated_defensive_experience=True),
            _scenario(scenario_id="S-2", memory_mode="enabled", duration_minutes=None),
        )
        result = evaluate_research_experiment(experiment=experiment)
        assert result["ablations"]["memory_enabled"]["mean_duration_minutes"] == pytest.approx(10.0)

    def test_108_ablation_group_with_scenarios_but_no_durations_is_null(self):
        scenario = _scenario(memory_mode="enabled", duration_minutes=None)
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["ablations"]["memory_enabled"]["mean_duration_minutes"] is None

    def test_109_no_causal_statement_anywhere_in_ablation_output(self):
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        rendered = str(result["ablations"]).lower()
        assert "causal" not in rendered
        assert "causes" not in rendered


# ---------------------------------------------------------------------------
# Determinism / immutability
# ---------------------------------------------------------------------------


class TestDeterminismAndImmutability:
    def test_110_same_input_same_output(self):
        experiment = _experiment(_scenario())
        first = evaluate_research_experiment(experiment=experiment)
        second = evaluate_research_experiment(experiment=experiment)
        assert first == second

    def test_111_experiment_never_mutated(self):
        experiment = _experiment(_scenario(handoff_stage_results=[_stage("threat_hunt", "planned")]))
        snapshot = copy.deepcopy(experiment)
        evaluate_research_experiment(experiment=experiment)
        assert experiment == snapshot

    def test_112_nested_lists_never_mutated(self):
        stage_results = [_stage("threat_hunt", "planned")]
        source_digests = [DIGEST_A]
        final_refs = [DIGEST_A]
        scenario = _scenario(
            handoff_stage_results=stage_results,
            source_evidence_digests=source_digests,
            final_evidence_references=final_refs,
        )
        experiment = _experiment(scenario)
        evaluate_research_experiment(experiment=experiment)
        assert stage_results == [_stage("threat_hunt", "planned")]
        assert source_digests == [DIGEST_A]
        assert final_refs == [DIGEST_A]

    def test_113_output_holds_no_reference_to_input_lists(self):
        scenario = _scenario(handoff_stage_results=[_stage("threat_hunt", "planned")])
        experiment = _experiment(scenario)
        result = evaluate_research_experiment(experiment=experiment)
        # Mutating the original input after the call must never affect
        # an already-returned result.
        scenario["handoff_stage_results"].append(_stage("red_validation", "blocked"))
        assert result["handoff"]["total_stage_results"] == 1


# ---------------------------------------------------------------------------
# Research-honesty review
# ---------------------------------------------------------------------------


class TestResearchHonesty:
    _FORBIDDEN_AFFIRMATIVE_PHRASES = (
        "proves causal",
        "causally improves",
        "is statistically significant",
        "statistically significant result",
        "guarantees production security",
        "guarantees defense",
        "successfully remediated",
        "prevented the exploitation",
        "confirms the vulnerability",
        "validates the vulnerability",
        "autonomously executed the attack",
        "automatically learned",
        "trains a model",
        "production defense improvement was confirmed",
    )

    def test_114_source_never_contains_forbidden_affirmative_phrases(self):
        import inspect

        source = inspect.getsource(research_evaluation).lower()
        for phrase in self._FORBIDDEN_AFFIRMATIVE_PHRASES:
            assert phrase not in source, f"forbidden affirmative phrase found: {phrase!r}"

    def test_115_output_values_are_never_free_text(self):
        # The output contract has no free-text field at all -- every
        # string value is a member of a small, fixed vocabulary or the
        # caller's own experiment_id. This is a structural guarantee
        # against accidentally injecting a prose claim into the result.
        result = evaluate_research_experiment(experiment=_experiment(_scenario()))
        allowed_strings = {"1"} | set(RESEARCH_LIMITATIONS) | {result["experiment_id"]}
        def _collect_strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for nested in value.values():
                    yield from _collect_strings(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from _collect_strings(nested)
        for text in _collect_strings(result):
            assert text in allowed_strings, f"unexpected free-text value in output: {text!r}"

    def test_116_error_messages_never_claim_authentication(self):
        scenario = _scenario(approval_state="maybe")
        with pytest.raises(ResearchEvaluationError) as excinfo:
            evaluate_research_experiment(experiment=_experiment(scenario))
        message = str(excinfo.value).lower()
        assert "authenticat" not in message

    def test_117_unsafe_violation_preserved_never_raises(self):
        # A Governor block/freeze co-occurring with memory_reusable=True is
        # an intentional invariant-violation research observation -- this
        # must never cause the whole experiment to be rejected.
        scenario = _scenario(governor_mode="enabled", governor_decision="freeze", memory_reusable=True)
        result = evaluate_research_experiment(experiment=_experiment(scenario))
        assert result["governor_memory_protection"]["unsafe_reusable_violations"] == 1

    def test_118_module_never_imports_other_core_modules(self):
        import ast
        import inspect

        source = inspect.getsource(research_evaluation)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("core."), f"unexpected core import: {node.module}"
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("core."), f"unexpected core import: {alias.name}"
