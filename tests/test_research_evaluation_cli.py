"""Tests for core.research_evaluation_cli -- the stdin/stdout JSON
adapter around core.research_evaluation (Block 15E, checkpoint B).

No network, filesystem, subprocess, clock, randomness, database/
Supabase, MCP, embedding, or LLM/model access occurs anywhere in this
file. Every input is a plain in-memory JSON object.

This file does not re-verify every core.research_evaluation validation/
metric case (see tests/test_research_evaluation.py for the 116-test
core suite) -- it tests only the CLI's own adapter boundary: envelope
dispatch, pass-through, exit codes, and output/error shape.
"""

from __future__ import annotations

import json
from io import StringIO

import pytest

import core.research_evaluation_cli as research_evaluation_cli
from core.research_evaluation import evaluate_research_experiment

DIGEST_A = "sha256:" + "a" * 8


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


def _envelope(**overrides):
    envelope = {"operation": "evaluate", "experiment": _experiment(_scenario())}
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = research_evaluation_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback", "ResearchEvaluationError", "ValueError", "RuntimeError",
        "KeyError", "AttributeError", "TypeError", "  File \"",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# Success -- simple and multi-scenario evaluations
# ---------------------------------------------------------------------------


class TestSuccessEvaluations:
    def test_001_simple_valid_evaluation_exit_zero(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 0
        assert stderr == ""
        result = json.loads(stdout)
        assert result["scenario_count"] == 1

    def test_002_multi_scenario_evaluation(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1"), _scenario(scenario_id="S-2"), _scenario(scenario_id="S-3"),
        )
        exit_code, stdout, stderr = _run(json.dumps({"operation": "evaluate", "experiment": experiment}))
        assert exit_code == 0
        assert json.loads(stdout)["scenario_count"] == 3

    def test_003_context_enabled_scenario(self):
        scenario = _scenario(
            context_mode="enabled", technical_severity="medium",
            operational_priority="critical", priority_direction="raised",
        )
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert json.loads(stdout)["ablations"]["context_enabled"]["scenario_count"] == 1

    def test_004_context_disabled_scenario(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 0
        assert json.loads(stdout)["ablations"]["context_disabled"]["scenario_count"] == 1

    def test_005_memory_enabled_scenario(self):
        scenario = _scenario(memory_mode="enabled")
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert json.loads(stdout)["ablations"]["memory_enabled"]["scenario_count"] == 1

    def test_006_memory_disabled_scenario(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 0
        assert json.loads(stdout)["ablations"]["memory_disabled"]["scenario_count"] == 1

    def test_007_governor_enabled_scenario(self):
        scenario = _scenario(governor_mode="enabled", governor_decision="warn")
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert json.loads(stdout)["ablations"]["governor_enabled"]["scenario_count"] == 1

    def test_008_governor_disabled_scenario(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 0
        assert json.loads(stdout)["ablations"]["governor_disabled"]["scenario_count"] == 1


# ---------------------------------------------------------------------------
# Unsafe reusable violation remains a normal, exit-0 result
# ---------------------------------------------------------------------------


class TestUnsafeReusableViolation:
    def test_009_unsafe_reusable_violation_is_exit_zero(self):
        scenario = _scenario(governor_mode="enabled", governor_decision="block", memory_reusable=True)
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stderr == ""

    def test_010_unsafe_reusable_violation_count_present_in_output(self):
        scenario = _scenario(governor_mode="enabled", governor_decision="freeze", memory_reusable=True)
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        _, stdout, _ = _run(json.dumps(envelope))
        result = json.loads(stdout)
        assert result["governor_memory_protection"]["unsafe_reusable_violations"] == 1

    def test_011_correctly_protected_case_also_exit_zero(self):
        scenario = _scenario(governor_mode="enabled", governor_decision="block", memory_reusable=False)
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert json.loads(stdout)["governor_memory_protection"]["protection_rate"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# MTVD / stage-count proxy
# ---------------------------------------------------------------------------


class TestMTVDAndStageCountProxy:
    def test_012_mtvd_available(self):
        scenario = _scenario(validated_defensive_experience=True, duration_minutes=15.0)
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        _, stdout, _ = _run(json.dumps(envelope))
        mtvd = json.loads(stdout)["mtvd"]
        assert mtvd["available"] is True
        assert mtvd["mean_minutes"] == pytest.approx(15.0)

    def test_013_mtvd_unavailable(self):
        scenario = _scenario(validated_defensive_experience=True, duration_minutes=None)
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        _, stdout, _ = _run(json.dumps(envelope))
        mtvd = json.loads(stdout)["mtvd"]
        assert mtvd["available"] is False
        assert mtvd["mean_minutes"] is None

    def test_014_stage_count_proxy_present(self):
        scenario = _scenario(
            validated_defensive_experience=True,
            handoff_stage_results=[_stage("threat_hunt", "planned"), _stage("detection_engineering", "candidate_ready")],
        )
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        _, stdout, _ = _run(json.dumps(envelope))
        proxy = json.loads(stdout)["stage_count_proxy"]
        assert proxy["available"] is True
        assert proxy["mean_stage_count_to_validated_experience"] == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# Red -> Blue revision / evidence preservation
# ---------------------------------------------------------------------------


class TestRevisionAndEvidence:
    def test_015_red_blue_revision_counted(self):
        scenario = _scenario(handoff_stage_results=[
            _stage("detection_engineering", "candidate_ready"),
            _stage("red_validation", "blocked"),
            _stage("detection_engineering", "candidate_ready"),
        ])
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        _, stdout, _ = _run(json.dumps(envelope))
        revision = json.loads(stdout)["red_blue_revision"]
        assert revision["revision_cycle_count"] == 1

    def test_016_evidence_preservation_perfect(self):
        scenario = _scenario(source_evidence_digests=[DIGEST_A], final_evidence_references=[DIGEST_A])
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        _, stdout, _ = _run(json.dumps(envelope))
        preservation = json.loads(stdout)["evidence_preservation"]
        assert preservation["evidence_preservation_rate"] == pytest.approx(1.0)

    def test_017_evidence_preservation_missing(self):
        scenario = _scenario(source_evidence_digests=[DIGEST_A], final_evidence_references=[])
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        _, stdout, _ = _run(json.dumps(envelope))
        preservation = json.loads(stdout)["evidence_preservation"]
        assert preservation["evidence_preservation_rate"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# CLI/core equivalence and output formatting
# ---------------------------------------------------------------------------


class TestOutputEquivalenceAndFormatting:
    def test_018_cli_output_equals_direct_core_call(self):
        experiment = _experiment(_scenario())
        direct = evaluate_research_experiment(experiment=experiment)
        _, stdout, _ = _run(json.dumps({"operation": "evaluate", "experiment": experiment}))
        assert json.loads(stdout) == direct

    def test_019_cli_output_equals_direct_core_call_multi_scenario(self):
        experiment = _experiment(
            _scenario(scenario_id="S-1", governor_mode="enabled", governor_decision="block"),
            _scenario(scenario_id="S-2", validated_defensive_experience=True, duration_minutes=5.0),
        )
        direct = evaluate_research_experiment(experiment=experiment)
        _, stdout, _ = _run(json.dumps({"operation": "evaluate", "experiment": experiment}))
        assert json.loads(stdout) == direct

    def test_020_deterministic_stdout_across_calls(self):
        raw = json.dumps(_envelope())
        _, first, _ = _run(raw)
        _, second, _ = _run(raw)
        assert first == second

    def test_021_output_keys_sorted(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        raw_keys = list(json.loads(stdout).keys())
        assert raw_keys == sorted(raw_keys)

    def test_022_no_wrapper_success_or_status_field(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        result = json.loads(stdout)
        assert "success" not in result
        assert "status" not in result
        assert "result" not in result

    def test_023_stdout_is_exactly_one_json_object_plus_newline(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert stdout.endswith("\n")
        assert stdout.count("\n") == 1

    def test_024_no_prose_on_stdout(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        # Every string value must parse as valid JSON content, i.e. the
        # entire stdout is exactly one JSON document -- nothing appended.
        json.loads(stdout)


# ---------------------------------------------------------------------------
# Envelope validation -> exit 2
# ---------------------------------------------------------------------------


class TestEnvelopeValidation:
    def test_025_malformed_json_exit_two(self):
        exit_code, stdout, stderr = _run("{not json")
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("RESEARCH_EVALUATION_VALIDATION_FAILED:")

    def test_026_top_level_array_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps([1, 2, 3]))
        assert exit_code == 2
        assert stdout == ""

    def test_027_top_level_string_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps("just a string"))
        assert exit_code == 2

    def test_028_top_level_null_exit_two(self):
        exit_code, stdout, stderr = _run("null")
        assert exit_code == 2

    def test_029_missing_operation_exit_two(self):
        envelope = _envelope()
        del envelope["operation"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stderr.startswith("RESEARCH_EVALUATION_VALIDATION_FAILED:")

    def test_030_missing_experiment_exit_two(self):
        envelope = _envelope()
        del envelope["experiment"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_031_unsupported_operation_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(operation="summarize")))
        assert exit_code == 2
        assert stdout == ""

    def test_032_extra_top_level_field_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(unexpected="x")))
        assert exit_code == 2

    def test_033_empty_object_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps({}))
        assert exit_code == 2

    def test_034_empty_stdin_exit_two(self):
        exit_code, stdout, stderr = _run("")
        assert exit_code == 2

    def test_035_null_experiment_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(experiment=None)))
        assert exit_code == 2

    def test_036_experiment_as_list_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(experiment=[1, 2])))
        assert exit_code == 2


# ---------------------------------------------------------------------------
# Core validation delegated through unchanged (ResearchEvaluationError)
# -> exit 2
# ---------------------------------------------------------------------------


class TestCoreValidationDelegation:
    def test_037_wrong_experiment_version_exit_two(self):
        experiment = _experiment(_scenario())
        experiment["experiment_version"] = "2"
        envelope = {"operation": "evaluate", "experiment": experiment}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("RESEARCH_EVALUATION_VALIDATION_FAILED:")

    def test_038_empty_scenario_records_exit_two(self):
        experiment = _experiment()
        envelope = {"operation": "evaluate", "experiment": experiment}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_039_duplicate_scenario_id_exit_two(self):
        experiment = _experiment(_scenario(scenario_id="S-1"), _scenario(scenario_id="S-1"))
        envelope = {"operation": "evaluate", "experiment": experiment}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_040_malformed_severity_exit_two(self):
        scenario = _scenario(technical_severity="extreme")
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_041_priority_direction_mismatch_exit_two(self):
        scenario = _scenario(
            context_mode="enabled", technical_severity="low",
            operational_priority="critical", priority_direction="unchanged",
        )
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_042_disabled_context_with_changed_priority_exit_two(self):
        scenario = _scenario(
            context_mode="disabled", technical_severity="low",
            operational_priority="high", priority_direction="raised",
        )
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_043_disabled_governor_non_allow_exit_two(self):
        scenario = _scenario(governor_mode="disabled", governor_decision="warn")
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_044_negative_duration_exit_two(self):
        scenario = _scenario(duration_minutes=-5)
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_045_infinite_duration_exit_two(self):
        # json.dumps(float("inf")) is not valid JSON, so the malformed
        # value must be smuggled in as raw text.
        raw = (
            '{"operation":"evaluate","experiment":{"experiment_version":"1","experiment_id":"E",'
            '"scenario_records":[{"scenario_id":"S-1","technical_severity":"medium",'
            '"operational_priority":"medium","priority_direction":"unchanged",'
            '"context_mode":"disabled","memory_mode":"disabled","governor_mode":"disabled",'
            '"governor_decision":"allow","memory_experience_status":"candidate",'
            '"memory_reusable":false,"handoff_stage_results":[],'
            '"source_evidence_digests":["sha256:aaaaaaaa"],"final_evidence_references":["sha256:aaaaaaaa"],'
            '"human_review_required":false,"approval_state":"not_required",'
            '"validated_defensive_experience":false,"duration_minutes":Infinity}]}}'
        )
        exit_code, stdout, stderr = _run(raw)
        assert exit_code == 2

    def test_046_malformed_handoff_stage_exit_two(self):
        scenario = _scenario(handoff_stage_results=[{"stage": "human_review", "outcome": "x"}])
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_047_empty_source_evidence_exit_two(self):
        scenario = _scenario(source_evidence_digests=[])
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_048_duplicate_final_evidence_exit_two(self):
        scenario = _scenario(final_evidence_references=[DIGEST_A, DIGEST_A])
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_049_invalid_approval_state_exit_two(self):
        scenario = _scenario(approval_state="maybe")
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_050_cli_never_reimplements_core_validation_message(self):
        scenario = _scenario(technical_severity="extreme")
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert "INVALID_SEVERITY" in stderr


# ---------------------------------------------------------------------------
# Internal failure -> exit 1
# ---------------------------------------------------------------------------


class TestInternalFailure:
    def test_051_unexpected_exception_exit_one(self, monkeypatch):
        def _boom(*, experiment):
            raise RuntimeError("boom")

        monkeypatch.setattr(research_evaluation_cli, "evaluate_research_experiment", _boom)
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 1
        assert stdout == ""
        assert stderr.startswith("RESEARCH_EVALUATION_INTERNAL_FAILURE:")

    def test_052_internal_failure_never_leaks_exception_class(self, monkeypatch):
        def _boom(*, experiment):
            raise RuntimeError("some internal detail")

        monkeypatch.setattr(research_evaluation_cli, "evaluate_research_experiment", _boom)
        _, _, stderr = _run(json.dumps(_envelope()))
        assert "RuntimeError" not in stderr
        assert "some internal detail" not in stderr

    def test_053_stdin_read_failure_exit_one(self):
        class _ExplodingStdin:
            def read(self):
                raise OSError("disk on fire")

        stdout = StringIO()
        stderr = StringIO()
        exit_code = research_evaluation_cli.main(stdin=_ExplodingStdin(), stdout=stdout, stderr=stderr)
        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert stderr.getvalue().startswith("RESEARCH_EVALUATION_INTERNAL_FAILURE:")


# ---------------------------------------------------------------------------
# No leakage of raw exception/traceback/large-payload content
# ---------------------------------------------------------------------------


class TestNoLeakage:
    def test_054_validation_failure_no_forbidden_content(self):
        exit_code, stdout, stderr = _run("{not json")
        _assert_no_forbidden_content(stdout + stderr)

    def test_055_core_validation_failure_no_forbidden_content(self):
        scenario = _scenario(technical_severity="extreme")
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        _assert_no_forbidden_content(stdout + stderr)

    def test_056_success_output_no_forbidden_content(self):
        _, stdout, stderr = _run(json.dumps(_envelope()))
        _assert_no_forbidden_content(stdout + stderr)

    def test_057_validation_failure_does_not_dump_entire_experiment(self):
        scenario = _scenario(source_evidence_digests=["a-very-specific-marker-value-12345"] * 1, technical_severity="extreme")
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        _, stdout, stderr = _run(json.dumps(envelope))
        assert "a-very-specific-marker-value-12345" not in stderr

    def test_058_validation_failure_message_is_short(self):
        scenario = _scenario(technical_severity="extreme")
        envelope = {"operation": "evaluate", "experiment": _experiment(scenario)}
        _, _, stderr = _run(json.dumps(envelope))
        assert len(stderr) < 300


# ---------------------------------------------------------------------------
# No external capability
# ---------------------------------------------------------------------------


class TestNoExternalCapability:
    def test_059_cli_module_imports_only_stdlib_and_research_core(self):
        import ast
        import inspect

        source = inspect.getsource(research_evaluation_cli)
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])
        assert imported_modules <= {"__future__", "json", "sys", "typing", "core"}

    def test_060_module_has_main_guard(self):
        source_path = research_evaluation_cli.__file__
        with open(source_path, encoding="utf-8") as handle:
            content = handle.read()
        assert 'if __name__ == "__main__":' in content

    def test_061_research_limitations_present_in_every_success_output(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        result = json.loads(stdout)
        assert result["research_limitations"] == [
            "OBSERVATIONAL_SUMMARY_ONLY",
            "NO_CAUSAL_CLAIM",
            "NO_STATISTICAL_SIGNIFICANCE_TEST",
            "CALLER_SUPPLIED_DURATION",
            "CALLER_SUPPLIED_APPROVAL_STATE",
            "RECORDED_STAGE_NOT_EXECUTION_PROOF",
            "EVIDENCE_REFERENCE_NOT_AUTHENTICITY_PROOF",
        ]

    def test_062_no_semantic_or_causal_claim_in_output_text(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        rendered = stdout.lower()
        assert "semantic" not in rendered
        assert "causal improvement" not in rendered
        assert "guaranteed" not in rendered
