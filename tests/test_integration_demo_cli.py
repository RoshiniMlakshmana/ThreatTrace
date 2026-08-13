"""Tests for core.integration_demo_cli -- the stdin/stdout JSON adapter
around core.integration_demo.run_integration_scenario (Block 15,
checkpoint B).

main() is called directly with in-memory StringIO streams. No Supabase,
MCP, file, subprocess, network, or clock/randomness access occurs
anywhere in this file; every input is a plain in-memory JSON object. No
tool is ever executed.

This file does not re-verify every core.integration_demo scenario
behavior (see tests/test_integration_demo.py for the 117 core tests) --
it tests only the CLI's own adapter boundary: envelope dispatch,
pass-through, exit codes, and output/error shape.
"""

from __future__ import annotations

import inspect
import json
from io import StringIO

import pytest

from core import integration_demo_cli
from core.integration_demo import run_integration_scenario

_SCENARIOS = (
    "identity_narrowing_deny",
    "emergency_mutation_freeze",
    "evaluation_feedback_audit",
    "decision_binding_argument_drift",
)

_EXPECTED_FINAL_OUTCOME = {
    "identity_narrowing_deny": "identity_scope_denied",
    "emergency_mutation_freeze": "mutation_freeze_denied",
    "evaluation_feedback_audit": "evaluation_feedback_audited",
    "decision_binding_argument_drift": "argument_drift_detected",
}

_RESULT_FIELDS = {
    "integration_version",
    "scenario",
    "steps",
    "final_outcome",
    "observed_evidence",
    "execution_performed",
}


def _envelope(**overrides):
    envelope = {"operation": "run", "scenario": "identity_narrowing_deny"}
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = integration_demo_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback",
        "IntegrationDemoError",
        "ValueError",
        "RuntimeError",
        "KeyError",
        "AttributeError",
        "TypeError",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# A. Valid operations
# ---------------------------------------------------------------------------


class TestValidOperations:
    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_001_exit_zero_for_each_scenario(self, scenario):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(scenario=scenario)))
        assert exit_code == 0
        assert stderr == ""

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_002_stdout_is_valid_json(self, scenario):
        _, stdout, _ = _run(json.dumps(_envelope(scenario=scenario)))
        parsed = json.loads(stdout)
        assert isinstance(parsed, dict)

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_003_stdout_exactly_equals_direct_core_call(self, scenario):
        _, stdout, _ = _run(json.dumps(_envelope(scenario=scenario)))
        cli_result = json.loads(stdout)
        direct_result = run_integration_scenario(scenario=scenario)
        assert cli_result == direct_result

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_004_execution_performed_false(self, scenario):
        _, stdout, _ = _run(json.dumps(_envelope(scenario=scenario)))
        assert json.loads(stdout)["execution_performed"] is False

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_005_expected_final_outcome_preserved(self, scenario):
        _, stdout, _ = _run(json.dumps(_envelope(scenario=scenario)))
        assert json.loads(stdout)["final_outcome"] == _EXPECTED_FINAL_OUTCOME[scenario]

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_006_exact_result_keys(self, scenario):
        _, stdout, _ = _run(json.dumps(_envelope(scenario=scenario)))
        assert set(json.loads(stdout).keys()) == _RESULT_FIELDS

    def test_007_stdout_ends_with_single_newline(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert stdout.endswith("\n")
        assert stdout.count("\n") == 1

    def test_008_key_order_in_envelope_does_not_matter(self):
        envelope_text = json.dumps({"scenario": "identity_narrowing_deny", "operation": "run"})
        exit_code, stdout, _ = _run(envelope_text)
        assert exit_code == 0
        assert json.loads(stdout)["scenario"] == "identity_narrowing_deny"


# ---------------------------------------------------------------------------
# B. Envelope validation
# ---------------------------------------------------------------------------


class TestEnvelopeValidation:
    def test_009_malformed_json_exits_two(self):
        exit_code, stdout, stderr = _run("{not valid json")
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("INTEGRATION_DEMO_VALIDATION_FAILED")

    def test_010_top_level_array_exits_two(self):
        exit_code, stdout, stderr = _run(json.dumps(["run", "identity_narrowing_deny"]))
        assert exit_code == 2
        assert stdout == ""

    def test_011_top_level_string_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps("identity_narrowing_deny"))
        assert exit_code == 2
        assert stdout == ""

    def test_012_top_level_null_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(None))
        assert exit_code == 2
        assert stdout == ""

    def test_013_top_level_number_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(42))
        assert exit_code == 2
        assert stdout == ""

    def test_014_empty_stdin_exits_two(self):
        exit_code, stdout, _ = _run("")
        assert exit_code == 2
        assert stdout == ""

    def test_015_missing_operation_exits_two(self):
        envelope = _envelope()
        del envelope["operation"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("INTEGRATION_DEMO_VALIDATION_FAILED")

    def test_016_missing_scenario_exits_two(self):
        envelope = _envelope()
        del envelope["scenario"]
        exit_code, stdout, _ = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""

    def test_017_extra_key_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(extra_field="not allowed")))
        assert exit_code == 2
        assert stdout == ""

    def test_018_unsupported_operation_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(operation="create")))
        assert exit_code == 2
        assert stdout == ""

    def test_019_blank_operation_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(operation="")))
        assert exit_code == 2
        assert stdout == ""

    def test_020_null_operation_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(operation=None)))
        assert exit_code == 2
        assert stdout == ""

    def test_021_blank_scenario_exits_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(scenario="   ")))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("INTEGRATION_DEMO_VALIDATION_FAILED")

    def test_022_unknown_scenario_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(scenario="not_a_real_scenario")))
        assert exit_code == 2
        assert stdout == ""

    def test_023_non_string_scenario_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(scenario=123)))
        assert exit_code == 2
        assert stdout == ""

    def test_024_null_scenario_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(scenario=None)))
        assert exit_code == 2
        assert stdout == ""

    def test_025_list_scenario_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(scenario=["identity_narrowing_deny"])))
        assert exit_code == 2
        assert stdout == ""

    def test_026_empty_object_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps({}))
        assert exit_code == 2
        assert stdout == ""

    def test_027_cli_does_not_trim_scenario_whitespace(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(scenario=" identity_narrowing_deny ")))
        assert exit_code == 0
        assert json.loads(stdout)["scenario"] == "identity_narrowing_deny"

    def test_028_cli_does_not_lowercase_scenario(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(scenario="Identity_Narrowing_Deny")))
        assert exit_code == 2
        assert stdout == ""


# ---------------------------------------------------------------------------
# C. Error behavior
# ---------------------------------------------------------------------------


class TestErrorBehavior:
    def test_029_integration_demo_error_maps_to_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(scenario="unknown_scenario_id")))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("INTEGRATION_DEMO_VALIDATION_FAILED")
        _assert_no_forbidden_content(stderr)

    def test_030_unexpected_internal_exception_maps_to_exit_one(self, monkeypatch):
        def _broken(**kwargs):
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(integration_demo_cli, "run_integration_scenario", _broken)
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 1
        assert stdout == ""
        assert stderr.startswith("INTEGRATION_DEMO_INTERNAL_FAILURE")

    def test_031_internal_failure_has_no_traceback(self, monkeypatch):
        def _broken(**kwargs):
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(integration_demo_cli, "run_integration_scenario", _broken)
        _, _, stderr = _run(json.dumps(_envelope()))
        _assert_no_forbidden_content(stderr)

    def test_032_internal_failure_does_not_leak_exception_message(self, monkeypatch):
        def _broken(**kwargs):
            raise RuntimeError("sensitive internal detail")

        monkeypatch.setattr(integration_demo_cli, "run_integration_scenario", _broken)
        _, _, stderr = _run(json.dumps(_envelope()))
        assert "sensitive internal detail" not in stderr

    def test_033_validation_failure_token_is_stable_across_causes(self):
        _, _, stderr_missing = _run(json.dumps({"operation": "run"}))
        _, _, stderr_unknown = _run(json.dumps(_envelope(scenario="bogus")))
        assert stderr_missing.startswith("INTEGRATION_DEMO_VALIDATION_FAILED")
        assert stderr_unknown.startswith("INTEGRATION_DEMO_VALIDATION_FAILED")

    def test_034_no_exception_class_name_leaked_on_validation_failure(self):
        _, _, stderr = _run(json.dumps(_envelope(scenario="bogus")))
        _assert_no_forbidden_content(stderr)


# ---------------------------------------------------------------------------
# D. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_035_same_input_yields_identical_stdout(self, scenario):
        envelope_text = json.dumps(_envelope(scenario=scenario))
        _, stdout_1, _ = _run(envelope_text)
        _, stdout_2, _ = _run(envelope_text)
        assert stdout_1 == stdout_2

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_036_same_input_yields_identical_parsed_json(self, scenario):
        envelope_text = json.dumps(_envelope(scenario=scenario))
        _, stdout_1, _ = _run(envelope_text)
        _, stdout_2, _ = _run(envelope_text)
        assert json.loads(stdout_1) == json.loads(stdout_2)


# ---------------------------------------------------------------------------
# E. Thin-wrapper behavior
# ---------------------------------------------------------------------------


class TestThinWrapperBehavior:
    def test_037_cli_delegates_to_real_core_function(self, monkeypatch):
        calls = []
        real = run_integration_scenario

        def _spy(**kwargs):
            calls.append(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(integration_demo_cli, "run_integration_scenario", _spy)
        _run(json.dumps(_envelope(scenario="evaluation_feedback_audit")))
        assert calls == [{"scenario": "evaluation_feedback_audit"}]

    def test_038_module_source_never_uses_hashlib(self):
        source = inspect.getsource(integration_demo_cli)
        assert "hashlib" not in source

    def test_039_module_source_never_defines_scenario_logic(self):
        source = inspect.getsource(integration_demo_cli)
        for token in ("MUTATION_FREEZE_ACTIVE", "ARGUMENT_DIGEST_MISMATCH", "OPERATION_CLASS_NOT_PERMITTED"):
            assert token not in source

    def test_040_module_source_never_performs_filesystem_io(self):
        source = inspect.getsource(integration_demo_cli)
        for token in ("open(", "os.environ", "pathlib", "Path("):
            assert token not in source

    def test_041_module_source_never_uses_clock_or_randomness(self):
        source = inspect.getsource(integration_demo_cli)
        for token in ("datetime.now", "utcnow", "import random", "import time", "import uuid"):
            assert token not in source

    def test_042_module_source_never_uses_database_supabase_or_mcp(self):
        source = inspect.getsource(integration_demo_cli)
        for token in ("supabase", "mcp__", "execute_sql", "import socket", "import requests", "subprocess"):
            assert token not in source

    def test_043_module_imports_only_integration_demo_public_symbols(self):
        source = inspect.getsource(integration_demo_cli)
        import_block = source.split("from __future__ import annotations", 1)[1].split("_VALIDATION_ERROR_PREFIX", 1)[0]
        for line in import_block.splitlines():
            stripped = line.strip()
            if stripped.startswith("from core."):
                assert stripped.startswith("from core.integration_demo import"), stripped

    def test_044_module_never_imports_a_private_helper(self):
        source = inspect.getsource(integration_demo_cli)
        assert "import _" not in source
        assert ", _" not in source.split("from core.integration_demo import", 1)[1].splitlines()[0]

    def test_045_no_argparse_used(self):
        source = inspect.getsource(integration_demo_cli)
        assert "argparse" not in source


# ---------------------------------------------------------------------------
# F. Security behavior remains normal result
# ---------------------------------------------------------------------------


class TestSecurityBehaviorIsNormalResult:
    def test_046_identity_narrowing_deny_exits_zero(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(scenario="identity_narrowing_deny")))
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout)["final_outcome"] == "identity_scope_denied"

    def test_047_mutation_freeze_denied_exits_zero(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(scenario="emergency_mutation_freeze")))
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout)["final_outcome"] == "mutation_freeze_denied"

    def test_048_argument_drift_detected_exits_zero(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(scenario="decision_binding_argument_drift")))
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout)["final_outcome"] == "argument_drift_detected"

    def test_049_denial_scenarios_are_not_treated_as_cli_errors(self):
        for scenario in ("identity_narrowing_deny", "emergency_mutation_freeze", "decision_binding_argument_drift"):
            exit_code, _, stderr = _run(json.dumps(_envelope(scenario=scenario)))
            assert exit_code == 0
            assert stderr == ""
