"""Focused integration tests for `core.integration_demo` (Block 15,
checkpoint A).

These tests prove composition, not policy: that `run_integration_scenario`
calls real, unmodified Block 8/9/10/11/11-12/13/14 public functions in
the documented order, that denial/narrowing/invalid outcomes are
represented as normal successful results, and that the result contract
is exactly as specified. They deliberately do not re-test the full rule
matrix of any individual block -- that coverage already exists in each
block's own dedicated test file.
"""

from __future__ import annotations

import inspect

import pytest

import core.integration_demo as integration_demo
from core.agent_gateway import evaluate_tool_call
from core.agent_identity_policy import evaluate_agent_tool_call
from core.ai_asset_registry import evaluate_ai_security_case
from core.analyst_feedback import create_analyst_feedback
from core.decision_binding import create_decision_binding, verify_decision_binding
from core.evaluation_dashboard import summarize_audit_dashboard
from core.integration_demo import IntegrationDemoError, run_integration_scenario
from core.mutation_freeze import evaluate_mutation_freeze
from core.tamper_evident_audit import create_audit_record, verify_audit_chain

_SCENARIOS = (
    "identity_narrowing_deny",
    "emergency_mutation_freeze",
    "evaluation_feedback_audit",
    "decision_binding_argument_drift",
)

_TOP_LEVEL_KEYS = {
    "integration_version",
    "scenario",
    "steps",
    "final_outcome",
    "observed_evidence",
    "execution_performed",
}

_STEP_KEYS = {"step", "block", "function", "outcome_field", "outcome_value"}


# ---------------------------------------------------------------------------
# A. API
# ---------------------------------------------------------------------------


class TestApi:
    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_001_all_four_scenarios_succeed(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        assert result["scenario"] == scenario

    def test_002_non_string_scenario_rejected(self):
        with pytest.raises(IntegrationDemoError):
            run_integration_scenario(scenario=123)

    def test_003_none_scenario_rejected(self):
        with pytest.raises(IntegrationDemoError):
            run_integration_scenario(scenario=None)

    def test_004_blank_scenario_rejected(self):
        with pytest.raises(IntegrationDemoError):
            run_integration_scenario(scenario="   ")

    def test_005_empty_string_scenario_rejected(self):
        with pytest.raises(IntegrationDemoError):
            run_integration_scenario(scenario="")

    def test_006_unknown_scenario_rejected(self):
        with pytest.raises(IntegrationDemoError):
            run_integration_scenario(scenario="not_a_real_scenario")

    def test_007_case_sensitive_scenario_rejected(self):
        with pytest.raises(IntegrationDemoError):
            run_integration_scenario(scenario="Identity_Narrowing_Deny")

    def test_008_list_scenario_rejected(self):
        with pytest.raises(IntegrationDemoError):
            run_integration_scenario(scenario=["identity_narrowing_deny"])

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_009_deterministic_repeated_output(self, scenario):
        first = run_integration_scenario(scenario=scenario)
        second = run_integration_scenario(scenario=scenario)
        assert first == second

    def test_010_scenario_trimmed_of_whitespace(self):
        result = run_integration_scenario(scenario="  identity_narrowing_deny  ")
        assert result["scenario"] == "identity_narrowing_deny"

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_011_exact_top_level_result_keys(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        assert set(result.keys()) == _TOP_LEVEL_KEYS

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_012_integration_version_is_one(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        assert result["integration_version"] == "1"

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_013_execution_performed_always_false(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        assert result["execution_performed"] is False

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_014_steps_is_a_nonempty_list(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        assert isinstance(result["steps"], list)
        assert len(result["steps"]) >= 2

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_015_observed_evidence_is_a_list(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        assert isinstance(result["observed_evidence"], list)

    def test_016_scenario_must_be_supplied_as_keyword(self):
        with pytest.raises(TypeError):
            run_integration_scenario("identity_narrowing_deny")  # type: ignore[misc]


# ---------------------------------------------------------------------------
# B. Scenario 1 -- identity_narrowing_deny
# ---------------------------------------------------------------------------


class TestScenario1IdentityNarrowingDeny:
    def _result(self):
        return run_integration_scenario(scenario="identity_narrowing_deny")

    def test_017_gateway_decision_is_non_deny(self):
        result = self._result()
        gateway_step = next(s for s in result["steps"] if s["step"] == "gateway_evaluation")
        assert gateway_step["outcome_value"] != "deny"

    def test_018_identity_final_decision_is_deny(self):
        result = self._result()
        identity_step = next(s for s in result["steps"] if s["step"] == "identity_evaluation")
        assert identity_step["outcome_value"] == "deny"

    def test_019_final_outcome_is_identity_scope_denied(self):
        result = self._result()
        assert result["final_outcome"] == "identity_scope_denied"

    def test_020_real_narrowing_evidence_exposed(self):
        result = self._result()
        assert "OPERATION_CLASS_NOT_PERMITTED" in result["observed_evidence"]

    def test_021_no_execution(self):
        result = self._result()
        assert result["execution_performed"] is False

    def test_022_exactly_two_steps(self):
        result = self._result()
        assert len(result["steps"]) == 2


# ---------------------------------------------------------------------------
# C. Scenario 2 -- emergency_mutation_freeze
# ---------------------------------------------------------------------------


class TestScenario2EmergencyMutationFreeze:
    def _result(self):
        return run_integration_scenario(scenario="emergency_mutation_freeze")

    def test_023_pre_freeze_final_decision_is_not_deny(self):
        result = self._result()
        pre_freeze_step = next(s for s in result["steps"] if s["step"] == "identity_evaluation_pre_freeze")
        assert pre_freeze_step["outcome_value"] != "deny"

    def test_024_frozen_final_decision_is_deny(self):
        result = self._result()
        freeze_step = next(s for s in result["steps"] if s["step"] == "mutation_freeze_evaluation")
        assert freeze_step["outcome_value"] == "deny"

    def test_025_mutation_freeze_active_appears(self):
        result = self._result()
        assert "MUTATION_FREEZE_ACTIVE" in result["observed_evidence"]

    def test_026_final_outcome_is_mutation_freeze_denied(self):
        result = self._result()
        assert result["final_outcome"] == "mutation_freeze_denied"

    def test_027_no_execution(self):
        result = self._result()
        assert result["execution_performed"] is False

    def test_028_pre_freeze_is_not_required_to_be_allow(self):
        result = self._result()
        pre_freeze_step = next(s for s in result["steps"] if s["step"] == "identity_evaluation_pre_freeze")
        assert pre_freeze_step["outcome_value"] in ("allow", "require_approval")


# ---------------------------------------------------------------------------
# D. Scenario 3 -- evaluation_feedback_audit
# ---------------------------------------------------------------------------


class TestScenario3EvaluationFeedbackAudit:
    def _result(self):
        return run_integration_scenario(scenario="evaluation_feedback_audit")

    def test_029_real_evaluation_outcome_is_pass(self):
        result = self._result()
        eval_step = next(s for s in result["steps"] if s["step"] == "security_evaluation")
        assert eval_step["outcome_value"] == "pass"

    def test_030_analyst_decision_is_disagree(self):
        result = self._result()
        feedback_step = next(s for s in result["steps"] if s["step"] == "analyst_feedback")
        assert feedback_step["outcome_value"] == "disagree"

    def test_031_original_evaluation_result_not_mutated(self):
        before = evaluate_ai_security_case(
            case_type=integration_demo._DEMO_EVALUATION_CASE_TYPE,
            asset_id=integration_demo._DEMO_EVALUATION_ASSET_ID,
        )
        run_integration_scenario(scenario="evaluation_feedback_audit")
        after = evaluate_ai_security_case(
            case_type=integration_demo._DEMO_EVALUATION_CASE_TYPE,
            asset_id=integration_demo._DEMO_EVALUATION_ASSET_ID,
        )
        assert before == after

    def test_032_two_audit_records_created_in_sequence(self):
        result = self._result()
        record_steps = [s for s in result["steps"] if s["function"] == "core.tamper_evident_audit.create_audit_record"]
        assert len(record_steps) == 2
        assert record_steps[0]["outcome_value"] == "security_evaluation_result"
        assert record_steps[1]["outcome_value"] == "analyst_feedback"

    def test_033_verification_valid(self):
        result = self._result()
        chain_step = next(s for s in result["steps"] if s["step"] == "chain_verification")
        assert chain_step["outcome_value"] == "valid"

    def test_034_internal_chain_valid_true_via_real_verify(self):
        record_1 = create_audit_record(
            sequence=1,
            event_type="security_evaluation_result",
            event_reference=integration_demo._DEMO_EVALUATION_EVENT_REFERENCE,
            event_summary={"outcome": "pass", "case_type": "mutation_policy_bypass"},
            occurred_at=integration_demo._DEMO_AUDIT_RECORD_1_OCCURRED_AT,
            previous_record_digest=None,
        )
        record_2 = create_audit_record(
            sequence=2,
            event_type="analyst_feedback",
            event_reference=integration_demo._DEMO_FEEDBACK_EVENT_REFERENCE,
            event_summary={"outcome": "disagree", "error_category": "evaluation_expectation_mismatch"},
            occurred_at=integration_demo._DEMO_AUDIT_RECORD_2_OCCURRED_AT,
            previous_record_digest=record_1["record_digest"],
        )
        verification = verify_audit_chain(records=[record_1, record_2], expected_head_digest=None)
        assert verification["internal_chain_valid"] is True

    def test_035_trusted_anchor_verified_is_none(self):
        record_1 = create_audit_record(
            sequence=1,
            event_type="security_evaluation_result",
            event_reference=integration_demo._DEMO_EVALUATION_EVENT_REFERENCE,
            event_summary={"outcome": "pass", "case_type": "mutation_policy_bypass"},
            occurred_at=integration_demo._DEMO_AUDIT_RECORD_1_OCCURRED_AT,
            previous_record_digest=None,
        )
        verification = verify_audit_chain(records=[record_1], expected_head_digest=None)
        assert verification["trusted_anchor_verified"] is None

    def test_036_real_dashboard_reflects_exactly_two_records(self):
        result = self._result()
        dashboard_step = next(s for s in result["steps"] if s["step"] == "dashboard_summary")
        assert dashboard_step["outcome_value"] == "valid"

    def test_037_dashboard_counts_match_the_two_records_via_real_call(self):
        record_1 = create_audit_record(
            sequence=1,
            event_type="security_evaluation_result",
            event_reference=integration_demo._DEMO_EVALUATION_EVENT_REFERENCE,
            event_summary={"outcome": "pass", "case_type": "mutation_policy_bypass"},
            occurred_at=integration_demo._DEMO_AUDIT_RECORD_1_OCCURRED_AT,
            previous_record_digest=None,
        )
        record_2 = create_audit_record(
            sequence=2,
            event_type="analyst_feedback",
            event_reference=integration_demo._DEMO_FEEDBACK_EVENT_REFERENCE,
            event_summary={"outcome": "disagree", "error_category": "evaluation_expectation_mismatch"},
            occurred_at=integration_demo._DEMO_AUDIT_RECORD_2_OCCURRED_AT,
            previous_record_digest=record_1["record_digest"],
        )
        dashboard = summarize_audit_dashboard(records=[record_1, record_2], expected_head_digest=None)
        assert dashboard["event_type_counts"]["security_evaluation_result"] == 1
        assert dashboard["event_type_counts"]["analyst_feedback"] == 1
        assert dashboard["evaluation_counts"]["outcome_counts"]["pass"] == 1
        assert dashboard["feedback_counts"]["decision_counts"]["disagree"] == 1
        assert dashboard["feedback_counts"]["error_category_counts"]["evaluation_expectation_mismatch"] == 1

    def test_038_final_outcome_is_evaluation_feedback_audited(self):
        result = self._result()
        assert result["final_outcome"] == "evaluation_feedback_audited"

    def test_039_no_execution(self):
        result = self._result()
        assert result["execution_performed"] is False

    def test_040_six_steps_present(self):
        result = self._result()
        assert len(result["steps"]) == 6


# ---------------------------------------------------------------------------
# E. Scenario 4 -- decision_binding_argument_drift
# ---------------------------------------------------------------------------


class TestScenario4DecisionBindingArgumentDrift:
    def _result(self):
        return run_integration_scenario(scenario="decision_binding_argument_drift")

    def test_041_real_block_9_result_supports_binding_creation(self):
        result = self._result()
        identity_step = next(s for s in result["steps"] if s["step"] == "identity_evaluation")
        assert identity_step["outcome_value"] != "deny"

    def test_042_binding_created_successfully(self):
        result = self._result()
        binding_step = next(s for s in result["steps"] if s["step"] == "binding_creation")
        assert binding_step["outcome_value"] == "created"

    def test_043_unchanged_verification_succeeds(self):
        result = self._result()
        unchanged_step = next(s for s in result["steps"] if s["step"] == "binding_verification_unchanged")
        assert unchanged_step["outcome_value"] == "valid"

    def test_044_changed_argument_fails_verification(self):
        result = self._result()
        drifted_step = next(s for s in result["steps"] if s["step"] == "binding_verification_drifted")
        assert drifted_step["outcome_value"] == "invalid"

    def test_045_argument_digest_mismatch_appears(self):
        result = self._result()
        assert "ARGUMENT_DIGEST_MISMATCH" in result["observed_evidence"]

    def test_046_final_outcome_is_argument_drift_detected(self):
        result = self._result()
        assert result["final_outcome"] == "argument_drift_detected"

    def test_047_no_execution(self):
        result = self._result()
        assert result["execution_performed"] is False

    def test_048_exactly_four_steps(self):
        result = self._result()
        assert len(result["steps"]) == 4


# ---------------------------------------------------------------------------
# F. Projection
# ---------------------------------------------------------------------------


class TestProjection:
    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_049_every_step_has_exactly_five_keys(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        for step in result["steps"]:
            assert set(step.keys()) == _STEP_KEYS

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_050_every_step_field_is_a_non_blank_string(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        for step in result["steps"]:
            for field in ("step", "block", "function", "outcome_field"):
                assert isinstance(step[field], str)
                assert step[field].strip()

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_051_outcome_value_is_string_bool_or_none(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        for step in result["steps"]:
            assert isinstance(step["outcome_value"], (str, bool)) or step["outcome_value"] is None

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_052_observed_evidence_is_list_of_strings(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        for code in result["observed_evidence"]:
            assert isinstance(code, str)

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_053_observed_evidence_is_deduplicated(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        codes = result["observed_evidence"]
        assert len(codes) == len(set(codes))

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_054_step_ids_are_unique_within_a_scenario(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        step_ids = [s["step"] for s in result["steps"]]
        assert len(step_ids) == len(set(step_ids))

    @pytest.mark.parametrize("scenario", _SCENARIOS)
    def test_055_function_field_is_fully_qualified(self, scenario):
        result = run_integration_scenario(scenario=scenario)
        for step in result["steps"]:
            assert step["function"].startswith("core.")
            assert "." in step["function"].split("core.", 1)[1]


# ---------------------------------------------------------------------------
# G. Structural architecture
# ---------------------------------------------------------------------------


class TestStructuralArchitecture:
    def test_056_module_source_never_uses_hashlib(self):
        source = inspect.getsource(integration_demo)
        assert "hashlib" not in source

    def test_057_module_source_never_uses_json_dumps_canonicalization(self):
        source = inspect.getsource(integration_demo)
        assert "json.dumps" not in source
        assert "sort_keys" not in source

    def test_058_module_source_never_defines_a_tool_or_agent_registry(self):
        source = inspect.getsource(integration_demo)
        assert "_REGISTRY" not in source
        assert "_ROLE_OPERATION_CLASS_CEILING" not in source

    def test_059_module_source_never_reimplements_dashboard_aggregation(self):
        source = inspect.getsource(integration_demo)
        assert "event_type_counts" not in source
        assert "case_type_counts" not in source

    def test_060_module_source_never_performs_filesystem_io(self):
        source = inspect.getsource(integration_demo)
        for token in ("open(", "os.environ", "pathlib", "Path("):
            assert token not in source

    def test_061_module_source_never_uses_clock_or_randomness(self):
        source = inspect.getsource(integration_demo)
        for token in ("datetime.now", "utcnow", "import random", "import time", "import uuid"):
            assert token not in source

    def test_062_module_source_never_uses_database_supabase_or_mcp(self):
        source = inspect.getsource(integration_demo)
        for token in ("supabase", "mcp__", "execute_sql", "import socket", "import requests"):
            assert token not in source

    def test_063_module_source_never_calls_subprocess(self):
        source = inspect.getsource(integration_demo)
        assert "subprocess" not in source

    def test_064_module_imports_only_the_permitted_public_functions(self):
        source = inspect.getsource(integration_demo)
        import_block = source.split("from __future__ import annotations", 1)[1].split("INTEGRATION_VERSION", 1)[0]
        allowed_modules = (
            "core.agent_gateway",
            "core.agent_identity_policy",
            "core.ai_asset_registry",
            "core.analyst_feedback",
            "core.decision_binding",
            "core.evaluation_dashboard",
            "core.mutation_freeze",
            "core.tamper_evident_audit",
            "typing",
        )
        for line in import_block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("from ") or stripped.startswith("import "):
                assert any(module in stripped for module in allowed_modules), stripped

    def test_065_module_never_imports_a_private_helper(self):
        source = inspect.getsource(integration_demo)
        import_block = source.split("from __future__ import annotations", 1)[1].split("INTEGRATION_VERSION", 1)[0]
        for line in import_block.splitlines():
            stripped = line.strip()
            if stripped.startswith("from core."):
                imported_names = stripped.split("import", 1)[1]
                for name in imported_names.split(","):
                    assert not name.strip().startswith("_"), stripped

    def test_066_calls_real_agent_gateway_function(self, monkeypatch):
        calls = []
        real = evaluate_tool_call

        def _spy(**kwargs):
            calls.append(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(integration_demo, "evaluate_tool_call", _spy)
        run_integration_scenario(scenario="identity_narrowing_deny")
        assert len(calls) == 1

    def test_067_calls_real_agent_identity_policy_function(self, monkeypatch):
        calls = []
        real = evaluate_agent_tool_call

        def _spy(**kwargs):
            calls.append(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(integration_demo, "evaluate_agent_tool_call", _spy)
        run_integration_scenario(scenario="identity_narrowing_deny")
        assert len(calls) == 1

    def test_068_calls_real_mutation_freeze_function(self, monkeypatch):
        calls = []
        real = evaluate_mutation_freeze

        def _spy(**kwargs):
            calls.append(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(integration_demo, "evaluate_mutation_freeze", _spy)
        run_integration_scenario(scenario="emergency_mutation_freeze")
        assert len(calls) == 1

    def test_069_calls_real_ai_security_case_function(self, monkeypatch):
        calls = []
        real = evaluate_ai_security_case

        def _spy(**kwargs):
            calls.append(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(integration_demo, "evaluate_ai_security_case", _spy)
        run_integration_scenario(scenario="evaluation_feedback_audit")
        assert len(calls) == 1

    def test_070_calls_real_analyst_feedback_function(self, monkeypatch):
        calls = []
        real = create_analyst_feedback

        def _spy(**kwargs):
            calls.append(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(integration_demo, "create_analyst_feedback", _spy)
        run_integration_scenario(scenario="evaluation_feedback_audit")
        assert len(calls) == 1

    def test_071_calls_real_audit_and_dashboard_functions(self, monkeypatch):
        record_calls = []
        real_create = create_audit_record

        def _spy_create(**kwargs):
            record_calls.append(kwargs)
            return real_create(**kwargs)

        verify_calls = []
        real_verify = verify_audit_chain

        def _spy_verify(**kwargs):
            verify_calls.append(kwargs)
            return real_verify(**kwargs)

        dashboard_calls = []
        real_dashboard = summarize_audit_dashboard

        def _spy_dashboard(**kwargs):
            dashboard_calls.append(kwargs)
            return real_dashboard(**kwargs)

        monkeypatch.setattr(integration_demo, "create_audit_record", _spy_create)
        monkeypatch.setattr(integration_demo, "verify_audit_chain", _spy_verify)
        monkeypatch.setattr(integration_demo, "summarize_audit_dashboard", _spy_dashboard)
        run_integration_scenario(scenario="evaluation_feedback_audit")
        assert len(record_calls) == 2
        assert len(verify_calls) == 1
        assert len(dashboard_calls) == 1

    def test_072_calls_real_decision_binding_functions(self, monkeypatch):
        create_calls = []
        real_create = create_decision_binding

        def _spy_create(**kwargs):
            create_calls.append(kwargs)
            return real_create(**kwargs)

        verify_calls = []
        real_verify = verify_decision_binding

        def _spy_verify(**kwargs):
            verify_calls.append(kwargs)
            return real_verify(**kwargs)

        monkeypatch.setattr(integration_demo, "create_decision_binding", _spy_create)
        monkeypatch.setattr(integration_demo, "verify_decision_binding", _spy_verify)
        run_integration_scenario(scenario="decision_binding_argument_drift")
        assert len(create_calls) == 1
        assert len(verify_calls) == 2

    def test_073_public_symbols_are_exactly_error_and_function(self):
        public_names = sorted(
            name for name in vars(integration_demo)
            if not name.startswith("_") and not inspect.ismodule(getattr(integration_demo, name))
        )
        assert "IntegrationDemoError" in public_names
        assert "run_integration_scenario" in public_names

    def test_074_integration_demo_error_is_a_value_error(self):
        assert issubclass(IntegrationDemoError, ValueError)

    def test_075_broken_fixture_lets_real_typed_exception_propagate(self, monkeypatch):
        from core.agent_gateway import AgentGatewayError

        def _broken(**kwargs):
            raise AgentGatewayError("simulated broken fixture")

        monkeypatch.setattr(integration_demo, "evaluate_tool_call", _broken)
        with pytest.raises(AgentGatewayError):
            run_integration_scenario(scenario="identity_narrowing_deny")
