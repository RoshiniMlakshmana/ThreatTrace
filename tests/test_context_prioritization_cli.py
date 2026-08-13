"""Tests for core.context_prioritization_cli -- the stdin/stdout JSON
adapter around core.context_prioritization.prioritize_finding
(Block 15B, checkpoint B).

No network, filesystem, subprocess, clock, randomness, database/
Supabase, MCP, or LLM/model access occurs anywhere in this file. Every
input is a plain in-memory JSON object.

This file does not re-verify every core.context_prioritization
validation/scoring case (see tests/test_context_prioritization.py for
the 222 core tests) -- it tests only the CLI's own adapter boundary:
envelope dispatch, pass-through, exit codes, and output/error shape.
"""

from __future__ import annotations

import inspect
import json
from io import StringIO

import pytest

import core.context_prioritization_cli as context_prioritization_cli
from core.context_prioritization import prioritize_finding

_RESULT_FIELDS = {
    "prioritization_version", "finding_id", "technical_severity", "finding_status", "confidence",
    "context", "priority_score", "operational_priority", "priority_direction",
    "priority_reasons", "context_completeness", "human_review_required", "execution_performed",
}


def _finding(**overrides):
    finding = {
        "finding_version": "1",
        "finding_id": "BB15A-0000000000000000",
        "target": "https://app.example.test/",
        "affected_path": "/",
        "affected_parameter": None,
        "title": "Example finding",
        "finding_status": "validated",
        "vulnerability_class": "security_header_misconfiguration",
        "owasp_category": "A05:2021 Security Misconfiguration",
        "cwe": "CWE-693",
        "technical_severity": "medium",
        "confidence": "high",
        "evidence": [{"evidence_version": "1"}],
        "validation": {"method": "deterministic_header_presence_check", "confirmed": True},
        "reproduction_summary": "Requested / and observed X.",
        "remediation": "Add the missing header.",
        "detection_opportunity": "Alert on missing header.",
        "human_approval_required": True,
        "assessment_performed": True,
        "network_requests_performed": 1,
        "execution_performed": False,
    }
    finding.update(overrides)
    return finding


def _context(**overrides):
    context = {
        "context_version": "1",
        "industry": "general",
        "environment": "staging",
        "asset_criticality": "medium",
        "exposure": "restricted",
        "data_sensitivity": "internal",
        "detection_coverage": "partial",
        "compensating_controls": "partial",
        "threat_activity": "emerging",
        "regulatory_relevance": "potential",
    }
    context.update(overrides)
    return context


def _envelope(**overrides):
    envelope = {"operation": "prioritize", "finding": _finding(), "context": _context()}
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = context_prioritization_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback", "ContextPrioritizationError", "ValueError", "RuntimeError",
        "KeyError", "AttributeError", "TypeError",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# A. Successful results across the priority range
# ---------------------------------------------------------------------------


class TestSuccessfulResults:
    def test_001_low_operational_priority_exit_zero(self):
        envelope = _envelope(
            finding=_finding(technical_severity="low", finding_status="observation"),
            context=_context(),
        )
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout)["operational_priority"] == "low"

    def test_002_medium_operational_priority_exit_zero(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout)["operational_priority"] == "medium"

    def test_003_high_operational_priority_exit_zero(self):
        envelope = _envelope(
            finding=_finding(technical_severity="high"),
            context=_context(),
        )
        exit_code, stdout, _ = _run(json.dumps(envelope))
        assert exit_code == 0
        assert json.loads(stdout)["operational_priority"] == "high"

    def test_004_critical_operational_priority_exit_zero(self):
        envelope = _envelope(
            finding=_finding(technical_severity="critical", finding_status="validated"),
            context=_context(
                environment="production", asset_criticality="critical", exposure="internet_facing",
                data_sensitivity="restricted", detection_coverage="none", threat_activity="active",
            ),
        )
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout)["operational_priority"] == "critical"

    def test_005_stdout_ends_with_single_newline(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert stdout.endswith("\n")
        assert stdout.count("\n") == 1


# ---------------------------------------------------------------------------
# B. Core equivalence
# ---------------------------------------------------------------------------


class TestCoreEquivalence:
    @pytest.mark.parametrize("technical_severity", ["low", "medium", "high", "critical"])
    def test_006_stdout_exactly_equals_direct_core_call(self, technical_severity):
        finding = _finding(technical_severity=technical_severity)
        context = _context(environment="production")
        _, stdout, _ = _run(json.dumps(_envelope(finding=finding, context=context)))
        cli_result = json.loads(stdout)
        direct_result = prioritize_finding(finding=finding, context=context)
        assert cli_result == direct_result

    def test_007_key_order_in_envelope_does_not_matter(self):
        envelope_text = json.dumps({"context": _context(), "finding": _finding(), "operation": "prioritize"})
        exit_code, stdout, _ = _run(envelope_text)
        assert exit_code == 0
        assert json.loads(stdout)["finding_id"] == "BB15A-0000000000000000"

    def test_008_exact_result_keys(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert set(json.loads(stdout).keys()) == _RESULT_FIELDS


# ---------------------------------------------------------------------------
# C. Candidate critical priority is a normal result
# ---------------------------------------------------------------------------


class TestCandidateCriticalPriority:
    def _high_risk_candidate_envelope(self):
        return _envelope(
            finding=_finding(finding_status="candidate", technical_severity="medium"),
            context=_context(
                environment="production", asset_criticality="critical", exposure="internet_facing",
                data_sensitivity="restricted", detection_coverage="none", threat_activity="active",
                regulatory_relevance="direct",
            ),
        )

    def test_009_exit_zero_for_candidate_critical(self):
        exit_code, stdout, stderr = _run(json.dumps(self._high_risk_candidate_envelope()))
        assert exit_code == 0
        assert stderr == ""

    def test_010_finding_status_remains_candidate(self):
        _, stdout, _ = _run(json.dumps(self._high_risk_candidate_envelope()))
        assert json.loads(stdout)["finding_status"] == "candidate"

    def test_011_operational_priority_is_critical(self):
        _, stdout, _ = _run(json.dumps(self._high_risk_candidate_envelope()))
        assert json.loads(stdout)["operational_priority"] == "critical"

    def test_012_not_treated_as_validation_failure(self):
        exit_code, stdout, stderr = _run(json.dumps(self._high_risk_candidate_envelope()))
        assert exit_code == 0
        assert not stderr.startswith("CONTEXT_PRIORITIZATION_VALIDATION_FAILED")


# ---------------------------------------------------------------------------
# D. Technical truth preservation
# ---------------------------------------------------------------------------


class TestTechnicalTruthPreservation:
    def test_013_finding_id_echoed_exactly(self):
        finding = _finding(finding_id="BB15A-specific-id-0001")
        _, stdout, _ = _run(json.dumps(_envelope(finding=finding)))
        assert json.loads(stdout)["finding_id"] == "BB15A-specific-id-0001"

    def test_014_technical_severity_echoed_exactly(self):
        finding = _finding(technical_severity="high")
        _, stdout, _ = _run(json.dumps(_envelope(finding=finding)))
        assert json.loads(stdout)["technical_severity"] == "high"

    def test_015_finding_status_echoed_exactly(self):
        finding = _finding(finding_status="observation")
        _, stdout, _ = _run(json.dumps(_envelope(finding=finding)))
        assert json.loads(stdout)["finding_status"] == "observation"

    def test_016_confidence_echoed_exactly(self):
        finding = _finding(confidence="low")
        _, stdout, _ = _run(json.dumps(_envelope(finding=finding)))
        assert json.loads(stdout)["confidence"] == "low"

    def test_017_result_never_reproduces_full_finding(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        result = json.loads(stdout)
        assert "target" not in result
        assert "evidence" not in result
        assert "validation" not in result
        assert "remediation" not in result


# ---------------------------------------------------------------------------
# E. Envelope validation
# ---------------------------------------------------------------------------


class TestEnvelopeValidation:
    def test_018_malformed_json_exits_two(self):
        exit_code, stdout, stderr = _run("{not valid json")
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("CONTEXT_PRIORITIZATION_VALIDATION_FAILED")

    def test_019_top_level_list_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(["prioritize"]))
        assert exit_code == 2
        assert stdout == ""

    def test_020_top_level_string_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps("prioritize"))
        assert exit_code == 2
        assert stdout == ""

    def test_021_top_level_null_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(None))
        assert exit_code == 2
        assert stdout == ""

    def test_022_top_level_number_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(3.14))
        assert exit_code == 2
        assert stdout == ""

    def test_023_empty_stdin_exits_two(self):
        exit_code, stdout, _ = _run("")
        assert exit_code == 2
        assert stdout == ""

    def test_024_missing_operation_exits_two(self):
        envelope = _envelope()
        del envelope["operation"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("CONTEXT_PRIORITIZATION_VALIDATION_FAILED")

    def test_025_missing_finding_exits_two(self):
        envelope = _envelope()
        del envelope["finding"]
        exit_code, stdout, _ = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""

    def test_026_missing_context_exits_two(self):
        envelope = _envelope()
        del envelope["context"]
        exit_code, stdout, _ = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""

    def test_027_extra_key_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(extra_field="not allowed")))
        assert exit_code == 2
        assert stdout == ""

    def test_028_unsupported_operation_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(operation="score")))
        assert exit_code == 2
        assert stdout == ""

    def test_029_blank_operation_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(operation="")))
        assert exit_code == 2
        assert stdout == ""

    def test_030_null_operation_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(operation=None)))
        assert exit_code == 2
        assert stdout == ""

    def test_031_empty_object_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps({}))
        assert exit_code == 2
        assert stdout == ""


# ---------------------------------------------------------------------------
# F. Nested validation delegation -- never reimplemented in the CLI
# ---------------------------------------------------------------------------


class TestNestedValidationDelegation:
    def test_032_unsupported_technical_severity_exits_two(self):
        finding = _finding(technical_severity="catastrophic")
        exit_code, stdout, stderr = _run(json.dumps(_envelope(finding=finding)))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("CONTEXT_PRIORITIZATION_VALIDATION_FAILED")

    def test_033_unsupported_finding_status_exits_two(self):
        finding = _finding(finding_status="confirmed_exploit")
        exit_code, stdout, _ = _run(json.dumps(_envelope(finding=finding)))
        assert exit_code == 2
        assert stdout == ""

    def test_034_invalid_context_vocabulary_exits_two(self):
        context = _context(asset_criticality="extreme")
        exit_code, stdout, _ = _run(json.dumps(_envelope(context=context)))
        assert exit_code == 2
        assert stdout == ""

    def test_035_missing_context_field_exits_two(self):
        context = _context()
        del context["threat_activity"]
        exit_code, stdout, _ = _run(json.dumps(_envelope(context=context)))
        assert exit_code == 2
        assert stdout == ""

    def test_036_extra_context_field_exits_two(self):
        context = _context(unexpected="value")
        exit_code, stdout, _ = _run(json.dumps(_envelope(context=context)))
        assert exit_code == 2
        assert stdout == ""

    def test_037_wrong_context_version_exits_two(self):
        context = _context(context_version="2")
        exit_code, stdout, _ = _run(json.dumps(_envelope(context=context)))
        assert exit_code == 2
        assert stdout == ""

    def test_038_finding_not_a_mapping_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(finding=["not", "a", "mapping"])))
        assert exit_code == 2
        assert stdout == ""

    def test_039_context_not_a_mapping_exits_two(self):
        exit_code, stdout, _ = _run(json.dumps(_envelope(context="not a mapping")))
        assert exit_code == 2
        assert stdout == ""

    def test_040_missing_truth_bearing_finding_field_exits_two(self):
        finding = _finding()
        del finding["evidence"]
        exit_code, stdout, _ = _run(json.dumps(_envelope(finding=finding)))
        assert exit_code == 2
        assert stdout == ""


# ---------------------------------------------------------------------------
# G. Internal error
# ---------------------------------------------------------------------------


class TestInternalError:
    def test_041_unexpected_internal_exception_maps_to_exit_one(self, monkeypatch):
        def _broken(**kwargs):
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(context_prioritization_cli, "prioritize_finding", _broken)
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 1
        assert stdout == ""
        assert stderr.startswith("CONTEXT_PRIORITIZATION_INTERNAL_FAILURE")

    def test_042_internal_failure_has_no_traceback(self, monkeypatch):
        def _broken(**kwargs):
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(context_prioritization_cli, "prioritize_finding", _broken)
        _, _, stderr = _run(json.dumps(_envelope()))
        _assert_no_forbidden_content(stderr)

    def test_043_internal_failure_does_not_leak_exception_message(self, monkeypatch):
        def _broken(**kwargs):
            raise RuntimeError("sensitive internal detail")

        monkeypatch.setattr(context_prioritization_cli, "prioritize_finding", _broken)
        _, _, stderr = _run(json.dumps(_envelope()))
        assert "sensitive internal detail" not in stderr

    def test_044_no_exception_class_name_leaked_on_validation_failure(self):
        finding = _finding(technical_severity="catastrophic")
        _, _, stderr = _run(json.dumps(_envelope(finding=finding)))
        _assert_no_forbidden_content(stderr)

    def test_045_validation_failure_token_is_stable_across_causes(self):
        _, _, stderr_missing = _run(json.dumps({"operation": "prioritize"}))
        _, _, stderr_bad_context = _run(json.dumps(_envelope(context=_context(environment="prod"))))
        assert stderr_missing.startswith("CONTEXT_PRIORITIZATION_VALIDATION_FAILED")
        assert stderr_bad_context.startswith("CONTEXT_PRIORITIZATION_VALIDATION_FAILED")


# ---------------------------------------------------------------------------
# H. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_046_same_input_yields_identical_stdout(self):
        envelope_text = json.dumps(_envelope())
        _, stdout_1, _ = _run(envelope_text)
        _, stdout_2, _ = _run(envelope_text)
        assert stdout_1 == stdout_2

    def test_047_same_input_yields_identical_parsed_json(self):
        envelope_text = json.dumps(_envelope(context=_context(environment="production")))
        _, stdout_1, _ = _run(envelope_text)
        _, stdout_2, _ = _run(envelope_text)
        assert json.loads(stdout_1) == json.loads(stdout_2)


# ---------------------------------------------------------------------------
# I. No normalization
# ---------------------------------------------------------------------------


class TestNoNormalization:
    def test_048_incorrect_case_industry_rejected_not_normalized(self):
        context = _context(industry="Financial_Services")
        exit_code, stdout, _ = _run(json.dumps(_envelope(context=context)))
        assert exit_code == 2
        assert stdout == ""

    def test_049_incorrect_case_environment_rejected_not_normalized(self):
        context = _context(environment="PRODUCTION")
        exit_code, stdout, _ = _run(json.dumps(_envelope(context=context)))
        assert exit_code == 2
        assert stdout == ""

    def test_050_whitespace_padded_value_rejected_not_trimmed(self):
        context = _context(environment=" production ")
        exit_code, stdout, _ = _run(json.dumps(_envelope(context=context)))
        assert exit_code == 2
        assert stdout == ""

    def test_051_correct_case_value_still_accepted(self):
        context = _context(environment="production")
        exit_code, stdout, _ = _run(json.dumps(_envelope(context=context)))
        assert exit_code == 0
        assert json.loads(stdout)["context"]["environment"] == "production"


# ---------------------------------------------------------------------------
# J. No external capability / structural
# ---------------------------------------------------------------------------


class TestStructuralPurity:
    def _code_body(self):
        return inspect.getsource(context_prioritization_cli).split("from __future__ import annotations", 1)[1]

    def test_052_module_never_imports_network_clients(self):
        code_body = self._code_body()
        for token in ("import requests", "import httpx", "import socket", "urllib.request", "http.client"):
            assert token not in code_body

    def test_053_module_never_uses_subprocess(self):
        code_body = self._code_body()
        assert "subprocess" not in code_body

    def test_054_module_never_uses_database_supabase_or_mcp(self):
        code_body = self._code_body()
        for token in ("supabase", "mcp__", "execute_sql"):
            assert token not in code_body

    def test_055_module_never_uses_clock_or_randomness(self):
        code_body = self._code_body()
        for token in ("datetime.now", "utcnow", "import random", "import time", "import uuid"):
            assert token not in code_body

    def test_056_module_never_invokes_llm_or_model(self):
        code_body = self._code_body()
        for token in ("openai", "anthropic", "model.generate"):
            assert token.lower() not in code_body.lower()

    def test_057_module_never_reimplements_scoring_logic(self):
        code_body = self._code_body()
        for token in ("raw_modifier =", "applied_modifier =", "_REASON_ORDER", "_SEVERITY_ORDINAL"):
            assert token not in code_body

    def test_058_no_argparse_used(self):
        code_body = self._code_body()
        assert "argparse" not in code_body

    def test_059_module_imports_only_the_permitted_symbols(self):
        code_body = self._code_body()
        import_block = code_body.split("_VALIDATION_ERROR_PREFIX", 1)[0]
        allowed_modules = ("core.context_prioritization", "typing", "json", "sys")
        for line in import_block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("from ") or stripped.startswith("import "):
                assert any(module in stripped for module in allowed_modules), stripped

    def test_060_cli_delegates_to_real_core_function(self, monkeypatch):
        calls = []
        real = prioritize_finding

        def _spy(**kwargs):
            calls.append(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(context_prioritization_cli, "prioritize_finding", _spy)
        _run(json.dumps(_envelope()))
        assert len(calls) == 1

    def test_061_stdout_never_wraps_result_in_extra_envelope(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        result = json.loads(stdout)
        assert "success" not in result
        assert "status" not in result
        assert "result" not in result
