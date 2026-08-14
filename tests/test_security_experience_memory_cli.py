"""Tests for core.security_experience_memory_cli -- the stdin/stdout
JSON adapter around core.security_experience_memory (Block 15D,
checkpoint B).

No network, filesystem, subprocess, clock, randomness, database/
Supabase, MCP, embedding, or LLM/model access occurs anywhere in this
file. Every input is a plain in-memory JSON object.

This file does not re-verify every core.security_experience_memory
validation/admission case (see tests/test_security_experience_memory.py
for the core suite) -- it tests only the CLI's own adapter boundary:
envelope dispatch, pass-through, exit codes, and output/error shape.
"""

from __future__ import annotations

import json
from io import StringIO

import pytest

import core.security_experience_memory_cli as memory_cli
from core.security_experience_memory import add_security_experience, create_security_experience

DIGEST_A = "sha256:" + "a" * 64


def _stage_result(stage, role, result_type, outcome):
    return {"stage": stage, "role": role, "result_type": result_type, "outcome": outcome}


def _case(**overrides):
    case = {
        "handoff_version": "1",
        "case_id": "SH-" + "1" * 16,
        "finding_reference": {
            "finding_id": "BB15A-0000000000000000",
            "technical_severity": "high",
            "finding_status": "validated",
            "confidence": "high",
            "evidence_digests": [DIGEST_A],
        },
        "priority_reference": {},
        "current_stage": "human_review",
        "required_role": "human_analyst",
        "stage_results": [
            _stage_result("threat_intel_review", "threat_intelligence", "assessment", "reviewed_relevant"),
            _stage_result("red_validation", "red_team", "assessment", "validated"),
            _stage_result("purple_remediation", "purple_ir", "recommendation", "planned"),
        ],
        "approval_state": "approved",
        "approval_reference": "APR-1",
        "human_review_required": True,
        "execution_performed": False,
    }
    case.update(overrides)
    return case


def _prioritization(**overrides):
    prioritization = {
        "prioritization_version": "1",
        "finding_id": "BB15A-0000000000000000",
        "technical_severity": "high",
        "finding_status": "validated",
        "confidence": "high",
        "operational_priority": "critical",
        "priority_direction": "raised",
        "context_completeness": "complete",
        "priority_score": {"base": 3, "raw_modifier": 3, "applied_modifier": 2, "final": 4},
        "context": {
            "context_version": "1",
            "industry": "financial_services",
            "environment": "production",
            "asset_criticality": "critical",
            "exposure": "internet_facing",
            "data_sensitivity": "confidential",
            "detection_coverage": "none",
            "compensating_controls": "none",
            "threat_activity": "active",
            "regulatory_relevance": "direct",
        },
        "priority_reasons": [],
        "human_review_required": True,
        "execution_performed": False,
    }
    prioritization.update(overrides)
    return prioritization


def _governor_result(decision="allow", reason_codes=None, **overrides):
    result = {
        "governor_version": "1",
        "decision": decision,
        "reason_codes": reason_codes if reason_codes is not None else [],
        "actor_role": "human_analyst",
        "action_class": "approval_decision",
        "human_review_required": decision != "allow",
        "mutation_freeze_recommended": decision == "freeze",
        "execution_allowed": decision == "allow",
        "observable_only": True,
        "execution_performed": False,
    }
    result.update(overrides)
    return result


def _create_envelope(**overrides):
    envelope = {
        "operation": "create_experience",
        "case": _case(),
        "prioritization": _prioritization(),
        "governor_result": _governor_result(),
    }
    envelope.update(overrides)
    return envelope


def _empty_memory():
    return {"memory_version": "1", "entries": []}


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = memory_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback", "SecurityExperienceMemoryError", "ValueError", "RuntimeError",
        "KeyError", "AttributeError", "TypeError", "  File \"",
    )
    for text in forbidden:
        assert text not in rendered


def _real_experience(**governor_overrides):
    return create_security_experience(
        case=_case(), prioritization=_prioritization(), governor_result=_governor_result(**governor_overrides),
    )


# ---------------------------------------------------------------------------
# create_experience
# ---------------------------------------------------------------------------


class TestCreateExperience:
    def test_001_exit_zero(self):
        exit_code, stdout, stderr = _run(json.dumps(_create_envelope()))
        assert exit_code == 0
        assert stderr == ""

    def test_002_cli_output_equals_direct_core_call(self):
        direct = create_security_experience(
            case=_case(), prioritization=_prioritization(), governor_result=_governor_result(),
        )
        _, stdout, _ = _run(json.dumps(_create_envelope()))
        assert json.loads(stdout) == direct

    def test_003_validated_reusable_experience(self):
        _, stdout, _ = _run(json.dumps(_create_envelope()))
        result = json.loads(stdout)
        assert result["experience_status"] == "validated"
        assert result["reusable"] is True

    def test_004_governor_block_yields_rejected_non_reusable(self):
        envelope = _create_envelope(governor_result=_governor_result(decision="block"))
        _, stdout, _ = _run(json.dumps(envelope))
        result = json.loads(stdout)
        assert result["experience_status"] == "rejected"
        assert result["reusable"] is False

    def test_005_governor_freeze_yields_rejected_non_reusable(self):
        envelope = _create_envelope(governor_result=_governor_result(decision="freeze"))
        _, stdout, _ = _run(json.dumps(envelope))
        result = json.loads(stdout)
        assert result["experience_status"] == "rejected"
        assert result["reusable"] is False

    def test_006_candidate_source_finding_stays_candidate(self):
        case = _case()
        case["finding_reference"] = dict(case["finding_reference"], finding_status="candidate")
        envelope = _create_envelope(case=case, prioritization=_prioritization(finding_status="candidate"))
        _, stdout, _ = _run(json.dumps(envelope))
        result = json.loads(stdout)
        assert result["source_finding_status"] == "candidate"
        assert result["experience_status"] == "validated"

    def test_007_missing_case_field_exit_two(self):
        envelope = _create_envelope()
        del envelope["case"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("SECURITY_EXPERIENCE_MEMORY_VALIDATION_FAILED:")

    def test_008_extra_field_exit_two(self):
        envelope = _create_envelope(unexpected="x")
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_009_malformed_case_core_error_exit_two(self):
        envelope = _create_envelope(case={"not": "a case"})
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stderr.startswith("SECURITY_EXPERIENCE_MEMORY_VALIDATION_FAILED:")

    def test_010_finding_id_mismatch_exit_two(self):
        envelope = _create_envelope(prioritization=_prioritization(finding_id="BB15A-9999999999999999"))
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_011_malformed_governor_result_exit_two(self):
        envelope = _create_envelope(governor_result={"decision": "maybe"})
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2


# ---------------------------------------------------------------------------
# add_experience
# ---------------------------------------------------------------------------


class TestAddExperience:
    def test_012_exit_zero(self):
        experience = _real_experience()
        envelope = {"operation": "add_experience", "memory": _empty_memory(), "experience": experience}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stderr == ""

    def test_013_cli_output_equals_direct_core_call(self):
        experience = _real_experience()
        direct = add_security_experience(memory=_empty_memory(), experience=experience)
        envelope = {"operation": "add_experience", "memory": _empty_memory(), "experience": experience}
        _, stdout, _ = _run(json.dumps(envelope))
        assert json.loads(stdout) == direct

    def test_014_entry_appended(self):
        experience = _real_experience()
        envelope = {"operation": "add_experience", "memory": _empty_memory(), "experience": experience}
        _, stdout, _ = _run(json.dumps(envelope))
        result = json.loads(stdout)
        assert len(result["entries"]) == 1
        assert result["entries"][0]["memory_id"] == experience["memory_id"]

    def test_015_missing_memory_field_exit_two(self):
        envelope = {"operation": "add_experience", "experience": _real_experience()}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_016_missing_experience_field_exit_two(self):
        envelope = {"operation": "add_experience", "memory": _empty_memory()}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_017_duplicate_memory_id_exit_two(self):
        experience = _real_experience()
        memory = add_security_experience(memory=_empty_memory(), experience=experience)
        envelope = {"operation": "add_experience", "memory": memory, "experience": experience}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stderr.startswith("SECURITY_EXPERIENCE_MEMORY_VALIDATION_FAILED:")

    def test_018_tampered_reusable_flag_exit_two(self):
        rejected = _real_experience(decision="block")
        tampered = dict(rejected)
        tampered["reusable"] = True
        envelope = {"operation": "add_experience", "memory": _empty_memory(), "experience": tampered}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_019_malformed_memory_exit_two(self):
        envelope = {"operation": "add_experience", "memory": {"entries": []}, "experience": _real_experience()}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_020_rejected_experience_still_addable(self):
        rejected = _real_experience(decision="block")
        envelope = {"operation": "add_experience", "memory": _empty_memory(), "experience": rejected}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        result = json.loads(stdout)
        assert result["entries"][0]["experience_status"] == "rejected"
        assert result["entries"][0]["reusable"] is False


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


class TestSearch:
    def _memory_with_one_entry(self, **governor_overrides):
        experience = _real_experience(**governor_overrides)
        return add_security_experience(memory=_empty_memory(), experience=experience)

    def test_021_exit_zero_empty_query(self):
        memory = self._memory_with_one_entry()
        envelope = {"operation": "search", "memory": memory, "query": {}}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stderr == ""

    def test_022_result_count_matches(self):
        memory = self._memory_with_one_entry()
        envelope = {"operation": "search", "memory": memory, "query": {}}
        _, stdout, _ = _run(json.dumps(envelope))
        assert json.loads(stdout)["result_count"] == 1

    def test_023_reusable_only_excludes_rejected(self):
        memory = self._memory_with_one_entry(decision="block")
        envelope = {"operation": "search", "memory": memory, "query": {"reusable_only": True}}
        _, stdout, _ = _run(json.dumps(envelope))
        assert json.loads(stdout)["result_count"] == 0

    def test_024_reusable_only_includes_validated(self):
        memory = self._memory_with_one_entry(decision="allow")
        envelope = {"operation": "search", "memory": memory, "query": {"reusable_only": True}}
        _, stdout, _ = _run(json.dumps(envelope))
        assert json.loads(stdout)["result_count"] == 1

    def test_025_technical_severity_query_scores(self):
        memory = self._memory_with_one_entry()
        envelope = {"operation": "search", "memory": memory, "query": {"technical_severity": "high"}}
        _, stdout, _ = _run(json.dumps(envelope))
        results = json.loads(stdout)["results"]
        assert results[0]["structured_match_score"] == 1.0

    def test_026_missing_query_field_exit_two(self):
        envelope = {"operation": "search", "memory": _empty_memory()}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_027_missing_memory_field_exit_two(self):
        envelope = {"operation": "search", "query": {}}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_028_unknown_query_field_exit_two(self):
        envelope = {"operation": "search", "memory": _empty_memory(), "query": {"nope": "x"}}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_029_unknown_query_vocab_value_exit_two(self):
        envelope = {"operation": "search", "memory": _empty_memory(), "query": {"technical_severity": "extreme"}}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_030_cli_output_equals_direct_core_call(self):
        from core.security_experience_memory import search_security_experiences
        memory = self._memory_with_one_entry()
        direct = search_security_experiences(memory=memory, query={"technical_severity": "high"})
        envelope = {"operation": "search", "memory": memory, "query": {"technical_severity": "high"}}
        _, stdout, _ = _run(json.dumps(envelope))
        assert json.loads(stdout) == direct

    def test_031_no_semantic_similarity_claim_in_output_keys(self):
        memory = self._memory_with_one_entry()
        envelope = {"operation": "search", "memory": memory, "query": {}}
        _, stdout, _ = _run(json.dumps(envelope))
        rendered = stdout.lower()
        assert "semantic" not in rendered
        assert "embedding" not in rendered
        assert "probability" not in rendered


# ---------------------------------------------------------------------------
# Envelope-level validation shared across operations
# ---------------------------------------------------------------------------


class TestEnvelopeValidation:
    def test_032_malformed_json_exit_two(self):
        exit_code, stdout, stderr = _run("{not json")
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("SECURITY_EXPERIENCE_MEMORY_VALIDATION_FAILED:")

    def test_033_top_level_array_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps([1, 2, 3]))
        assert exit_code == 2

    def test_034_missing_operation_exit_two(self):
        envelope = _create_envelope()
        del envelope["operation"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_035_unsupported_operation_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_create_envelope(operation="delete_experience")))
        assert exit_code == 2

    def test_036_wrong_envelope_shape_for_operation_exit_two(self):
        # A create_experience envelope's fields sent under "search" should
        # be rejected for the wrong shape, not silently accepted.
        envelope = _create_envelope()
        envelope["operation"] = "search"
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_037_empty_stdin_exit_two(self):
        exit_code, stdout, stderr = _run("")
        assert exit_code == 2

    def test_038_empty_object_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps({}))
        assert exit_code == 2


# ---------------------------------------------------------------------------
# Internal failure -> exit 1
# ---------------------------------------------------------------------------


class TestInternalFailure:
    def test_039_unexpected_exception_in_create_exit_one(self, monkeypatch):
        def _boom(*, case, prioritization, governor_result):
            raise RuntimeError("boom")

        monkeypatch.setattr(memory_cli, "create_security_experience", _boom)
        exit_code, stdout, stderr = _run(json.dumps(_create_envelope()))
        assert exit_code == 1
        assert stdout == ""
        assert stderr.startswith("SECURITY_EXPERIENCE_MEMORY_INTERNAL_FAILURE:")

    def test_040_internal_failure_never_leaks_exception_class(self, monkeypatch):
        def _boom(*, case, prioritization, governor_result):
            raise RuntimeError("some internal detail")

        monkeypatch.setattr(memory_cli, "create_security_experience", _boom)
        _, _, stderr = _run(json.dumps(_create_envelope()))
        assert "RuntimeError" not in stderr
        assert "some internal detail" not in stderr

    def test_041_stdin_read_failure_exit_one(self):
        class _ExplodingStdin:
            def read(self):
                raise OSError("disk on fire")

        stdout = StringIO()
        stderr = StringIO()
        exit_code = memory_cli.main(stdin=_ExplodingStdin(), stdout=stdout, stderr=stderr)
        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert stderr.getvalue().startswith("SECURITY_EXPERIENCE_MEMORY_INTERNAL_FAILURE:")


# ---------------------------------------------------------------------------
# No leakage / determinism / no external capability
# ---------------------------------------------------------------------------


class TestNoLeakageAndDeterminism:
    def test_042_validation_failure_no_forbidden_content(self):
        exit_code, stdout, stderr = _run("{not json")
        _assert_no_forbidden_content(stdout + stderr)

    def test_043_success_output_no_forbidden_content(self):
        _, stdout, stderr = _run(json.dumps(_create_envelope()))
        _assert_no_forbidden_content(stdout + stderr)

    def test_044_deterministic_stdout_across_calls(self):
        raw = json.dumps(_create_envelope())
        _, first, _ = _run(raw)
        _, second, _ = _run(raw)
        assert first == second

    def test_045_output_keys_sorted(self):
        _, stdout, _ = _run(json.dumps(_create_envelope()))
        raw_keys = list(json.loads(stdout).keys())
        assert raw_keys == sorted(raw_keys)

    def test_046_cli_module_imports_only_stdlib_and_memory_core(self):
        import ast
        import inspect

        source = inspect.getsource(memory_cli)
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])
        assert imported_modules <= {"__future__", "json", "sys", "typing", "core"}

    def test_047_no_persistence_no_file_written(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _run(json.dumps(_create_envelope()))
        assert list(tmp_path.iterdir()) == []

    def test_048_stdout_is_exactly_one_json_object_plus_newline(self):
        _, stdout, _ = _run(json.dumps(_create_envelope()))
        assert stdout.endswith("\n")
        assert stdout.count("\n") == 1
