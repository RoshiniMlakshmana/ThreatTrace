"""Tests for core.security_governor_cli -- the stdin/stdout JSON adapter
around core.security_governor (Block 15C.5, checkpoint B).

No network, filesystem, subprocess, clock, randomness, database/
Supabase, MCP, or LLM/model access occurs anywhere in this file. Every
input is a plain in-memory JSON object.

This file does not re-verify every core.security_governor validation/
decision case (see tests/test_security_governor.py for the core suite)
-- it tests only the CLI's own adapter boundary: envelope dispatch,
pass-through, exit codes, and output/error shape.
"""

from __future__ import annotations

import json
from io import StringIO

import pytest

import core.security_governor_cli as security_governor_cli
from core.security_governor import evaluate_security_governor_event


def _event(**overrides):
    event = {
        "event_version": "1",
        "actor_role": "threat_intelligence",
        "action_class": "stage_contribution",
        "current_stage": "threat_intel_review",
        "required_role": "threat_intelligence",
        "gateway_decision": "allow",
        "identity_decision": "allow",
        "mutation_freeze_active": False,
        "approval_state": "not_required",
        "decision_binding_state": "not_required",
        "scope_state": "within_scope",
        "source_truth_state": "unchanged",
        "remote_content_state": "not_present",
        "audit_state": "recorded",
        "prior_policy_denials": 0,
        "execution_requested": False,
    }
    event.update(overrides)
    return event


def _envelope(**overrides):
    envelope = {"operation": "evaluate", "event": _event()}
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = security_governor_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback", "SecurityGovernorError", "ValueError", "RuntimeError",
        "KeyError", "AttributeError", "TypeError", "  File \"",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# Success -- every decision value, and CLI/core equivalence
# ---------------------------------------------------------------------------


class TestSuccessDecisions:
    def test_001_allow_exit_zero(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout)["decision"] == "allow"

    def test_002_warn_exit_zero(self):
        envelope = _envelope(event=_event(mutation_freeze_active=True))
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert json.loads(stdout)["decision"] == "warn"

    def test_003_require_review_exit_zero(self):
        envelope = _envelope(event=_event(gateway_decision="require_approval"))
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert json.loads(stdout)["decision"] == "require_review"

    def test_004_block_exit_zero(self):
        envelope = _envelope(event=_event(gateway_decision="deny"))
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert json.loads(stdout)["decision"] == "block"

    def test_005_freeze_exit_zero(self):
        envelope = _envelope(event=_event(audit_state="bypass_attempted"))
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert json.loads(stdout)["decision"] == "freeze"

    def test_006_block_is_not_a_cli_failure(self):
        envelope = _envelope(event=_event(identity_decision="deny"))
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stderr == ""

    def test_007_freeze_is_not_a_cli_failure(self):
        envelope = _envelope(event=_event(source_truth_state="modification_attempted"))
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stderr == ""

    def test_008_cli_output_equals_direct_core_call_allow(self):
        event = _event()
        direct = evaluate_security_governor_event(event=event)
        _, stdout, _ = _run(json.dumps(_envelope(event=event)))
        assert json.loads(stdout) == direct

    def test_009_cli_output_equals_direct_core_call_freeze(self):
        event = _event(prior_policy_denials=3, scope_state="expansion_attempt")
        direct = evaluate_security_governor_event(event=event)
        _, stdout, _ = _run(json.dumps(_envelope(event=event)))
        assert json.loads(stdout) == direct

    def test_010_stdout_is_exactly_one_json_object_plus_newline(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert stdout.endswith("\n")
        assert json.loads(stdout.strip())  # parses cleanly, no trailing content
        assert stdout.count("\n") == 1


# ---------------------------------------------------------------------------
# Determinism / output formatting
# ---------------------------------------------------------------------------


class TestOutputFormatting:
    def test_011_deterministic_stdout_across_calls(self):
        raw = json.dumps(_envelope())
        _, first, _ = _run(raw)
        _, second, _ = _run(raw)
        assert first == second

    def test_012_output_keys_sorted(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        raw_keys = list(json.loads(stdout).keys())
        assert raw_keys == sorted(raw_keys)

    def test_013_result_has_exact_ten_field_contract(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        result = json.loads(stdout)
        assert set(result.keys()) == {
            "governor_version", "decision", "reason_codes", "actor_role", "action_class",
            "human_review_required", "mutation_freeze_recommended", "execution_allowed",
            "observable_only", "execution_performed",
        }

    def test_014_execution_performed_always_false_in_stdout(self):
        for override in ({}, {"gateway_decision": "deny"}, {"audit_state": "bypass_attempted"}):
            _, stdout, _ = _run(json.dumps(_envelope(event=_event(**override))))
            assert json.loads(stdout)["execution_performed"] is False


# ---------------------------------------------------------------------------
# Envelope validation -> exit 2
# ---------------------------------------------------------------------------


class TestEnvelopeValidation:
    def test_015_malformed_json_exit_two(self):
        exit_code, stdout, stderr = _run("{not json")
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("SECURITY_GOVERNOR_VALIDATION_FAILED:")

    def test_016_top_level_array_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps([1, 2, 3]))
        assert exit_code == 2
        assert stdout == ""

    def test_017_top_level_string_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps("just a string"))
        assert exit_code == 2

    def test_018_missing_operation_exit_two(self):
        envelope = _envelope()
        del envelope["operation"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stderr.startswith("SECURITY_GOVERNOR_VALIDATION_FAILED:")

    def test_019_unsupported_operation_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(operation="delete")))
        assert exit_code == 2
        assert stdout == ""

    def test_020_missing_event_field_exit_two(self):
        envelope = _envelope()
        del envelope["event"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_021_extra_top_level_field_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(unexpected="x")))
        assert exit_code == 2

    def test_022_empty_object_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps({}))
        assert exit_code == 2

    def test_023_empty_stdin_exit_two(self):
        exit_code, stdout, stderr = _run("")
        assert exit_code == 2

    def test_024_null_event_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=None)))
        assert exit_code == 2

    def test_025_event_as_list_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=[1, 2])))
        assert exit_code == 2


# ---------------------------------------------------------------------------
# Core validation delegated through unchanged (SecurityGovernorError) -> exit 2
# ---------------------------------------------------------------------------


class TestCoreValidationDelegation:
    def test_026_missing_event_key_exit_two(self):
        bad_event = _event()
        del bad_event["actor_role"]
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=bad_event)))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("SECURITY_GOVERNOR_VALIDATION_FAILED:")

    def test_027_unknown_actor_role_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=_event(actor_role="not_a_role"))))
        assert exit_code == 2

    def test_028_unknown_action_class_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=_event(action_class="not_a_class"))))
        assert exit_code == 2

    def test_029_unknown_current_stage_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=_event(current_stage="nope"))))
        assert exit_code == 2

    def test_030_bad_prior_policy_denials_type_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=_event(prior_policy_denials="3"))))
        assert exit_code == 2

    def test_031_negative_prior_policy_denials_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=_event(prior_policy_denials=-1))))
        assert exit_code == 2

    def test_032_extra_event_field_exit_two(self):
        bad_event = _event()
        bad_event["extra"] = "x"
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=bad_event)))
        assert exit_code == 2

    def test_033_cli_never_reimplements_core_validation_message(self):
        # The CLI forwards the core's own error text verbatim -- it never
        # substitutes its own validation wording for a core-level failure.
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=_event(actor_role="nope"))))
        assert "INVALID_EVENT" in stderr


# ---------------------------------------------------------------------------
# Internal failure -> exit 1
# ---------------------------------------------------------------------------


class TestInternalFailure:
    def test_034_unexpected_exception_exit_one(self, monkeypatch):
        def _boom(*, event):
            raise RuntimeError("boom")

        monkeypatch.setattr(security_governor_cli, "evaluate_security_governor_event", _boom)
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 1
        assert stdout == ""
        assert stderr.startswith("SECURITY_GOVERNOR_INTERNAL_FAILURE:")

    def test_035_internal_failure_never_leaks_exception_class(self, monkeypatch):
        def _boom(*, event):
            raise RuntimeError("some internal detail")

        monkeypatch.setattr(security_governor_cli, "evaluate_security_governor_event", _boom)
        _, _, stderr = _run(json.dumps(_envelope()))
        assert "RuntimeError" not in stderr
        assert "some internal detail" not in stderr

    def test_036_stdin_read_failure_exit_one(self):
        class _ExplodingStdin:
            def read(self):
                raise OSError("disk on fire")

        stdout = StringIO()
        stderr = StringIO()
        exit_code = security_governor_cli.main(stdin=_ExplodingStdin(), stdout=stdout, stderr=stderr)
        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert stderr.getvalue().startswith("SECURITY_GOVERNOR_INTERNAL_FAILURE:")


# ---------------------------------------------------------------------------
# No leakage of raw exception/traceback content
# ---------------------------------------------------------------------------


class TestNoLeakage:
    def test_037_validation_failure_no_forbidden_content(self):
        exit_code, stdout, stderr = _run("{not json")
        _assert_no_forbidden_content(stdout + stderr)

    def test_038_core_validation_failure_no_forbidden_content(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(event=_event(actor_role="nope"))))
        _assert_no_forbidden_content(stdout)

    def test_039_success_output_no_forbidden_content(self):
        _, stdout, stderr = _run(json.dumps(_envelope()))
        _assert_no_forbidden_content(stdout + stderr)

    def test_040_freeze_result_no_forbidden_content(self):
        envelope = _envelope(event=_event(audit_state="bypass_attempted"))
        _, stdout, stderr = _run(json.dumps(envelope))
        _assert_no_forbidden_content(stdout + stderr)


# ---------------------------------------------------------------------------
# No external capability -- module-level import check
# ---------------------------------------------------------------------------


class TestNoExternalCapability:
    def test_041_cli_module_imports_only_stdlib_and_governor_core(self):
        import ast
        import inspect

        source = inspect.getsource(security_governor_cli)
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])
        assert imported_modules <= {"__future__", "json", "sys", "typing", "core"}

    def test_042_freeze_output_execution_allowed_false(self):
        envelope = _envelope(event=_event(audit_state="bypass_attempted"))
        _, stdout, _ = _run(json.dumps(envelope))
        assert json.loads(stdout)["execution_allowed"] is False

    def test_043_observable_only_always_true_in_cli_output(self):
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert json.loads(stdout)["observable_only"] is True

    def test_044_module_has_main_guard(self):
        source = security_governor_cli.__file__
        with open(source, encoding="utf-8") as handle:
            content = handle.read()
        assert 'if __name__ == "__main__":' in content


# ---------------------------------------------------------------------------
# Reason codes pass through unchanged
# ---------------------------------------------------------------------------


class TestReasonCodesPassThrough:
    def test_045_multiple_reason_codes_all_present(self):
        envelope = _envelope(event=_event(gateway_decision="deny", identity_decision="deny"))
        _, stdout, _ = _run(json.dumps(envelope))
        result = json.loads(stdout)
        assert result["reason_codes"] == ["TOOL_OR_GATEWAY_DENIED", "IDENTITY_POLICY_DENIED"]

    def test_046_repeated_policy_denial_reason_present(self):
        envelope = _envelope(event=_event(prior_policy_denials=2))
        _, stdout, _ = _run(json.dumps(envelope))
        assert "REPEATED_POLICY_DENIAL" in json.loads(stdout)["reason_codes"]
