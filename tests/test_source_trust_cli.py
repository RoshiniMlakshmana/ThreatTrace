"""Tests for core.source_trust_cli -- the stdin/stdout JSON adapter around
core.source_trust_policy.assess_source_trust.

main() is called directly with in-memory StringIO streams. No external
process, Supabase call, Hayabusa run, or network access occurs anywhere
in this file.
"""

import copy
import json
from io import StringIO

import pytest

from core import source_trust_cli
from core.source_trust_policy import assess_source_trust


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = source_trust_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _full_provenance(**overrides):
    provenance = {
        "collector": "hayabusa_server",
        "collection_method": "run_evtx_analysis:csv_timeline",
        "source_reference": "evidence/evtx/sample.evtx",
        "captured_at": "2024-01-01T00:00:00Z",
        "integrity_verified": True,
        "corroborated_by": ["evidence-2"],
    }
    provenance.update(overrides)
    return provenance


def _evidence(**overrides):
    payload = {
        "source_type": "hayabusa",
        "assertion_type": "observation",
        "source_identifier": "case-1234",
        "source_location": "evidence/evtx/sample.evtx",
        "observed_at": "2024-01-01T00:00:00Z",
        "provenance": {},
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# 1-2: successful runs
# ---------------------------------------------------------------------------

def test_valid_verified_hayabusa_evidence_returns_exit_code_0():
    payload = _evidence(assertion_type="derived_fact", provenance=_full_provenance())

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 0


def test_valid_external_threat_intelligence_returns_exit_code_0():
    payload = _evidence(source_type="threat_intelligence", provenance=_full_provenance())

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 0


# ---------------------------------------------------------------------------
# 3-8: success output shape
# ---------------------------------------------------------------------------

def test_successful_stdout_is_valid_json():
    _exit_code, stdout, _stderr = _run(json.dumps(_evidence()))

    parsed = json.loads(stdout)

    assert isinstance(parsed, dict)


def test_output_contains_exactly_three_supported_keys():
    _exit_code, stdout, _stderr = _run(json.dumps(_evidence()))

    parsed = json.loads(stdout)

    assert set(parsed.keys()) == {
        "recommended_trust_level",
        "reason_codes",
        "conflicts_with_supplied_trust_level",
    }


def test_output_ends_with_exactly_one_newline():
    _exit_code, stdout, _stderr = _run(json.dumps(_evidence()))

    assert stdout.endswith("\n")
    assert not stdout.endswith("\n\n")


def test_success_writes_nothing_to_stderr():
    _exit_code, _stdout, stderr = _run(json.dumps(_evidence()))

    assert stderr == ""


def test_output_key_ordering_is_deterministic():
    _exit_code, stdout, _stderr = _run(json.dumps(_evidence()))

    expected_order = [
        "conflicts_with_supplied_trust_level",
        "reason_codes",
        "recommended_trust_level",
    ]
    positions = [stdout.index(f'"{key}"') for key in expected_order]

    assert positions == sorted(positions)


def test_reason_code_ordering_is_preserved():
    payload = _evidence(source_type="unknown", trust_level="high", provenance={})

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    cli_result = json.loads(stdout)
    direct_result = assess_source_trust(payload)

    assert cli_result["reason_codes"] == direct_result["reason_codes"]


# ---------------------------------------------------------------------------
# 9-17: rejected raw input
# ---------------------------------------------------------------------------

def test_empty_input_rejected():
    exit_code, stdout, stderr = _run("")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_whitespace_only_input_rejected():
    exit_code, stdout, stderr = _run("   \n\t  ")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_malformed_json_rejected():
    exit_code, stdout, stderr = _run("{not valid json")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


@pytest.mark.parametrize("raw", ["[]", '"a string"', "42", "true", "false", "null"])
def test_non_object_json_rejected(raw):
    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_trailing_content_rejected():
    raw = json.dumps(_evidence()) + " garbage"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


# ---------------------------------------------------------------------------
# 18-22: policy validation failures surfaced as exit code 2
# ---------------------------------------------------------------------------

def test_invalid_source_type_returns_exit_code_2():
    payload = _evidence(source_type="not_a_real_type")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_invalid_assertion_type_returns_exit_code_2():
    payload = _evidence(assertion_type="not_a_real_type")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_invalid_trust_level_returns_exit_code_2():
    payload = _evidence(trust_level="definitely_not_valid")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_invalid_provenance_shape_returns_exit_code_2():
    payload = _evidence(provenance="not a mapping")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_invalid_provenance_field_type_returns_exit_code_2():
    payload = _evidence(provenance={"collector": 123})

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


# ---------------------------------------------------------------------------
# 23-27: error presentation
# ---------------------------------------------------------------------------

def test_policy_failure_writes_nothing_to_stdout():
    payload = _evidence(source_type="not_a_real_type")

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    assert stdout == ""


def test_policy_error_begins_with_expected_prefix():
    payload = _evidence(source_type="not_a_real_type")

    _exit_code, _stdout, stderr = _run(json.dumps(payload))

    assert stderr.startswith("Source trust assessment failed:")


def test_json_error_begins_with_expected_prefix():
    _exit_code, _stdout, stderr = _run("not json at all {{{")

    assert stderr.startswith("Invalid JSON input:")


def test_validation_errors_contain_no_traceback():
    payload = _evidence(source_type="not_a_real_type")

    _exit_code, _stdout, stderr = _run(json.dumps(payload))

    assert "Traceback" not in stderr


def test_json_errors_contain_no_traceback():
    _exit_code, _stdout, stderr = _run("{bad json")

    assert "Traceback" not in stderr


# ---------------------------------------------------------------------------
# 28-30: call integrity and non-mutation
# ---------------------------------------------------------------------------

def test_assess_source_trust_called_exactly_once(monkeypatch):
    calls = []
    original = source_trust_cli.assess_source_trust

    def counting_assess(evidence, **kwargs):
        calls.append(evidence)
        return original(evidence, **kwargs)

    monkeypatch.setattr(source_trust_cli, "assess_source_trust", counting_assess)

    exit_code, _stdout, _stderr = _run(json.dumps(_evidence()))

    assert exit_code == 0
    assert len(calls) == 1


def test_callers_parsed_evidence_object_not_mutated():
    payload = _evidence(provenance=_full_provenance())
    snapshot = copy.deepcopy(payload)

    _run(json.dumps(payload))

    assert payload == snapshot


def test_conflicting_supplied_trust_level_does_not_change_recommendation():
    payload = _evidence(trust_level="high", provenance={})

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert parsed["recommended_trust_level"] != "high"
    assert parsed["conflicts_with_supplied_trust_level"] is True


# ---------------------------------------------------------------------------
# 31-34: unexpected internal failure handling
# ---------------------------------------------------------------------------

def test_unexpected_internal_exception_returns_exit_code_1(monkeypatch):
    def boom(evidence, **kwargs):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(source_trust_cli, "assess_source_trust", boom)

    exit_code, _stdout, _stderr = _run(json.dumps(_evidence()))

    assert exit_code == 1


def test_unexpected_failure_writes_expected_message(monkeypatch):
    def boom(evidence, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(source_trust_cli, "assess_source_trust", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_evidence()))

    assert stderr.strip() == "Source trust assessment failed."


def test_unexpected_failure_exposes_no_exception_text(monkeypatch):
    secret_marker = "super-secret-internal-detail-xyz"

    def boom(evidence, **kwargs):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(source_trust_cli, "assess_source_trust", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_evidence()))

    assert secret_marker not in stderr
    assert "Traceback" not in stderr
    assert "RuntimeError" not in stderr


def test_unexpected_failure_exposes_no_payload_content(monkeypatch):
    payload = _evidence(source_identifier="very-unique-source-marker-12345")

    def boom(evidence, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(source_trust_cli, "assess_source_trust", boom)

    _exit_code, stdout, stderr = _run(json.dumps(payload))

    assert "very-unique-source-marker-12345" not in stdout
    assert "very-unique-source-marker-12345" not in stderr
    assert stdout == ""


# ---------------------------------------------------------------------------
# 35: no automatic trust_level update
# ---------------------------------------------------------------------------

def test_cli_performs_no_automatic_update_to_trust_level():
    payload = _evidence(trust_level="low", provenance=_full_provenance())

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert "trust_level" not in parsed
    assert "evidence" not in parsed
    assert set(parsed.keys()) == {
        "recommended_trust_level",
        "reason_codes",
        "conflicts_with_supplied_trust_level",
    }
