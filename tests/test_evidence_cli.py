"""Tests for core.evidence_cli -- the stdin/stdout JSON adapter around
core.evidence_normalizer.normalize_evidence.

main() is called directly with in-memory StringIO streams. No external
process, Supabase call, Hayabusa run, or network access occurs anywhere
in this file.
"""

import copy
import json
from io import StringIO

import pytest

from core import evidence_cli


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = evidence_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _minimal_payload(**overrides):
    payload = {
        "investigation_id": "inv-1",
        "evidence_type": "note",
        "source": "analyst",
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# 1-2: successful runs
# ---------------------------------------------------------------------------

def test_valid_analyst_payload_returns_exit_code_0():
    payload = _minimal_payload(source_type="analyst", assertion_type="observation")

    exit_code, stdout, stderr = _run(json.dumps(payload))

    assert exit_code == 0


def test_valid_hayabusa_payload_returns_exit_code_0():
    payload = _minimal_payload(source_type="hayabusa", event_id=4688)

    exit_code, stdout, stderr = _run(json.dumps(payload))

    assert exit_code == 0


# ---------------------------------------------------------------------------
# 3-7: success output shape
# ---------------------------------------------------------------------------

def test_successful_output_is_valid_json():
    _exit_code, stdout, _stderr = _run(json.dumps(_minimal_payload()))

    parsed = json.loads(stdout)

    assert isinstance(parsed, dict)


def test_successful_output_ends_with_exactly_one_newline():
    _exit_code, stdout, _stderr = _run(json.dumps(_minimal_payload()))

    assert stdout.endswith("\n")
    assert not stdout.endswith("\n\n")


def test_successful_execution_writes_nothing_to_stderr():
    _exit_code, _stdout, stderr = _run(json.dumps(_minimal_payload()))

    assert stderr == ""


def test_output_uses_deterministic_key_ordering():
    _exit_code, stdout, _stderr = _run(json.dumps(_minimal_payload()))

    parsed = json.loads(stdout)

    assert list(parsed.keys()) == sorted(parsed.keys())


def test_unicode_evidence_values_preserved():
    payload = _minimal_payload(source="café analyst 注意")

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert parsed["source"] == payload["source"]
    assert "\\u" not in stdout


# ---------------------------------------------------------------------------
# 8-16: rejected raw input
# ---------------------------------------------------------------------------

def test_empty_stdin_rejected():
    exit_code, stdout, stderr = _run("")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_whitespace_only_stdin_rejected():
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


def test_extra_content_after_json_object_rejected():
    raw = json.dumps(_minimal_payload()) + " garbage"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


# ---------------------------------------------------------------------------
# 17-19: normalize_evidence rejections surfaced as exit code 2
# ---------------------------------------------------------------------------

def test_missing_required_field_returns_exit_code_2():
    payload = _minimal_payload()
    del payload["source"]

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_invalid_controlled_vocabulary_returns_exit_code_2():
    payload = _minimal_payload(trust_level="not_real")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_invalid_timestamp_returns_exit_code_2():
    payload = _minimal_payload(observed_at="not-a-timestamp")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


# ---------------------------------------------------------------------------
# 20-24: validation/JSON error presentation
# ---------------------------------------------------------------------------

def test_validation_failure_writes_nothing_to_stdout():
    payload = _minimal_payload()
    del payload["evidence_type"]

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    assert stdout == ""


def test_validation_error_begins_with_expected_prefix():
    payload = _minimal_payload()
    del payload["evidence_type"]

    _exit_code, _stdout, stderr = _run(json.dumps(payload))

    assert stderr.startswith("Evidence validation failed:")


def test_invalid_json_error_begins_with_expected_prefix():
    _exit_code, _stdout, stderr = _run("not json at all {{{")

    assert stderr.startswith("Invalid JSON input:")


def test_validation_errors_do_not_include_traceback():
    payload = _minimal_payload()
    del payload["source"]

    _exit_code, _stdout, stderr = _run(json.dumps(payload))

    assert "Traceback" not in stderr


def test_json_errors_do_not_include_traceback():
    _exit_code, _stdout, stderr = _run("{bad json")

    assert "Traceback" not in stderr


# ---------------------------------------------------------------------------
# 25-27: rejected top-level fields
# ---------------------------------------------------------------------------

def test_unknown_top_level_fields_rejected():
    payload = _minimal_payload(totally_unknown_field="x")

    exit_code, _stdout, stderr = _run(json.dumps(payload))

    assert exit_code == 2
    assert stderr.startswith("Evidence validation failed:")


def test_id_field_rejected():
    payload = _minimal_payload(id="should-not-be-here")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_created_at_field_rejected():
    payload = _minimal_payload(created_at="2024-01-01T00:00:00Z")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


# ---------------------------------------------------------------------------
# 28-29: input integrity and single normalization call
# ---------------------------------------------------------------------------

def test_callers_input_object_not_modified():
    payload = _minimal_payload(details={"a": 1})
    snapshot = copy.deepcopy(payload)

    _run(json.dumps(payload))

    assert payload == snapshot


def test_normalize_evidence_called_exactly_once(monkeypatch):
    calls = []
    original = evidence_cli.normalize_evidence

    def counting_normalize(payload, **kwargs):
        calls.append(payload)
        return original(payload, **kwargs)

    monkeypatch.setattr(evidence_cli, "normalize_evidence", counting_normalize)

    exit_code, _stdout, _stderr = _run(json.dumps(_minimal_payload()))

    assert exit_code == 0
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# 30-33: unexpected internal failure handling
# ---------------------------------------------------------------------------

def test_unexpected_internal_exception_returns_exit_code_1(monkeypatch):
    def boom(payload, **kwargs):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(evidence_cli, "normalize_evidence", boom)

    exit_code, _stdout, _stderr = _run(json.dumps(_minimal_payload()))

    assert exit_code == 1


def test_unexpected_failure_writes_expected_message(monkeypatch):
    def boom(payload, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(evidence_cli, "normalize_evidence", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_minimal_payload()))

    assert stderr.strip() == "Evidence normalization failed."


def test_unexpected_failure_does_not_expose_exception_text(monkeypatch):
    secret_marker = "super-secret-internal-detail-xyz"

    def boom(payload, **kwargs):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(evidence_cli, "normalize_evidence", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_minimal_payload()))

    assert secret_marker not in stderr
    assert "Traceback" not in stderr
    assert "RuntimeError" not in stderr


def test_unexpected_failure_does_not_print_payload_contents(monkeypatch):
    payload = _minimal_payload(source="very-unique-source-marker-12345")

    def boom(payload_arg, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(evidence_cli, "normalize_evidence", boom)

    _exit_code, stdout, stderr = _run(json.dumps(payload))

    assert "very-unique-source-marker-12345" not in stdout
    assert "very-unique-source-marker-12345" not in stderr
    assert stdout == ""
