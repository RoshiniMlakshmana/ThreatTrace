"""Tests for core.hayabusa_evidence_cli -- the stdin/stdout JSON adapter
around core.hayabusa_evidence_adapter.adapt_hayabusa_row.

main() is called directly with in-memory StringIO streams. No external
process, CSV/EVTX file, Supabase call, Hayabusa run, or network access
occurs anywhere in this file.
"""

import copy
import json
from io import StringIO

import pytest

from core import hayabusa_evidence_cli
import core.evidence_normalizer as evidence_normalizer
import core.source_trust_policy as source_trust_policy


def _row(**overrides):
    row = {
        "EventID": "4104",
        "Computer": "WIN-HOST",
        "CommandLine": "powershell -enc ...",
        "SomeOtherColumn": "unmapped value",
    }
    row.update(overrides)
    return row


def _request(**overrides):
    request = {
        "row": _row(),
        "investigation_id": "inv-1",
        "analysis_type": "csv_timeline",
        "source_location": "output/hayabusa/case-001.csv",
        "row_identifier": "row-42",
        "evidence_type": "windows_event",
    }
    request.update(overrides)
    return request


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = hayabusa_evidence_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


# ---------------------------------------------------------------------------
# 1-10: successful requests
# ---------------------------------------------------------------------------

def test_valid_request_returns_exit_code_0():
    exit_code, _stdout, _stderr = _run(json.dumps(_request()))

    assert exit_code == 0


def test_successful_stdout_contains_valid_json():
    _exit_code, stdout, _stderr = _run(json.dumps(_request()))

    json.loads(stdout)


def test_successful_output_is_an_object():
    _exit_code, stdout, _stderr = _run(json.dumps(_request()))

    assert isinstance(json.loads(stdout), dict)


def test_successful_output_ends_with_exactly_one_newline():
    _exit_code, stdout, _stderr = _run(json.dumps(_request()))

    assert stdout.endswith("\n")
    assert not stdout.endswith("\n\n")


def test_success_writes_nothing_to_stderr():
    _exit_code, _stdout, stderr = _run(json.dumps(_request()))

    assert stderr == ""


def test_output_ordering_is_deterministic():
    _exit_code, stdout, _stderr = _run(json.dumps(_request()))

    parsed = json.loads(stdout)
    assert list(parsed.keys()) == sorted(parsed.keys())


def test_unicode_row_values_are_preserved():
    request = _request(row=_row(Computer="café-hôte-注意"))

    _exit_code, stdout, _stderr = _run(json.dumps(request))

    parsed = json.loads(stdout)
    assert parsed["details"]["hayabusa_row"]["Computer"] == "café-hôte-注意"
    assert "\\u" not in stdout


def test_complete_original_row_preserved_in_details():
    request = _request()

    _exit_code, stdout, _stderr = _run(json.dumps(request))

    parsed = json.loads(stdout)
    assert parsed["details"]["hayabusa_row"] == request["row"]


def test_explicit_aliases_promote_only_selected_fields():
    request = _request(field_aliases={"event_id": "EventID", "host_name": "Computer"})

    _exit_code, stdout, _stderr = _run(json.dumps(request))

    parsed = json.loads(stdout)
    assert parsed["event_id"] == "4104"
    assert parsed["host_name"] == "WIN-HOST"
    assert "command_line" not in parsed


def test_no_field_promoted_without_an_alias():
    request = _request()
    request.pop("field_aliases", None)

    _exit_code, stdout, _stderr = _run(json.dumps(request))

    parsed = json.loads(stdout)
    for field in ("event_id", "host_name", "user_name", "process_name", "command_line", "ip_address", "file_hash"):
        assert field not in parsed


# ---------------------------------------------------------------------------
# 11-19: rejected raw input
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
    raw = json.dumps(_request()) + " garbage"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


# ---------------------------------------------------------------------------
# 20-26: request-envelope structural validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "field",
    ["row", "investigation_id", "analysis_type", "source_location", "row_identifier", "evidence_type"],
)
def test_missing_required_field_rejected(field):
    request = _request()
    del request[field]

    exit_code, stdout, stderr = _run(json.dumps(request))

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_unknown_request_field_rejected():
    request = _request(totally_unknown_field="x")

    exit_code, stdout, stderr = _run(json.dumps(request))

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


# ---------------------------------------------------------------------------
# 27-31: adapter validation failures surfaced as exit code 2
# ---------------------------------------------------------------------------

def test_non_mapping_row_returns_exit_code_2():
    request = _request(row=["not", "a", "mapping"])

    exit_code, _stdout, _stderr = _run(json.dumps(request))

    assert exit_code == 2


def test_log_metrics_returns_exit_code_2():
    request = _request(analysis_type="log_metrics")

    exit_code, _stdout, _stderr = _run(json.dumps(request))

    assert exit_code == 2


def test_eid_metrics_returns_exit_code_2():
    request = _request(analysis_type="eid_metrics")

    exit_code, _stdout, _stderr = _run(json.dumps(request))

    assert exit_code == 2


def test_invalid_source_path_returns_exit_code_2():
    request = _request(source_location="/etc/case.csv")

    exit_code, _stdout, _stderr = _run(json.dumps(request))

    assert exit_code == 2


def test_invalid_field_alias_returns_exit_code_2():
    request = _request(field_aliases={"event_id": "DoesNotExist"})

    exit_code, _stdout, _stderr = _run(json.dumps(request))

    assert exit_code == 2


# ---------------------------------------------------------------------------
# 32-36: error presentation
# ---------------------------------------------------------------------------

def test_adapter_validation_failure_writes_nothing_to_stdout():
    request = _request(analysis_type="log_metrics")

    _exit_code, stdout, _stderr = _run(json.dumps(request))

    assert stdout == ""


def test_adapter_error_begins_with_expected_prefix():
    request = _request(analysis_type="log_metrics")

    _exit_code, _stdout, stderr = _run(json.dumps(request))

    assert stderr.startswith("Hayabusa evidence adaptation failed:")


def test_invalid_request_error_begins_with_expected_prefix():
    _exit_code, _stdout, stderr = _run("not json at all {{{")

    assert stderr.startswith("Invalid JSON input:")


def test_validation_errors_contain_no_traceback():
    request = _request(analysis_type="log_metrics")

    _exit_code, _stdout, stderr = _run(json.dumps(request))

    assert "Traceback" not in stderr


def test_json_errors_contain_no_traceback():
    _exit_code, _stdout, stderr = _run("{bad json")

    assert "Traceback" not in stderr


# ---------------------------------------------------------------------------
# 37-38: call integrity and non-mutation
# ---------------------------------------------------------------------------

def test_adapt_hayabusa_row_called_exactly_once(monkeypatch):
    calls = []
    original = hayabusa_evidence_cli.adapt_hayabusa_row

    def counting_adapt(row, **kwargs):
        calls.append((row, kwargs))
        return original(row, **kwargs)

    monkeypatch.setattr(hayabusa_evidence_cli, "adapt_hayabusa_row", counting_adapt)

    exit_code, _stdout, _stderr = _run(json.dumps(_request()))

    assert exit_code == 0
    assert len(calls) == 1


def test_parsed_request_and_nested_row_not_mutated():
    request = _request()
    snapshot = copy.deepcopy(request)

    _run(json.dumps(request))

    assert request == snapshot


# ---------------------------------------------------------------------------
# 39-43: unexpected internal failure handling
# ---------------------------------------------------------------------------

def test_unexpected_exception_returns_exit_code_1(monkeypatch):
    def boom(row, **kwargs):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(hayabusa_evidence_cli, "adapt_hayabusa_row", boom)

    exit_code, _stdout, _stderr = _run(json.dumps(_request()))

    assert exit_code == 1


def test_unexpected_failure_writes_expected_message(monkeypatch):
    def boom(row, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(hayabusa_evidence_cli, "adapt_hayabusa_row", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_request()))

    assert stderr.strip() == "Hayabusa evidence adaptation failed."


def test_unexpected_failure_exposes_no_exception_text(monkeypatch):
    secret_marker = "super-secret-internal-detail-xyz"

    def boom(row, **kwargs):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(hayabusa_evidence_cli, "adapt_hayabusa_row", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_request()))

    assert secret_marker not in stderr
    assert "Traceback" not in stderr
    assert "RuntimeError" not in stderr


def test_unexpected_failure_exposes_no_selected_row_value(monkeypatch):
    request = _request(row=_row(Computer="very-unique-host-marker-12345"))

    def boom(row, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(hayabusa_evidence_cli, "adapt_hayabusa_row", boom)

    _exit_code, stdout, stderr = _run(json.dumps(request))

    assert "very-unique-host-marker-12345" not in stdout
    assert "very-unique-host-marker-12345" not in stderr
    assert stdout == ""


def test_unexpected_failure_exposes_no_local_path(monkeypatch):
    def boom(row, **kwargs):
        raise RuntimeError(r"failure near C:\Users\someone\secret\path")

    monkeypatch.setattr(hayabusa_evidence_cli, "adapt_hayabusa_row", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_request()))

    assert "C:\\Users" not in stderr
    assert "someone" not in stderr


# ---------------------------------------------------------------------------
# 44-48: no forbidden fields in output
# ---------------------------------------------------------------------------

def test_output_contains_no_trust_level():
    _exit_code, stdout, _stderr = _run(json.dumps(_request()))

    assert "trust_level" not in json.loads(stdout)


def test_output_contains_no_confidence():
    _exit_code, stdout, _stderr = _run(json.dumps(_request()))

    assert "confidence" not in json.loads(stdout)


def test_output_contains_no_attack_mapping():
    _exit_code, stdout, _stderr = _run(json.dumps(_request()))

    parsed = json.loads(stdout)
    assert not any("attack" in key.lower() or "technique" in key.lower() for key in parsed)


def test_output_contains_no_evidence_hash():
    _exit_code, stdout, _stderr = _run(json.dumps(_request()))

    parsed = json.loads(stdout)
    assert "evidence_hash" not in parsed
    assert "hash" not in parsed


def test_output_contains_no_approval_or_audit_field():
    _exit_code, stdout, _stderr = _run(json.dumps(_request()))

    parsed = json.loads(stdout)
    forbidden_substrings = ("approval", "reviewer", "audit", "action_hash", "expiry")
    assert not any(
        substring in key.lower() for key in parsed for substring in forbidden_substrings
    )


# ---------------------------------------------------------------------------
# 49-50: normalization and trust assessment are never invoked
# ---------------------------------------------------------------------------

def test_no_normalization_function_is_called(monkeypatch):
    def forbidden_normalize(*args, **kwargs):
        raise AssertionError("normalize_evidence must not be called by the Hayabusa evidence CLI")

    monkeypatch.setattr(evidence_normalizer, "normalize_evidence", forbidden_normalize)

    exit_code, _stdout, _stderr = _run(json.dumps(_request()))

    assert exit_code == 0


def test_no_trust_assessment_function_is_called(monkeypatch):
    def forbidden_assess(*args, **kwargs):
        raise AssertionError("assess_source_trust must not be called by the Hayabusa evidence CLI")

    monkeypatch.setattr(source_trust_policy, "assess_source_trust", forbidden_assess)

    exit_code, _stdout, _stderr = _run(json.dumps(_request()))

    assert exit_code == 0


# ---------------------------------------------------------------------------
# 51-53: no file, Supabase, subprocess, Hayabusa, or network access
# ---------------------------------------------------------------------------

def _module_source_text():
    import core.hayabusa_evidence_cli as module

    with open(module.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def test_no_file_access_occurs():
    source = _module_source_text()

    assert "open(" not in source
    assert "os.path" not in source
    assert "pathlib" not in source
    assert "Path(" not in source


def test_no_supabase_access_occurs():
    source = _module_source_text()

    assert "import supabase" not in source.lower()
    assert "from supabase" not in source.lower()
    assert "mcp__supabase" not in source.lower()


def test_no_subprocess_hayabusa_or_network_action_occurs():
    source = _module_source_text()

    assert "subprocess" not in source
    assert "socket" not in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "hayabusa_server" not in source.lower()
