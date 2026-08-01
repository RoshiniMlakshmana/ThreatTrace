"""Permanent in-memory integration test for the verified ThreatTrace evidence
chain:

    core.hayabusa_evidence_cli.main
            -> core.evidence_cli.main
            -> core.source_trust_cli.main
            -> core.evidence_cli.main (again)
            -> core.source_trust_cli.main (again)

Every stage runs as a direct in-process function call using StringIO streams.
No subprocess, real file, Supabase call, Hayabusa execution, slash command,
or network access occurs anywhere in this file.
"""

import copy
import json
import socket
import subprocess
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import pytest

from core.evidence_cli import main as evidence_main
from core.hayabusa_evidence_cli import main as hayabusa_main
from core.source_trust_cli import main as trust_main

ORIGINAL_REQUEST = {
    "row": {
        "Timestamp": "2026-07-31T20:15:30Z",
        "EventID": "4104",
        "Computer": "SYNTHETIC-HOST",
        "User": "LAB\\analyst",
        "CommandLine": 'powershell.exe -NoProfile -Command "Write-Output synthetic-test"',
        "RuleTitle": "Synthetic PowerShell Observation",
        "Level": "medium",
        "ExtraColumn": "preserved",
    },
    "investigation_id": "11111111-1111-4111-8111-111111111111",
    "analysis_type": "csv_timeline",
    "source_location": "output/hayabusa/synthetic-case.csv",
    "row_identifier": "row-17",
    "evidence_type": "windows_event",
    "field_aliases": {
        "observed_at": "Timestamp",
        "event_id": "EventID",
        "host_name": "Computer",
        "user_name": "User",
        "command_line": "CommandLine",
    },
}

EXPECTED_ADVISORY = {
    "recommended_trust_level": "low",
    "reason_codes": ["INTEGRITY_NOT_RECORDED"],
    "conflicts_with_supplied_trust_level": None,
}


def _run_cli(main_fn, payload):
    """Serialize payload to JSON, run one CLI main() in-process, and return its result.

    On exit code 0: requires empty stderr, exactly one JSON value on stdout
    (json.loads rejects trailing non-whitespace content on its own), and
    that the parsed value is an object.
    """
    stdin = StringIO(json.dumps(payload))
    stdout = StringIO()
    stderr = StringIO()

    exit_code = main_fn(stdin=stdin, stdout=stdout, stderr=stderr)

    out_text = stdout.getvalue()
    err_text = stderr.getvalue()
    parsed = None

    if exit_code == 0:
        assert err_text == "", f"expected empty stderr on success, got {err_text!r}"
        parsed = json.loads(out_text)
        assert isinstance(parsed, dict), "expected exactly one JSON object on stdout"

    return exit_code, out_text, err_text, parsed


def _run_chain(request):
    original_copy = copy.deepcopy(request)

    exit1, _out1, _err1, candidate = _run_cli(hayabusa_main, request)
    exit2, _out2, _err2, normalized1 = _run_cli(evidence_main, candidate)
    exit3, _out3, _err3, advisory1 = _run_cli(trust_main, normalized1)
    exit4, _out4, _err4, normalized2 = _run_cli(evidence_main, normalized1)
    exit5, _out5, _err5, advisory2 = _run_cli(trust_main, normalized2)

    return {
        "original_request": request,
        "original_request_copy": original_copy,
        "exit_codes": (exit1, exit2, exit3, exit4, exit5),
        "candidate": candidate,
        "normalized1": normalized1,
        "advisory1": advisory1,
        "normalized2": normalized2,
        "advisory2": advisory2,
    }


@pytest.fixture(scope="module")
def chain_result():
    request = copy.deepcopy(ORIGINAL_REQUEST)
    return _run_chain(request)


def _parse_utc_z(text):
    assert isinstance(text, str) and text.endswith("Z")
    parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(None)
    return parsed


# ---------------------------------------------------------------------------
# 1-3: chain-level success
# ---------------------------------------------------------------------------

def test_01_complete_chain_succeeds(chain_result):
    assert chain_result["candidate"] is not None
    assert chain_result["normalized1"] is not None
    assert chain_result["advisory1"] is not None
    assert chain_result["normalized2"] is not None
    assert chain_result["advisory2"] is not None


def test_02_all_five_exit_codes_are_zero(chain_result):
    assert chain_result["exit_codes"] == (0, 0, 0, 0, 0)


def test_03_all_five_successful_calls_write_empty_stderr(chain_result):
    # Enforced inside _run_cli for every stage that produced a result;
    # re-assert here that every stage actually reached a parsed result.
    for key in ("candidate", "normalized1", "advisory1", "normalized2", "advisory2"):
        assert chain_result[key] is not None


# ---------------------------------------------------------------------------
# 4-14: candidate field checks
# ---------------------------------------------------------------------------

def test_04_candidate_source(chain_result):
    assert chain_result["candidate"]["source"] == "Hayabusa csv_timeline row"


def test_05_candidate_source_type(chain_result):
    assert chain_result["candidate"]["source_type"] == "hayabusa"


def test_06_candidate_source_identifier(chain_result):
    assert chain_result["candidate"]["source_identifier"] == "row-17"


def test_07_candidate_source_location_is_project_relative(chain_result):
    source_location = chain_result["candidate"]["source_location"]
    assert source_location == "output/hayabusa/synthetic-case.csv"
    assert not source_location.startswith("/")
    assert ":" not in source_location


def test_08_candidate_assertion_type(chain_result):
    assert chain_result["candidate"]["assertion_type"] == "derived_fact"


def test_09_candidate_observed_at(chain_result):
    assert chain_result["candidate"]["observed_at"] == "2026-07-31T20:15:30Z"


def test_10_candidate_event_id(chain_result):
    assert chain_result["candidate"]["event_id"] == "4104"


def test_11_candidate_host_name(chain_result):
    assert chain_result["candidate"]["host_name"] == "SYNTHETIC-HOST"


def test_12_candidate_user_name(chain_result):
    assert chain_result["candidate"]["user_name"] == "LAB\\analyst"


def test_13_candidate_command_line(chain_result):
    assert chain_result["candidate"]["command_line"] == ORIGINAL_REQUEST["row"]["CommandLine"]


def test_14_candidate_supports_hypothesis_is_none(chain_result):
    assert chain_result["candidate"]["supports_hypothesis"] is None


# ---------------------------------------------------------------------------
# 15-21: forbidden/unpromoted candidate fields
# ---------------------------------------------------------------------------

def test_15_candidate_contains_no_trust_level(chain_result):
    assert "trust_level" not in chain_result["candidate"]


def test_16_candidate_contains_no_confidence(chain_result):
    assert "confidence" not in chain_result["candidate"]


def test_17_candidate_contains_no_integrity_verified(chain_result):
    assert "integrity_verified" not in chain_result["candidate"]
    assert "integrity_verified" not in chain_result["candidate"]["provenance"]


def test_18_only_explicitly_aliased_fields_promoted(chain_result):
    candidate = chain_result["candidate"]
    for field in ("process_name", "ip_address", "file_hash"):
        assert field not in candidate


def test_19_rule_title_not_promoted(chain_result):
    assert "RuleTitle" not in chain_result["candidate"]
    assert "rule_title" not in chain_result["candidate"]


def test_20_level_not_promoted(chain_result):
    assert "Level" not in chain_result["candidate"]
    assert "level" not in chain_result["candidate"]


def test_21_extra_column_not_promoted(chain_result):
    assert "ExtraColumn" not in chain_result["candidate"]
    assert "extra_column" not in chain_result["candidate"]


# ---------------------------------------------------------------------------
# 22-25: candidate provenance
# ---------------------------------------------------------------------------

def test_22_candidate_provenance_has_exactly_required_keys(chain_result):
    assert set(chain_result["candidate"]["provenance"].keys()) == {
        "collector",
        "collection_method",
        "source_reference",
        "transformation_steps",
    }


def test_23_provenance_collector(chain_result):
    assert chain_result["candidate"]["provenance"]["collector"] == "threattrace.hayabusa_evidence_adapter"


def test_24_provenance_collection_method(chain_result):
    assert chain_result["candidate"]["provenance"]["collection_method"] == "hayabusa:csv_timeline"


def test_25_provenance_source_reference(chain_result):
    assert (
        chain_result["candidate"]["provenance"]["source_reference"]
        == "output/hayabusa/synthetic-case.csv#row=row-17"
    )


# ---------------------------------------------------------------------------
# 26-37: first normalization
# ---------------------------------------------------------------------------

def test_26_first_normalization_defaults_trust_level(chain_result):
    assert chain_result["normalized1"]["trust_level"] == "unknown"


def test_27_first_normalization_defaults_confidence(chain_result):
    assert chain_result["normalized1"]["confidence"] == "unknown"


def test_28_first_normalization_creates_ingested_at(chain_result):
    assert "ingested_at" in chain_result["normalized1"]
    assert chain_result["normalized1"]["ingested_at"]


def test_29_ingested_at_is_string_ending_in_z(chain_result):
    ingested_at = chain_result["normalized1"]["ingested_at"]
    assert isinstance(ingested_at, str)
    assert ingested_at.endswith("Z")


def test_30_ingested_at_parses_as_aware_utc(chain_result):
    _parse_utc_z(chain_result["normalized1"]["ingested_at"])


def test_31_observed_at_unchanged_after_normalization(chain_result):
    assert chain_result["normalized1"]["observed_at"] == "2026-07-31T20:15:30Z"


def test_32_event_id_remains_4104(chain_result):
    assert chain_result["normalized1"]["event_id"] == "4104"


def test_33_assertion_type_remains_derived_fact(chain_result):
    assert chain_result["normalized1"]["assertion_type"] == "derived_fact"


def test_34_source_location_remains_unchanged(chain_result):
    assert chain_result["normalized1"]["source_location"] == "output/hayabusa/synthetic-case.csv"


def test_35_process_name_is_none(chain_result):
    assert chain_result["normalized1"]["process_name"] is None


def test_36_ip_address_is_none(chain_result):
    assert chain_result["normalized1"]["ip_address"] is None


def test_37_file_hash_is_none(chain_result):
    assert chain_result["normalized1"]["file_hash"] is None


# ---------------------------------------------------------------------------
# 38: first source-trust result
# ---------------------------------------------------------------------------

def test_38_first_source_trust_result_matches_exactly(chain_result):
    assert chain_result["advisory1"] == EXPECTED_ADVISORY


# ---------------------------------------------------------------------------
# 39-41: second pass equivalence
# ---------------------------------------------------------------------------

def test_39_second_normalized_object_equals_first(chain_result):
    assert chain_result["normalized2"] == chain_result["normalized1"]


def test_40_ingested_at_identical_across_both_passes(chain_result):
    assert chain_result["normalized2"]["ingested_at"] == chain_result["normalized1"]["ingested_at"]


def test_41_second_source_trust_result_equals_first(chain_result):
    assert chain_result["advisory2"] == chain_result["advisory1"]


# ---------------------------------------------------------------------------
# 42-45: original row survival
# ---------------------------------------------------------------------------

def test_42_complete_original_row_survives(chain_result):
    assert chain_result["normalized2"]["details"]["hayabusa_row"] == ORIGINAL_REQUEST["row"]


def test_43_rule_title_survives_unchanged(chain_result):
    assert (
        chain_result["normalized2"]["details"]["hayabusa_row"]["RuleTitle"]
        == ORIGINAL_REQUEST["row"]["RuleTitle"]
    )


def test_44_level_survives_unchanged(chain_result):
    assert chain_result["normalized2"]["details"]["hayabusa_row"]["Level"] == ORIGINAL_REQUEST["row"]["Level"]


def test_45_extra_column_survives_unchanged(chain_result):
    assert (
        chain_result["normalized2"]["details"]["hayabusa_row"]["ExtraColumn"]
        == ORIGINAL_REQUEST["row"]["ExtraColumn"]
    )


# ---------------------------------------------------------------------------
# 46-48: input non-mutation
# ---------------------------------------------------------------------------

def test_46_original_request_remains_unchanged(chain_result):
    assert chain_result["original_request"] == chain_result["original_request_copy"]


def test_47_nested_original_row_remains_unchanged(chain_result):
    assert chain_result["original_request"]["row"] == chain_result["original_request_copy"]["row"]


def test_48_field_aliases_remain_unchanged(chain_result):
    assert (
        chain_result["original_request"]["field_aliases"]
        == chain_result["original_request_copy"]["field_aliases"]
    )


# ---------------------------------------------------------------------------
# 49-52: forbidden field categories across every output
# ---------------------------------------------------------------------------

def _all_outputs(chain_result):
    return [
        chain_result["candidate"],
        chain_result["normalized1"],
        chain_result["advisory1"],
        chain_result["normalized2"],
        chain_result["advisory2"],
    ]


def test_49_no_output_contains_attack_mapping_fields(chain_result):
    for output in _all_outputs(chain_result):
        assert not any("attack" in str(key).lower() or "technique" in str(key).lower() for key in output)


def test_50_no_output_contains_evidence_hash(chain_result):
    for output in _all_outputs(chain_result):
        assert "evidence_hash" not in output


def test_51_no_output_contains_approval_fields(chain_result):
    for output in _all_outputs(chain_result):
        assert not any("approval" in str(key).lower() or "reviewer" in str(key).lower() for key in output)


def test_52_no_output_contains_audit_fields(chain_result):
    for output in _all_outputs(chain_result):
        assert not any("audit" in str(key).lower() for key in output)


# ---------------------------------------------------------------------------
# Runtime-boundary guard: forbidden entry points must never be reached
# ---------------------------------------------------------------------------

def test_chain_never_touches_forbidden_entry_points(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during the evidence chain")

    # Import optional third-party modules *before* patching socket.socket:
    # some of them (e.g. requests -> urllib3 -> PySocks) subclass
    # socket.socket at import time, which would break if the class were
    # already replaced with a plain forbidden callable.
    import urllib.request

    try:
        import requests
    except ImportError:
        requests = None

    try:
        import supabase
    except ImportError:
        supabase = None

    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr(Path, "open", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)

    if requests is not None:
        monkeypatch.setattr(requests, "get", _forbidden)
        monkeypatch.setattr(requests, "post", _forbidden)

    if supabase is not None and hasattr(supabase, "create_client"):
        monkeypatch.setattr(supabase, "create_client", _forbidden)

    assert "mcp.hayabusa_server" not in sys.modules

    request = copy.deepcopy(ORIGINAL_REQUEST)
    guarded_result = _run_chain(request)

    assert guarded_result["exit_codes"] == (0, 0, 0, 0, 0)
    assert "mcp.hayabusa_server" not in sys.modules
