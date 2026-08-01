"""Tests for core.hayabusa_evidence_adapter -- converting one already-selected
Hayabusa csv_timeline row into an unnormalized evidence candidate.

No file reading, CSV parsing, Supabase access, Hayabusa execution, subprocess
call, or network access occurs anywhere in this file; every input is a plain
in-memory mapping.
"""

import copy

import pytest

from core.hayabusa_evidence_adapter import (
    HayabusaEvidenceAdapterError,
    adapt_hayabusa_row,
)


def _row(**overrides):
    row = {
        "EventID": "4104",
        "Computer": "WIN-HOST",
        "User": "alice",
        "CommandLine": "powershell -enc ...",
        "IpAddress": "10.0.0.5",
        "FileHash": "ABCDEF1234",
        "Timestamp": "2024-01-01T00:00:00Z",
        "SomeOtherColumn": "unmapped value",
    }
    row.update(overrides)
    return row


def _aliases(**overrides):
    aliases = {
        "event_id": "EventID",
        "host_name": "Computer",
        "user_name": "User",
        "command_line": "CommandLine",
        "ip_address": "IpAddress",
        "file_hash": "FileHash",
    }
    aliases.update(overrides)
    return aliases


def _call(**overrides):
    kwargs = dict(
        row=_row(),
        investigation_id="inv-1",
        analysis_type="csv_timeline",
        source_location="output/hayabusa/case-001.csv",
        row_identifier="row-42",
        evidence_type="windows_event",
    )
    kwargs.update(overrides)
    return adapt_hayabusa_row(**kwargs)


# ---------------------------------------------------------------------------
# 1-7: baseline candidate shape
# ---------------------------------------------------------------------------

def test_valid_csv_timeline_row_creates_a_candidate():
    result = _call(field_aliases=_aliases())

    assert isinstance(result, dict)
    assert result["investigation_id"] == "inv-1"
    assert result["evidence_type"] == "windows_event"


def test_fixed_source_is_correct():
    result = _call()

    assert result["source"] == "Hayabusa csv_timeline row"


def test_source_type_is_hayabusa():
    result = _call()

    assert result["source_type"] == "hayabusa"


def test_assertion_type_is_derived_fact():
    result = _call()

    assert result["assertion_type"] == "derived_fact"


def test_source_identifier_uses_row_identifier():
    result = _call(row_identifier="row-99")

    assert result["source_identifier"] == "row-99"


def test_valid_project_relative_csv_path_accepted():
    result = _call(source_location="output/hayabusa/case-001.csv")

    assert result["source_location"] == "output/hayabusa/case-001.csv"


def test_backslashes_normalized_to_forward_slashes():
    result = _call(source_location="output\\hayabusa\\case-001.csv")

    assert result["source_location"] == "output/hayabusa/case-001.csv"


# ---------------------------------------------------------------------------
# 8-21: required argument and source_location validation
# ---------------------------------------------------------------------------

def test_blank_investigation_id_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(investigation_id="   ")


def test_blank_row_identifier_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(row_identifier="")


def test_blank_evidence_type_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(evidence_type="  ")


def test_blank_source_location_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(source_location="")


def test_non_mapping_row_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(row=["not", "a", "mapping"])


def test_log_metrics_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(analysis_type="log_metrics")


def test_eid_metrics_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(analysis_type="eid_metrics")


def test_unknown_analysis_type_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(analysis_type="bogus_type")


def test_absolute_windows_path_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(source_location=r"C:\Users\analyst\case.csv")


def test_absolute_unix_path_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(source_location="/etc/case.csv")


def test_unc_path_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(source_location=r"\\server\share\case.csv")


def test_drive_qualified_path_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(source_location="D:relative.csv")


def test_parent_traversal_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(source_location="output/../case.csv")


def test_non_csv_source_location_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(source_location="output/hayabusa/case.txt")


# ---------------------------------------------------------------------------
# 22-26: field_aliases validation
# ---------------------------------------------------------------------------

def test_field_aliases_must_be_a_mapping():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(field_aliases="not a mapping")


def test_unsupported_alias_key_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(field_aliases={"trust_level": "SomeColumn"})


def test_blank_alias_column_name_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(field_aliases={"event_id": "   "})


def test_missing_aliased_csv_column_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(field_aliases={"event_id": "DoesNotExist"})


def test_duplicate_csv_column_assignment_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(field_aliases={"event_id": "EventID", "host_name": "EventID"})


# ---------------------------------------------------------------------------
# 27-34: aliased field copying
# ---------------------------------------------------------------------------

def test_explicit_event_id_copied():
    result = _call(field_aliases={"event_id": "EventID"})

    assert result["event_id"] == "4104"


def test_numeric_event_id_becomes_a_string():
    result = _call(row=_row(EventID=4104), field_aliases={"event_id": "EventID"})

    assert result["event_id"] == "4104"


def test_explicit_host_name_copied():
    result = _call(field_aliases={"host_name": "Computer"})

    assert result["host_name"] == "WIN-HOST"


def test_explicit_command_line_copied():
    result = _call(field_aliases={"command_line": "CommandLine"})

    assert result["command_line"] == "powershell -enc ..."


def test_explicit_file_hash_lowercased():
    result = _call(field_aliases={"file_hash": "FileHash"})

    assert result["file_hash"] == "abcdef1234"


def test_unknown_csv_columns_remain_in_details_hayabusa_row():
    result = _call()

    assert result["details"]["hayabusa_row"]["SomeOtherColumn"] == "unmapped value"
    assert result["details"]["hayabusa_row"]["EventID"] == "4104"


def test_no_field_promoted_without_explicit_alias():
    result = _call(field_aliases=None)

    for field in ("event_id", "host_name", "user_name", "process_name", "command_line", "ip_address", "file_hash"):
        assert field not in result


def test_blank_aliased_strings_become_none():
    result = _call(row=_row(User="   "), field_aliases={"user_name": "User"})

    assert result["user_name"] is None


# ---------------------------------------------------------------------------
# 35-37: observed_at handling
# ---------------------------------------------------------------------------

def test_direct_observed_at_is_copied():
    result = _call(observed_at="2024-02-02T00:00:00Z")

    assert result["observed_at"] == "2024-02-02T00:00:00Z"


def test_aliased_observed_at_is_copied():
    result = _call(field_aliases={"observed_at": "Timestamp"})

    assert result["observed_at"] == "2024-01-01T00:00:00Z"


def test_direct_and_aliased_observed_at_together_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(observed_at="2024-02-02T00:00:00Z", field_aliases={"observed_at": "Timestamp"})


# ---------------------------------------------------------------------------
# 38-41: supports_hypothesis
# ---------------------------------------------------------------------------

def test_supports_hypothesis_accepts_true():
    result = _call(supports_hypothesis=True)

    assert result["supports_hypothesis"] is True


def test_supports_hypothesis_accepts_false():
    result = _call(supports_hypothesis=False)

    assert result["supports_hypothesis"] is False


def test_supports_hypothesis_accepts_none():
    result = _call(supports_hypothesis=None)

    assert result["supports_hypothesis"] is None


def test_invalid_supports_hypothesis_rejected():
    with pytest.raises(HayabusaEvidenceAdapterError):
        _call(supports_hypothesis="true")


# ---------------------------------------------------------------------------
# 42-45: purity and determinism
# ---------------------------------------------------------------------------

def test_original_row_not_mutated():
    row = _row()
    snapshot = copy.deepcopy(row)

    _call(row=row, field_aliases=_aliases())

    assert row == snapshot


def test_nested_row_values_independently_copied():
    row = _row(Nested={"inner": "value"})
    result = _call(row=row)

    result["details"]["hayabusa_row"]["Nested"]["inner"] = "mutated"

    assert row["Nested"]["inner"] == "value"


def test_field_aliases_not_mutated():
    aliases = _aliases()
    snapshot = copy.deepcopy(aliases)

    _call(field_aliases=aliases)

    assert aliases == snapshot


def test_output_deterministic_for_identical_input():
    first = _call(field_aliases=_aliases(), observed_at=None)
    second = _call(field_aliases=_aliases(), observed_at=None)

    assert first == second


# ---------------------------------------------------------------------------
# 46-51: no forbidden fields
# ---------------------------------------------------------------------------

def test_provenance_has_exactly_required_keys():
    result = _call()

    assert set(result["provenance"].keys()) == {
        "collector",
        "collection_method",
        "source_reference",
        "transformation_steps",
    }


def test_provenance_does_not_include_integrity_verified():
    result = _call()

    assert "integrity_verified" not in result["provenance"]


def test_output_contains_no_trust_level():
    result = _call()

    assert "trust_level" not in result


def test_output_contains_no_confidence():
    result = _call()

    assert "confidence" not in result


def test_output_contains_no_attack_mapping():
    result = _call()

    assert not any("attack" in key.lower() or "technique" in key.lower() for key in result)


def test_output_contains_no_evidence_hash():
    result = _call()

    assert "evidence_hash" not in result
    assert "hash" not in result


# ---------------------------------------------------------------------------
# 52-54: no filesystem, Supabase, subprocess, or network access
# ---------------------------------------------------------------------------

def _module_source_text():
    import core.hayabusa_evidence_adapter as module

    with open(module.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def test_no_filesystem_access_occurs():
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


def test_no_subprocess_or_network_action_occurs():
    source = _module_source_text()

    assert "subprocess" not in source
    assert "socket" not in source
    assert "requests" not in source
    assert "urllib" not in source
