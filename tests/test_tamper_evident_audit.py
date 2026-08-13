"""Tests for core.tamper_evident_audit -- the pure, deterministic
tamper-evident audit chain (Block 14, module 1 of 2).

No Supabase, MCP, file, subprocess, network, Hayabusa, or AI/model access
occurs anywhere in this file; every input is a plain in-memory value, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time(). No tool is ever executed, and no prior security-policy
function (Block 8/9/10/Mutation-Freeze/evaluation lab/analyst feedback)
is ever called -- this module only records that such an event happened.
"""

import copy
import inspect

import core.tamper_evident_audit as audit_module
from core.tamper_evident_audit import (
    EVENT_TYPES,
    AuditRecordError,
    create_audit_record,
    verify_audit_chain,
)

OCCURRED_AT_1 = "2026-01-01T00:00:00Z"
OCCURRED_AT_2 = "2026-01-01T00:05:00Z"
OCCURRED_AT_3 = "2026-01-01T00:10:00Z"

_RECORD_FIELDS = {
    "audit_version", "sequence", "event_type", "event_reference", "event_summary",
    "occurred_at", "previous_record_digest", "audit_persisted", "execution_performed",
    "record_digest",
}


def _genesis(**overrides):
    kwargs = {
        "sequence": 1,
        "event_type": "security_evaluation_result",
        "event_reference": "evaluate:emergency_freeze_bypass:identity_agent:coordinator_agent",
        "event_summary": {"outcome": "pass", "case_type": "emergency_freeze_bypass"},
        "occurred_at": OCCURRED_AT_1,
        "previous_record_digest": None,
    }
    kwargs.update(overrides)
    return create_audit_record(**kwargs)


def _chain(length):
    records = [_genesis()]
    for i in range(2, length + 1):
        records.append(create_audit_record(
            sequence=i,
            event_type="analyst_feedback",
            event_reference=f"investigation-{i}",
            event_summary={"outcome": "agree"},
            occurred_at=OCCURRED_AT_2,
            previous_record_digest=records[-1]["record_digest"],
        ))
    return records


def _assert_raises(func, **kwargs):
    try:
        func(**kwargs)
        assert False, f"expected AuditRecordError for kwargs={kwargs!r}"
    except AuditRecordError:
        pass


# ---------------------------------------------------------------------------
# Successful creation
# ---------------------------------------------------------------------------


def test_001_genesis_record():
    result = _genesis()
    assert result["sequence"] == 1
    assert result["previous_record_digest"] is None
    assert set(result) == _RECORD_FIELDS


def test_002_second_chained_record():
    genesis = _genesis()
    second = create_audit_record(
        sequence=2, event_type="analyst_feedback", event_reference="investigation-123",
        event_summary={"outcome": "disagree", "error_category": "incorrect_classification"},
        occurred_at=OCCURRED_AT_2, previous_record_digest=genesis["record_digest"],
    )
    assert second["sequence"] == 2
    assert second["previous_record_digest"] == genesis["record_digest"]


def test_003_third_chained_record():
    records = _chain(3)
    assert [r["sequence"] for r in records] == [1, 2, 3]
    assert records[2]["previous_record_digest"] == records[1]["record_digest"]


def test_004_every_event_type_accepted():
    for event_type in EVENT_TYPES:
        result = _genesis(event_type=event_type, event_summary=None)
        assert result["event_type"] == event_type


def test_005_event_summary_none_accepted():
    result = _genesis(event_summary=None)
    assert result["event_summary"] is None


def test_006_valid_event_summary_combinations():
    combos = [
        {"outcome": "pass"},
        {"case_type": "identity_privilege_bypass"},
        {"error_category": "false_positive"},
        {"outcome": "pass", "case_type": "identity_privilege_bypass"},
        {"outcome": "disagree", "error_category": "missing_evidence"},
        {"outcome": "pass", "case_type": "x", "error_category": "y"},
        {},
    ]
    for combo in combos:
        result = _genesis(event_summary=combo)
        assert result["event_summary"] == combo


def test_007_deterministic_repeated_creation():
    first = _genesis()
    second = _genesis()
    assert first == second


def test_008_same_content_same_digest():
    first = _genesis()
    second = _genesis()
    assert first["record_digest"] == second["record_digest"]


def test_009_content_mutation_changes_digest():
    base = _genesis()
    changed = _genesis(event_reference="a-different-reference")
    assert base["record_digest"] != changed["record_digest"]


# ---------------------------------------------------------------------------
# sequence validation
# ---------------------------------------------------------------------------


def test_010_bool_sequence_rejected():
    _assert_raises(_genesis, sequence=True)


def test_011_non_int_sequence_rejected():
    for bad_value in ("1", 1.0, None, [1]):
        _assert_raises(_genesis, sequence=bad_value)


def test_012_zero_sequence_rejected():
    _assert_raises(_genesis, sequence=0)


def test_013_negative_sequence_rejected():
    _assert_raises(_genesis, sequence=-1)


def test_014_genesis_sequence_other_than_one_rejected():
    _assert_raises(_genesis, sequence=2)


def test_015_non_genesis_sequence_below_two_rejected():
    _assert_raises(
        create_audit_record, sequence=1, event_type="analyst_feedback", event_reference="x",
        event_summary=None, occurred_at=OCCURRED_AT_1, previous_record_digest="sha256:" + "a" * 64,
    )


def test_016_non_genesis_sequence_two_or_more_accepted():
    digest = "sha256:" + "a" * 64
    for sequence in (2, 3, 100):
        result = create_audit_record(
            sequence=sequence, event_type="analyst_feedback", event_reference="x",
            event_summary=None, occurred_at=OCCURRED_AT_1, previous_record_digest=digest,
        )
        assert result["sequence"] == sequence


# ---------------------------------------------------------------------------
# event_type / event_reference
# ---------------------------------------------------------------------------


def test_017_invalid_event_type_rejected():
    for bad_value in ("approval_request", "", None, 123, "investigation_decisions"):
        _assert_raises(_genesis, event_type=bad_value)


def test_018_valid_event_reference_accepted():
    result = _genesis(event_reference="investigation-abc-123")
    assert result["event_reference"] == "investigation-abc-123"


def test_019_blank_event_reference_rejected():
    for bad_value in ("", "   "):
        _assert_raises(_genesis, event_reference=bad_value)


def test_020_non_string_event_reference_rejected():
    for bad_value in (None, 123, ["ref"], {}):
        _assert_raises(_genesis, event_reference=bad_value)


# ---------------------------------------------------------------------------
# event_summary
# ---------------------------------------------------------------------------


def test_021_event_summary_unknown_key_rejected():
    _assert_raises(_genesis, event_summary={"outcome": "pass", "extra": "nope"})


def test_022_event_summary_nested_object_rejected():
    _assert_raises(_genesis, event_summary={"outcome": {"nested": "value"}})


def test_023_event_summary_list_value_rejected():
    _assert_raises(_genesis, event_summary={"outcome": ["pass"]})


def test_024_event_summary_bool_value_rejected():
    _assert_raises(_genesis, event_summary={"outcome": True})


def test_025_event_summary_blank_string_value_rejected():
    _assert_raises(_genesis, event_summary={"outcome": "   "})


def test_026_event_summary_non_mapping_rejected():
    for bad_value in ("outcome", ["outcome", "pass"], 123):
        _assert_raises(_genesis, event_summary=bad_value)


def test_027_event_summary_caller_mapping_not_mutated_or_aliased():
    original = {"outcome": "pass", "case_type": "identity_privilege_bypass"}
    snapshot = copy.deepcopy(original)

    result = _genesis(event_summary=original)

    assert original == snapshot
    assert result["event_summary"] is not original
    result["event_summary"]["outcome"] = "tampered"
    assert original["outcome"] == "pass"


# ---------------------------------------------------------------------------
# digest formats
# ---------------------------------------------------------------------------


def test_028_record_digest_correct_sha256_format():
    result = _genesis()
    digest = result["record_digest"]
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
    int(digest.removeprefix("sha256:"), 16)  # raises ValueError if not valid hex


def test_029_malformed_previous_digest_rejected():
    for bad_value in ("not-a-digest", "sha256:tooshort", "", 123):
        _assert_raises(
            create_audit_record, sequence=2, event_type="analyst_feedback", event_reference="x",
            event_summary=None, occurred_at=OCCURRED_AT_1, previous_record_digest=bad_value,
        )


def test_030_uppercase_digest_rejected():
    bad_digest = "sha256:" + "A" * 64
    _assert_raises(
        create_audit_record, sequence=2, event_type="analyst_feedback", event_reference="x",
        event_summary=None, occurred_at=OCCURRED_AT_1, previous_record_digest=bad_digest,
    )


def test_031_short_digest_rejected():
    bad_digest = "sha256:" + "a" * 63
    _assert_raises(
        create_audit_record, sequence=2, event_type="analyst_feedback", event_reference="x",
        event_summary=None, occurred_at=OCCURRED_AT_1, previous_record_digest=bad_digest,
    )


def test_032_other_algorithm_prefix_rejected():
    bad_digest = "sha1:" + "a" * 40
    _assert_raises(
        create_audit_record, sequence=2, event_type="analyst_feedback", event_reference="x",
        event_summary=None, occurred_at=OCCURRED_AT_1, previous_record_digest=bad_digest,
    )


# ---------------------------------------------------------------------------
# timestamp
# ---------------------------------------------------------------------------


def test_033_valid_occurred_at_accepted():
    result = _genesis(occurred_at="2026-06-15T08:30:00Z")
    assert result["occurred_at"] == "2026-06-15T08:30:00Z"


def test_034_malformed_occurred_at_rejected():
    for bad_value in ("not-a-timestamp", "", None, 123, "2026-01-01T00:00:00"):
        _assert_raises(_genesis, occurred_at=bad_value)


def test_035_no_clock_read_deterministic_value_used():
    result = _genesis(occurred_at=OCCURRED_AT_1)
    assert result["occurred_at"] == OCCURRED_AT_1


# ---------------------------------------------------------------------------
# Chain verification: success
# ---------------------------------------------------------------------------


def test_036_empty_chain_valid():
    result = verify_audit_chain(records=[])
    assert result["verification_outcome"] == "valid"
    assert result["internal_chain_valid"] is True
    assert result["trusted_anchor_verified"] is None
    assert result["record_count"] == 0
    assert result["head_digest"] is None
    assert result["observed_evidence"] == []


def test_037_empty_chain_with_expected_anchor_invalid():
    result = verify_audit_chain(records=[], expected_head_digest="sha256:" + "a" * 64)
    assert result["verification_outcome"] == "invalid"
    assert result["trusted_anchor_verified"] is False
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "TRUSTED_ANCHOR_MISMATCH" in codes


def test_038_one_genesis_record_valid():
    result = verify_audit_chain(records=[_genesis()])
    assert result["verification_outcome"] == "valid"
    assert result["internal_chain_valid"] is True
    assert result["record_count"] == 1


def test_039_two_record_chain_valid():
    result = verify_audit_chain(records=_chain(2))
    assert result["verification_outcome"] == "valid"
    assert result["record_count"] == 2


def test_040_three_record_chain_valid():
    result = verify_audit_chain(records=_chain(3))
    assert result["verification_outcome"] == "valid"
    assert result["record_count"] == 3


def test_041_deterministic_verification():
    records = _chain(3)
    first = verify_audit_chain(records=records)
    second = verify_audit_chain(records=records)
    assert first == second


def test_042_verify_does_not_mutate_records():
    records = _chain(2)
    snapshot = copy.deepcopy(records)
    verify_audit_chain(records=records)
    assert records == snapshot


# ---------------------------------------------------------------------------
# Chain verification: tamper detection
# ---------------------------------------------------------------------------


def test_043_altered_content_stale_digest_detected():
    records = _chain(2)
    tampered = dict(records[1])
    tampered["event_reference"] = "tampered-reference"
    result = verify_audit_chain(records=[records[0], tampered])
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "DIGEST_MISMATCH" in codes


def test_044_broken_previous_link_detected():
    records = _chain(2)
    tampered = dict(records[1])
    tampered["previous_record_digest"] = "sha256:" + "b" * 64
    # recompute digest so DIGEST_MISMATCH doesn't also fire, isolating the link check
    tampered["record_digest"] = audit_module._recompute_record_digest({
        "sequence": tampered["sequence"], "event_type": tampered["event_type"],
        "event_reference": tampered["event_reference"], "event_summary": tampered["event_summary"],
        "occurred_at": tampered["occurred_at"], "previous_record_digest": tampered["previous_record_digest"],
        "audit_persisted": False, "execution_performed": False,
    })
    result = verify_audit_chain(records=[records[0], tampered])
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "PREVIOUS_DIGEST_MISMATCH" in codes
    assert "DIGEST_MISMATCH" not in codes


def test_045_sequence_gap_detected():
    records = _chain(2)
    tampered = dict(records[1])
    tampered["sequence"] = 5
    tampered["record_digest"] = audit_module._recompute_record_digest({
        "sequence": 5, "event_type": tampered["event_type"], "event_reference": tampered["event_reference"],
        "event_summary": tampered["event_summary"], "occurred_at": tampered["occurred_at"],
        "previous_record_digest": tampered["previous_record_digest"], "audit_persisted": False,
        "execution_performed": False,
    })
    result = verify_audit_chain(records=[records[0], tampered])
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "SEQUENCE_MISMATCH" in codes


def test_046_invalid_genesis_previous_digest_detected():
    genesis = _genesis()
    tampered = dict(genesis)
    tampered["sequence"] = 2
    result = verify_audit_chain(records=[tampered])
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "GENESIS_LINK_INVALID" in codes


def test_047_malformed_record_reported_not_raised():
    result = verify_audit_chain(records=[{"not": "a valid record"}])
    assert result["verification_outcome"] == "invalid"
    assert result["internal_chain_valid"] is False
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "INVALID_RECORD_STRUCTURE" in codes


def test_048_malformed_record_among_valid_ones_reported_not_raised():
    records = _chain(2)
    result = verify_audit_chain(records=[records[0], "not-a-record"])
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "INVALID_RECORD_STRUCTURE" in codes


# ---------------------------------------------------------------------------
# Trusted anchor
# ---------------------------------------------------------------------------


def test_049_no_anchor_trusted_anchor_verified_none():
    result = verify_audit_chain(records=_chain(2))
    assert result["trusted_anchor_verified"] is None


def test_050_matching_anchor_true():
    records = _chain(2)
    result = verify_audit_chain(records=records, expected_head_digest=records[-1]["record_digest"])
    assert result["trusted_anchor_verified"] is True
    assert result["verification_outcome"] == "valid"


def test_051_mismatching_anchor_false():
    records = _chain(2)
    result = verify_audit_chain(records=records, expected_head_digest="sha256:" + "c" * 64)
    assert result["trusted_anchor_verified"] is False
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "TRUSTED_ANCHOR_MISMATCH" in codes


def test_052_invalid_chain_with_anchor_still_false():
    result = verify_audit_chain(records=[{"broken": "record"}], expected_head_digest="sha256:" + "d" * 64)
    assert result["trusted_anchor_verified"] is False
    assert result["verification_outcome"] == "invalid"


def test_053_malformed_expected_head_digest_raises():
    _assert_raises(verify_audit_chain, records=_chain(1), expected_head_digest="not-a-digest")


def test_054_records_not_a_list_raises():
    for bad_value in (None, "records", {"a": 1}, 123):
        _assert_raises(verify_audit_chain, records=bad_value)


# ---------------------------------------------------------------------------
# verification_outcome semantics
# ---------------------------------------------------------------------------


def test_055_verification_version_and_execution_performed():
    result = verify_audit_chain(records=_chain(1))
    assert result["verification_version"] == "1"
    assert result["execution_performed"] is False


def test_056_valid_outcome_requires_both_internal_and_anchor_not_false():
    records = _chain(2)
    valid_anchor_result = verify_audit_chain(records=records, expected_head_digest=records[-1]["record_digest"])
    assert valid_anchor_result["verification_outcome"] == "valid"

    bad_anchor_result = verify_audit_chain(records=records, expected_head_digest="sha256:" + "e" * 64)
    assert bad_anchor_result["verification_outcome"] == "invalid"


# ---------------------------------------------------------------------------
# Purity / structural boundary
# ---------------------------------------------------------------------------


def test_057_module_never_reads_clock_env_filesystem_network_mcp_database():
    full_source = inspect.getsource(audit_module)
    source = full_source.split("from __future__", 1)[1]
    forbidden_substrings = (
        "datetime.now",
        "utcnow",
        "time.time",
        "os.environ",
        "os.getenv",
        "open(",
        "Path(",
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "mcp__",
        "random.",
    )
    for forbidden in forbidden_substrings:
        assert forbidden not in source, f"forbidden substring found: {forbidden!r}"


def test_058_module_never_imports_other_blocks():
    # A code comment legitimately explains why core.decision_binding's
    # canonicalization helper is not imported -- only an actual import
    # statement for any of these modules is forbidden.
    full_source = inspect.getsource(audit_module)
    source = full_source.split("from __future__", 1)[1]
    forbidden_modules = (
        "core.agent_gateway",
        "core.agent_identity_policy",
        "core.decision_binding",
        "core.mutation_freeze",
        "core.ai_asset_registry",
        "core.analyst_feedback",
    )
    for forbidden in forbidden_modules:
        assert f"import {forbidden}" not in source, f"forbidden import found: {forbidden!r}"
        assert f"from {forbidden}" not in source, f"forbidden import found: {forbidden!r}"
