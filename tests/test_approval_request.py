"""Tests for core.approval_request -- the pure, deterministic validator for
the request side of a future approval lifecycle (an analyst proposing a
specific investigation-state update for later review).

No Supabase, file, subprocess, network, or AI/model access occurs anywhere
in this file; every input is a plain in-memory mapping.
"""

import copy
import socket
import subprocess
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.approval_request import (
    ACTION_TYPES,
    ApprovalRequestError,
    validate_approval_request,
)
from core.decision_context import INVESTIGATION_STATUSES
from core.evidence_normalizer import CONFIDENCE_LEVELS

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"


class _CustomMapping(Mapping):
    """A non-dict Mapping implementation, to prove the validator accepts
    any Mapping, not specifically a dict."""

    def __init__(self, data):
        self._data = dict(data)

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)


def _payload(**overrides):
    payload = {
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated"},
        "requested_by": "analyst-jane",
    }
    payload.update(overrides)
    return payload


def _module_source_text():
    import core.approval_request as module

    with open(module.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def _this_module_ast():
    import ast

    return ast.parse(Path(__file__).read_text(encoding="utf-8"))


def _imported_module_names(tree):
    import ast

    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


# ---------------------------------------------------------------------------
# 1-10: basic valid requests
# ---------------------------------------------------------------------------

def test_001_status_only_request_succeeds():
    result = validate_approval_request(_payload(action_payload={"status": "escalated"}))

    assert result["action_payload"] == {"status": "escalated"}


def test_002_confidence_only_request_succeeds():
    result = validate_approval_request(_payload(action_payload={"confidence": "high"}))

    assert result["action_payload"] == {"confidence": "high"}


def test_003_status_and_confidence_request_succeeds():
    result = validate_approval_request(
        _payload(action_payload={"status": "investigating", "confidence": "medium"})
    )

    assert result["action_payload"] == {"status": "investigating", "confidence": "medium"}


def test_004_output_contains_exactly_five_top_level_fields():
    result = validate_approval_request(_payload())

    assert set(result.keys()) == {
        "investigation_id",
        "action_type",
        "action_payload",
        "requested_by",
        "requested_at",
    }


def test_005_output_action_payload_contains_only_supplied_fields():
    result = validate_approval_request(_payload(action_payload={"status": "escalated"}))

    assert set(result["action_payload"].keys()) == {"status"}


def test_006_status_appears_before_confidence_in_normalized_payload_order():
    result = validate_approval_request(
        _payload(action_payload={"confidence": "medium", "status": "investigating"})
    )

    assert list(result["action_payload"].keys()) == ["status", "confidence"]


def test_007_input_mapping_implementation_need_not_be_a_dict():
    payload = _CustomMapping(_payload())

    result = validate_approval_request(payload)

    assert result["investigation_id"] == INVESTIGATION_ID


def test_008_approval_request_error_subclasses_value_error():
    assert issubclass(ApprovalRequestError, ValueError)


def test_009_action_types_is_a_frozenset():
    assert isinstance(ACTION_TYPES, frozenset)


def test_010_action_types_contains_exactly_update_investigation_state():
    assert ACTION_TYPES == frozenset({"update_investigation_state"})


# ---------------------------------------------------------------------------
# 11-26: top-level validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_payload", [None, "a string", ["list"], ("tuple",), 42, True])
def test_011_to_016_non_mapping_payload_rejected(bad_payload):
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(bad_payload)


def test_017_missing_investigation_id_rejected():
    payload = _payload()
    del payload["investigation_id"]

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


def test_018_missing_action_type_rejected():
    payload = _payload()
    del payload["action_type"]

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


def test_019_missing_action_payload_rejected():
    payload = _payload()
    del payload["action_payload"]

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


def test_020_missing_requested_by_rejected():
    payload = _payload()
    del payload["requested_by"]

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


def test_021_unknown_top_level_field_rejected():
    payload = _payload(totally_unknown_field="x")

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


def test_022_multiple_unknown_fields_rejected():
    payload = _payload(unknown_one="x", unknown_two="y")

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


@pytest.mark.parametrize(
    "field",
    [
        "id",
        "status",
        "approved_by",
        "approved_at",
        "rejected_by",
        "rejected_at",
        "rejection_reason",
        "expires_at",
        "consumed_at",
        "revoked_at",
        "created_at",
        "updated_at",
        "action_hash",
        "target_type",
        "target_id",
        "approval_id",
        "reviewer",
    ],
)
def test_023_to_024_reviewer_and_persistence_fields_rejected(field):
    payload = _payload(**{field: "x"})

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


@pytest.mark.parametrize("field", ["execute", "persist"])
def test_025_execution_fields_rejected(field):
    payload = _payload(**{field: "x"})

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


def test_026_no_partial_output_returned_after_failure():
    payload = _payload()
    del payload["requested_by"]

    try:
        validate_approval_request(payload)
        assert False, "expected ApprovalRequestError"
    except ApprovalRequestError:
        pass


# ---------------------------------------------------------------------------
# 27-35: investigation UUID
# ---------------------------------------------------------------------------

def test_027_canonical_uuid_accepted():
    result = validate_approval_request(_payload(investigation_id=INVESTIGATION_ID))

    assert result["investigation_id"] == INVESTIGATION_ID


def test_028_uppercase_uuid_accepted_and_canonicalized():
    result = validate_approval_request(_payload(investigation_id=INVESTIGATION_ID.upper()))

    assert result["investigation_id"] == INVESTIGATION_ID


def test_029_whitespace_padded_uuid_accepted_and_canonicalized():
    result = validate_approval_request(_payload(investigation_id=f"  {INVESTIGATION_ID}  "))

    assert result["investigation_id"] == INVESTIGATION_ID


def test_030_brace_wrapped_uuid_accepted_and_canonicalized():
    result = validate_approval_request(_payload(investigation_id=f"{{{INVESTIGATION_ID}}}"))

    assert result["investigation_id"] == INVESTIGATION_ID


def test_031_blank_investigation_id_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(investigation_id="   "))


def test_032_non_string_investigation_id_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(investigation_id=12345))


def test_033_malformed_uuid_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(investigation_id="not-a-uuid"))


def test_034_uuid_version_is_not_restricted():
    uuid1_like = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"  # UUID version 1 example

    result = validate_approval_request(_payload(investigation_id=uuid1_like))

    assert result["investigation_id"] == uuid1_like


def test_035_input_uuid_string_is_not_mutated():
    original = f"  {INVESTIGATION_ID.upper()}  "
    snapshot = str(original)

    validate_approval_request(_payload(investigation_id=original))

    assert original == snapshot


# ---------------------------------------------------------------------------
# 36-44: action type
# ---------------------------------------------------------------------------

def test_036_canonical_action_type_accepted():
    result = validate_approval_request(_payload(action_type="update_investigation_state"))

    assert result["action_type"] == "update_investigation_state"


def test_037_uppercase_action_type_canonicalized():
    result = validate_approval_request(_payload(action_type="UPDATE_INVESTIGATION_STATE"))

    assert result["action_type"] == "update_investigation_state"


def test_038_whitespace_padded_action_type_canonicalized():
    result = validate_approval_request(_payload(action_type="  update_investigation_state  "))

    assert result["action_type"] == "update_investigation_state"


def test_039_blank_action_type_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_type="   "))


def test_040_non_string_action_type_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_type=123))


def test_041_unknown_action_type_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_type="delete_investigation"))


def test_042_action_type_is_not_inferred_from_payload():
    # Even though action_payload only contains "confidence", action_type
    # must still be supplied explicitly -- omitting it is still an error.
    payload = _payload(action_payload={"confidence": "high"})
    del payload["action_type"]

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


def test_043_only_action_types_owns_the_action_vocabulary():
    source = _module_source_text()
    assert "ACTION_TYPES = frozenset" in source
    assert "DECISION_STATUSES" not in source
    assert "WARNING_CODES" not in source


def test_044_no_action_type_is_generated_when_missing():
    payload = _payload()
    del payload["action_type"]

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(payload)


# ---------------------------------------------------------------------------
# 45-55: action-payload envelope
# ---------------------------------------------------------------------------

def test_045_action_payload_must_be_a_mapping():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload="not a mapping"))


def test_046_none_action_payload_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload=None))


def test_047_list_action_payload_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload=["status", "escalated"]))


def test_048_string_action_payload_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload="escalated"))


def test_049_empty_action_payload_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload={}))


def test_050_unknown_action_payload_field_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload={"status": "escalated", "extra": "x"}))


def test_051_both_status_and_confidence_may_be_supplied():
    result = validate_approval_request(
        _payload(action_payload={"status": "closed", "confidence": "low"})
    )

    assert result["action_payload"] == {"status": "closed", "confidence": "low"}


def test_052_status_only_payload_does_not_gain_confidence():
    result = validate_approval_request(_payload(action_payload={"status": "escalated"}))

    assert "confidence" not in result["action_payload"]


def test_053_confidence_only_payload_does_not_gain_status():
    result = validate_approval_request(_payload(action_payload={"confidence": "high"}))

    assert "status" not in result["action_payload"]


def test_054_nested_mapping_is_not_mutated():
    action_payload = {"status": "escalated"}
    snapshot = copy.deepcopy(action_payload)

    validate_approval_request(_payload(action_payload=action_payload))

    assert action_payload == snapshot


def test_055_returned_action_payload_is_independent():
    action_payload = {"status": "escalated"}

    result = validate_approval_request(_payload(action_payload=action_payload))
    result["action_payload"]["status"] = "mutated"

    assert action_payload == {"status": "escalated"}


# ---------------------------------------------------------------------------
# 56-64: investigation status
# ---------------------------------------------------------------------------

def test_056_every_imported_investigation_status_value_is_accepted():
    for status in INVESTIGATION_STATUSES:
        result = validate_approval_request(_payload(action_payload={"status": status}))
        assert result["action_payload"]["status"] == status


def test_057_status_is_trimmed():
    result = validate_approval_request(_payload(action_payload={"status": "  escalated  "}))

    assert result["action_payload"]["status"] == "escalated"


def test_058_status_is_canonicalized_to_lowercase():
    result = validate_approval_request(_payload(action_payload={"status": "ESCALATED"}))

    assert result["action_payload"]["status"] == "escalated"


def test_059_blank_status_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload={"status": "   "}))


def test_060_non_string_status_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload={"status": 123}))


def test_061_unknown_status_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload={"status": "not-a-real-status"}))


def test_062_no_current_state_comparison_occurs():
    # No investigation_id or current-state argument exists in the public
    # interface for the validator to compare against -- passing any status
    # from the controlled vocabulary succeeds regardless of what an
    # investigation's "current" value might be, because there is no
    # database read here at all.
    result = validate_approval_request(_payload(action_payload={"status": "closed"}))
    assert result["action_payload"]["status"] == "closed"


def test_063_no_database_lookup_occurs():
    source = _module_source_text()
    assert "import supabase" not in source
    assert "from supabase" not in source
    assert ".table(" not in source


def test_064_no_investigation_update_occurs():
    source = _module_source_text()
    assert ".update(" not in source


# ---------------------------------------------------------------------------
# 65-73: investigation confidence
# ---------------------------------------------------------------------------

def test_065_every_imported_confidence_level_value_is_accepted():
    for confidence in CONFIDENCE_LEVELS:
        result = validate_approval_request(_payload(action_payload={"confidence": confidence}))
        assert result["action_payload"]["confidence"] == confidence


def test_066_confidence_is_trimmed():
    result = validate_approval_request(_payload(action_payload={"confidence": "  high  "}))

    assert result["action_payload"]["confidence"] == "high"


def test_067_confidence_is_canonicalized_to_lowercase():
    result = validate_approval_request(_payload(action_payload={"confidence": "HIGH"}))

    assert result["action_payload"]["confidence"] == "high"


def test_068_blank_confidence_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload={"confidence": "   "}))


def test_069_non_string_confidence_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload={"confidence": 1}))


def test_070_unknown_confidence_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(action_payload={"confidence": "extreme"}))


def test_071_confidence_is_never_calculated():
    source = _module_source_text()
    assert "calculate_confidence" not in source
    assert "compute_confidence" not in source


def test_072_evidence_count_cannot_influence_confidence():
    # There is no evidence-related parameter anywhere in the public
    # interface -- confirmed structurally, not just by absence of a code
    # path, since the function signature itself has no evidence argument.
    import inspect

    from core.approval_request import validate_approval_request as func

    signature = inspect.signature(func)
    assert "evidence" not in signature.parameters


def test_073_warning_count_cannot_influence_confidence():
    import inspect

    from core.approval_request import validate_approval_request as func

    signature = inspect.signature(func)
    assert "warnings" not in signature.parameters


# ---------------------------------------------------------------------------
# 74-84: requested identity
# ---------------------------------------------------------------------------

def test_074_valid_requested_by_accepted():
    result = validate_approval_request(_payload(requested_by="analyst-jane"))

    assert result["requested_by"] == "analyst-jane"


def test_075_requested_by_is_trimmed():
    result = validate_approval_request(_payload(requested_by="  analyst-jane  "))

    assert result["requested_by"] == "analyst-jane"


def test_076_requested_by_case_is_preserved():
    result = validate_approval_request(_payload(requested_by="Analyst-Jane"))

    assert result["requested_by"] == "Analyst-Jane"


def test_077_blank_requested_by_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(requested_by=""))


def test_078_whitespace_only_requested_by_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(requested_by="   "))


def test_079_non_string_requested_by_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(requested_by=42))


def test_080_requested_by_error_does_not_echo_its_value():
    secret_marker = "SECRET-REQUESTER-MARKER-xyz"

    try:
        validate_approval_request(_payload(requested_by=secret_marker, action_payload="bad"))
    except ApprovalRequestError as exc:
        assert secret_marker not in str(exc)


def test_081_identity_is_not_verified():
    source = _module_source_text()
    assert "def verify_identity" not in source
    assert ".auth." not in source
    assert "supabase.auth" not in source.lower()


def test_082_supabase_auth_is_not_called():
    source = _module_source_text()
    assert "import supabase" not in source
    assert "from supabase" not in source


def test_083_no_reviewer_comparison_occurs():
    # "approved_by"/"reviewer" appear in the module's own explanatory
    # docstring (explaining that this validator never accepts them) -- a
    # bare substring search over the whole file would false-match that
    # prose. Slice past the first triple-quoted docstring block and check
    # only the executable code that follows.
    source = _module_source_text()
    first_quote = source.find('"""')
    second_quote = source.find('"""', first_quote + 3)
    executable_source = source[second_quote + 3 :]

    assert "approved_by" not in executable_source
    assert "reviewer" not in executable_source.lower()


def test_084_no_approved_by_field_is_generated():
    result = validate_approval_request(_payload())

    assert "approved_by" not in result


# ---------------------------------------------------------------------------
# 85-100: requested timestamp
# ---------------------------------------------------------------------------

def test_085_requested_at_omitted_generates_timestamp():
    payload = _payload()
    assert "requested_at" not in payload

    result = validate_approval_request(payload)

    assert result["requested_at"]


def test_086_requested_at_none_generates_timestamp():
    result = validate_approval_request(_payload(requested_at=None))

    assert result["requested_at"]


def test_087_injected_aware_now_is_used():
    now = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)

    result = validate_approval_request(_payload(), now=now)

    assert result["requested_at"] == "2026-08-01T12:00:00Z"


def test_088_injected_offset_now_canonicalizes_to_utc():
    now = datetime(2026, 8, 1, 8, 45, 0, tzinfo=timezone(timedelta(hours=-7)))

    result = validate_approval_request(_payload(), now=now)

    assert result["requested_at"] == "2026-08-01T15:45:00Z"


def test_089_generated_timestamp_ends_in_z():
    result = validate_approval_request(_payload())

    assert result["requested_at"].endswith("Z")


def test_090_generated_timestamp_parses_as_aware_utc():
    result = validate_approval_request(_payload())

    parsed = datetime.fromisoformat(result["requested_at"].replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def test_091_supplied_z_timestamp_preserved():
    result = validate_approval_request(_payload(requested_at="2026-08-01T15:45:00Z"))

    assert result["requested_at"] == "2026-08-01T15:45:00Z"


def test_092_supplied_offset_timestamp_canonicalized():
    result = validate_approval_request(_payload(requested_at="2026-08-01T08:45:00-07:00"))

    assert result["requested_at"] == "2026-08-01T15:45:00Z"


def test_093_supplied_timezone_naive_timestamp_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(requested_at="2026-08-01T15:45:00"))


def test_094_invalid_timestamp_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(requested_at="not-a-timestamp"))


def test_095_blank_timestamp_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(requested_at="   "))


def test_096_non_string_requested_at_rejected():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(requested_at=12345))


def test_097_naive_injected_now_rejected():
    naive_now = datetime(2026, 8, 1, 12, 0, 0)

    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(), now=naive_now)


def test_098_non_datetime_injected_now_rejected_when_generation_required():
    with pytest.raises(ApprovalRequestError):
        validate_approval_request(_payload(), now="2026-08-01T12:00:00Z")


def test_099_supplied_requested_at_is_not_replaced():
    result = validate_approval_request(
        _payload(requested_at="2026-08-01T15:45:00Z"),
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )

    assert result["requested_at"] == "2026-08-01T15:45:00Z"


def test_100_canonical_requested_at_survives_idempotent_validation():
    first = validate_approval_request(_payload())
    second = validate_approval_request(first)

    assert first["requested_at"] == second["requested_at"]


# ---------------------------------------------------------------------------
# 101-109: determinism and independence
# ---------------------------------------------------------------------------

def test_101_identical_input_and_identical_now_produce_identical_output():
    now = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)

    first = validate_approval_request(_payload(), now=now)
    second = validate_approval_request(_payload(), now=now)

    assert first == second


def test_102_normalized_output_validates_idempotently():
    first = validate_approval_request(_payload())
    second = validate_approval_request(first)

    assert first == second


def test_103_top_level_input_remains_unchanged():
    payload = _payload()
    snapshot = copy.deepcopy(payload)

    validate_approval_request(payload)

    assert payload == snapshot


def test_104_nested_action_payload_remains_unchanged():
    payload = _payload(action_payload={"status": "escalated", "confidence": "medium"})
    snapshot = copy.deepcopy(payload)

    validate_approval_request(payload)

    assert payload == snapshot


def test_105_returned_top_level_dictionary_is_independent():
    result = validate_approval_request(_payload())
    result["investigation_id"] = "mutated"

    second_result = validate_approval_request(_payload())
    assert second_result["investigation_id"] == INVESTIGATION_ID


def test_106_returned_action_payload_dictionary_is_independent():
    result = validate_approval_request(_payload())
    result["action_payload"]["status"] = "mutated"

    second_result = validate_approval_request(_payload())
    assert second_result["action_payload"]["status"] == "escalated"


def test_107_mutating_one_result_does_not_affect_a_fresh_result():
    payload = _payload()

    first = validate_approval_request(payload)
    first["requested_by"] = "mutated"

    second = validate_approval_request(payload)
    assert second["requested_by"] == "analyst-jane"


def test_108_function_returns_a_plain_dictionary():
    result = validate_approval_request(_payload())

    assert type(result) is dict
    assert type(result["action_payload"]) is dict


def test_109_no_original_mutable_input_reference_is_retained():
    action_payload = {"status": "escalated"}
    payload = _payload(action_payload=action_payload)

    result = validate_approval_request(payload)

    assert result["action_payload"] is not action_payload
    assert result is not payload


# ---------------------------------------------------------------------------
# 110-121: exact exclusions
# ---------------------------------------------------------------------------

def test_110_output_contains_no_approval_id():
    result = validate_approval_request(_payload())
    assert "approval_id" not in result
    assert "id" not in result


def test_111_output_contains_no_lifecycle_status():
    result = validate_approval_request(_payload())
    assert "status" not in result


def test_112_output_contains_no_approved_by():
    result = validate_approval_request(_payload())
    assert "approved_by" not in result
    assert "approved_at" not in result


def test_113_output_contains_no_rejected_by():
    result = validate_approval_request(_payload())
    assert "rejected_by" not in result
    assert "rejected_at" not in result
    assert "rejection_reason" not in result


def test_114_output_contains_no_consumed_at():
    result = validate_approval_request(_payload())
    assert "consumed_at" not in result


def test_115_output_contains_no_expires_at():
    result = validate_approval_request(_payload())
    assert "expires_at" not in result


def test_116_output_contains_no_action_hash():
    result = validate_approval_request(_payload())
    assert "action_hash" not in result


def test_117_output_contains_no_target_type_or_target_id():
    result = validate_approval_request(_payload())
    assert "target_type" not in result
    assert "target_id" not in result


def test_118_output_contains_no_created_at_or_updated_at():
    result = validate_approval_request(_payload())
    assert "created_at" not in result
    assert "updated_at" not in result


def test_119_output_contains_no_decision_analysis_fields():
    result = validate_approval_request(_payload())
    for field in ("current_assessment", "decision_status", "hypothesis_id", "generated_at"):
        assert field not in result


def test_120_output_contains_no_evidence_records():
    result = validate_approval_request(_payload())
    assert "evidence_records" not in result
    assert "supporting_evidence_ids" not in result
    assert "contradicting_evidence_ids" not in result


def test_121_output_contains_no_review_or_execution_result():
    result = validate_approval_request(_payload())
    assert "review_result" not in result
    assert "execution_result" not in result
    assert "containment_result" not in result


# ---------------------------------------------------------------------------
# 122-138: runtime side-effect guards
# ---------------------------------------------------------------------------

def test_runtime_guard_no_forbidden_entry_points_reached(monkeypatch):
    import os
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during approval-request validation")

    try:
        import requests
    except ImportError:
        requests = None

    try:
        import supabase
    except ImportError:
        supabase = None

    original_cwd = os.getcwd()
    original_environ = dict(os.environ)

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

    result = validate_approval_request(_payload())

    assert result["investigation_id"] == INVESTIGATION_ID
    assert "mcp.hayabusa_server" not in sys.modules
    assert os.getcwd() == original_cwd
    assert dict(os.environ) == original_environ


def test_135_no_approval_transition_occurs():
    source = _module_source_text()
    assert "def approve" not in source
    assert "def reject" not in source
    assert "def consume" not in source


def test_136_no_persistence_occurs():
    source = _module_source_text()
    assert ".insert(" not in source
    assert ".update(" not in source
    assert ".delete(" not in source
    assert "commit(" not in source


def test_137_no_containment_occurs():
    source = _module_source_text()
    assert "containment" not in source.lower()


def test_138_no_red_team_execution_occurs():
    source = _module_source_text()
    assert "execute_simulation" not in source.lower()
    assert "run_atomic" not in source.lower()


# ---------------------------------------------------------------------------
# 139-150: source-boundary checks
# ---------------------------------------------------------------------------

def test_139_module_imports_investigation_statuses_rather_than_redefining_it():
    source = _module_source_text()
    assert "from core.decision_context import INVESTIGATION_STATUSES" in source
    assert 'INVESTIGATION_STATUSES = frozenset' not in source


def test_140_module_imports_confidence_levels_rather_than_redefining_it():
    source = _module_source_text()
    assert "from core.evidence_normalizer import CONFIDENCE_LEVELS" in source
    assert 'CONFIDENCE_LEVELS = frozenset' not in source


def test_141_module_does_not_import_supabase():
    source = _module_source_text()
    assert "import supabase" not in source
    assert "from supabase" not in source


def test_142_module_does_not_import_requests():
    source = _module_source_text()
    assert "import requests" not in source


def test_143_module_does_not_import_subprocess():
    source = _module_source_text()
    assert "import subprocess" not in source


def test_144_module_does_not_import_decision_clis():
    source = _module_source_text()
    assert "decision_context_cli" not in source
    assert "decision_analysis_cli" not in source


def test_145_module_does_not_import_warning_formatter_modules():
    source = _module_source_text()
    assert "decision_warning_formatter" not in source


def test_146_module_does_not_import_ai_model_libraries():
    source = _module_source_text()
    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()


def test_147_module_contains_no_database_write_call():
    source = _module_source_text()
    assert ".insert(" not in source
    assert ".update(" not in source
    assert ".delete(" not in source


def test_148_module_contains_no_approval_rejection_transition_function():
    source = _module_source_text()
    assert "def approve_request" not in source
    assert "def reject_request" not in source


def test_149_module_contains_no_hashing_implementation():
    source = _module_source_text()
    assert "hashlib" not in source
    assert "sha256" not in source.lower()


def test_150_module_uses_only_stdlib_and_two_approved_constant_sources():
    import ast

    tree = ast.parse(_module_source_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module)

    allowed = {"__future__", "uuid", "collections.abc", "datetime", "typing", "core.decision_context", "core.evidence_normalizer"}
    assert imported <= allowed


# ---------------------------------------------------------------------------
# Source-boundary checks on the test module itself
# ---------------------------------------------------------------------------

def test_static_test_module_does_not_import_supabase_or_requests_at_module_scope():
    tree = _this_module_ast()

    import ast

    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module)

    assert not any(name == "supabase" or name.startswith("supabase.") for name in top_level_imports)
    assert "requests" not in top_level_imports


def test_static_test_module_imports_subprocess_only_for_monkeypatch_targets():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "subprocess" in imported

    import ast

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    pytest.fail("subprocess call executed directly in the test module")
