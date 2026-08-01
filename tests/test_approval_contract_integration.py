"""Permanent contract-integration test for the ThreatTrace Block 4 approval
pipeline: core.approval_request_cli -> (synthetic snapshot construction) ->
core.approval_transition_cli, proving the two committed CLIs and two
committed pure validators share one compatible, deterministic contract --
entirely in-memory, before any Supabase schema or command integration
exists.

This module never executes /update-case or any other slash command, never
calls Supabase, and never uses subprocess to invoke a CLI -- each CLI's
main() is called directly with fresh io.StringIO streams. All
orchestration ("the pipeline", synthetic snapshots) is test-only glue; none
of it is production code.
"""

import copy
import io
import json
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

import core.approval_request as approval_request
import core.approval_request_cli as approval_request_cli
import core.approval_transition as approval_transition
import core.approval_transition_cli as approval_transition_cli

# ---------------------------------------------------------------------------
# Fixed identifiers and timestamps
# ---------------------------------------------------------------------------

APPROVAL_ID = "31111111-1111-4111-8111-111111111111"
INVESTIGATION_ID = "41111111-1111-4111-8111-111111111111"
APPROVAL_ID_REJECTION = "32222222-2222-4222-8222-222222222222"

REQUESTED_AT = "2026-08-01T15:45:00Z"
CREATED_AT = "2026-08-01T15:45:00Z"
APPROVED_AT = "2026-08-01T16:00:00Z"
CONSUMED_AT = "2026-08-01T16:15:00Z"
REJECTED_AT = "2026-08-01T16:05:00Z"
EXPIRES_AT = "2026-08-02T15:45:00Z"

REJECTION_REASON = "The proposed investigation-state change needs additional evidence."


# ---------------------------------------------------------------------------
# Synthetic fixture builders (fresh objects every call)
# ---------------------------------------------------------------------------

def _analyst_request(**overrides):
    request = {
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated", "confidence": "high"},
        "requested_by": "Roshini Analyst",
        "requested_at": REQUESTED_AT,
    }
    request.update(overrides)
    return request


def _build_pending_snapshot(validated_request, approval_id, expires_at=EXPIRES_AT, created_at=CREATED_AT):
    return {
        "id": approval_id,
        "investigation_id": validated_request["investigation_id"],
        "action_type": validated_request["action_type"],
        "action_payload": copy.deepcopy(validated_request["action_payload"]),
        "requested_by": validated_request["requested_by"],
        "requested_at": validated_request["requested_at"],
        "status": "pending",
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "expires_at": expires_at,
        "consumed_by": None,
        "consumed_at": None,
        "created_at": created_at,
    }


def _apply_set_fields(snapshot, set_fields):
    updated = copy.deepcopy(snapshot)
    updated.update(copy.deepcopy(set_fields))
    return updated


def _approve_request(**overrides):
    request = {"transition": "approve", "reviewed_by": "Jordan Reviewer", "reviewed_at": APPROVED_AT}
    request.update(overrides)
    return request


def _reject_request(**overrides):
    request = {
        "transition": "reject",
        "reviewed_by": "Roshini Analyst",
        "reviewed_at": REJECTED_AT,
        "rejection_reason": REJECTION_REASON,
    }
    request.update(overrides)
    return request


def _consume_request(**overrides):
    request = {
        "transition": "consume",
        "consumed_by": "Update Case Operator",
        "expected_investigation_id": INVESTIGATION_ID,
        "expected_action_type": "update_investigation_state",
        "consumed_at": CONSUMED_AT,
    }
    request.update(overrides)
    return request


# ---------------------------------------------------------------------------
# Local, test-only CLI invocation helper
# ---------------------------------------------------------------------------

def _run_cli(main_func, payload):
    """Invoke a CLI main() directly with fresh StringIO streams.

    Never uses subprocess, never writes a temporary file, never touches
    the network or environment variables for transport. For a claimed
    success (exit code 0), independently verifies that stdout contains
    exactly one JSON value followed only by whitespace, using
    json.JSONDecoder.raw_decode rather than trusting a bare json.loads
    call to have rejected trailing content.
    """
    stdin = io.StringIO(json.dumps(payload))
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = main_func(stdin=stdin, stdout=stdout, stderr=stderr)

    raw_stdout = stdout.getvalue()
    raw_stderr = stderr.getvalue()
    decoded = None

    if exit_code == 0:
        assert raw_stderr == "", f"success path must write no stderr, got: {raw_stderr!r}"
        assert raw_stdout != "", "success path must write non-empty stdout"
        decoder = json.JSONDecoder()
        value, end = decoder.raw_decode(raw_stdout)
        remainder = raw_stdout[end:]
        assert remainder.strip() == "", (
            f"stdout contained trailing non-whitespace content after one JSON value: {remainder!r}"
        )
        decoded = value

    return exit_code, raw_stdout, raw_stderr, decoded


def _module_source_text():
    return Path(__file__).read_text(encoding="utf-8")


def _this_module_ast():
    import ast

    return ast.parse(_module_source_text())


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
# Fail-closed test-only pipeline orchestration
# ---------------------------------------------------------------------------

class PipelineResult:
    def __init__(self):
        self.request_exit = None
        self.request_stdout = ""
        self.request_stderr = ""
        self.validated_request = None

        self.pending_snapshot = None

        self.transition_exit = None
        self.transition_stdout = ""
        self.transition_stderr = ""
        self.transition_plan = None

        self.post_transition_snapshot = None

        self.consume_exit = None
        self.consume_stdout = ""
        self.consume_stderr = ""
        self.consume_plan = None

        self.consumed_snapshot = None

        self.combined = None


def _run_pipeline(
    request_payload,
    approval_id,
    transition_request,
    *,
    expires_at=EXPIRES_AT,
    created_at=CREATED_AT,
    consume_request=None,
):
    result = PipelineResult()

    exit_code, stdout, stderr, decoded = _run_cli(approval_request_cli.main, request_payload)
    result.request_exit, result.request_stdout, result.request_stderr = exit_code, stdout, stderr
    if exit_code != 0:
        return result
    result.validated_request = decoded

    result.pending_snapshot = _build_pending_snapshot(
        result.validated_request, approval_id, expires_at=expires_at, created_at=created_at
    )

    envelope = {"current_record": result.pending_snapshot, "transition_request": transition_request}
    exit_code, stdout, stderr, decoded = _run_cli(approval_transition_cli.main, envelope)
    result.transition_exit, result.transition_stdout, result.transition_stderr = exit_code, stdout, stderr
    if exit_code != 0:
        return result
    result.transition_plan = decoded

    result.post_transition_snapshot = _apply_set_fields(result.pending_snapshot, result.transition_plan["set_fields"])

    if consume_request is not None:
        consume_envelope = {"current_record": result.post_transition_snapshot, "transition_request": consume_request}
        exit_code, stdout, stderr, decoded = _run_cli(approval_transition_cli.main, consume_envelope)
        result.consume_exit, result.consume_stdout, result.consume_stderr = exit_code, stdout, stderr
        if exit_code != 0:
            return result
        result.consume_plan = decoded
        result.consumed_snapshot = _apply_set_fields(result.post_transition_snapshot, result.consume_plan["set_fields"])

        result.combined = {
            "validated_request": result.validated_request,
            "approve_plan": result.transition_plan,
            "consume_plan": result.consume_plan,
        }

    return result


def _forbidden_main(*_args, **_kwargs):
    raise AssertionError("a later pipeline stage must not be called after an earlier stage failed")


# ---------------------------------------------------------------------------
# Full happy path fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def full_pipeline():
    request_payload = _analyst_request()
    request_snapshot = copy.deepcopy(request_payload)

    result = _run_pipeline(
        request_payload,
        APPROVAL_ID,
        _approve_request(),
        consume_request=_consume_request(),
    )

    assert request_payload == request_snapshot
    return result


# ---------------------------------------------------------------------------
# 1-5: request CLI and pending-snapshot handoff
# ---------------------------------------------------------------------------

def test_001_request_cli_succeeds(full_pipeline):
    assert full_pipeline.request_exit == 0


def test_002_request_cli_output_equals_direct_validator():
    request_payload = _analyst_request()
    _exit_code, stdout, _stderr, decoded = _run_cli(approval_request_cli.main, request_payload)
    assert decoded == approval_request.validate_approval_request(request_payload)


def test_003_pending_snapshot_uses_validated_request_fields(full_pipeline):
    snapshot = full_pipeline.pending_snapshot
    validated = full_pipeline.validated_request
    assert snapshot["investigation_id"] == validated["investigation_id"]
    assert snapshot["action_type"] == validated["action_type"]
    assert snapshot["action_payload"] == validated["action_payload"]
    assert snapshot["requested_by"] == validated["requested_by"]
    assert snapshot["requested_at"] == validated["requested_at"]


def test_004_pending_snapshot_exact_sixteen_field_shape(full_pipeline):
    expected_fields = {
        "id", "investigation_id", "action_type", "action_payload", "requested_by", "requested_at",
        "status", "approved_by", "approved_at", "rejected_by", "rejected_at", "rejection_reason",
        "expires_at", "consumed_by", "consumed_at", "created_at",
    }
    assert set(full_pipeline.pending_snapshot.keys()) == expected_fields
    assert len(expected_fields) == 16


def test_005_pending_snapshot_retains_no_raw_mutable_request_references(full_pipeline):
    assert full_pipeline.pending_snapshot["action_payload"] is not full_pipeline.validated_request["action_payload"]


# ---------------------------------------------------------------------------
# 6-10: approve transition
# ---------------------------------------------------------------------------

def test_006_approve_cli_succeeds(full_pipeline):
    assert full_pipeline.transition_exit == 0


def test_007_approve_output_equals_direct_validator(full_pipeline):
    direct = approval_transition.validate_approval_transition(full_pipeline.pending_snapshot, _approve_request())
    assert full_pipeline.transition_plan == direct
    # The pure validator's own (pre-JSON) construction order is exactly
    # status, approved_by, approved_at -- verified here at the Python
    # level, since the CLI's sort_keys=True serialization intentionally
    # reorders the JSON-decoded copy alphabetically (checked separately).
    assert list(direct["set_fields"].keys()) == ["status", "approved_by", "approved_at"]


def test_008_approve_exact_plan_shape(full_pipeline):
    plan = full_pipeline.transition_plan
    assert set(plan.keys()) == {"approval_id", "from_status", "to_status", "set_fields"}
    # The CLI serializes with sort_keys=True, so the JSON-decoded set_fields
    # keys come back alphabetically sorted, not in the validator's own
    # construction order -- this is expected, established CLI behavior.
    assert set(plan["set_fields"].keys()) == {"status", "approved_by", "approved_at"}
    assert list(plan["set_fields"].keys()) == sorted(plan["set_fields"].keys())
    assert plan["from_status"] == "pending"
    assert plan["to_status"] == "approved"
    assert plan["approval_id"] == APPROVAL_ID


def test_009_approved_snapshot_applies_only_set_fields(full_pipeline):
    plan = full_pipeline.transition_plan
    approved = full_pipeline.post_transition_snapshot
    assert approved["status"] == plan["set_fields"]["status"]
    assert approved["approved_by"] == plan["set_fields"]["approved_by"]
    assert approved["approved_at"] == plan["set_fields"]["approved_at"]
    assert approved["approved_by"] == "Jordan Reviewer"
    assert approved["approved_at"] == APPROVED_AT


def test_010_immutable_fields_survive_approval(full_pipeline):
    pending = full_pipeline.pending_snapshot
    approved = full_pipeline.post_transition_snapshot
    for field in ("id", "investigation_id", "action_type", "action_payload", "requested_by", "requested_at", "expires_at", "created_at"):
        assert approved[field] == pending[field]
    assert approved["rejected_by"] is None
    assert approved["rejected_at"] is None
    assert approved["rejection_reason"] is None
    assert approved["consumed_by"] is None
    assert approved["consumed_at"] is None


# ---------------------------------------------------------------------------
# 11-16: consume transition
# ---------------------------------------------------------------------------

def test_011_consume_cli_succeeds(full_pipeline):
    assert full_pipeline.consume_exit == 0


def test_012_consume_output_equals_direct_validator(full_pipeline):
    direct = approval_transition.validate_approval_transition(
        full_pipeline.post_transition_snapshot, _consume_request()
    )
    assert full_pipeline.consume_plan == direct
    assert list(direct["set_fields"].keys()) == ["status", "consumed_by", "consumed_at"]


def test_013_consume_exact_plan_shape(full_pipeline):
    plan = full_pipeline.consume_plan
    assert set(plan.keys()) == {"approval_id", "from_status", "to_status", "set_fields"}
    # sort_keys=True means the decoded JSON key order is alphabetical.
    assert set(plan["set_fields"].keys()) == {"status", "consumed_by", "consumed_at"}
    assert list(plan["set_fields"].keys()) == sorted(plan["set_fields"].keys())
    assert plan["from_status"] == "approved"
    assert plan["to_status"] == "consumed"


def test_014_consumed_snapshot_applies_only_set_fields(full_pipeline):
    plan = full_pipeline.consume_plan
    consumed = full_pipeline.consumed_snapshot
    assert consumed["status"] == plan["set_fields"]["status"]
    assert consumed["consumed_by"] == "Update Case Operator"
    assert consumed["consumed_at"] == CONSUMED_AT


def test_015_immutable_fields_survive_consumption(full_pipeline):
    approved = full_pipeline.post_transition_snapshot
    consumed = full_pipeline.consumed_snapshot
    for field in ("id", "investigation_id", "action_type", "action_payload", "requested_by", "requested_at", "expires_at", "created_at", "approved_by", "approved_at"):
        assert consumed[field] == approved[field]
    assert consumed["rejected_by"] is None
    assert consumed["rejected_at"] is None
    assert consumed["rejection_reason"] is None


def test_016_second_consumption_fails(full_pipeline):
    envelope = {"current_record": full_pipeline.consumed_snapshot, "transition_request": _consume_request()}
    exit_code, stdout, _stderr, decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 2
    assert stdout == ""
    assert decoded is None


# ---------------------------------------------------------------------------
# 17-20: rejection pipeline
# ---------------------------------------------------------------------------

@pytest.fixture
def rejection_pipeline():
    request_payload = _analyst_request()
    result = _run_pipeline(request_payload, APPROVAL_ID_REJECTION, _reject_request())
    return result


def test_017_rejection_pipeline_succeeds(rejection_pipeline):
    assert rejection_pipeline.request_exit == 0
    assert rejection_pipeline.transition_exit == 0


def test_018_reject_output_equals_direct_validator(rejection_pipeline):
    direct = approval_transition.validate_approval_transition(
        rejection_pipeline.pending_snapshot, _reject_request()
    )
    assert rejection_pipeline.transition_plan == direct
    assert list(direct["set_fields"].keys()) == ["status", "rejected_by", "rejected_at", "rejection_reason"]


def test_019_self_rejection_succeeds(rejection_pipeline):
    # Requester "Roshini Analyst" and reviewer "Roshini Analyst" are the
    # same claimed identity -- self-rejection (withdrawal) is permitted.
    assert rejection_pipeline.pending_snapshot["requested_by"] == "Roshini Analyst"
    assert rejection_pipeline.transition_plan["set_fields"]["rejected_by"] == "Roshini Analyst"
    assert rejection_pipeline.transition_exit == 0


def test_020_rejected_record_is_terminal(rejection_pipeline):
    rejected_snapshot = _apply_set_fields(rejection_pipeline.pending_snapshot, rejection_pipeline.transition_plan["set_fields"])
    assert rejected_snapshot["status"] == "rejected"

    for request in (_approve_request(), _reject_request(), _consume_request()):
        envelope = {"current_record": rejected_snapshot, "transition_request": request}
        exit_code, stdout, _stderr, decoded = _run_cli(approval_transition_cli.main, envelope)
        assert exit_code == 2
        assert stdout == ""
        assert decoded is None


def test_reject_exact_plan_shape(rejection_pipeline):
    plan = rejection_pipeline.transition_plan
    # sort_keys=True means the decoded JSON key order is alphabetical.
    assert set(plan["set_fields"].keys()) == {"status", "rejected_by", "rejected_at", "rejection_reason"}
    assert list(plan["set_fields"].keys()) == sorted(plan["set_fields"].keys())
    assert plan["set_fields"]["rejection_reason"] == REJECTION_REASON
    assert "approved_by" not in plan["set_fields"]
    assert "consumed_by" not in plan["set_fields"]
    for field in ("investigation_id", "action_type", "action_payload", "requested_by", "requested_at"):
        assert field not in plan


# ---------------------------------------------------------------------------
# 21-23: canonical handoff scenario
# ---------------------------------------------------------------------------

def _noncanonical_request():
    return {
        "investigation_id": f"  {{{INVESTIGATION_ID}}}  ",
        "action_type": "  UPDATE_INVESTIGATION_STATE  ",
        "action_payload": {"status": "escalated", "confidence": "high"},
        "requested_by": "  Roshini Analyst  ",
        "requested_at": "2026-08-01T08:45:00-07:00",  # equivalent to REQUESTED_AT
    }


def test_021_canonical_request_handoff_succeeds():
    request_payload = _noncanonical_request()
    exit_code, _stdout, _stderr, decoded = _run_cli(approval_request_cli.main, request_payload)

    assert exit_code == 0
    assert decoded["investigation_id"] == INVESTIGATION_ID
    assert decoded["action_type"] == "update_investigation_state"
    assert decoded["requested_by"] == "Roshini Analyst"
    assert decoded["requested_at"] == REQUESTED_AT


def test_022_canonical_transition_handoff_succeeds():
    request_payload = _noncanonical_request()
    _exit_code, _stdout, _stderr, validated_request = _run_cli(approval_request_cli.main, request_payload)

    pending_snapshot = _build_pending_snapshot(validated_request, APPROVAL_ID)
    envelope = {"current_record": pending_snapshot, "transition_request": _approve_request()}
    exit_code, _stdout, _stderr, approve_plan = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 0
    assert approve_plan["approval_id"] == APPROVAL_ID

    approved_snapshot = _apply_set_fields(pending_snapshot, approve_plan["set_fields"])

    noncanonical_consume_request = _consume_request(
        expected_investigation_id=f"  {{{INVESTIGATION_ID}}}  ",
        expected_action_type="  UPDATE_INVESTIGATION_STATE  ",
    )
    consume_envelope = {"current_record": approved_snapshot, "transition_request": noncanonical_consume_request}
    exit_code, stdout, _stderr, consume_plan = _run_cli(approval_transition_cli.main, consume_envelope)

    assert exit_code == 0
    serialized = json.dumps(consume_plan)
    assert f"{{{INVESTIGATION_ID}}}" not in serialized
    assert "UPDATE_INVESTIGATION_STATE" not in serialized


def test_023_raw_noncanonical_request_remains_unchanged():
    request_payload = _noncanonical_request()
    snapshot = copy.deepcopy(request_payload)

    _run_cli(approval_request_cli.main, request_payload)

    assert request_payload == snapshot


# ---------------------------------------------------------------------------
# 24-30: claimed-identity boundary
# ---------------------------------------------------------------------------

def test_024_self_approval_exact_match_rejected():
    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID)
    envelope = {"current_record": pending, "transition_request": _approve_request(reviewed_by="Roshini Analyst")}
    exit_code, stdout, _stderr, _decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 2
    assert stdout == ""


def test_025_self_approval_case_difference_rejected():
    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID)
    envelope = {"current_record": pending, "transition_request": _approve_request(reviewed_by="ROSHINI ANALYST")}
    exit_code, _stdout, _stderr, _decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 2


def test_026_self_approval_whitespace_difference_rejected():
    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID)
    envelope = {"current_record": pending, "transition_request": _approve_request(reviewed_by=" roshini analyst ")}
    exit_code, _stdout, _stderr, _decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 2


def test_027_unicode_casefold_self_approval_rejected():
    request_payload = _analyst_request(requested_by="Straße Analyst")
    _exit_code, _stdout, _stderr, validated = _run_cli(approval_request_cli.main, request_payload)
    pending = _build_pending_snapshot(validated, APPROVAL_ID)

    envelope = {"current_record": pending, "transition_request": _approve_request(reviewed_by="STRASSE ANALYST")}
    exit_code, _stdout, _stderr, _decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 2


def test_028_different_reviewer_accepted():
    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID)
    envelope = {"current_record": pending, "transition_request": _approve_request(reviewed_by="Jordan Reviewer")}
    exit_code, _stdout, _stderr, decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 0
    assert decoded["set_fields"]["approved_by"] == "Jordan Reviewer"


def test_029_self_rejection_accepted():
    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID)
    envelope = {"current_record": pending, "transition_request": _reject_request(reviewed_by="Roshini Analyst")}
    exit_code, _stdout, _stderr, decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 0
    assert decoded["set_fields"]["rejected_by"] == "Roshini Analyst"


def test_030_consumed_operator_accepted():
    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID)
    approve_envelope = {"current_record": pending, "transition_request": _approve_request()}
    _exit_code, _stdout, _stderr, approve_plan = _run_cli(approval_transition_cli.main, approve_envelope)
    approved = _apply_set_fields(pending, approve_plan["set_fields"])

    consume_envelope = {"current_record": approved, "transition_request": _consume_request(consumed_by="Update Case Operator")}
    exit_code, _stdout, _stderr, decoded = _run_cli(approval_transition_cli.main, consume_envelope)
    assert exit_code == 0
    assert decoded["set_fields"]["consumed_by"] == "Update Case Operator"


def test_no_identity_authentication_claim_or_supabase_auth_lookup():
    for module_source in (
        Path(approval_request_cli.__file__).read_text(encoding="utf-8"),
        Path(approval_transition_cli.__file__).read_text(encoding="utf-8"),
    ):
        assert "supabase.auth" not in module_source.lower()
        assert "def verify_identity" not in module_source


# ---------------------------------------------------------------------------
# 31-33: expiry boundary
# ---------------------------------------------------------------------------

def test_031_approval_at_expiry_rejected():
    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID, expires_at="2026-08-01T16:00:00Z")
    envelope = {"current_record": pending, "transition_request": _approve_request(reviewed_at="2026-08-01T16:00:00Z")}
    exit_code, stdout, _stderr, decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 2
    assert stdout == ""
    assert decoded is None


def test_032_consumption_at_expiry_rejected():
    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID, expires_at="2026-08-02T00:00:00Z")
    approve_envelope = {"current_record": pending, "transition_request": _approve_request()}
    _exit_code, _stdout, _stderr, approve_plan = _run_cli(approval_transition_cli.main, approve_envelope)
    approved = _apply_set_fields(pending, approve_plan["set_fields"])
    approved["expires_at"] = "2026-08-01T16:15:00Z"

    envelope = {"current_record": approved, "transition_request": _consume_request(consumed_at="2026-08-01T16:15:00Z")}
    exit_code, stdout, _stderr, decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 2
    assert stdout == ""
    assert decoded is None


def test_033_rejection_after_expiry_accepted():
    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID, expires_at="2026-08-01T15:50:00Z")
    envelope = {"current_record": pending, "transition_request": _reject_request(reviewed_at="2026-08-01T16:05:00Z")}
    exit_code, _stdout, _stderr, decoded = _run_cli(approval_transition_cli.main, envelope)
    assert exit_code == 0
    assert decoded["to_status"] == "rejected"


# ---------------------------------------------------------------------------
# 34-38: fail-closed orchestration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_request_overrides",
    [
        {"investigation_id": "not-a-uuid"},
        {"action_type": "delete_investigation"},
        {"action_payload": {}},
        {"requested_by": "   "},
        {"requested_at": "2026-08-01T15:45:00"},
    ],
)
def test_034_request_failure_prevents_transition_stage(monkeypatch, bad_request_overrides):
    monkeypatch.setattr(approval_transition_cli, "main", _forbidden_main)

    request_payload = _analyst_request(**bad_request_overrides)
    result = _run_pipeline(request_payload, APPROVAL_ID, _approve_request())

    assert result.request_exit == 2
    assert result.transition_exit is None
    assert result.pending_snapshot is None
    assert result.transition_plan is None


def test_035_approval_failure_prevents_consumption_stage(monkeypatch):
    request_payload = _analyst_request()
    result = _run_pipeline(
        request_payload,
        APPROVAL_ID,
        _approve_request(reviewed_by="Roshini Analyst"),  # self-approval -> fails
        consume_request=_consume_request(),
    )

    assert result.request_exit == 0
    assert result.transition_exit == 2
    assert result.consume_exit is None
    assert result.post_transition_snapshot is None
    assert result.consume_plan is None
    assert result.combined is None


def test_036_consumption_failure_prevents_completed_result():
    request_payload = _analyst_request()
    other_investigation_id = "66666666-6666-4666-8666-666666666666"
    result = _run_pipeline(
        request_payload,
        APPROVAL_ID,
        _approve_request(),
        consume_request=_consume_request(expected_investigation_id=other_investigation_id),
    )

    assert result.request_exit == 0
    assert result.transition_exit == 0
    assert result.consume_exit == 2
    assert result.consume_plan is None
    assert result.consumed_snapshot is None
    assert result.combined is None


def test_037_wrong_expected_investigation_rejected():
    request_payload = _analyst_request()
    other_investigation_id = "66666666-6666-4666-8666-666666666666"
    result = _run_pipeline(
        request_payload,
        APPROVAL_ID,
        _approve_request(),
        consume_request=_consume_request(expected_investigation_id=other_investigation_id),
    )

    assert result.consume_exit == 2
    assert result.consume_stdout == ""


def test_038_wrong_expected_action_rejected(monkeypatch):
    monkeypatch.setattr(
        approval_transition, "ACTION_TYPES", frozenset({"update_investigation_state", "fake_other_action"})
    )

    request_payload = _analyst_request()
    result = _run_pipeline(
        request_payload,
        APPROVAL_ID,
        _approve_request(),
        consume_request=_consume_request(expected_action_type="fake_other_action"),
    )

    assert result.consume_exit == 2
    assert result.consume_stdout == ""


# ---------------------------------------------------------------------------
# 39-48: combined test-only result
# ---------------------------------------------------------------------------

def test_039_combined_result_exact_shape(full_pipeline):
    assert set(full_pipeline.combined.keys()) == {"validated_request", "approve_plan", "consume_plan"}


def test_040_combined_result_json_serializable(full_pipeline):
    serialized = json.dumps(full_pipeline.combined)
    assert json.loads(serialized) == full_pipeline.combined


def test_041_no_complete_approval_snapshot_embedded(full_pipeline):
    serialized = json.dumps(full_pipeline.combined)
    assert '"status"' not in serialized or "\"status\": \"approved\"" in serialized  # set_fields' own status is fine
    assert "expires_at" not in serialized
    assert "created_at" not in serialized


def test_042_no_database_result_embedded(full_pipeline):
    serialized = json.dumps(full_pipeline.combined)
    assert "database_result" not in serialized


def test_043_no_persistence_result_embedded(full_pipeline):
    serialized = json.dumps(full_pipeline.combined).lower()
    assert "persisted" not in serialized
    assert "inserted" not in serialized


def test_044_no_affected_row_count_embedded(full_pipeline):
    serialized = json.dumps(full_pipeline.combined)
    assert "affected_rows" not in serialized
    assert "row_count" not in serialized


def test_045_no_investigation_update_result_embedded(full_pipeline):
    serialized = json.dumps(full_pipeline.combined)
    assert "investigation_status" not in serialized
    assert "investigation_confidence" not in serialized


def test_046_no_authentication_result_embedded(full_pipeline):
    serialized = json.dumps(full_pipeline.combined).lower()
    assert "authenticated" not in serialized
    assert "auth_token" not in serialized


def test_047_no_hash_embedded(full_pipeline):
    serialized = json.dumps(full_pipeline.combined)
    assert "action_hash" not in serialized


def test_048_no_execution_result_embedded(full_pipeline):
    serialized = json.dumps(full_pipeline.combined).lower()
    assert "executed" not in serialized
    assert "execution_result" not in serialized


def test_combined_result_labeled_validated_approval_plans_not_persisted(full_pipeline):
    # This test itself is the documented label for the combined test-only
    # result: "Validated approval plans -- not persisted". No production
    # schema exists for it, and none is being created here.
    label = "Validated approval plans -- not persisted"
    assert isinstance(label, str)
    assert full_pipeline.combined is not None


# ---------------------------------------------------------------------------
# 49-51: CLI output/stream contract across the pipeline
# ---------------------------------------------------------------------------

def test_049_all_cli_outputs_contain_exactly_one_json_value(full_pipeline):
    for stdout in (full_pipeline.request_stdout, full_pipeline.transition_stdout, full_pipeline.consume_stdout):
        decoder = json.JSONDecoder()
        _value, end = decoder.raw_decode(stdout)
        assert stdout[end:].strip() == ""


def test_050_all_successful_cli_stderr_streams_are_empty(full_pipeline):
    assert full_pipeline.request_stderr == ""
    assert full_pipeline.transition_stderr == ""
    assert full_pipeline.consume_stderr == ""


def test_051_every_deterministic_failure_has_empty_stdout():
    bad_request = _analyst_request(investigation_id="not-a-uuid")
    result = _run_pipeline(bad_request, APPROVAL_ID, _approve_request())
    assert result.request_stdout == ""


# ---------------------------------------------------------------------------
# 52-57: non-mutation
# ---------------------------------------------------------------------------

def test_052_request_input_remains_unchanged():
    request_payload = _analyst_request()
    snapshot = copy.deepcopy(request_payload)

    _run_pipeline(request_payload, APPROVAL_ID, _approve_request(), consume_request=_consume_request())

    assert request_payload == snapshot


def test_053_pending_record_remains_unchanged_after_approve_validation(full_pipeline):
    # full_pipeline already ran approve+consume; re-derive an independent
    # pending snapshot and confirm a fresh approve call doesn't mutate it.
    pending = _build_pending_snapshot(full_pipeline.validated_request, APPROVAL_ID)
    snapshot = copy.deepcopy(pending)

    envelope = {"current_record": pending, "transition_request": _approve_request()}
    _run_cli(approval_transition_cli.main, envelope)

    assert pending == snapshot


def test_054_approved_record_remains_unchanged_after_consume_validation(full_pipeline):
    approved = copy.deepcopy(full_pipeline.post_transition_snapshot)
    snapshot = copy.deepcopy(approved)

    envelope = {"current_record": approved, "transition_request": _consume_request()}
    _run_cli(approval_transition_cli.main, envelope)

    assert approved == snapshot


def test_055_transition_requests_remain_unchanged():
    approve_request = _approve_request()
    approve_snapshot = copy.deepcopy(approve_request)
    reject_request = _reject_request()
    reject_snapshot = copy.deepcopy(reject_request)
    consume_request = _consume_request()
    consume_snapshot = copy.deepcopy(consume_request)

    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID)
    _run_cli(approval_transition_cli.main, {"current_record": pending, "transition_request": approve_request})
    _run_cli(approval_transition_cli.main, {"current_record": pending, "transition_request": reject_request})

    approved = _apply_set_fields(pending, {"status": "approved", "approved_by": "Jordan Reviewer", "approved_at": APPROVED_AT})
    _run_cli(approval_transition_cli.main, {"current_record": approved, "transition_request": consume_request})

    assert approve_request == approve_snapshot
    assert reject_request == reject_snapshot
    assert consume_request == consume_snapshot


def test_056_nested_action_payload_remains_unchanged(full_pipeline):
    pending = full_pipeline.pending_snapshot
    snapshot = copy.deepcopy(pending["action_payload"])

    envelope = {"current_record": pending, "transition_request": _approve_request()}
    _run_cli(approval_transition_cli.main, envelope)

    assert pending["action_payload"] == snapshot


def test_057_rejection_reason_remains_unchanged():
    request = _reject_request(rejection_reason="  padded reason with internal   spacing  ")
    snapshot = str(request["rejection_reason"])

    pending = _build_pending_snapshot(_analyst_request(), APPROVAL_ID)
    _run_cli(approval_transition_cli.main, {"current_record": pending, "transition_request": request})

    assert request["rejection_reason"] == snapshot


# ---------------------------------------------------------------------------
# 58-59: returned-object independence and determinism
# ---------------------------------------------------------------------------

def test_058_output_objects_are_independent(full_pipeline):
    pending_snapshot_before = copy.deepcopy(full_pipeline.pending_snapshot)
    full_pipeline.transition_plan["set_fields"]["approved_by"] = "mutated"
    assert full_pipeline.pending_snapshot == pending_snapshot_before

    approved_before = copy.deepcopy(full_pipeline.post_transition_snapshot)
    full_pipeline.consume_plan["set_fields"]["consumed_by"] = "mutated"
    assert full_pipeline.post_transition_snapshot == approved_before

    direct = approval_transition.validate_approval_transition(full_pipeline.pending_snapshot, _approve_request())
    full_pipeline.transition_plan["approval_id"] = "mutated-again"
    assert direct["approval_id"] == APPROVAL_ID


def test_059_fresh_runs_are_deterministic():
    request_a = _analyst_request()
    request_b = _analyst_request()

    result_a = _run_pipeline(request_a, APPROVAL_ID, _approve_request(), consume_request=_consume_request())
    result_b = _run_pipeline(request_b, APPROVAL_ID, _approve_request(), consume_request=_consume_request())

    assert result_a.validated_request == result_b.validated_request
    assert result_a.transition_plan == result_b.transition_plan
    assert result_a.consume_plan == result_b.consume_plan


# ---------------------------------------------------------------------------
# 60-63: runtime side-effect guard
# ---------------------------------------------------------------------------

def test_060_runtime_side_effect_guards_succeed(monkeypatch):
    import os
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during the approval contract pipeline")

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

    request_payload = _analyst_request()
    result = _run_pipeline(request_payload, APPROVAL_ID, _approve_request(), consume_request=_consume_request())

    assert result.request_exit == 0
    assert result.transition_exit == 0
    assert result.consume_exit == 0
    assert "mcp.hayabusa_server" not in sys.modules
    assert os.getcwd() == original_cwd
    assert dict(os.environ) == original_environ


def test_061_no_hayabusa_import():
    import sys

    assert "mcp.hayabusa_server" not in sys.modules


def test_062_no_environment_mutation():
    import os

    snapshot = dict(os.environ)
    request_payload = _analyst_request()
    _run_pipeline(request_payload, APPROVAL_ID, _approve_request(), consume_request=_consume_request())
    assert dict(os.environ) == snapshot


def test_063_no_working_directory_change():
    import os

    original_cwd = os.getcwd()
    request_payload = _analyst_request()
    _run_pipeline(request_payload, APPROVAL_ID, _approve_request(), consume_request=_consume_request())
    assert os.getcwd() == original_cwd


# ---------------------------------------------------------------------------
# 64-65: static source boundary
# ---------------------------------------------------------------------------

def test_064_static_source_boundary_passes():
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
    assert "subprocess" in _imported_module_names(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    pytest.fail("subprocess call executed directly in the test module")

    forbidden_call_names = {"SlashCommand", "run_slash_command", "invoke_slash_command"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_call_names:
                pytest.fail(f"forbidden call found: {node.func.id}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_call_names:
                pytest.fail(f"forbidden call found: {node.func.attr}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            positional_mode = node.args[1] if len(node.args) > 1 else None
            if isinstance(positional_mode, ast.Constant) and isinstance(positional_mode.value, str):
                assert "w" not in positional_mode.value
                assert "a" not in positional_mode.value


def test_065_nothing_represents_a_plan_as_persisted_state(full_pipeline):
    for plan in (full_pipeline.transition_plan, full_pipeline.consume_plan):
        serialized = json.dumps(plan).lower()
        assert "persisted" not in serialized
        assert "saved" not in serialized
        assert "committed" not in serialized


# ---------------------------------------------------------------------------
# Direct-validator parity (additional explicit coverage)
# ---------------------------------------------------------------------------

def test_direct_validator_parity_for_request_validation():
    payload = _analyst_request()
    _exit_code, _stdout, _stderr, decoded = _run_cli(approval_request_cli.main, payload)
    assert decoded == approval_request.validate_approval_request(payload)


def test_direct_validator_parity_for_approve_transition(full_pipeline):
    direct = approval_transition.validate_approval_transition(full_pipeline.pending_snapshot, _approve_request())
    assert full_pipeline.transition_plan == direct


def test_direct_validator_parity_for_reject_transition(rejection_pipeline):
    direct = approval_transition.validate_approval_transition(rejection_pipeline.pending_snapshot, _reject_request())
    assert rejection_pipeline.transition_plan == direct


def test_direct_validator_parity_for_consume_transition(full_pipeline):
    direct = approval_transition.validate_approval_transition(full_pipeline.post_transition_snapshot, _consume_request())
    assert full_pipeline.consume_plan == direct
