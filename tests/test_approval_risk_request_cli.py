"""Tests for core.approval_risk_request_cli -- the stdin/stdout JSON
adapter around core.approval_request.validate_risk_aware_approval_request.

main() is called directly with in-memory StringIO streams. No Supabase,
file, subprocess, network, AI-model, or other external access occurs
anywhere in this file; every input is a plain in-memory JSON object.

Exactly six tests are defined below, per the Block 6 Step 7 specification.
"""

import copy
import json
from io import StringIO

from core import approval_risk_request_cli

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"


def _request(**overrides):
    request = {
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated"},
        "requested_by": "analyst-jane",
    }
    request.update(overrides)
    return request


def _current_investigation(**overrides):
    investigation = {"status": "open", "confidence": "low"}
    investigation.update(overrides)
    return investigation


def _envelope(request=None, current_investigation=None):
    return {
        "request": _request() if request is None else request,
        "current_investigation": _current_investigation() if current_investigation is None else current_investigation,
    }


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = approval_risk_request_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def test_001_confidence_only_request_produces_low_risk_and_one_required_approval():
    envelope = _envelope(
        request=_request(action_payload={"confidence": "high"}),
        current_investigation=_current_investigation(status="open", confidence="low"),
    )
    exit_code, stdout, stderr = _run(json.dumps(envelope))

    assert exit_code == 0
    assert stderr == ""
    parsed = json.loads(stdout)
    assert parsed["risk_level"] == "low"
    assert parsed["required_approvals"] == 1


def test_002_ordinary_status_request_produces_medium_risk_and_one_required_approval():
    envelope = _envelope(
        request=_request(action_payload={"status": "investigating"}),
        current_investigation=_current_investigation(status="open", confidence="medium"),
    )
    exit_code, stdout, stderr = _run(json.dumps(envelope))

    assert exit_code == 0
    assert stderr == ""
    parsed = json.loads(stdout)
    assert parsed["risk_level"] == "medium"
    assert parsed["required_approvals"] == 1


def test_003_closing_request_produces_high_risk_and_two_required_approvals():
    envelope = _envelope(
        request=_request(action_payload={"status": "closed"}),
        current_investigation=_current_investigation(status="open", confidence="medium"),
    )
    exit_code, stdout, stderr = _run(json.dumps(envelope))

    assert exit_code == 0
    assert stderr == ""
    parsed = json.loads(stdout)
    assert parsed["risk_level"] == "high"
    assert parsed["required_approvals"] == 2


def test_004_caller_supplied_risk_level_or_required_approvals_fails():
    # risk_level inside the request itself is not an allowed request field.
    envelope_a = _envelope(request=_request(risk_level="low"))
    exit_code_a, stdout_a, _stderr_a = _run(json.dumps(envelope_a))
    assert exit_code_a == 2
    assert stdout_a == ""

    # required_approvals inside the request itself is not an allowed
    # request field either.
    envelope_b = _envelope(request=_request(required_approvals=1))
    exit_code_b, stdout_b, _stderr_b = _run(json.dumps(envelope_b))
    assert exit_code_b == 2
    assert stdout_b == ""

    # current_investigation must contain exactly status and confidence --
    # a caller-supplied risk_level there is also rejected.
    envelope_c = _envelope(current_investigation=_current_investigation(risk_level="high"))
    exit_code_c, stdout_c, _stderr_c = _run(json.dumps(envelope_c))
    assert exit_code_c == 2
    assert stdout_c == ""


def test_005_malformed_top_level_fields_or_malformed_json_fail_closed():
    scenarios = [
        "",
        "{not valid json",
        "null",
        "[]",
        json.dumps(_envelope()) + " garbage",
    ]
    for raw in scenarios:
        exit_code, stdout, stderr = _run(raw)
        assert exit_code == 2
        assert stdout == ""
        assert "Traceback" not in stderr

    # missing top-level field
    envelope_missing = _envelope()
    del envelope_missing["current_investigation"]
    exit_code, stdout, stderr = _run(json.dumps(envelope_missing))
    assert exit_code == 2
    assert stdout == ""
    assert "Traceback" not in stderr

    # unknown top-level field
    envelope_unknown = _envelope()
    envelope_unknown["extra_field"] = "x"
    exit_code, stdout, stderr = _run(json.dumps(envelope_unknown))
    assert exit_code == 2
    assert stdout == ""
    assert "Traceback" not in stderr


def test_006_input_objects_unmodified_and_output_serialization_deterministic():
    envelope = _envelope(
        request=_request(action_payload={"status": "closed", "confidence": "high"}),
        current_investigation=_current_investigation(status="open", confidence="low"),
    )
    snapshot = copy.deepcopy(envelope)

    exit_code, stdout, _stderr = _run(json.dumps(envelope))

    assert exit_code == 0
    assert envelope == snapshot

    parsed = json.loads(stdout)
    assert list(parsed.keys()) == sorted(parsed.keys())
    round_tripped = json.dumps(parsed, sort_keys=True, ensure_ascii=False) + "\n"
    assert round_tripped == stdout
