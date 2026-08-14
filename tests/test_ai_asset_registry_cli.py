"""Tests for core.ai_asset_registry_cli -- the stdin/stdout JSON adapter
around core.ai_asset_registry's lookup_ai_asset, list_ai_assets, and
evaluate_ai_security_case (Combined Block 11-12).

main() is called directly with in-memory StringIO streams. No Supabase,
MCP, file, subprocess, network, Hayabusa, or AI/model access occurs
anywhere in this file. No tool is ever executed.

This file does not re-verify every core.ai_asset_registry validation
case (see tests/test_ai_asset_registry.py for the 58 core tests) -- it
tests only the CLI's own adapter boundary: envelope dispatch,
pass-through, exit codes, and output/error shape.
"""

import inspect
import json
from io import StringIO

from core import ai_asset_registry_cli

_LOOKUP_RESULT_FIELDS = {
    "inventory_version", "asset_id", "asset_type", "found", "name", "enabled", "declared_in", "provenance",
}
_LIST_RESULT_FIELDS = {"inventory_version", "asset_type", "count", "assets"}
_EVALUATE_RESULT_FIELDS = {
    "evaluation_version", "case_type", "asset_id", "asset_found", "evaluation_outcome",
    "expected_property", "observed_decision", "observed_evidence", "execution_performed",
}

_ALL_CASE_TYPES = (
    "unregistered_asset",
    "identity_privilege_bypass",
    "mutation_policy_bypass",
    "emergency_freeze_bypass",
    "decision_binding_substitution",
)

_ALL_ASSET_TYPES = (
    "gateway_tool", "identity_agent", "claude_subagent", "claude_command", "claude_skill", "mcp_server",
)


def _lookup_envelope(**overrides):
    envelope = {"operation": "lookup", "asset_id": "gateway_tool:execute_sql"}
    envelope.update(overrides)
    return envelope


def _list_envelope(**overrides):
    envelope = {"operation": "list", "asset_type": None}
    envelope.update(overrides)
    return envelope


def _evaluate_envelope(**overrides):
    envelope = {
        "operation": "evaluate",
        "case_type": "identity_privilege_bypass",
        "asset_id": "identity_agent:observer_agent",
    }
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = ai_asset_registry_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback",
        "AIAssetRegistryError",
        "ValueError",
        "RuntimeError",
        "KeyError",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------


def test_001_lookup_registered_asset_found_true():
    exit_code, stdout, stderr = _run(json.dumps(_lookup_envelope()))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert set(result) == _LOOKUP_RESULT_FIELDS
    assert result["found"] is True
    assert result["asset_id"] == "gateway_tool:execute_sql"


def test_002_lookup_unknown_well_formed_asset_found_false():
    exit_code, stdout, stderr = _run(json.dumps(_lookup_envelope(asset_id="gateway_tool:not_a_real_tool")))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["found"] is False
    assert result["asset_id"] == "gateway_tool:not_a_real_tool"
    assert result["asset_type"] is None


def test_003_lookup_representative_assets_from_multiple_types():
    representative_ids = (
        "gateway_tool:load_risk_aware_approval_record",
        "identity_agent:observer_agent",
        "claude_subagent:purple-team",
        "claude_command:red-team",
        "claude_skill:detection-engineering",
        "mcp_server:supabase",
    )
    for asset_id in representative_ids:
        exit_code, stdout, _ = _run(json.dumps(_lookup_envelope(asset_id=asset_id)))
        assert exit_code == 0
        result = json.loads(stdout)
        assert result["found"] is True
        assert result["asset_id"] == asset_id


def test_004_lookup_key_order_independence():
    envelope = _lookup_envelope()
    forward = json.dumps(envelope)
    reordered = json.dumps(dict(reversed(list(envelope.items()))))

    exit_code1, stdout1, _ = _run(forward)
    exit_code2, stdout2, _ = _run(reordered)

    assert exit_code1 == 0
    assert exit_code2 == 0
    assert json.loads(stdout1) == json.loads(stdout2)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def test_005_list_all_assets_count_fifty_four():
    exit_code, stdout, stderr = _run(json.dumps(_list_envelope()))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert set(result) == _LIST_RESULT_FIELDS
    assert result["count"] == 54
    assert len(result["assets"]) == 54


def test_006_list_filter_each_asset_type():
    expected_counts = {
        "gateway_tool": 8,
        "identity_agent": 6,
        "claude_subagent": 5,
        "claude_command": 32,
        "claude_skill": 1,
        "mcp_server": 2,
    }
    for asset_type, expected_count in expected_counts.items():
        exit_code, stdout, _ = _run(json.dumps(_list_envelope(asset_type=asset_type)))
        assert exit_code == 0
        result = json.loads(stdout)
        assert result["count"] == expected_count
        assert all(asset["asset_type"] == asset_type for asset in result["assets"])


def test_007_list_asset_type_null_returns_everything():
    exit_code, stdout, _ = _run(json.dumps(_list_envelope(asset_type=None)))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["count"] == 54
    assert result["asset_type"] is None


def test_008_list_deterministic_sorted_output():
    raw_input = json.dumps(_list_envelope())
    _, stdout1, _ = _run(raw_input)
    _, stdout2, _ = _run(raw_input)
    assert stdout1 == stdout2

    result = json.loads(stdout1)
    ids = [asset["asset_id"] for asset in result["assets"]]
    assert ids == sorted(ids)


def test_009_list_invalid_asset_type_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_list_envelope(asset_type="not_a_real_type")))
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("AI asset registry CLI validation failed:")
    _assert_no_forbidden_content(stderr)


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


def test_010_evaluate_representative_passing_evaluation():
    exit_code, stdout, stderr = _run(json.dumps(_evaluate_envelope()))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert set(result) == _EVALUATE_RESULT_FIELDS
    assert result["evaluation_outcome"] == "pass"
    assert result["case_type"] == "identity_privilege_bypass"


def test_011_evaluate_not_applicable_is_exit_zero():
    exit_code, stdout, stderr = _run(json.dumps(_evaluate_envelope(
        case_type="mutation_policy_bypass", asset_id="claude_command:red-team",
    )))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["evaluation_outcome"] == "not_applicable"


def test_012_evaluate_all_five_case_types_accepted_by_adapter():
    for case_type in _ALL_CASE_TYPES:
        exit_code, stdout, stderr = _run(json.dumps(_evaluate_envelope(
            case_type=case_type, asset_id="identity_agent:observer_agent",
        )))
        assert exit_code == 0, f"case_type={case_type} unexpectedly failed: {stderr}"
        assert stderr == ""
        result = json.loads(stdout)
        assert result["case_type"] == case_type
        assert result["evaluation_outcome"] in ("pass", "fail", "not_applicable")


def test_013_evaluate_execution_performed_always_false():
    for case_type in _ALL_CASE_TYPES:
        exit_code, stdout, _ = _run(json.dumps(_evaluate_envelope(
            case_type=case_type, asset_id="identity_agent:observer_agent",
        )))
        result = json.loads(stdout)
        assert result["execution_performed"] is False


def test_014_evaluate_unregistered_asset_case_passes():
    exit_code, stdout, stderr = _run(json.dumps(_evaluate_envelope(
        case_type="unregistered_asset", asset_id="gateway_tool:definitely_not_registered",
    )))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["asset_found"] is False
    assert result["evaluation_outcome"] == "pass"


# ---------------------------------------------------------------------------
# Envelope failures
# ---------------------------------------------------------------------------


def test_015_malformed_json_input():
    exit_code, stdout, stderr = _run("{not valid json")
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("AI asset registry CLI validation failed:")
    _assert_no_forbidden_content(stderr)


def test_016_non_object_top_level_json_rejected():
    for bad_payload in (json.dumps([1, 2, 3]), json.dumps("just a string"), json.dumps(None)):
        exit_code, stdout, stderr = _run(bad_payload)
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("AI asset registry CLI validation failed:")
        _assert_no_forbidden_content(stderr)


def test_017_missing_operation_rejected():
    envelope = _lookup_envelope()
    del envelope["operation"]
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""


def test_018_unknown_operation_rejected():
    exit_code, stdout, stderr = _run(json.dumps(_lookup_envelope(operation="delete")))
    assert exit_code == 2
    assert stdout == ""
    assert "operation" in stderr


def test_019_lookup_missing_asset_id_rejected():
    envelope = _lookup_envelope()
    del envelope["asset_id"]
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""
    assert "asset_id" in stderr


def test_020_lookup_extra_field_rejected():
    envelope = _lookup_envelope()
    envelope["unexpected_field"] = "nope"
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""
    assert "unexpected_field" in stderr


def test_021_list_missing_asset_type_key_rejected():
    envelope = _list_envelope()
    del envelope["asset_type"]
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""
    assert "asset_type" in stderr


def test_022_list_extra_field_rejected():
    envelope = _list_envelope()
    envelope["unexpected_field"] = "nope"
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""
    assert "unexpected_field" in stderr


def test_023_evaluate_missing_case_type_rejected():
    envelope = _evaluate_envelope()
    del envelope["case_type"]
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""
    assert "case_type" in stderr


def test_024_evaluate_missing_asset_id_rejected():
    envelope = _evaluate_envelope()
    del envelope["asset_id"]
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""
    assert "asset_id" in stderr


def test_025_evaluate_extra_field_rejected():
    envelope = _evaluate_envelope()
    envelope["unexpected_field"] = "nope"
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""
    assert "unexpected_field" in stderr


# ---------------------------------------------------------------------------
# Core-level typed validation errors surfaced through the CLI
# ---------------------------------------------------------------------------


def test_026_lookup_blank_asset_id_core_validation_error_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_lookup_envelope(asset_id="   ")))
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("AI asset registry CLI validation failed:")
    _assert_no_forbidden_content(stderr)


def test_027_list_non_string_asset_type_core_validation_error_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_list_envelope(asset_type=123)))
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("AI asset registry CLI validation failed:")


def test_028_evaluate_invalid_case_type_core_validation_error_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_evaluate_envelope(case_type="prompt_injection")))
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("AI asset registry CLI validation failed:")
    _assert_no_forbidden_content(stderr)


# ---------------------------------------------------------------------------
# Adapter / security behavior
# ---------------------------------------------------------------------------


def test_029_stdout_contains_exactly_one_sorted_json_line():
    for envelope in (_lookup_envelope(), _list_envelope(), _evaluate_envelope()):
        exit_code, stdout, _ = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stdout.endswith("\n")
        assert stdout.count("\n") == 1
        result = json.loads(stdout)
        reserialized = json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n"
        assert reserialized == stdout


def test_030_no_stderr_on_any_handled_result():
    for envelope in (
        _lookup_envelope(),
        _lookup_envelope(asset_id="gateway_tool:unknown"),
        _list_envelope(),
        _evaluate_envelope(),
        _evaluate_envelope(case_type="mutation_policy_bypass", asset_id="claude_skill:detection-engineering"),
    ):
        exit_code, _, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stderr == ""


def test_031_unexpected_internal_failure_is_exit_one(monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("secret internal detail XYZ123")

    monkeypatch.setattr(ai_asset_registry_cli, "lookup_ai_asset", _boom)
    exit_code, stdout, stderr = _run(json.dumps(_lookup_envelope()))

    assert exit_code == 1
    assert stdout == ""
    assert stderr.startswith("AI asset registry CLI internal error:")
    assert "secret internal detail" not in stderr
    _assert_no_forbidden_content(stderr)


def test_032_no_traceback_leakage_across_error_paths():
    error_payloads = (
        "{not valid json",
        json.dumps([1, 2, 3]),
        json.dumps(_lookup_envelope(operation="bogus")),
        json.dumps(_list_envelope(asset_type="nonsense")),
        json.dumps(_evaluate_envelope(case_type="jailbreak")),
    )
    for payload in error_payloads:
        _, stdout, stderr = _run(payload)
        assert stdout == ""
        _assert_no_forbidden_content(stderr)


def test_033_cli_never_touches_filesystem_network_clock_mcp_database():
    full_source = inspect.getsource(ai_asset_registry_cli)
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
        "supabase",
        "random.",
    )
    for forbidden in forbidden_substrings:
        assert forbidden not in source, f"forbidden substring found: {forbidden!r}"


def test_034_cli_never_imports_block8_block9_block10_or_mutation_freeze_directly():
    full_source = inspect.getsource(ai_asset_registry_cli)
    source = full_source.split("from __future__", 1)[1]
    forbidden_imports = (
        "core.agent_gateway",
        "core.agent_identity_policy",
        "core.decision_binding",
        "core.mutation_freeze",
    )
    for forbidden in forbidden_imports:
        assert forbidden not in source, f"forbidden import found: {forbidden!r}"
    assert "from core.ai_asset_registry import" in source
