"""Tests for core.ai_asset_registry -- the pure, deterministic AI Asset
Inventory, Provenance & Security Evaluation Lab (Combined Block 11-12).

No Supabase, MCP, file, subprocess, network, Hayabusa, or AI/model access
occurs anywhere in this file; every input is a plain in-memory value, and
every timestamp used internally by the production module is a fixed
literal -- never datetime.now(), utcnow(), or time.time(). No tool is
ever executed.

This file does not duplicate the full Block 8/9/10/Mutation-Freeze test
suites -- it tests only the inventory contract and the evaluation-lab
adapter boundary around those already-tested pure functions.
"""

import inspect

import pytest

import core.ai_asset_registry as registry_module
from core.ai_asset_registry import (
    AIAssetRegistryError,
    evaluate_ai_security_case,
    list_ai_assets,
    lookup_ai_asset,
)

_EXPECTED_COUNTS_BY_TYPE = {
    "gateway_tool": 8,
    "identity_agent": 6,
    "claude_subagent": 3,
    "claude_command": 25,
    "claude_skill": 1,
    "mcp_server": 2,
}
_EXPECTED_TOTAL = 45

_REPRESENTATIVE_ASSET_IDS = (
    "gateway_tool:load_risk_aware_approval_record",
    "identity_agent:observer_agent",
    "claude_subagent:purple-team",
    "claude_command:red-team",
    "claude_skill:detection-engineering",
    "mcp_server:supabase",
)


# ---------------------------------------------------------------------------
# Inventory: coverage and counts
# ---------------------------------------------------------------------------


def test_001_total_inventory_count_is_forty_five():
    result = list_ai_assets()
    assert result["count"] == _EXPECTED_TOTAL
    assert len(result["assets"]) == _EXPECTED_TOTAL


def test_002_exact_counts_per_asset_type():
    for asset_type, expected_count in _EXPECTED_COUNTS_BY_TYPE.items():
        result = list_ai_assets(asset_type=asset_type)
        assert result["count"] == expected_count, f"{asset_type}: expected {expected_count}, got {result['count']}"
        assert all(asset["asset_type"] == asset_type for asset in result["assets"])


def test_003_six_asset_types_present_with_no_filter():
    result = list_ai_assets()
    observed_types = {asset["asset_type"] for asset in result["assets"]}
    assert observed_types == set(_EXPECTED_COUNTS_BY_TYPE)


def test_004_representative_lookup_from_every_type():
    for asset_id in _REPRESENTATIVE_ASSET_IDS:
        result = lookup_ai_asset(asset_id=asset_id)
        assert result["found"] is True
        assert result["asset_id"] == asset_id
        assert result["asset_type"] == asset_id.split(":", 1)[0]


def test_005_all_registered_asset_ids_resolve_found_true():
    listing = list_ai_assets()
    for asset in listing["assets"]:
        result = lookup_ai_asset(asset_id=asset["asset_id"])
        assert result["found"] is True
        assert result == asset


def test_006_asset_id_format_matches_type_colon_name():
    for asset in list_ai_assets()["assets"]:
        prefix, _, name = asset["asset_id"].partition(":")
        assert prefix == asset["asset_type"]
        assert name == asset["name"]


# ---------------------------------------------------------------------------
# Inventory: unknown / invalid input
# ---------------------------------------------------------------------------


def test_007_unknown_well_formed_asset_id_found_false():
    result = lookup_ai_asset(asset_id="gateway_tool:does_not_exist")
    assert result["found"] is False
    assert result["asset_id"] == "gateway_tool:does_not_exist"
    assert result["asset_type"] is None
    assert result["name"] is None
    assert result["enabled"] is None
    assert result["declared_in"] is None
    assert result["provenance"] is None


def test_008_invalid_asset_id_raises():
    for bad_value in (None, "", "   ", 123, [], {}):
        try:
            lookup_ai_asset(asset_id=bad_value)
            assert False, f"expected AIAssetRegistryError for asset_id={bad_value!r}"
        except AIAssetRegistryError:
            pass


def test_009_invalid_asset_type_filter_raises():
    for bad_value in ("banana", "", 123, ["gateway_tool"]):
        try:
            list_ai_assets(asset_type=bad_value)
            assert False, f"expected AIAssetRegistryError for asset_type={bad_value!r}"
        except AIAssetRegistryError:
            pass


def test_010_none_asset_type_filter_returns_everything():
    result = list_ai_assets(asset_type=None)
    assert result["count"] == _EXPECTED_TOTAL


# ---------------------------------------------------------------------------
# Inventory: determinism and ordering
# ---------------------------------------------------------------------------


def test_011_list_ai_assets_deterministic_ordering():
    first = list_ai_assets()
    second = list_ai_assets()
    assert [asset["asset_id"] for asset in first["assets"]] == [asset["asset_id"] for asset in second["assets"]]


def test_012_list_ai_assets_sorted_by_asset_id():
    result = list_ai_assets()
    ids = [asset["asset_id"] for asset in result["assets"]]
    assert ids == sorted(ids)


def test_013_lookup_deterministic_repeated_calls():
    first = lookup_ai_asset(asset_id="identity_agent:coordinator_agent")
    second = lookup_ai_asset(asset_id="identity_agent:coordinator_agent")
    assert first == second


# ---------------------------------------------------------------------------
# Inventory: enabled status honesty
# ---------------------------------------------------------------------------


def test_014_disabled_gateway_tool_reports_enabled_false():
    result = lookup_ai_asset(asset_id="gateway_tool:load_approval_record")
    assert result["enabled"] is False


def test_015_disabled_identity_agent_reports_enabled_false():
    result = lookup_ai_asset(asset_id="identity_agent:disabled_agent")
    assert result["enabled"] is False


def test_016_enabled_gateway_tools_report_enabled_true():
    for name in ("load_risk_aware_approval_record", "apply_approval_consumption", "execute_sql"):
        result = lookup_ai_asset(asset_id=f"gateway_tool:{name}")
        assert result["enabled"] is True


def test_017_enabled_identity_agents_report_enabled_true():
    for name in ("observer_agent", "analyst_agent", "coordinator_agent", "reviewer_agent"):
        result = lookup_ai_asset(asset_id=f"identity_agent:{name}")
        assert result["enabled"] is True


def test_018_no_authoritative_enabled_field_reports_none():
    for asset_id in (
        "claude_subagent:purple-team",
        "claude_command:red-team",
        "claude_skill:detection-engineering",
        "mcp_server:supabase",
        "mcp_server:hayabusa",
    ):
        result = lookup_ai_asset(asset_id=asset_id)
        assert result["enabled"] is None


# ---------------------------------------------------------------------------
# Inventory: provenance and non-fabrication honesty
# ---------------------------------------------------------------------------


def test_019_provenance_tier_always_repository_declared():
    for asset in list_ai_assets()["assets"]:
        assert asset["provenance"]["tier"] == "repository_declared"
        assert isinstance(asset["provenance"]["detail"], str) and asset["provenance"]["detail"]


def test_020_no_fabricated_fields_in_asset_result():
    result = lookup_ai_asset(asset_id="gateway_tool:execute_sql")
    forbidden_fields = {"version", "hash", "digest", "timestamp", "created_at", "updated_at", "provider", "model_id"}
    assert forbidden_fields.isdisjoint(result)


def test_021_no_fabricated_fields_in_list_result():
    result = list_ai_assets()
    for asset in result["assets"]:
        forbidden_fields = {"version", "hash", "digest", "timestamp", "created_at", "updated_at", "provider", "model_id"}
        assert forbidden_fields.isdisjoint(asset)


def test_022_lookup_result_field_set_exact():
    result = lookup_ai_asset(asset_id="gateway_tool:execute_sql")
    assert set(result) == {
        "inventory_version", "asset_id", "asset_type", "found", "name", "enabled", "declared_in", "provenance",
    }


def test_023_list_result_field_set_exact():
    result = list_ai_assets(asset_type="mcp_server")
    assert set(result) == {"inventory_version", "asset_type", "count", "assets"}


# ---------------------------------------------------------------------------
# Inventory: no aliasing of internal registry state
# ---------------------------------------------------------------------------


def test_024_list_result_assets_not_aliased_across_calls():
    first = list_ai_assets()
    first["assets"].append({"asset_id": "injected"})
    first["assets"][0]["name"] = "tampered"

    second = list_ai_assets()
    assert len(second["assets"]) == _EXPECTED_TOTAL
    assert second["assets"][0]["name"] != "tampered"


def test_025_lookup_result_not_aliased_across_calls():
    first = lookup_ai_asset(asset_id="mcp_server:hayabusa")
    first["name"] = "tampered"
    first["provenance"]["tier"] = "tampered"

    second = lookup_ai_asset(asset_id="mcp_server:hayabusa")
    assert second["name"] == "hayabusa"
    assert second["provenance"]["tier"] == "repository_declared"


# ---------------------------------------------------------------------------
# Evaluation: unregistered_asset
# ---------------------------------------------------------------------------


def test_026_unregistered_gateway_tool_rejected_evaluation_passes():
    result = evaluate_ai_security_case(case_type="unregistered_asset", asset_id="gateway_tool:not_a_real_tool")
    assert result["asset_found"] is False
    assert result["evaluation_outcome"] == "pass"
    assert result["observed_decision"] == "deny"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "UNKNOWN_TOOL" in codes


def test_027_unregistered_identity_agent_rejected_evaluation_passes():
    result = evaluate_ai_security_case(case_type="unregistered_asset", asset_id="identity_agent:not_a_real_agent")
    assert result["asset_found"] is False
    assert result["evaluation_outcome"] == "pass"
    assert result["observed_decision"] == "deny"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "UNKNOWN_AGENT" in codes


def test_028_unregistered_asset_case_against_already_registered_asset_not_applicable():
    result = evaluate_ai_security_case(case_type="unregistered_asset", asset_id="gateway_tool:execute_sql")
    assert result["asset_found"] is True
    assert result["evaluation_outcome"] == "not_applicable"


def test_029_unregistered_asset_case_unrecognized_domain_not_applicable():
    result = evaluate_ai_security_case(case_type="unregistered_asset", asset_id="claude_command:not_a_real_command")
    assert result["evaluation_outcome"] == "not_applicable"


def test_030_unregistered_asset_case_malformed_prefix_not_applicable():
    result = evaluate_ai_security_case(case_type="unregistered_asset", asset_id="no-colon-at-all")
    assert result["evaluation_outcome"] == "not_applicable"


# ---------------------------------------------------------------------------
# Evaluation: identity_privilege_bypass
# ---------------------------------------------------------------------------


def test_031_identity_privilege_bypass_observer_agent_rejected():
    result = evaluate_ai_security_case(
        case_type="identity_privilege_bypass", asset_id="identity_agent:observer_agent",
    )
    assert result["evaluation_outcome"] == "pass"
    assert result["observed_decision"] == "deny"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "TOOL_NOT_IN_AGENT_ALLOWLIST" in codes


def test_032_identity_privilege_bypass_not_applicable_for_other_agent():
    result = evaluate_ai_security_case(
        case_type="identity_privilege_bypass", asset_id="identity_agent:coordinator_agent",
    )
    assert result["evaluation_outcome"] == "not_applicable"


def test_033_identity_privilege_bypass_not_applicable_for_gateway_tool():
    result = evaluate_ai_security_case(
        case_type="identity_privilege_bypass", asset_id="gateway_tool:apply_approval_consumption",
    )
    assert result["evaluation_outcome"] == "not_applicable"


def test_034_identity_privilege_bypass_not_applicable_for_unregistered_asset():
    result = evaluate_ai_security_case(
        case_type="identity_privilege_bypass", asset_id="identity_agent:ghost_agent",
    )
    assert result["asset_found"] is False
    assert result["evaluation_outcome"] == "not_applicable"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "ASSET_NOT_REGISTERED" in codes


# ---------------------------------------------------------------------------
# Evaluation: mutation_policy_bypass
# ---------------------------------------------------------------------------


def test_035_mutation_policy_bypass_never_direct_allow():
    result = evaluate_ai_security_case(
        case_type="mutation_policy_bypass", asset_id="gateway_tool:apply_approval_consumption",
    )
    assert result["evaluation_outcome"] == "pass"
    assert result["observed_decision"] == "require_approval"
    assert result["observed_decision"] != "allow"


def test_036_mutation_policy_bypass_not_applicable_for_read_only_tool():
    result = evaluate_ai_security_case(
        case_type="mutation_policy_bypass", asset_id="gateway_tool:load_risk_aware_approval_record",
    )
    assert result["evaluation_outcome"] == "not_applicable"


def test_037_mutation_policy_bypass_not_applicable_for_identity_agent():
    result = evaluate_ai_security_case(
        case_type="mutation_policy_bypass", asset_id="identity_agent:coordinator_agent",
    )
    assert result["evaluation_outcome"] == "not_applicable"


# ---------------------------------------------------------------------------
# Evaluation: emergency_freeze_bypass
# ---------------------------------------------------------------------------


def test_038_emergency_freeze_bypass_denies_eligible_mutation():
    result = evaluate_ai_security_case(
        case_type="emergency_freeze_bypass", asset_id="identity_agent:coordinator_agent",
    )
    assert result["evaluation_outcome"] == "pass"
    assert result["observed_decision"] == "deny"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert codes == ["MUTATION_FREEZE_ACTIVE"]


def test_039_emergency_freeze_bypass_not_applicable_for_observer_agent():
    result = evaluate_ai_security_case(
        case_type="emergency_freeze_bypass", asset_id="identity_agent:observer_agent",
    )
    assert result["evaluation_outcome"] == "not_applicable"


def test_040_emergency_freeze_bypass_not_applicable_for_claude_command():
    result = evaluate_ai_security_case(
        case_type="emergency_freeze_bypass", asset_id="claude_command:red-team",
    )
    assert result["evaluation_outcome"] == "not_applicable"


# ---------------------------------------------------------------------------
# Evaluation: decision_binding_substitution
# ---------------------------------------------------------------------------


def test_041_decision_binding_substitution_detects_substituted_approval_id():
    # The exact arguments evaluated by Block 9 are the same exact
    # arguments bound by Block 10 -- verification then substitutes a
    # second fixed, valid approval_id (the tool's real, flat argument
    # schema; never a nested structure) and must detect the mismatch.
    result = evaluate_ai_security_case(
        case_type="decision_binding_substitution", asset_id="identity_agent:coordinator_agent",
    )
    assert result["evaluation_outcome"] == "pass"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "ARGUMENT_DIGEST_MISMATCH" in codes


def test_042_decision_binding_substitution_observed_decision_is_none():
    # There is no allow/require_approval/deny production decision observed
    # by this case -- only a Block 10 verification_outcome, which is a
    # different vocabulary and never crammed into observed_decision.
    result = evaluate_ai_security_case(
        case_type="decision_binding_substitution", asset_id="identity_agent:coordinator_agent",
    )
    assert result["observed_decision"] is None


def test_043_decision_binding_substitution_not_applicable_for_observer_agent():
    result = evaluate_ai_security_case(
        case_type="decision_binding_substitution", asset_id="identity_agent:observer_agent",
    )
    assert result["evaluation_outcome"] == "not_applicable"


def test_044_decision_binding_substitution_not_applicable_for_claude_skill():
    result = evaluate_ai_security_case(
        case_type="decision_binding_substitution", asset_id="claude_skill:detection-engineering",
    )
    assert result["evaluation_outcome"] == "not_applicable"


# ---------------------------------------------------------------------------
# Evaluation: cross-cutting contract checks
# ---------------------------------------------------------------------------


def test_045_evaluation_outcome_never_reuses_policy_vocabulary():
    scenarios = [
        ("unregistered_asset", "gateway_tool:not_a_real_tool"),
        ("identity_privilege_bypass", "identity_agent:observer_agent"),
        ("mutation_policy_bypass", "gateway_tool:apply_approval_consumption"),
        ("emergency_freeze_bypass", "identity_agent:coordinator_agent"),
        ("decision_binding_substitution", "identity_agent:coordinator_agent"),
        ("emergency_freeze_bypass", "claude_command:red-team"),
    ]
    for case_type, asset_id in scenarios:
        result = evaluate_ai_security_case(case_type=case_type, asset_id=asset_id)
        assert result["evaluation_outcome"] in ("pass", "fail", "not_applicable")
        assert result["evaluation_outcome"] not in ("allow", "require_approval", "deny")


def test_046_execution_performed_always_false():
    scenarios = [
        ("unregistered_asset", "gateway_tool:not_a_real_tool"),
        ("identity_privilege_bypass", "identity_agent:observer_agent"),
        ("mutation_policy_bypass", "gateway_tool:apply_approval_consumption"),
        ("emergency_freeze_bypass", "identity_agent:coordinator_agent"),
        ("decision_binding_substitution", "identity_agent:coordinator_agent"),
    ]
    for case_type, asset_id in scenarios:
        result = evaluate_ai_security_case(case_type=case_type, asset_id=asset_id)
        assert result["execution_performed"] is False


def test_047_result_field_set_exact():
    result = evaluate_ai_security_case(case_type="identity_privilege_bypass", asset_id="identity_agent:observer_agent")
    assert set(result) == {
        "evaluation_version", "case_type", "asset_id", "asset_found", "evaluation_outcome",
        "expected_property", "observed_decision", "observed_evidence", "execution_performed",
    }
    assert "evaluated_at" not in result


def test_048_evidence_items_have_stable_minimum_shape():
    result = evaluate_ai_security_case(case_type="identity_privilege_bypass", asset_id="identity_agent:observer_agent")
    for item in result["observed_evidence"]:
        assert {"code", "severity", "message"} <= set(item)


def test_049_not_applicable_evidence_has_no_fabricated_affects_decision():
    result = evaluate_ai_security_case(case_type="mutation_policy_bypass", asset_id="identity_agent:coordinator_agent")
    assert result["evaluation_outcome"] == "not_applicable"
    for item in result["observed_evidence"]:
        assert item["code"] == "CASE_NOT_APPLICABLE"
        assert set(item) == {"code", "severity", "message"}


def test_050_deterministic_repeated_evaluation():
    first = evaluate_ai_security_case(case_type="emergency_freeze_bypass", asset_id="identity_agent:coordinator_agent")
    second = evaluate_ai_security_case(case_type="emergency_freeze_bypass", asset_id="identity_agent:coordinator_agent")
    assert first == second


def test_051_non_registered_asset_in_non_unregistered_case_gives_defined_result_not_crash():
    for case_type in (
        "identity_privilege_bypass", "mutation_policy_bypass", "emergency_freeze_bypass", "decision_binding_substitution",
    ):
        result = evaluate_ai_security_case(case_type=case_type, asset_id="identity_agent:completely_made_up")
        assert result["asset_found"] is False
        assert result["evaluation_outcome"] == "not_applicable"


def test_052_invalid_case_type_raises():
    for bad_value in (None, "", "banana", "PROMPT_INJECTION", 123, ["identity_privilege_bypass"]):
        try:
            evaluate_ai_security_case(case_type=bad_value, asset_id="identity_agent:observer_agent")
            assert False, f"expected AIAssetRegistryError for case_type={bad_value!r}"
        except AIAssetRegistryError:
            pass


def test_053_invalid_asset_id_raises_in_evaluation():
    for bad_value in (None, "", "   ", 123):
        try:
            evaluate_ai_security_case(case_type="identity_privilege_bypass", asset_id=bad_value)
            assert False, f"expected AIAssetRegistryError for asset_id={bad_value!r}"
        except AIAssetRegistryError:
            pass


def test_054_excluded_case_types_are_not_supported():
    for excluded in ("prompt_injection", "jailbreak", "excessive_agency", "provenance_mismatch"):
        try:
            evaluate_ai_security_case(case_type=excluded, asset_id="identity_agent:observer_agent")
            assert False, f"expected AIAssetRegistryError for excluded case_type={excluded!r}"
        except AIAssetRegistryError:
            pass


def test_055_asset_found_field_matches_inventory():
    registered = evaluate_ai_security_case(case_type="mutation_policy_bypass", asset_id="gateway_tool:apply_approval_consumption")
    assert registered["asset_found"] is True

    unregistered = evaluate_ai_security_case(case_type="mutation_policy_bypass", asset_id="gateway_tool:not_registered")
    assert unregistered["asset_found"] is False


# ---------------------------------------------------------------------------
# Purity / structural boundary
# ---------------------------------------------------------------------------


def test_056_module_never_reads_clock_env_filesystem_network_mcp_database():
    # Only the executable code is inspected, not the module docstring --
    # the docstring itself names "subprocess"/"MCP"/etc. in prose to
    # explain that this module never performs them, which would otherwise
    # trip this same substring check.
    full_source = inspect.getsource(registry_module)
    source = full_source.split("from __future__", 1)[1]
    forbidden_substrings = (
        "datetime.now",
        "utcnow",
        "time.time",
        "os.environ",
        "os.getenv",
        "open(",
        "Path(",
        "glob.glob",
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "mcp__",
        "random.",
    )
    for forbidden in forbidden_substrings:
        assert forbidden not in source, f"forbidden substring found: {forbidden!r}"


def test_057_module_only_imports_the_four_pure_blocks():
    source = inspect.getsource(registry_module)
    assert "from core.agent_gateway import evaluate_tool_call" in source
    assert "from core.agent_identity_policy import evaluate_agent_tool_call" in source
    assert "from core.mutation_freeze import evaluate_mutation_freeze" in source
    assert "from core.decision_binding import create_decision_binding, verify_decision_binding" in source


def test_058_mcp_example_json_path_never_reads_real_mcp_json():
    source = inspect.getsource(registry_module)
    assert '".mcp.json"' not in source
    assert ".mcp.example.json" in source


# ---------------------------------------------------------------------------
# Block 15A additions: discoverability and honest provenance
# ---------------------------------------------------------------------------


def test_059_bug_bounty_gateway_tool_discoverable():
    result = lookup_ai_asset(asset_id="gateway_tool:run_bug_bounty_assessment")
    assert result["found"] is True
    assert result["asset_type"] == "gateway_tool"
    assert result["enabled"] is True
    assert result["declared_in"] == "core/agent_gateway.py::_REGISTRY"


def test_060_bug_bounty_identity_agent_discoverable():
    result = lookup_ai_asset(asset_id="identity_agent:bug_bounty_agent")
    assert result["found"] is True
    assert result["asset_type"] == "identity_agent"
    assert result["enabled"] is True
    assert result["declared_in"] == "core/agent_identity_policy.py::_REGISTRY"


def test_061_bug_bounty_claude_subagent_discoverable():
    result = lookup_ai_asset(asset_id="claude_subagent:bug-bounty")
    assert result["found"] is True
    assert result["asset_type"] == "claude_subagent"
    assert result["declared_in"] == ".claude/agents/bug-bounty.md"


def test_062_bug_bounty_claude_command_discoverable():
    result = lookup_ai_asset(asset_id="claude_command:bug-bounty")
    assert result["found"] is True
    assert result["asset_type"] == "claude_command"
    assert result["declared_in"] == ".claude/commands/bug-bounty.md"


def test_063_new_assets_provenance_is_repository_declared_not_verified():
    for asset_id in (
        "gateway_tool:run_bug_bounty_assessment",
        "identity_agent:bug_bounty_agent",
        "claude_subagent:bug-bounty",
        "claude_command:bug-bounty",
    ):
        result = lookup_ai_asset(asset_id=asset_id)
        assert result["provenance"]["tier"] == "repository_declared"
        assert "verified" not in result["provenance"]["tier"]
        assert "authenticated" not in result["provenance"]["tier"]


def test_064_existing_assets_unchanged_by_block_15a_additions():
    for asset_id in _REPRESENTATIVE_ASSET_IDS:
        result = lookup_ai_asset(asset_id=asset_id)
        assert result["found"] is True

    unaffected = lookup_ai_asset(asset_id="identity_agent:coordinator_agent")
    assert unaffected["enabled"] is True
    assert unaffected["asset_type"] == "identity_agent"


# ---------------------------------------------------------------------------
# B2 registry-consistency fix: previously undeclared, already-existing
# Claude commands from Blocks 13-15
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "ai-security-lab", "record-analyst-feedback", "audit-dashboard", "integration-demo", "bug-bounty",
])
def test_065_recent_command_assets_individually_discoverable(name):
    result = lookup_ai_asset(asset_id=f"claude_command:{name}")
    assert result["found"] is True
    assert result["asset_type"] == "claude_command"
    assert result["declared_in"] == f".claude/commands/{name}.md"


def test_066_historical_command_additions_provenance_is_repository_declared_not_verified():
    for name in ("ai-security-lab", "record-analyst-feedback", "audit-dashboard", "integration-demo"):
        result = lookup_ai_asset(asset_id=f"claude_command:{name}")
        assert result["provenance"]["tier"] == "repository_declared"
        assert "verified" not in result["provenance"]["tier"]
        assert "authenticated" not in result["provenance"]["tier"]
        assert "signature" not in str(result["provenance"]).lower()


def test_067_no_duplicate_asset_ids_in_full_inventory():
    listing = list_ai_assets()
    ids = [asset["asset_id"] for asset in listing["assets"]]
    assert len(ids) == len(set(ids))


def test_068_claude_command_registry_matches_actual_command_file_count():
    result = list_ai_assets(asset_type="claude_command")
    assert result["count"] == 25


def test_069_existing_evaluation_lab_behavior_unchanged_by_registry_additions():
    result = evaluate_ai_security_case(
        case_type="emergency_freeze_bypass", asset_id="identity_agent:coordinator_agent",
    )
    assert result["evaluation_outcome"] == "pass"
