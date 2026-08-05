"""Static tests for the Block 9 Agent Identity and Least Privilege closure
documentation: README.md's project-status update and
docs/block9-agent-identity.md.

These tests only read repository text files and check their content
structurally. They never execute a ThreatTrace command, never invoke any
project CLI, never call Supabase or MCP, never execute SQL or an RPC,
never invoke Hayabusa, never access the network, never launch a shell
command, and never modify any file.

Exactly 6 tests are defined below.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README_PATH = REPO_ROOT / "README.md"
BLOCK9_PATH = REPO_ROOT / "docs" / "block9-agent-identity.md"

FIVE_ROLES = (
    "observer", "analyst", "investigation_coordinator", "approval_reviewer", "disabled",
)

FIVE_AGENTS = (
    "observer_agent", "analyst_agent", "coordinator_agent", "reviewer_agent", "disabled_agent",
)

FIFTEEN_RESULT_FIELDS = (
    "identity_policy_version", "canonical_agent_id", "agent_role", "identity_authenticated",
    "canonical_tool_name", "operation_class", "gateway_decision", "final_decision",
    "eligible_for_execution", "requires_approval", "matched_identity_rules",
    "safe_capability_summary", "required_next_action", "evaluated_at", "execution_performed",
)

FIVE_SUMMARY_FIELDS = (
    "role", "requested_tool_allowed", "requested_operation_class_permitted",
    "mutation_request_allowed", "allowed_tool_count",
)

RULE_ORDER = (
    "UNKNOWN_AGENT",
    "AGENT_DISABLED",
    "GATEWAY_DENIED",
    "OPERATION_CLASS_NOT_PERMITTED",
    "TOOL_NOT_IN_AGENT_ALLOWLIST",
    "MUTATION_REQUEST_NOT_PERMITTED",
    "GATEWAY_APPROVAL_REQUIRED",
    "IDENTITY_POLICY_ALLOWED",
    "CLAIMED_IDENTITY_NOT_AUTHENTICATED",
    "EXECUTION_NOT_PERFORMED",
)


@pytest.fixture(scope="module")
def readme_text():
    return README_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def block9_text():
    return BLOCK9_PATH.read_text(encoding="utf-8")


def _ordered_indices(text, needles):
    indices = []
    search_start = 0
    for needle in needles:
        idx = text.find(needle, search_start)
        assert idx != -1, f"not found in expected order: {needle!r}"
        indices.append(idx)
        search_start = idx + len(needle)
    return indices


def _section(text, heading, next_heading):
    start = text.find(heading)
    assert start != -1, f"heading not found: {heading}"
    end = text.find(next_heading, start + len(heading))
    assert end != -1, f"end marker not found after {heading}: {next_heading}"
    return text[start:end]


# ---------------------------------------------------------------------------
# 1: README marks the Block 9 MVP complete and links to the canonical doc
# ---------------------------------------------------------------------------


def test_001_readme_marks_block9_mvp_complete_and_links_to_block9_document(readme_text):
    assert "Block 9" in readme_text
    assert "MVP is complete" in readme_text
    assert "[docs/block9-agent-identity.md](docs/block9-agent-identity.md)" in readme_text
    assert "claimed" in readme_text
    assert "`identity_authenticated` is always `false`" in readme_text
    assert "`execution_performed` is always `false`" in readme_text
    assert "five-scenario demonstration" in readme_text
    assert "**Block 10** begins with a separate, read-only architecture audit" in readme_text


# ---------------------------------------------------------------------------
# 2: roles, registry, and combined capability model
# ---------------------------------------------------------------------------


def test_002_document_contains_roles_registry_and_capability_model(block9_text):
    for role in FIVE_ROLES:
        assert f"`{role}`" in block9_text, f"missing role: {role}"

    for agent in FIVE_AGENTS:
        assert f"`{agent}`" in block9_text, f"missing agent: {agent}"

    assert "case-sensitive" in block9_text
    assert "alias-free" in block9_text
    assert "fuzzy-match-free" in block9_text

    registry_section = _section(block9_text, "## Immutable Agent Registry", "## Combined Capability Model")
    assert "immutable" in registry_section
    assert "MappingProxyType" in registry_section
    assert "frozen dataclass" in registry_section
    assert "frozenset" in registry_section

    ceiling_section = _section(block9_text, "## Fixed Roles", "## Immutable Agent Registry")
    assert "Permitted operation classes" in ceiling_section

    capability_section = _section(block9_text, "## Combined Capability Model", "## Integration with Block 8")
    assert "operation-class ceiling permits" in capability_section
    assert "canonical-tool allowlist" in capability_section
    assert "`mutation_request_allowed`" in capability_section


# ---------------------------------------------------------------------------
# 3: exact fifteen-field result contract and five-field capability summary
# ---------------------------------------------------------------------------


def test_003_document_contains_exact_result_and_summary_contracts(block9_text):
    contract_section = _section(block9_text, "## Result Contract", "## Safe Capability Summary")

    for field in FIFTEEN_RESULT_FIELDS:
        assert f"`{field}`" in contract_section, f"missing result field: {field}"

    assert '`identity_policy_version` is always `"1"`' in contract_section
    assert "`identity_authenticated` is always `false`" in contract_section
    assert "`execution_performed` is always `false`" in contract_section

    assert "`required_next_action` = `proceed_to_separate_execution_boundary`" in contract_section
    assert "`required_next_action` = `submit_to_approval_workflow`" in contract_section
    assert "`required_next_action` = `do_not_execute`" in contract_section

    summary_section = _section(block9_text, "## Safe Capability Summary", "## Structural Validation vs. Policy Denial")
    for field in FIVE_SUMMARY_FIELDS:
        assert f"`{field}`" in summary_section, f"missing summary field: {field}"


# ---------------------------------------------------------------------------
# 4: exact ten-rule order and gateway-to-final monotonicity
# ---------------------------------------------------------------------------


def test_004_document_contains_exact_rule_order_and_monotonicity(block9_text):
    rule_section = _section(block9_text, "## Fixed Identity-Rule Order", "## Result Contract")
    indices = _ordered_indices(rule_section, [f"`{code}`" for code in RULE_ORDER])
    assert indices == sorted(indices)
    assert "Exactly ten rules exist" in rule_section
    assert "no invented eleventh rule" in rule_section

    monotonicity_section = _section(
        block9_text, "## Gateway-to-Final Monotonicity", "## Fixed Identity-Rule Order"
    )
    assert "`deny` | `deny` only" in monotonicity_section
    assert "`require_approval` | `require_approval` or `deny`" in monotonicity_section
    assert "`allow` | `allow` or `deny`" in monotonicity_section
    assert "`null` (unknown/disabled agent) | `deny` only" in monotonicity_section
    assert "`deny` → `require_approval`" in monotonicity_section
    assert "`deny` → `allow`" in monotonicity_section
    assert "`require_approval` → `allow`" in monotonicity_section


# ---------------------------------------------------------------------------
# 5: local five-scenario demonstration and identity honesty
# ---------------------------------------------------------------------------


def test_005_document_contains_five_scenarios_and_honesty_facts(block9_text):
    demo_section = _section(block9_text, "## Local Five-Scenario Demonstration", "## Automated Verification")

    assert "### Analyst read-only allow" in demo_section
    assert "### Observer allowlist denial" in demo_section
    assert "### Analyst mutation denial" in demo_section
    assert "### Coordinator mutation request" in demo_section
    assert "### Unknown claimed agent" in demo_section

    assert "the lookup itself was never executed" in demo_section
    assert "No approval was created and no mutation was executed" in demo_section
    assert "no approval workflow was invoked" in demo_section
    assert "Block 8 was never reached" in demo_section
    assert "the raw unknown claimed identity was never disclosed" in demo_section
    assert "`identity_authenticated` was `false` in every report" in demo_section
    assert "`execution_performed` was `false` in every report" in demo_section
    assert "no known agent was substituted in its place" in demo_section


# ---------------------------------------------------------------------------
# 6: security boundaries, limitations, roadmap, and next block
# ---------------------------------------------------------------------------


def test_006_document_contains_security_limitations_roadmap_and_next_block(block9_text):
    identity_section = _section(block9_text, "## Claimed Identity Is Not Authentication", "## Fixed Roles")
    assert "proves only that the caller typed a string equal to a known registry key" in block9_text
    assert "no caller-selected role or capability ever accepted" in identity_section
    assert "Impersonation" in identity_section
    assert "remains an explicitly documented limitation" in identity_section

    no_fallback_section = _section(block9_text, "## No-Retry and No-Fallback Behavior", "## Advisory Block 6 Integration")
    assert "substitutes `coordinator_agent`" in no_fallback_section
    assert "enables a disabled agent" in no_fallback_section

    security_section = _section(block9_text, "## Security and Safe-Output Controls", "## No-Retry and No-Fallback Behavior")
    assert "caller-selected roles" in security_section
    assert "caller-selected capabilities" in security_section
    assert "complete tool allowlist" in security_section

    advisory_section = _section(block9_text, "## Advisory Block 6 Integration", "## Local Five-Scenario Demonstration")
    assert "advisory only" in advisory_section
    assert "never automatically invoked" in advisory_section

    assert "## Presentation Walkthrough" in block9_text
    assert "## Limitations" in block9_text
    assert "## Future Authentication Roadmap" in block9_text
    assert "not implemented" in block9_text
    assert "## Next Block" in block9_text

    next_block_section = block9_text[block9_text.find("## Next Block"):]
    assert "separate, read-only architecture audit" in next_block_section
    assert "does not invent or implement Block 10" in next_block_section
