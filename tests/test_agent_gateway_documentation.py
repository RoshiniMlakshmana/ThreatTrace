"""Static tests for the Block 8 AI Agent Gateway / Runtime Firewall
closure documentation: README.md's project-status update and
docs/block8-agent-gateway.md.

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
BLOCK8_PATH = REPO_ROOT / "docs" / "block8-agent-gateway.md"

TWELVE_RESULT_FIELDS = (
    "gateway_version", "canonical_tool_name", "operation_class", "decision",
    "eligible_for_execution", "requires_approval", "matched_rules", "safe_argument_summary",
    "blocked_argument_fields", "required_next_action", "evaluated_at", "execution_performed",
)

OPERATION_CLASSES = (
    "read_only", "state_mutation", "approval_mutation",
    "schema_mutation", "external_side_effect", "prohibited",
)

RULE_ORDER = (
    "UNKNOWN_TOOL",
    "TOOL_DISABLED",
    "MALFORMED_ARGUMENTS",
    "MISSING_ARGUMENT",
    "UNKNOWN_ARGUMENT",
    "PROHIBITED_ARGUMENT",
    "SCHEMA_MUTATION_DENIED",
    "GENERIC_SQL_TOOL_DENIED",
    "EXTERNAL_SIDE_EFFECT_DENIED",
    "MUTATION_REQUIRES_APPROVAL",
    "APPROVAL_MUTATION_RESTRICTED",
    "READ_ONLY_TOOL_ALLOWED",
    "SENSITIVE_ARGUMENT_SUPPRESSED",
    "EXECUTION_NOT_PERFORMED",
)


@pytest.fixture(scope="module")
def readme_text():
    return README_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def block8_text():
    return BLOCK8_PATH.read_text(encoding="utf-8")


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
# 1: README marks the Block 8 MVP complete and links to the canonical doc
# ---------------------------------------------------------------------------


def test_001_readme_marks_block8_mvp_complete_and_links_to_block8_document(readme_text):
    assert "Block 8" in readme_text
    assert "MVP is complete" in readme_text
    assert "[docs/block8-agent-gateway.md](docs/block8-agent-gateway.md)" in readme_text


# ---------------------------------------------------------------------------
# 2: decision vocabulary, operation classes, registered-tool categories
# ---------------------------------------------------------------------------


def test_002_document_contains_decisions_classes_and_registered_tools(block8_text):
    assert "`allow`" in block8_text
    assert "`require_approval`" in block8_text
    assert "`deny`" in block8_text

    for operation_class in OPERATION_CLASSES:
        assert f"`{operation_class}`" in block8_text, f"missing operation class: {operation_class}"

    registry_section = _section(block8_text, "## Immutable Tool Registry", "## Argument Validation")
    assert "`load_risk_aware_approval_record`" in registry_section
    assert "`load_investigation_approval_context`" in registry_section
    assert "`apply_approval_consumption`" in registry_section
    assert "`load_approval_record`" in registry_section
    assert "`apply_migration`" in registry_section
    assert "`execute_sql`" in registry_section
    assert "`run_evtx_analysis`" in registry_section


# ---------------------------------------------------------------------------
# 3: twelve exact result fields and decision-consistency invariants
# ---------------------------------------------------------------------------


def test_003_document_contains_twelve_field_contract_and_invariants(block8_text):
    contract_section = _section(block8_text, "## Result Contract", "## Safe-Output Controls")

    for field in TWELVE_RESULT_FIELDS:
        assert f"`{field}`" in contract_section, f"missing result field: {field}"

    assert '`gateway_version` is always `"1"`' in contract_section
    assert "`execution_performed` is always `false`" in contract_section

    assert "| `allow` | `true` | `false` | `proceed_to_separate_execution_boundary` |" in contract_section
    assert "| `require_approval` | `false` | `true` | `submit_to_approval_workflow` |" in contract_section
    assert "| `deny` | `false` | `false` | `do_not_execute` |" in contract_section


# ---------------------------------------------------------------------------
# 4: exact fourteen-rule order and deterministic policy precedence
# ---------------------------------------------------------------------------


def test_004_document_contains_exact_rule_order_and_precedence(block8_text):
    rule_section = _section(block8_text, "## Fixed Policy-Rule Order", "## Result Contract")
    indices = _ordered_indices(rule_section, [f"`{code}`" for code in RULE_ORDER])
    assert indices == sorted(indices)

    precedence_section = _section(block8_text, "## Policy Precedence", "## Advisory Block 6 Integration")
    assert "unknown tool" in precedence_section
    assert "disabled tool" in precedence_section
    assert "argument violation" in precedence_section
    assert "state or approval mutation" in precedence_section
    assert "read-only operation" in precedence_section
    assert "never falls back to execution" in precedence_section


# ---------------------------------------------------------------------------
# 5: the three local demonstration scenarios
# ---------------------------------------------------------------------------


def test_005_document_contains_demonstration_scenarios_and_facts(block8_text):
    demo_section = _section(block8_text, "## Local Three-Decision Demonstration", "## Automated Verification")

    assert "No lookup was actually executed." in demo_section
    assert "no approval was created" in demo_section.lower()
    assert "no mutation was executed" in demo_section.lower()
    assert "no SQL was executed" in demo_section

    assert "redacted" in demo_section
    assert "execution_performed` was `false` in every case" in demo_section
    assert "exactly twelve fields" in demo_section


# ---------------------------------------------------------------------------
# 6: security/no-fallback/advisory-integration/limitations/demo/roadmap
# ---------------------------------------------------------------------------


def test_006_document_contains_boundaries_limitations_demo_and_next_block(block8_text):
    assert "## Policy Precedence" in block8_text
    assert "never falls back to execution" in block8_text
    assert "never repairs a tool name through an alias" in block8_text

    assert "## Advisory Block 6 Integration" in block8_text
    assert "advisory only" in block8_text
    assert "never automatically invoked" in block8_text

    assert "## Limitations" in block8_text
    assert "## Presentation Walkthrough" in block8_text
    assert "## Next: Block 9 — Agent Identity and Least Privilege" in block8_text

    roadmap_section = block8_text[block8_text.find("## Next: Block 9"):]
    assert "least-privilege permissions" in roadmap_section
    assert "Block 9 is not implemented" in roadmap_section
