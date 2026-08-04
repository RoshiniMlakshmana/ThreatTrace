"""Static tests for the Block 7 Shadow Execution / Digital Twin closure
documentation: README.md's project-status update and
docs/block7-shadow-execution.md.

These tests only read repository text files and check their content
structurally. They never execute a ThreatTrace command, never invoke any
project CLI, never call Supabase or MCP, never execute SQL or an RPC,
never access the network, never launch a shell command, and never modify
any file.

Exactly 6 tests are defined below.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README_PATH = REPO_ROOT / "README.md"
BLOCK7_PATH = REPO_ROOT / "docs" / "block7-shadow-execution.md"

FIFTEEN_RESULT_FIELDS = (
    "simulation_version", "approval_id", "investigation_id", "action_type", "risk_level",
    "required_approvals", "eligible_for_execution", "current_state", "proposed_state",
    "changed_fields", "unchanged_fields", "warnings", "rollback", "simulated_at",
    "mutation_performed",
)

WARNING_ORDER = (
    "ALREADY_CONSUMED",
    "NOT_APPROVED",
    "APPROVAL_EXPIRED",
    "STALE_BINDING",
    "CLOSING_INVESTIGATION",
    "REOPENING_INVESTIGATION",
    "CONFIDENCE_LOWERED",
    "COMBINED_FIELD_CHANGE",
    "NO_OP_ACTION",
    "ROLLBACK_UNCERTAIN",
)

ROLLBACK_CLASSIFICATIONS = ("fully_reversible", "conditionally_reversible", "not_reversible", "unknown")


@pytest.fixture(scope="module")
def readme_text():
    return README_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def block7_text():
    return BLOCK7_PATH.read_text(encoding="utf-8")


def _ordered_indices(text, needles):
    indices = []
    search_start = 0
    for needle in needles:
        idx = text.find(needle, search_start)
        assert idx != -1, f"not found in expected order: {needle!r}"
        indices.append(idx)
        search_start = idx + len(needle)
    return indices


# ---------------------------------------------------------------------------
# 1: README marks the Block 7 MVP complete and links to the canonical doc
# ---------------------------------------------------------------------------


def test_001_readme_marks_block7_mvp_complete_and_links_to_block7_document(readme_text):
    assert "Block 7" in readme_text
    assert "MVP is complete" in readme_text
    assert "[docs/block7-shadow-execution.md](docs/block7-shadow-execution.md)" in readme_text


# ---------------------------------------------------------------------------
# 2: fifteen exact result fields, simulation_version, mutation_performed
# ---------------------------------------------------------------------------


def test_002_document_contains_fifteen_field_contract(block7_text):
    for field in FIFTEEN_RESULT_FIELDS:
        assert f"`{field}`" in block7_text, f"missing result field: {field}"
    assert '`simulation_version` is always `"1"`' in block7_text
    assert "`mutation_performed` is always `false`" in block7_text


# ---------------------------------------------------------------------------
# 3: trusted pipeline and separation from /apply-case-update
# ---------------------------------------------------------------------------


def test_003_document_contains_trusted_pipeline_and_apply_separation(block7_text):
    indices = _ordered_indices(block7_text, [
        "Trusted Approval Lookup",
        "Trusted Investigation Lookup",
        "Pinned UTC simulated_at",
        "shadow_execution_cli",
        "Pure simulate_case_update",
        "Fifteen-Field Read-Only Report",
    ])
    assert indices == sorted(indices)

    assert "/apply-case-update" in block7_text
    assert "sits entirely apart from this pipeline" in block7_text
    assert "the only command that ever actually mutates an approval or an investigation" in block7_text


# ---------------------------------------------------------------------------
# 4: exact warning order and four rollback classifications
# ---------------------------------------------------------------------------


def test_004_document_contains_exact_warning_order_and_rollback_vocabulary(block7_text):
    warning_section_start = block7_text.find("## Warning Behavior")
    warning_section_end = block7_text.find("## Rollback Classification")
    assert warning_section_start != -1 and warning_section_end != -1
    warning_section = block7_text[warning_section_start:warning_section_end]

    indices = _ordered_indices(warning_section, [f"`{code}`" for code in WARNING_ORDER])
    assert indices == sorted(indices)

    rollback_section_start = block7_text.find("## Rollback Classification")
    rollback_section_end = block7_text.find("## Eligibility")
    assert rollback_section_start != -1 and rollback_section_end != -1
    rollback_section = block7_text[rollback_section_start:rollback_section_end]
    for classification in ROLLBACK_CLASSIFICATIONS:
        assert f"`{classification}`" in rollback_section, f"missing rollback classification: {classification}"


# ---------------------------------------------------------------------------
# 5: honest live-verification status
# ---------------------------------------------------------------------------


def test_005_document_contains_honest_live_verification_status(block7_text):
    live_section_start = block7_text.find("## Live Read-Only Verification")
    live_section_end = block7_text.find("## Automated Verification")
    assert live_section_start != -1 and live_section_end != -1
    live_section = block7_text[live_section_start:live_section_end]

    assert "LIVE_VERIFICATION_BLOCKED_NO_EXISTING_APPROVAL" in live_section
    assert "2 investigations" in live_section
    assert "0 approvals" in live_section
    assert "0 approval reviews" in live_section
    assert "no synthetic" in live_section.lower()
    assert "no row, column, or schema object was changed" in live_section
    assert "remains pending" in live_section


# ---------------------------------------------------------------------------
# 6: security boundaries, limitations, demo walkthrough, Block 8 roadmap
# ---------------------------------------------------------------------------


def test_006_document_contains_security_limitations_demo_and_next_block(block7_text):
    assert "## Security Boundaries" in block7_text
    assert "## Limitations" in block7_text
    assert "## Presentation Walkthrough" in block7_text
    assert "## Next: Block 8 — AI Agent Gateway / Runtime Firewall" in block7_text

    roadmap_section_start = block7_text.find("## Next: Block 8")
    roadmap_section = block7_text[roadmap_section_start:]
    assert "tool allowlists" in roadmap_section
    assert "least-privilege policies" in roadmap_section
    assert "Block 8 is not implemented" in roadmap_section
