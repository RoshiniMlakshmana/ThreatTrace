"""Static tests for .claude/commands/simulate-case-update.md.

These tests only read the command Markdown file as text and check its
content structurally. They never execute /simulate-case-update, never
invoke any project CLI, never call Supabase or MCP, never perform network
access, never launch a subprocess, never create a temporary file, and
never modify any command file.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMAND_PATH = REPO_ROOT / ".claude" / "commands" / "simulate-case-update.md"

FORBIDDEN_TOP_LEVEL_FIELDS = (
    "investigation_id", "status", "confidence", "action_type", "action_payload",
    "current_state", "proposed_state", "simulated_at", "risk_level", "required_approvals",
)

MUTATING_OPERATIONS = (
    "insert_risk_aware_pending_approval",
    "apply_multi_review_transition",
    "apply_approval_consumption",
    "record_approval_review_and_promote_status",
    "consume_approval_and_update_investigation_state",
)

FIFTEEN_RESULT_FIELDS = (
    "simulation_version", "approval_id", "investigation_id", "action_type", "risk_level",
    "required_approvals", "eligible_for_execution", "current_state", "proposed_state",
    "changed_fields", "unchanged_fields", "warnings", "rollback", "simulated_at",
    "mutation_performed",
)


@pytest.fixture(scope="module")
def command_text():
    return COMMAND_PATH.read_text(encoding="utf-8")


def _section(text, heading, next_heading):
    start = text.find(heading)
    assert start != -1, f"heading not found: {heading}"
    end = text.find(next_heading, start + len(heading))
    assert end != -1, f"end marker not found after {heading}: {next_heading}"
    return text[start:end]


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
# 1: command identity and invocation
# ---------------------------------------------------------------------------


def test_001_command_identity_and_invocation(command_text):
    assert COMMAND_PATH.is_file()
    assert "/simulate-case-update" in command_text
    assert "/simulate-case-update <approval-id>" in command_text
    assert "exactly one caller argument" in command_text
    assert "caller-provided investigation state" in command_text
    assert "caller-provided proposed state" in command_text


# ---------------------------------------------------------------------------
# 2: strict caller-input boundary
# ---------------------------------------------------------------------------


def test_002_strict_caller_input_boundary(command_text):
    security_section = _section(command_text, "## Security Boundaries", "## Example Invocation")
    for field in FORBIDDEN_TOP_LEVEL_FIELDS:
        assert f"`{field}`" in security_section, f"forbidden field not addressed: {field}"
    assert "SQL fragment" in security_section
    assert "bridge descriptor" in security_section
    assert "RPC parameter" in security_section


# ---------------------------------------------------------------------------
# 3: complete approval lookup pipeline
# ---------------------------------------------------------------------------


def test_003_complete_approval_lookup_pipeline_order(command_text):
    indices = _ordered_indices(command_text, [
        "## Stage 1 — Approval Lookup Bridge Prepare",
        "## Stage 2 — Approval Lookup MCP Adapter Prepare Call",
        "## Stage 3 — Execute Through Supabase MCP (Approval Lookup)",
        "## Stage 4 — Approval Lookup MCP Adapter Normalize Response",
        "## Stage 5 — Approval Lookup Bridge Verify",
    ])
    assert indices == sorted(indices)

    stage1_section = _section(command_text, "## Stage 1", "## Stage 2")
    assert '"operation": "load_risk_aware_approval_record"' in stage1_section

    stage5_section = _section(command_text, "## Stage 5", "## Stage 6")
    assert '"operation": "load_risk_aware_approval_record"' in stage5_section
    assert "eighteen risk-aware approval-record fields" in stage5_section


# ---------------------------------------------------------------------------
# 4: trusted investigation binding
# ---------------------------------------------------------------------------


def test_004_trusted_investigation_binding(command_text):
    stage6_section = _section(command_text, "## Stage 6", "## Stage 7")
    assert "trusted approval record's own `investigation_id`" in stage6_section
    assert "never from the caller" in stage6_section

    security_section = _section(command_text, "## Security Boundaries", "## Example Invocation")
    assert (
        "derive the investigation ID for Stage 6 from anything other than the trusted approval "
        "record's own `investigation_id`" in security_section
    )


# ---------------------------------------------------------------------------
# 5: complete investigation lookup pipeline
# ---------------------------------------------------------------------------


def test_005_complete_investigation_lookup_pipeline_order(command_text):
    indices = _ordered_indices(command_text, [
        "## Stage 6 — Investigation Context Lookup Bridge Prepare",
        "## Stage 7 — Investigation Context Lookup MCP Adapter Prepare Call",
        "## Stage 8 — Execute Through Supabase MCP (Investigation Context Lookup)",
        "## Stage 9 — Investigation Context Lookup MCP Adapter Normalize Response",
        "## Stage 10 — Investigation Context Lookup Bridge Verify",
    ])
    assert indices == sorted(indices)

    stage6_section = _section(command_text, "## Stage 6", "## Stage 7")
    assert '"operation": "load_investigation_approval_context"' in stage6_section

    stage10_section = _section(command_text, "## Stage 10", "## Stage 11")
    assert '"operation": "load_investigation_approval_context"' in stage10_section
    assert "`investigation_id`, `status`, `confidence`" in stage10_section


# ---------------------------------------------------------------------------
# 6: exact simulation CLI envelope
# ---------------------------------------------------------------------------


def test_006_exact_simulation_cli_envelope(command_text):
    stage12_section = _section(command_text, "## Stage 12", "## Required Output")
    assert "py -m core.shadow_execution_cli" in stage12_section
    assert '"approval_record"' in stage12_section
    assert '"investigation_context"' in stage12_section
    assert '"simulated_at"' in stage12_section
    assert "Never add, remove, rename, or transform any field." in stage12_section
    assert "Never substitute a caller-supplied value for any of the three fields." in stage12_section


# ---------------------------------------------------------------------------
# 7: timestamp pinning
# ---------------------------------------------------------------------------


def test_007_timestamp_pinning(command_text):
    stage11_section = _section(command_text, "## Stage 11", "## Stage 12")
    assert "Only after Stage 10 succeeds" in stage11_section
    assert "timezone-aware UTC" in stage11_section
    assert "Generate it exactly once for this invocation" in stage11_section
    assert "the caller can never supply or override it" in stage11_section
    assert "never regenerated between this stage and Stage 12" in stage11_section
    assert "never read the system clock themselves" in stage11_section


# ---------------------------------------------------------------------------
# 8: eligible and ineligible result handling
# ---------------------------------------------------------------------------


def test_008_eligible_and_ineligible_result_handling(command_text):
    stage12_section = _section(command_text, "## Stage 12", "## Required Output")
    assert "regardless of its own `eligible_for_execution` value" in stage12_section

    output_section = _section(command_text, "## Required Output", "## Required Failure Categories")
    assert "### When `eligible_for_execution` is `true`" in output_section
    assert "### When `eligible_for_execution` is `false`" in output_section

    ineligible_section = _section(
        output_section, "### When `eligible_for_execution` is `false`", "Never display:"
    )
    assert "every blocking warning it contains" in ineligible_section
    assert "never treat this outcome as a command transport failure" in ineligible_section
    assert "Never attempt a fallback execution" in ineligible_section


# ---------------------------------------------------------------------------
# 9: explicit mutation prohibition
# ---------------------------------------------------------------------------


def test_009_explicit_mutation_prohibition(command_text):
    security_section = _section(command_text, "## Security Boundaries", "## Example Invocation")
    for operation in MUTATING_OPERATIONS:
        assert f"`{operation}`" in security_section, f"mutating operation not prohibited: {operation}"
    for keyword in ("INSERT", "UPDATE", "DELETE", "UPSERT", "apply_migration"):
        assert f"`{keyword}`" in security_section, f"mutation keyword not prohibited: {keyword}"
    assert "create, approve, reject, review, or consume an approval" in security_section
    assert "update `public.investigations` through any path" in security_section


# ---------------------------------------------------------------------------
# 10: output-safety boundary
# ---------------------------------------------------------------------------


def test_010_output_safety_boundary(command_text):
    output_section = _section(command_text, "## Required Output", "## Required Failure Categories")
    never_display_start = output_section.find("Never display:")
    assert never_display_start != -1
    never_display_section = output_section[never_display_start:]

    for field in ("`requested_by`", "`approved_by`", "`rejected_by`", "`consumed_by`"):
        assert field in never_display_section
    assert "raw stored `action_payload`" in never_display_section
    assert "raw SQL" in never_display_section
    assert "bridge descriptors" in never_display_section
    assert "MCP request or tool-call objects" in never_display_section
    assert "credential" in never_display_section
    assert "database connection or ownership metadata" in never_display_section
    assert "filesystem path" in never_display_section
    assert "stack trace" in never_display_section

    for field in FIFTEEN_RESULT_FIELDS:
        assert field in command_text


# ---------------------------------------------------------------------------
# 11: failure and no-fallback behavior
# ---------------------------------------------------------------------------


def test_011_failure_and_no_fallback_behavior(command_text):
    stage5_section = _section(command_text, "## Stage 5", "## Stage 6")
    assert "Do not proceed to Stage 6 for any failure above." in stage5_section

    stage10_section = _section(command_text, "## Stage 10", "## Stage 11")
    assert "Do not proceed to Stage 11 for any failure above" in stage10_section
    assert "never invoke the simulation CLI without a Stage 10 success" in stage10_section

    stage12_section = _section(command_text, "## Stage 12", "## Required Output")
    assert "Never automatically retry any of these outcomes" in stage12_section

    fallback_section = _section(command_text, "## Failure and No-Fallback Policy", "## Security Boundaries")
    assert "do not silently continue to the next stage" in fallback_section
    assert "do not build a substitute trusted record or trusted context by hand" in fallback_section
    assert "do not switch to direct SQL" in fallback_section
    assert "do not automatically retry any stage" in fallback_section
    assert "do not consume, approve, reject, or otherwise mutate the approval" in fallback_section
    assert "do not update the investigation" in fallback_section


# ---------------------------------------------------------------------------
# 12: explicit no-mutation statement and separation from apply
# ---------------------------------------------------------------------------


def test_012_explicit_no_mutation_statement_and_apply_separation(command_text):
    output_section = _section(command_text, "## Required Output", "## Required Failure Categories")
    assert "**`mutation_performed: false`**" in output_section
    assert "No approval, review, or investigation record was modified." in output_section

    eligible_section = _section(
        output_section, "### When `eligible_for_execution` is `true`", "### When `eligible_for_execution` is `false`"
    )
    assert "/apply-case-update` remains a separate, later, explicit action this command never triggers" in eligible_section

    assert "Never claim a preview was executed" in command_text
    assert "`/apply-case-update` remains the only command that ever actually applies a change" in command_text
