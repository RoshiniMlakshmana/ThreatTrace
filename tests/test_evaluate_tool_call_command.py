"""Static tests for .claude/commands/evaluate-tool-call.md.

These tests only read the command Markdown file as text and check its
content structurally. They never execute /evaluate-tool-call, never
invoke any project CLI, never call Supabase or MCP, never execute SQL or
an RPC, never invoke Hayabusa, never perform network access, never
launch a subprocess, never create a temporary file, and never modify any
command file.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMAND_PATH = REPO_ROOT / ".claude" / "commands" / "evaluate-tool-call.md"

TWELVE_RESULT_FIELDS = (
    "gateway_version", "canonical_tool_name", "operation_class", "decision",
    "eligible_for_execution", "requires_approval", "matched_rules", "safe_argument_summary",
    "blocked_argument_fields", "required_next_action", "evaluated_at", "execution_performed",
)

MUTATING_OPERATIONS = (
    "insert_risk_aware_pending_approval",
    "apply_multi_review_transition",
    "apply_approval_consumption",
    "record_approval_review_and_promote_status",
    "consume_approval_and_update_investigation_state",
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
    assert "/evaluate-tool-call" in command_text
    assert "/evaluate-tool-call <tool-name> <json-arguments>" in command_text
    assert "exactly one tool-name token" in command_text
    assert "exactly one JSON argument object" in command_text


# ---------------------------------------------------------------------------
# 2: command-level shape validation
# ---------------------------------------------------------------------------


def test_002_command_level_shape_validation(command_text):
    stage0_section = _section(command_text, "## Stage 0", "## Python Launcher Selection")

    assert "Reject a blank result" in stage0_section
    assert "Reject when there is no whitespace at all" in stage0_section
    assert "Reject malformed JSON" in stage0_section
    assert "Reject a top-level value that is not a JSON object" in stage0_section
    assert "Reject trailing non-whitespace content after the one parsed JSON value" in stage0_section

    assert "no local UUID check, tool-name check, or argument-content check" in stage0_section


# ---------------------------------------------------------------------------
# 3: exact CLI invocation
# ---------------------------------------------------------------------------


def test_003_exact_cli_invocation(command_text):
    stage2_section = _section(command_text, "## Stage 2", "## Required Output")

    assert "py -m core.agent_gateway_cli" in stage2_section
    assert '"tool_name"' in stage2_section
    assert '"arguments"' in stage2_section
    assert '"evaluated_at"' in stage2_section
    assert "Never add, remove, rename, normalize, redact, or otherwise transform any field or value." in stage2_section


# ---------------------------------------------------------------------------
# 4: timestamp pinning
# ---------------------------------------------------------------------------


def test_004_timestamp_pinning(command_text):
    stage1_section = _section(command_text, "## Stage 1", "## Stage 2")

    assert "Only after Stage 0 succeeds" in stage1_section
    assert "timezone-aware UTC" in stage1_section
    assert "the caller can never supply or override it" in stage1_section
    assert "it is never regenerated after this stage" in stage1_section
    assert "never read the system clock themselves" in stage1_section


# ---------------------------------------------------------------------------
# 5: no command-level policy duplication
# ---------------------------------------------------------------------------


def test_005_no_command_level_policy_duplication(command_text):
    stage0_section = _section(command_text, "## Stage 0", "## Python Launcher Selection")

    assert "whether the named tool is known" in stage0_section
    assert "whether it is enabled" in stage0_section
    assert "what its operation class is" in stage0_section
    assert "whether its arguments are individually valid" in stage0_section
    assert "what the final decision should be" in stage0_section
    assert "entirely by `core.agent_gateway.evaluate_tool_call`" in stage0_section


# ---------------------------------------------------------------------------
# 6: allow handling
# ---------------------------------------------------------------------------


def test_006_allow_handling(command_text):
    allow_section = _section(
        command_text, "### When `decision` is `allow`", "### When `decision` is `require_approval`"
    )

    assert "currently passes deterministic policy" in allow_section
    assert "may proceed only to a separate execution boundary this command never crosses" in allow_section
    assert "this command itself did not execute it" in allow_section
    assert "`execution_performed` remains `false`" in allow_section
    assert "Never automatically execute the tool" in allow_section


# ---------------------------------------------------------------------------
# 7: require-approval handling
# ---------------------------------------------------------------------------


def test_007_require_approval_handling(command_text):
    require_approval_section = _section(
        command_text, "### When `decision` is `require_approval`", "### When `decision` is `deny`"
    )

    assert "no approval was created by this command" in require_approval_section
    assert "`required_next_action` is advisory text only" in require_approval_section
    assert "Never automatically invoke `/request-case-update`" in require_approval_section

    output_section = _section(command_text, "## Required Output", "## Required Failure Categories")
    assert "**`execution_performed: false`**" in output_section


# ---------------------------------------------------------------------------
# 8: deny handling
# ---------------------------------------------------------------------------


def test_008_deny_handling(command_text):
    deny_section = _section(command_text, "### When `decision` is `deny`", "Never display:")

    assert "denied by policy" in deny_section
    assert "display the matched policy rules" in deny_section
    assert "Never retry the same request under a different tool name" in deny_section
    assert "never fall back to a different execution path" in deny_section
    assert "never treat a `deny` decision as a command-level (transport) failure" in deny_section


# ---------------------------------------------------------------------------
# 9: twelve-field report and decision-consistency validation
# ---------------------------------------------------------------------------


def test_009_twelve_field_report_and_decision_consistency(command_text):
    validation_section = _section(
        command_text, "### Gateway CLI success-output validation", "## Required Output"
    )

    for field in TWELVE_RESULT_FIELDS:
        assert f"`{field}`" in validation_section, f"missing result field: {field}"

    assert "| `allow` | `true` | `false` | `proceed_to_separate_execution_boundary` |" in validation_section
    assert "| `require_approval` | `false` | `true` | `submit_to_approval_workflow` |" in validation_section
    assert "| `deny` | `false` | `false` | `do_not_execute` |" in validation_section

    assert "never execute anything" in validation_section
    assert "Do not repair, complete, or reinterpret a malformed report by hand." in validation_section


# ---------------------------------------------------------------------------
# 10: explicit execution prohibitions
# ---------------------------------------------------------------------------


def test_010_explicit_execution_prohibitions(command_text):
    prohibitions_section = _section(command_text, "## Explicit Execution Prohibitions", "## Security Boundaries")

    assert "`mcp__supabase__execute_sql`" in prohibitions_section
    assert "`execute_sql`" in prohibitions_section
    assert "`apply_migration`" in prohibitions_section
    assert "`run_evtx_analysis`" in prohibitions_section
    for operation in MUTATING_OPERATIONS:
        assert f"`{operation}`" in prohibitions_section, f"mutating operation not prohibited: {operation}"
    assert "`/request-case-update`" in prohibitions_section
    assert "`/apply-case-update`" in prohibitions_section
    assert "subprocess" in prohibitions_section
    assert "dynamically imported" in prohibitions_section
    assert "shell command" in prohibitions_section


# ---------------------------------------------------------------------------
# 11: output safety
# ---------------------------------------------------------------------------


def test_011_output_safety(command_text):
    output_section = _section(command_text, "## Required Output", "## Required Failure Categories")
    never_display_start = output_section.find("Never display:")
    assert never_display_start != -1
    never_display_section = output_section[never_display_start:]

    assert "raw arguments separately from `safe_argument_summary`" in never_display_section
    assert "raw unknown tool name" in never_display_section
    assert "any UUID or other argument value" in never_display_section
    assert "SQL or migration text" in never_display_section
    assert "filesystem paths" in never_display_section
    assert "authorization phrases" in never_display_section
    assert "identities" in never_display_section
    assert "credentials" in never_display_section
    assert "tokens" in never_display_section
    assert "descriptor or RPC parameter payload" in never_display_section
    assert "stack trace, exception class name" in never_display_section

    assert "No tool, approval workflow, database operation, or external process was executed." in output_section


# ---------------------------------------------------------------------------
# 12: failure and no-fallback behavior
# ---------------------------------------------------------------------------


def test_012_failure_and_no_fallback_behavior(command_text):
    stage0_section = _section(command_text, "## Stage 0", "## Python Launcher Selection")
    assert "before any timestamp is pinned and before any CLI invocation" in stage0_section

    exit_handling_section = _section(command_text, "### Gateway CLI exit handling", "### Gateway CLI success-output validation")
    assert "`AGENT_GATEWAY_VALIDATION_FAILED`" in exit_handling_section
    assert "`AGENT_GATEWAY_INTERNAL_FAILURE`" in exit_handling_section
    assert "Never automatically retry any of these outcomes" in exit_handling_section

    fallback_section = _section(command_text, "## No-Fallback and No-Retry Policy", "## Explicit Execution Prohibitions")
    assert "do not retry automatically" in fallback_section
    assert "do not choose an alias" in fallback_section
    assert "do not remove, rename, or \"fix\" any argument" in fallback_section
    assert "do not substitute a different, known tool" in fallback_section
    assert "do not switch to a raw `mcp__supabase__execute_sql` call" in fallback_section
    assert "do not switch to direct or hand-written SQL" in fallback_section
    assert "do not invoke Hayabusa" in fallback_section
    assert "do not execute the requested operation manually" in fallback_section

    validation_section = _section(command_text, "### Gateway CLI success-output validation", "## Required Output")
    assert "Do not repair, complete, or reinterpret a malformed report by hand." in validation_section
