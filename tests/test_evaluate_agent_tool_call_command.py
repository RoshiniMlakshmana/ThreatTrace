"""Static tests for .claude/commands/evaluate-agent-tool-call.md.

These tests only read the command Markdown file as text and check its
content structurally. They never execute /evaluate-agent-tool-call,
never invoke any project CLI, never call Supabase or MCP, never execute
SQL or an RPC, never invoke Hayabusa, never perform network access,
never launch a subprocess, never create a temporary file, and never
modify any command file.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMAND_PATH = REPO_ROOT / ".claude" / "commands" / "evaluate-agent-tool-call.md"

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
    assert "/evaluate-agent-tool-call" in command_text
    assert "/evaluate-agent-tool-call <agent-id> <tool-name> <json-arguments>" in command_text
    assert "exactly one agent-ID token" in command_text
    assert "exactly one tool-name token" in command_text
    assert "exactly one JSON argument object" in command_text


# ---------------------------------------------------------------------------
# 2: identity honesty
# ---------------------------------------------------------------------------


def test_002_identity_honesty(command_text):
    boundary_section = _section(command_text, "## Claimed Identity Boundary", "## Evaluation Input")

    assert "caller-supplied claimed identifier" in boundary_section
    assert "never authenticated, never verified, never cryptographically proven" in boundary_section
    assert (
        "no login, no token validation, no session validation, no certificate validation, "
        "no cryptographic verification, and no identity-provider lookup"
    ) in boundary_section
    assert "A match is not authentication." in boundary_section
    assert "`identity_authenticated` is always `false`" in boundary_section
    assert "authenticated" in boundary_section and "**authenticated**" in boundary_section
    assert "**verified**" in boundary_section
    assert "**trusted**" in boundary_section
    assert "**proven**" in boundary_section
    assert "**securely identified**" in boundary_section
    assert (
        "No agent was authenticated, and no tool, approval workflow, database operation, "
        "or external process was executed."
    ) in boundary_section

    assert "was successfully authenticated" not in command_text
    assert "identity was verified" not in command_text


# ---------------------------------------------------------------------------
# 3: command-level shape validation
# ---------------------------------------------------------------------------


def test_003_command_level_shape_validation(command_text):
    stage0_section = _section(
        command_text, "## Stage 0 — Command-Level Input Shape Validation", "## Python Launcher Selection"
    )

    assert "Reject a blank result" in stage0_section
    assert "Reject when there is no whitespace at all" in stage0_section
    assert "Reject malformed JSON" in stage0_section
    assert "Reject a top-level value that is not a JSON object" in stage0_section
    assert "Reject trailing non-whitespace content after the one parsed JSON value" in stage0_section

    assert "no local agent-ID check, tool-name check, or argument-content check" in stage0_section

    assert "whether the claimed agent is known" in stage0_section
    assert "whether it is enabled" in stage0_section
    assert "which role it has" in stage0_section
    assert "which capabilities it has" in stage0_section
    assert "whether the tool is within the claimed agent's allowlist" in stage0_section
    assert "whether a mutation request is permitted" in stage0_section
    assert "what the final decision should be" in stage0_section
    assert "entirely by `core.agent_identity_policy.evaluate_agent_tool_call`" in stage0_section


# ---------------------------------------------------------------------------
# 4: exact CLI invocation
# ---------------------------------------------------------------------------


def test_004_exact_cli_invocation(command_text):
    stage2_section = _section(
        command_text, "## Stage 2 — Invoke the Agent Identity Policy CLI", "### Identity Policy CLI exit handling"
    )

    assert "py -m core.agent_identity_policy_cli" in stage2_section
    assert '"agent_id"' in stage2_section
    assert '"tool_name"' in stage2_section
    assert '"arguments"' in stage2_section
    assert '"evaluated_at"' in stage2_section
    assert "Never add, remove, rename, normalize, redact, or otherwise transform any field or value." in stage2_section
    assert "never call `core.agent_gateway` directly" in stage2_section

    envelope_start = stage2_section.find("```json")
    envelope_end = stage2_section.find("```", envelope_start + len("```json"))
    envelope_block = stage2_section[envelope_start:envelope_end]
    for forbidden_field in ("role", "capabilities", "identity_authenticated", "final_decision", "decision"):
        assert f'"{forbidden_field}"' not in envelope_block


# ---------------------------------------------------------------------------
# 5: timestamp pinning
# ---------------------------------------------------------------------------


def test_005_timestamp_pinning(command_text):
    stage1_section = _section(
        command_text, "## Stage 1 — Pin the Evaluation Timestamp", "## Stage 2 — Invoke the Agent Identity Policy CLI"
    )

    assert "Only after Stage 0 succeeds" in stage1_section
    assert "timezone-aware UTC" in stage1_section
    assert "the caller can never supply or override it" in stage1_section
    assert "it is never regenerated after this stage" in stage1_section
    assert "never read the system clock themselves" in stage1_section


# ---------------------------------------------------------------------------
# 6: no identity or gateway policy duplication
# ---------------------------------------------------------------------------


def test_006_no_identity_or_gateway_policy_duplication(command_text):
    stage0_section = _section(
        command_text, "## Stage 0 — Command-Level Input Shape Validation", "## Python Launcher Selection"
    )
    stage2_section = _section(
        command_text, "## Stage 2 — Invoke the Agent Identity Policy CLI", "### Identity Policy CLI exit handling"
    )

    assert "whether the claimed agent is known" in stage0_section
    assert "whether it is enabled" in stage0_section
    assert "which role it has" in stage0_section
    assert "which capabilities it has" in stage0_section
    assert "whether the tool is within the claimed agent's allowlist" in stage0_section
    assert "whether a mutation request is permitted" in stage0_section
    assert (
        "never reimplement any part of the agent registry, role map, capability map, "
        "argument validation, or policy logic in this document"
    ) in stage2_section
    assert "never reimplement any part of the agent registry, role map, capability map" in stage2_section


# ---------------------------------------------------------------------------
# 7: allow handling
# ---------------------------------------------------------------------------


def test_007_allow_handling(command_text):
    allow_section = _section(
        command_text, "### When `final_decision` is `allow`", "### When `final_decision` is `require_approval`"
    )

    assert "matched a known, enabled registry entry" in allow_section
    assert "currently passes both Block 8's policy and this agent's own least-privilege capability check" in allow_section
    assert "this is not authentication" in allow_section
    assert "may proceed only to a separate execution boundary this command never crosses" in allow_section
    assert "this command itself did not execute it" in allow_section
    assert "`identity_authenticated` remains `false`" in allow_section
    assert "`execution_performed` remains `false`" in allow_section
    assert "Never automatically execute the tool" in allow_section


# ---------------------------------------------------------------------------
# 8: require-approval handling
# ---------------------------------------------------------------------------


def test_008_require_approval_handling(command_text):
    require_approval_section = _section(
        command_text, "### When `final_decision` is `require_approval`", "### When `final_decision` is `deny`"
    )

    assert "no approval was created by this command" in require_approval_section
    assert "no authentication occurred" in require_approval_section
    assert "no other command was automatically invoked" in require_approval_section
    assert "`required_next_action` is advisory text only" in require_approval_section
    assert (
        "Never automatically invoke `/request-case-update`, `/review-approval`, or `/apply-case-update`"
        in require_approval_section
    )

    output_section = _section(command_text, "## Required Output", "## Required Failure Categories")
    assert "**`execution_performed: false`**" in output_section
    assert "**`identity_authenticated: false`**" in output_section


# ---------------------------------------------------------------------------
# 9: deny handling
# ---------------------------------------------------------------------------


def test_009_deny_handling(command_text):
    deny_section = _section(command_text, "### When `final_decision` is `deny`", "Never display:")

    assert "denied by identity policy, gateway policy, or both" in deny_section
    assert "display the matched identity rules" in deny_section
    assert "does not authenticate the caller" in deny_section
    assert "Never retry the same request" in deny_section
    assert "never substitute a different, more privileged agent" in deny_section
    assert "never enable a disabled agent" in deny_section
    assert "never add a capability" in deny_section
    assert "never treat a `deny` decision as a command-level (transport) failure" in deny_section


# ---------------------------------------------------------------------------
# 10: exact report validation
# ---------------------------------------------------------------------------


def test_010_exact_report_validation(command_text):
    validation_section = _section(
        command_text, "### Identity Policy CLI success-output validation", "## Required Output"
    )

    for field in FIFTEEN_RESULT_FIELDS:
        assert f"`{field}`" in validation_section, f"missing result field: {field}"

    assert '`identity_policy_version` to equal exactly `"1"`' in validation_section
    assert "`identity_authenticated` to equal exactly `false`" in validation_section
    assert "`execution_performed` to equal exactly `false`" in validation_section

    assert "| `allow` | `true` | `false` | `proceed_to_separate_execution_boundary` |" in validation_section
    assert "| `require_approval` | `false` | `true` | `submit_to_approval_workflow` |" in validation_section
    assert "| `deny` | `false` | `false` | `do_not_execute` |" in validation_section

    assert "`gateway_decision` of `deny` may only pair with `final_decision` of `deny`" in validation_section
    assert (
        "`gateway_decision` of `require_approval` may pair with `final_decision` of `require_approval` or `deny`, "
        "never `allow`"
    ) in validation_section
    assert (
        "`gateway_decision` of `allow` may pair with `final_decision` of `allow` or `deny`, never `require_approval`"
        in validation_section
    )
    assert "`gateway_decision` of `null`" in validation_section

    for field in FIVE_SUMMARY_FIELDS:
        assert f"`{field}`" in validation_section, f"missing summary field: {field}"

    assert "Do not repair, complete, or reinterpret a malformed report by hand." in validation_section


# ---------------------------------------------------------------------------
# 11: explicit prohibitions and output safety
# ---------------------------------------------------------------------------


def test_011_explicit_prohibitions_and_output_safety(command_text):
    prohibitions_section = _section(command_text, "## Explicit Execution Prohibitions", "## Security Boundaries")

    assert "`mcp__supabase__execute_sql`" in prohibitions_section
    assert "`execute_sql`" in prohibitions_section
    assert "`apply_migration`" in prohibitions_section
    assert "`run_evtx_analysis`" in prohibitions_section
    for operation in MUTATING_OPERATIONS:
        assert f"`{operation}`" in prohibitions_section, f"mutating operation not prohibited: {operation}"
    assert "`/request-case-update`" in prohibitions_section
    assert "`/review-approval`" in prohibitions_section
    assert "`/apply-case-update`" in prohibitions_section
    assert "a login command" in prohibitions_section
    assert "a token-validation command" in prohibitions_section
    assert "a session-creation command" in prohibitions_section
    assert "a certificate-validation command" in prohibitions_section
    assert "a dynamically imported, caller-selected module or function" in prohibitions_section
    assert "subprocess" in prohibitions_section

    output_section = _section(command_text, "## Required Output", "## Required Failure Categories")
    never_display_start = output_section.find("Never display:")
    assert never_display_start != -1
    never_display_section = output_section[never_display_start:]

    assert "raw unknown or unregistered agent ID" in never_display_section
    assert "raw `arguments` separately from `safe_capability_summary`" in never_display_section
    assert "any UUID or other argument value" in never_display_section
    assert "SQL or migration text" in never_display_section
    assert "filesystem paths" in never_display_section
    assert "authorization phrases" in never_display_section
    assert "identities from Block 6" in never_display_section
    assert "credentials" in never_display_section
    assert "tokens" in never_display_section
    assert "full tool allowlist or a complete capability set" in never_display_section
    assert "registry internals" in never_display_section
    assert "descriptor or RPC parameter payload" in never_display_section
    assert "stack trace, exception class name" in never_display_section


# ---------------------------------------------------------------------------
# 12: failure and no-fallback behavior
# ---------------------------------------------------------------------------


def test_012_failure_and_no_fallback_behavior(command_text):
    failure_section = _section(
        command_text, "## Required Failure Categories", "## No-Fallback and No-Retry Policy"
    )
    assert "AGENT_IDENTITY_POLICY_CLI_UNAVAILABLE" in failure_section
    assert "AGENT_IDENTITY_POLICY_VALIDATION_FAILED" in failure_section
    assert "AGENT_IDENTITY_POLICY_INTERNAL_FAILURE" in failure_section
    assert "Do not automatically retry any failure in any category above." in failure_section

    fallback_section = _section(
        command_text, "## No-Fallback and No-Retry Policy", "## Explicit Execution Prohibitions"
    )
    assert "do not retry automatically" in fallback_section
    assert "do not substitute `coordinator_agent`" in fallback_section
    assert "do not enable a disabled agent" in fallback_section
    assert "do not add a capability the registry does not already grant" in fallback_section
    assert "do not choose an alias, a near-miss name, or a different letter case for the tool name" in fallback_section
    assert "do not switch to a raw `mcp__supabase__execute_sql` call" in fallback_section
    assert "do not switch to direct or hand-written SQL" in fallback_section
    assert "do not invoke Hayabusa" in fallback_section
    assert "do not invoke `/request-case-update`, `/review-approval`, or `/apply-case-update`" in fallback_section
    assert "do not execute the requested operation manually" in fallback_section

    stage0_section = _section(
        command_text, "## Stage 0 — Command-Level Input Shape Validation", "## Python Launcher Selection"
    )
    assert "before any timestamp is pinned and before any CLI invocation" in stage0_section

    validation_section = _section(
        command_text, "### Identity Policy CLI success-output validation", "## Required Output"
    )
    assert "Do not repair, complete, or reinterpret a malformed report by hand." in validation_section
