"""Static tests for .claude/commands/update-case.md -- the deprecated,
static-guidance-only compatibility command that replaced the legacy
direct-write `/update-case` workflow.

These tests only read the command Markdown file as text and check its
content structurally. They never execute /update-case, never invoke any
project CLI, never call Supabase or MCP, never execute SQL, never access
the network, never launch a shell command, and never modify any command
file.

Exactly 48 tests are defined below, each mapped to one required
confirmation item from the Step 34 specification.
"""

import ast
import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMAND_PATH = REPO_ROOT / ".claude" / "commands" / "update-case.md"

WORKFLOW_COMMANDS_IN_ORDER = ("/request-case-update", "/review-approval", "/apply-case-update")

_NEGATION_MARKERS = (
    "do not", "does not", "never", "no ", "none ", "must not", "not perform",
    "not accepted", "cannot", "removed", "disabled", "is removed",
)

# A generously wide lookback window: this document's negative instructions
# are expressed as one long, multi-line "must never:" bulleted list, where
# the negation-introducing line sits many list items before some of the
# specific forbidden terms being checked. A short fixed-character window
# would falsely flag those later list items as unguarded affirmative
# instructions -- exactly the mistake corrected in earlier Block 5 steps.
_WIDE_WINDOW = 2000


@pytest.fixture(scope="module")
def command_text():
    return COMMAND_PATH.read_text(encoding="utf-8")


def _find_all(text, needle):
    return [m.start() for m in re.finditer(re.escape(needle), text)]


def _assert_negated(command_text, index, label=""):
    preceding = command_text.lower()[max(0, index - _WIDE_WINDOW) : index]
    assert any(marker in preceding for marker in _NEGATION_MARKERS), (
        f"possible affirmative instruction near {label}: "
        f"{command_text[max(0, index - 20):index + 60]!r}"
    )


def _boundaries_section(command_text):
    start = command_text.find("## Absolute Non-Execution Boundaries")
    end = command_text.find("## Required Output", start)
    return command_text[start:end]


def _example_line(command_text):
    section_start = command_text.find("### Example")
    section_end = command_text.find("`requested_by` above", section_start)
    section = command_text[section_start:section_end]
    match = re.search(r"/request-case-update\s+(\{.*\})", section, re.DOTALL)
    assert match is not None, "example invocation line not found"
    return match.group(1)


def _this_module_ast():
    return ast.parse(Path(__file__).read_text(encoding="utf-8"))


def _imported_module_names(tree):
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
# 1: file existence
# ---------------------------------------------------------------------------

def test_001_command_file_exists_at_exact_path():
    assert COMMAND_PATH.is_file()


# ---------------------------------------------------------------------------
# 2-5: identity and labeling
# ---------------------------------------------------------------------------

def test_002_command_is_update_case(command_text):
    assert "/update-case" in command_text
    assert "# ThreatTrace Update Case — Deprecated Compatibility Command" in command_text


def test_003_labeled_deprecated(command_text):
    assert "**deprecated compatibility command**" in command_text
    assert "deprecated" in command_text.lower()


def test_004_labeled_compatibility_command(command_text):
    assert "compatibility command" in command_text.lower()


def test_005_provides_static_response(command_text):
    assert "This command always returns the one static response below" in command_text
    assert "Always produce exactly this response" in command_text


# ---------------------------------------------------------------------------
# 6-10: $ARGUMENTS handling
# ---------------------------------------------------------------------------

def test_006_does_not_parse_arguments(command_text):
    assert "$ARGUMENTS" in command_text
    assert "never parses" in command_text.lower()


def test_007_does_not_inspect_arguments(command_text):
    assert "inspects" in command_text.lower()
    section_start = command_text.find("## Command Input (Ignored)")
    section = command_text[section_start : section_start + 500]
    assert "inspects" in section.lower()


def test_008_does_not_interpret_arguments(command_text):
    section_start = command_text.find("## Command Input (Ignored)")
    section = command_text[section_start : section_start + 500]
    assert "interprets" in section.lower()


def test_009_does_not_validate_arguments(command_text):
    section_start = command_text.find("## Command Input (Ignored)")
    section = command_text[section_start : section_start + 500]
    assert "validates" in section.lower()


def test_010_does_not_echo_arguments(command_text):
    section_start = command_text.find("## Command Input (Ignored)")
    section = command_text[section_start : section_start + 500]
    assert "echoes" in section.lower()
    assert "never includes any part of it in its own response" in section


# ---------------------------------------------------------------------------
# 11-13: no lookup, no preview
# ---------------------------------------------------------------------------

def test_011_no_investigation_lookup(command_text):
    section = _boundaries_section(command_text)
    assert "query an investigation" in section
    assert "Never look up an investigation" in command_text


def test_012_no_approval_lookup(command_text):
    section = _boundaries_section(command_text)
    assert "query an approval" in section


def test_013_no_preview(command_text):
    section = _boundaries_section(command_text)
    assert "perform a preview" in section
    assert "Never show a preview of any kind." in command_text


# ---------------------------------------------------------------------------
# 14-15: confirmation phrase removal
# ---------------------------------------------------------------------------

def test_014_old_confirmation_phrase_absent(command_text):
    assert "Update case" not in command_text


def test_015_no_replacement_confirmation_phrase(command_text):
    section_start = command_text.find("## No Confirmation Phrase")
    section_end = command_text.find("## Absolute Non-Execution Boundaries")
    section = command_text[section_start:section_end]
    assert "removed completely" in section
    assert "No replacement phrase is defined in its place." in section
    for word in ("yes", "confirm", "proceed", "approve"):
        assert f'"{word}"' in section or f"'{word}'" in section
    assert "does not authorize" in section.lower() or "never performs a mutating action" in section.lower()


# ---------------------------------------------------------------------------
# 16-19: workflow guidance
# ---------------------------------------------------------------------------

def test_016_directs_to_request_case_update(command_text):
    assert "`/request-case-update`" in command_text


def test_017_directs_to_review_approval(command_text):
    assert "`/review-approval`" in command_text


def test_018_directs_to_apply_case_update(command_text):
    assert "`/apply-case-update`" in command_text


def test_019_three_commands_in_correct_order(command_text):
    section_start = command_text.find("## Required Response")
    section_end = command_text.find("### Example", section_start)
    section = command_text[section_start:section_end]
    indices = []
    search_start = 0
    for name in WORKFLOW_COMMANDS_IN_ORDER:
        idx = section.find(name, search_start)
        assert idx != -1, f"command not found in required-response workflow list: {name}"
        indices.append(idx)
        search_start = idx + len(name)
    assert indices == sorted(indices)


# ---------------------------------------------------------------------------
# 20-24: workflow explanation and outcome statements
# ---------------------------------------------------------------------------

def test_020_explains_request_creates_pending_approval(command_text):
    assert "creates a pending approval request" in command_text
    assert "it does not update the investigation" in command_text


def test_021_explains_approve_reject_review_behavior(command_text):
    assert "a reviewer approves or rejects the pending request" in command_text


def test_022_explains_atomic_application_behavior(command_text):
    assert "atomically consumes an approved request and applies the change to the investigation" in command_text


def test_023_states_no_database_operation_occurred(command_text):
    assert '"No database operation was performed."' in command_text


def test_024_states_investigation_not_updated(command_text):
    assert '"The investigation was not updated."' in command_text


# ---------------------------------------------------------------------------
# 25-27: no automatic invocation of the real commands
# ---------------------------------------------------------------------------

def test_025_does_not_execute_request_case_update(command_text):
    section_start = command_text.find("## This Command Never Invokes the Workflow It Describes")
    section = command_text[section_start : section_start + 500]
    assert "never invokes, executes, forwards to, delegates to, or simulates" in section
    assert "/request-case-update" in section


def test_026_does_not_execute_review_approval(command_text):
    section_start = command_text.find("## This Command Never Invokes the Workflow It Describes")
    section = command_text[section_start : section_start + 500]
    assert "/review-approval" in section


def test_027_does_not_execute_apply_case_update(command_text):
    section_start = command_text.find("## This Command Never Invokes the Workflow It Describes")
    section = command_text[section_start : section_start + 500]
    assert "/apply-case-update" in section


# ---------------------------------------------------------------------------
# 28-36: request example
# ---------------------------------------------------------------------------

def test_028_contains_valid_request_example(command_text):
    assert "### Example" in command_text
    example_json_text = _example_line(command_text)
    assert example_json_text.strip().startswith("{")


def test_029_example_is_exactly_one_json_object(command_text):
    example_json_text = _example_line(command_text)
    parsed = json.loads(example_json_text)
    assert isinstance(parsed, dict)


def test_030_example_contains_valid_uuid(command_text):
    example_json_text = _example_line(command_text)
    parsed = json.loads(example_json_text)
    uuid_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
    )
    assert uuid_pattern.match(parsed["investigation_id"])


def test_031_example_contains_investigation_id(command_text):
    parsed = json.loads(_example_line(command_text))
    assert "investigation_id" in parsed


def test_032_example_contains_requested_by(command_text):
    parsed = json.loads(_example_line(command_text))
    assert "requested_by" in parsed


def test_033_example_contains_status_or_confidence(command_text):
    parsed = json.loads(_example_line(command_text))
    assert "status" in parsed or "confidence" in parsed


def test_034_example_does_not_contain_approval_id(command_text):
    parsed = json.loads(_example_line(command_text))
    assert "approval_id" not in parsed


def test_035_example_does_not_contain_action_type(command_text):
    parsed = json.loads(_example_line(command_text))
    assert "action_type" not in parsed


def test_036_example_does_not_contain_action_payload(command_text):
    parsed = json.loads(_example_line(command_text))
    assert "action_payload" not in parsed


# ---------------------------------------------------------------------------
# 37: claimed identity wording
# ---------------------------------------------------------------------------

def test_037_requested_by_described_as_claimed_identity(command_text):
    section_start = command_text.find("### Example")
    section = command_text[section_start : section_start + 700]
    assert "claimed requester identity" in section
    assert "not an authenticated or verified one" in section


# ---------------------------------------------------------------------------
# 38-46: absolute non-execution boundaries
# ---------------------------------------------------------------------------

def test_038_does_not_call_supabase_or_mcp(command_text):
    section = _boundaries_section(command_text)
    assert "call Supabase" in section
    assert "call MCP" in section


def test_039_does_not_name_executable_execute_sql_step(command_text):
    for index in _find_all(command_text, "execute_sql"):
        _assert_negated(command_text, index, label="execute_sql")
    section = _boundaries_section(command_text)
    assert "mcp__supabase__execute_sql" in section


def test_040_does_not_call_apply_migration(command_text):
    section = _boundaries_section(command_text)
    assert "apply_migration" in section
    for index in _find_all(command_text, "apply_migration"):
        _assert_negated(command_text, index, label="apply_migration")


def test_041_does_not_generate_or_execute_sql(command_text):
    section = _boundaries_section(command_text)
    assert "execute SQL" in section
    assert "generate SQL" in section


def test_042_does_not_update_investigations(command_text):
    section = _boundaries_section(command_text)
    assert "update `public.investigations`" in section


def test_043_does_not_update_approvals(command_text):
    section = _boundaries_section(command_text)
    assert "update `public.approvals`" in section


def test_044_does_not_invoke_atomic_consumption_rpc(command_text):
    section = _boundaries_section(command_text)
    assert "consume_approval_and_update_investigation_state" in section
    for index in _find_all(command_text, "consume_approval_and_update_investigation_state"):
        _assert_negated(command_text, index, label="atomic RPC")


def test_045_does_not_call_approval_validator_bridge_or_adapter_cli(command_text):
    section = _boundaries_section(command_text)
    for module_name in (
        "core.approval_request_cli",
        "core.approval_transition_cli",
        "core.approval_bridge_cli",
        "core.approval_mcp_adapter_cli",
    ):
        assert module_name in section
        for index in _find_all(command_text, module_name):
            _assert_negated(command_text, index, label=module_name)


def test_046_no_retry_or_fallback_behavior(command_text):
    section = _boundaries_section(command_text)
    assert "perform a retry" in section
    assert "perform a fallback mutation" in section
    assert "Never retry or fall back to any mutation." in command_text


# ---------------------------------------------------------------------------
# 47: no sensitive content
# ---------------------------------------------------------------------------

def test_047_no_credential_token_url_project_reference_or_raw_error(command_text):
    forbidden_patterns = (
        r"postgres://\S+:\S+@",
        r"https?://\S*supabase\S*",
        r"eyJ[a-zA-Z0-9_-]{10,}",
        r"sk-[a-zA-Z0-9]{10,}",
        r"service_role_key\s*[:=]\s*\S+",
    )
    for pattern in forbidden_patterns:
        assert re.search(pattern, command_text) is None
    section = _boundaries_section(command_text)
    assert "expose a credential, a token, a project URL, a project reference" in section


# ---------------------------------------------------------------------------
# 48: static-test self-boundary
# ---------------------------------------------------------------------------

def test_048_static_test_module_is_offline():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    forbidden_modules = {
        "core.approval_request_cli",
        "core.approval_transition_cli",
        "core.approval_bridge_cli",
        "core.approval_mcp_adapter_cli",
        "core.approval_request",
        "core.approval_transition",
        "core.approval_bridge",
        "core.approval_mcp_adapter",
        "core.approval_persistence",
        "supabase",
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "http",
    }
    assert not (imported & forbidden_modules)
    assert not any(name.startswith("supabase.") for name in imported)
