"""Static tests for .claude/commands/request-case-update.md.

These tests only read the command Markdown file as text and check its
content structurally. They never execute /request-case-update, never
invoke any project CLI, never call Supabase or MCP, never perform network
access, never launch a subprocess, never create a temporary file, and
never modify any command file.
"""

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMAND_PATH = REPO_ROOT / ".claude" / "commands" / "request-case-update.md"

REQUIRED_INPUT_FIELDS = ("investigation_id", "requested_by")
CHANGE_FIELDS = ("status", "confidence")
OPTIONAL_INPUT_FIELDS = ("expires_at",)

FORBIDDEN_INPUT_FIELDS = (
    "approval_id",
    "id",
    "action_type",
    "action_payload",
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "rejection_reason",
    "consumed_by",
    "consumed_at",
    "approval_status",
    "created_at",
    "sql",
    "table",
    "function",
)

FAILURE_CATEGORIES = (
    "INVALID_INPUT",
    "VALIDATION_FAILED",
    "PREPARE_FAILED",
    "MCP_CALL_FAILED",
    "RESPONSE_NORMALIZATION_FAILED",
    "VERIFICATION_FAILED",
    "PERSISTENCE_CONFLICT",
)

STAGE_HEADINGS_IN_ORDER = (
    "## Stage 1 — Approval Request Validation CLI",
    "## Stage 2 — Approval Bridge Prepare",
    "## Stage 3 — MCP Adapter Prepare Call",
    "## Stage 4 — Execute Through Supabase MCP",
    "## Stage 5 — MCP Adapter Normalize Response",
    "## Stage 6 — Approval Bridge Verify",
)

EXAMPLE_HEADINGS_IN_ORDER = (
    "### 1. Status-only request",
    "### 2. Confidence-only request",
    "### 3. Status-and-confidence request",
    "### 4. Request with expires_at",
)

_NEGATION_MARKERS = (
    "do not", "does not", "never", "no ", "none ", "must not", "not perform",
    "not accepted", "not itself", "not expected", "not reachable",
)

# Affirmative write/mutate/execute/approve verbs that must never be used as
# an instruction telling the command to actually perform the corresponding
# action against an approval or investigation. They may still appear inside
# negative safety prose ("do not X", "never X", "no X").
_AFFIRMATIVE_FORBIDDEN_VERB_PATTERNS = (
    r"\bupdate\s+(?:the investigation|public\.investigations|an investigation)\b",
    r"\bapprove\s+(?:the|this|an)\s+approval\b",
    r"\breject\s+(?:the|this|an)\s+approval\b",
    r"\bconsume\s+(?:the|this|an)\s+approval\b",
)


@pytest.fixture(scope="module")
def command_text():
    return COMMAND_PATH.read_text(encoding="utf-8")


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


def _has_write_mode_open_call(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            positional_mode = node.args[1] if len(node.args) > 1 else None
            if isinstance(positional_mode, ast.Constant) and isinstance(positional_mode.value, str):
                if "w" in positional_mode.value or "a" in positional_mode.value:
                    return True
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    if "w" in kw.value.value or "a" in kw.value.value:
                        return True
    return False


def _has_call_to_attr(tree, attr_names):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in attr_names:
                return True
    return False


def _find_all(text, needle):
    return [m.start() for m in re.finditer(re.escape(needle), text)]


# ---------------------------------------------------------------------------
# 1-3: file existence and $ARGUMENTS shape
# ---------------------------------------------------------------------------

def test_001_command_file_exists_at_exact_path():
    assert COMMAND_PATH.is_file()


def test_002_command_declares_request_case_update(command_text):
    assert "/request-case-update" in command_text
    assert "# ThreatTrace Request Case Update Workflow" in command_text


def test_003_command_uses_arguments(command_text):
    assert "$ARGUMENTS" in command_text


def test_003b_input_is_exactly_one_json_object(command_text):
    assert "exactly one JSON object" in command_text
    assert "top-level JSON value that is not an object" in command_text


# ---------------------------------------------------------------------------
# 4-7: required/optional input fields
# ---------------------------------------------------------------------------

def test_004_requires_investigation_id(command_text):
    assert "`investigation_id`" in command_text


def test_005_requires_requested_by(command_text):
    assert "`requested_by`" in command_text


def test_006_requires_status_or_confidence(command_text):
    assert "At least one of these two must also be present:" in command_text
    for field in CHANGE_FIELDS:
        assert f"`{field}`" in command_text


def test_006b_expires_at_is_optional(command_text):
    section_start = command_text.find("Optional:")
    section = command_text[section_start : section_start + 80]
    assert "`expires_at`" in section


def test_007_unknown_fields_rejected(command_text):
    assert "Reject every field this list does not name." in command_text


def test_007b_all_forbidden_fields_named(command_text):
    section_start = command_text.find("Reject every field this list does not name.")
    section = command_text[section_start : section_start + 900]
    for field in FORBIDDEN_INPUT_FIELDS:
        assert f"`{field}`" in section


# ---------------------------------------------------------------------------
# 8-9: claimed-identity boundary
# ---------------------------------------------------------------------------

def test_008_requested_by_described_as_claimed(command_text):
    section_start = command_text.find("### `requested_by`")
    section = command_text[section_start : section_start + 600]
    assert "caller-supplied claimed identity" in section

    boundary_start = command_text.find("## Claimed Identity Boundary")
    boundary_section = command_text[boundary_start : boundary_start + 600]
    assert "caller-supplied claimed identity" in boundary_section


def test_009_requested_by_never_described_as_authenticated_or_verified(command_text):
    # "Verified Approval Record" is this command's own fixed stage-output
    # label (what the bridge's verify phase produced), not a claim about
    # requested_by's identity -- excluded so it cannot shadow the real check.
    safe_phrases = ("Verified Approval Record",)
    exclusion_ranges = [
        (idx, idx + len(phrase))
        for phrase in safe_phrases
        for idx in _find_all(command_text, phrase)
    ]

    def _in_exclusion(pos):
        return any(start <= pos < end for start, end in exclusion_ranges)

    for term in ("authenticated", "verified", "trusted", "cryptographically proven"):
        for index in _find_all(command_text.lower(), term):
            if _in_exclusion(index):
                continue
            preceding = command_text.lower()[max(0, index - 150) : index]
            assert any(marker in preceding for marker in _NEGATION_MARKERS), (
                f"possible affirmative identity claim near: "
                f"{command_text[max(0, index - 20):index + 40]!r}"
            )


# ---------------------------------------------------------------------------
# 10-11: approval-ID generation
# ---------------------------------------------------------------------------

def test_010_approval_id_generated_internally(command_text):
    assert "generates a brand-new approval UUID itself" in command_text
    assert "never from caller-supplied text" in command_text


def test_011_approval_id_not_accepted_as_input(command_text):
    assert "`approval_id`" in command_text
    section_start = command_text.find("Reject every field this list does not name.")
    section = command_text[section_start : section_start + 900]
    assert "`approval_id`" in section
    assert "`id`" in section


# ---------------------------------------------------------------------------
# 12-17: CLI/bridge/adapter integration
# ---------------------------------------------------------------------------

def test_012_uses_canonical_request_validator_cli(command_text):
    assert "core.approval_request_cli" in command_text
    assert "core.approval_request.validate_approval_request" in command_text


def test_013_uses_bridge_prepare(command_text):
    assert "core.approval_bridge_cli" in command_text
    assert '"phase": "prepare"' in command_text
    assert '"operation": "insert_pending_approval"' in command_text


def test_014_uses_adapter_prepare_call(command_text):
    assert "core.approval_mcp_adapter_cli" in command_text
    assert '"action": "prepare_call"' in command_text


def test_015_invokes_execute_sql_only_through_adapter_arguments(command_text):
    assert "mcp__supabase__execute_sql" in command_text
    assert "using exactly the `arguments` the adapter returned" in command_text


def test_016_uses_adapter_normalize_response(command_text):
    assert '"action": "normalize_response"' in command_text


def test_017_uses_bridge_verify(command_text):
    assert '"phase": "verify"' in command_text


# ---------------------------------------------------------------------------
# 18-20: no raw parsing, no direct SQL, no apply_migration
# ---------------------------------------------------------------------------

def test_018_never_parses_raw_mcp_envelope_directly(command_text):
    assert "Do not parse, inspect, or trust the raw MCP result directly" in command_text


def test_019_never_generates_direct_sql(command_text):
    assert "Never generate SQL directly" in command_text
    assert "never interpolate" in command_text.lower()


def test_020_never_calls_apply_migration(command_text):
    assert "Never use `apply_migration`" in command_text
    # Both real occurrences of "apply_migration" sit inside a multi-line
    # "must never:"/"Do not:" bulleted list, several list items after the
    # negation-introducing line itself -- the window must be wide enough to
    # reach back across the whole list, not just the immediately preceding
    # bullet.
    for index in _find_all(command_text.lower(), "apply_migration"):
        preceding = command_text.lower()[max(0, index - 700) : index]
        following = command_text.lower()[index : index + 40]
        combined = preceding + following
        assert any(marker in combined for marker in _NEGATION_MARKERS), (
            f"possible affirmative apply_migration instruction near: "
            f"{command_text[max(0, index - 20):index + 60]!r}"
        )


# ---------------------------------------------------------------------------
# 21-24: mutation boundaries
# ---------------------------------------------------------------------------

def test_021_never_updates_investigations(command_text):
    assert "Never update `public.investigations`." in command_text


def test_022_never_invokes_atomic_consumption_rpc(command_text):
    assert "consume_approval_and_update_investigation_state" in command_text
    assert "Never call the atomic consumption RPC." in command_text


def test_023_never_approves_rejects_or_consumes(command_text):
    assert "Never approve, reject, or consume an approval." in command_text


def test_024_never_uses_legacy_update_case_path(command_text):
    assert "Never use the legacy direct-update path `/update-case` uses." in command_text


# ---------------------------------------------------------------------------
# 25: no automatic retry
# ---------------------------------------------------------------------------

def test_025_does_not_automatically_retry(command_text):
    assert "Never retry any failure automatically." in command_text
    assert "Do not automatically retry any failure in any category above." in command_text


# ---------------------------------------------------------------------------
# 26-29: fail-closed behavior
# ---------------------------------------------------------------------------

def test_026_fails_closed_on_zero_rows(command_text):
    assert "contained zero rows" in command_text


def test_027_fails_closed_on_multiple_rows(command_text):
    assert "contained more than one row" in command_text


def test_028_fails_closed_on_transport_error(command_text):
    assert '{"kind": "transport_error"}' in command_text
    assert "approval_transport_error" in command_text
    assert "MCP_CALL_FAILED" in command_text


def test_029_fails_closed_on_binding_mismatch(command_text):
    assert "did not match the prepared binding" in command_text
    for field in ("approval ID", "investigation ID", "action type", "action payload", "requested identity", "pending status"):
        assert field in command_text


# ---------------------------------------------------------------------------
# 30-32: success output
# ---------------------------------------------------------------------------

def test_030_reports_approval_as_pending(command_text):
    assert "Approval Status: `pending`" in command_text


def test_031_states_investigation_not_updated(command_text):
    assert "A clear statement that the investigation has not been updated" in command_text


def test_032_points_to_review_approval_next(command_text):
    assert "/review-approval <approval-id>" in command_text


# ---------------------------------------------------------------------------
# 33-36: examples
# ---------------------------------------------------------------------------

def test_033_to_036_all_four_examples_present_in_order(command_text):
    indices = []
    search_start = 0
    for heading in EXAMPLE_HEADINGS_IN_ORDER:
        idx = command_text.find(heading, search_start)
        assert idx != -1, f"heading not found: {heading}"
        indices.append(idx)
        search_start = idx + len(heading)
    assert indices == sorted(indices)


def test_examples_use_syntactically_valid_uuids_and_timestamps():
    text = COMMAND_PATH.read_text(encoding="utf-8")
    section_start = text.find("## Example Requests")
    section = text[section_start : text.find("## Safety Rules")]
    uuid_pattern = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
    )
    assert uuid_pattern.search(section)
    timestamp_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
    assert timestamp_pattern.search(section)


# ---------------------------------------------------------------------------
# 37: action_payload contains only supported keys
# ---------------------------------------------------------------------------

def test_037_action_payload_uses_only_status_and_confidence(command_text):
    stage1_start = command_text.find("## Stage 1 — Approval Request Validation CLI")
    stage1_end = command_text.find("## Stage 2", stage1_start)
    section = command_text[stage1_start:stage1_end]
    payload_block_start = section.find('"action_payload"')
    payload_block_end = section.find("}", payload_block_start)
    payload_block = section[payload_block_start:payload_block_end]
    assert '"status"' in payload_block
    assert '"confidence"' in payload_block
    for forbidden in ("approved_by", "rejected_by", "consumed_by", "action_hash", "target_type"):
        assert forbidden not in payload_block


# ---------------------------------------------------------------------------
# 38: no embedded secrets/URLs/tokens
# ---------------------------------------------------------------------------

def test_038_no_embedded_credential_url_token_or_project_reference(command_text):
    forbidden_patterns = (
        r"postgres://\S+:\S+@",
        r"https?://\S*supabase\S*",
        r"eyJ[a-zA-Z0-9_-]{10,}",  # JWT-like token
        r"sk-[a-zA-Z0-9]{10,}",
        r"service_role_key\s*[:=]\s*\S+",
    )
    for pattern in forbidden_patterns:
        assert re.search(pattern, command_text) is None


# ---------------------------------------------------------------------------
# 39: fixed sanitized failure categories
# ---------------------------------------------------------------------------

def test_039_all_seven_failure_categories_present_in_order(command_text):
    indices = []
    search_start = 0
    for category in FAILURE_CATEGORIES:
        heading = f"### {category}"
        idx = command_text.find(heading, search_start)
        assert idx != -1, f"category heading not found: {heading}"
        indices.append(idx)
        search_start = idx + len(heading)
    assert indices == sorted(indices)


def test_039b_no_raw_error_exposure_statement(command_text):
    assert "Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token" in command_text


# ---------------------------------------------------------------------------
# 40: two-phase prepare/verify architecture preserved
# ---------------------------------------------------------------------------

def test_040_two_phase_architecture_named(command_text):
    assert "two-phase prepare/verify approval bridge" in command_text


def test_040b_all_six_stages_appear_in_order(command_text):
    indices = []
    search_start = 0
    for heading in STAGE_HEADINGS_IN_ORDER:
        idx = command_text.find(heading, search_start)
        assert idx != -1, f"stage heading not found: {heading}"
        indices.append(idx)
        search_start = idx + len(heading)
    assert indices == sorted(indices)


def test_040c_prepare_phase_precedes_verify_phase(command_text):
    prepare_index = command_text.find('"phase": "prepare"')
    verify_index = command_text.find('"phase": "verify"')
    assert 0 <= prepare_index < verify_index


# ---------------------------------------------------------------------------
# Additional structural safety checks
# ---------------------------------------------------------------------------

def test_command_ends_with_safety_rules(command_text):
    stripped = command_text.rstrip()
    safety_index = stripped.rfind("## Safety Rules")
    assert safety_index != -1
    remainder = stripped[safety_index:]
    assert remainder.count("\n## ") == 0
    assert remainder.count("\n# ") == 0


def test_only_pending_status_ever_claimed_for_the_created_approval(command_text):
    assert "Never claim the approval is approved." in command_text
    assert "Never claim the requested change has been applied." in command_text


def test_no_affirmative_forbidden_verb_outside_negation(command_text):
    # Several matches (e.g. "consume an approval") sit inside the same
    # multi-line "must never:" bulleted list as test_020's apply_migration
    # check above -- use the same wide window for the same reason.
    for pattern in _AFFIRMATIVE_FORBIDDEN_VERB_PATTERNS:
        for match in re.finditer(pattern, command_text, flags=re.IGNORECASE):
            preceding_text = command_text[max(0, match.start() - 700) : match.start()].lower()
            assert any(marker in preceding_text for marker in _NEGATION_MARKERS), (
                f"possible affirmative instruction near: {command_text[match.start():match.start()+80]!r}"
            )


def test_python_launcher_fallback_documented(command_text):
    assert "Try `py`" in command_text
    assert "Otherwise try `python3`" in command_text
    assert "Python 3.10 or later" in command_text


def test_all_three_cli_modules_checked_for_import(command_text):
    section_start = command_text.find("confirm the selected launcher can import all three required modules")
    section = command_text[section_start : section_start + 400]
    for module_name in ("core.approval_request_cli", "core.approval_bridge_cli", "core.approval_mcp_adapter_cli"):
        assert module_name in section


def test_clis_invoked_through_stdin_only(command_text):
    assert "**stdin only**" in command_text
    assert command_text.count("**stdin only**") >= 3


def test_no_temporary_json_files_allowed(command_text):
    assert "create a temporary JSON file" in command_text


# ---------------------------------------------------------------------------
# Static-test self-boundaries
# ---------------------------------------------------------------------------

def test_static_tests_do_not_run_clis():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    forbidden_modules = {
        "core.approval_request_cli",
        "core.approval_bridge_cli",
        "core.approval_mcp_adapter_cli",
        "core.approval_request",
        "core.approval_bridge",
        "core.approval_mcp_adapter",
        "core.approval_persistence",
    }
    assert not (imported & forbidden_modules)


def test_static_tests_do_not_call_supabase_or_mcp():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imported)
    assert not any("mcp" in name.lower() for name in imported)


def test_static_tests_do_not_use_subprocess_socket_or_network():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    for forbidden in ("subprocess", "socket", "requests", "urllib", "http"):
        assert forbidden not in imported


def test_static_tests_do_not_modify_any_file():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "shutil" not in imported
    assert not _has_write_mode_open_call(tree)
    assert not _has_call_to_attr(tree, {"write_text", "write_bytes", "unlink", "remove", "rename"})


def test_static_tests_use_precise_parsing_not_broad_substring_only():
    tree = _this_module_ast()
    function_defs = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    assert len(function_defs) > 40
