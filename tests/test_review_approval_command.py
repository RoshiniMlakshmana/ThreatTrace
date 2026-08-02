"""Static tests for .claude/commands/review-approval.md.

These tests only read the command Markdown file as text and check its
content structurally. They never execute /review-approval, never invoke
any project CLI, never call Supabase or MCP, never perform network
access, never launch a subprocess, never create a temporary file, and
never modify any command file.
"""

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMAND_PATH = REPO_ROOT / ".claude" / "commands" / "review-approval.md"

REQUIRED_INPUT_FIELDS = ("approval_id", "decision", "reviewed_by")
DECISION_VALUES = ("approve", "reject")

FORBIDDEN_INPUT_FIELDS = (
    "investigation_id",
    "action_type",
    "action_payload",
    "status",
    "confidence",
    "requested_by",
    "requested_at",
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "consumed_by",
    "consumed_at",
    "created_at",
    "expires_at",
    "sql",
    "table",
    "function",
    "transition_plan",
    "descriptor",
)

FAILURE_CATEGORIES = (
    "INVALID_INPUT",
    "LOOKUP_PREPARE_FAILED",
    "LOOKUP_MCP_CALL_FAILED",
    "LOOKUP_NORMALIZATION_FAILED",
    "APPROVAL_NOT_FOUND",
    "LOOKUP_VERIFICATION_FAILED",
    "REVIEW_NOT_ALLOWED",
    "SELF_REVIEW_FORBIDDEN",
    "TRANSITION_VALIDATION_FAILED",
    "REVIEW_PREPARE_FAILED",
    "REVIEW_MCP_CALL_FAILED",
    "REVIEW_NORMALIZATION_FAILED",
    "REVIEW_VERIFICATION_FAILED",
    "PERSISTENCE_CONFLICT",
)

STAGE_HEADINGS_IN_ORDER = (
    "## Stage 1 — Lookup Bridge Prepare",
    "## Stage 2 — Lookup MCP Adapter Prepare Call",
    "## Stage 3 — Execute Through Supabase MCP (Lookup)",
    "## Stage 4 — Lookup MCP Adapter Normalize Response",
    "## Stage 5 — Lookup Bridge Verify",
    "## Stage 6 — Review Eligibility and Transition Validation",
    "## Stage 7 — Review Bridge Prepare",
    "## Stage 8 — Review MCP Adapter Prepare Call",
    "## Stage 9 — Execute Through Supabase MCP (Review Update)",
    "## Stage 10 — Review MCP Adapter Normalize Response",
    "## Stage 11 — Review Bridge Verify",
)

EXAMPLE_HEADINGS_IN_ORDER = (
    "### 1. Approve",
    "### 2. Reject",
)

_NEGATION_MARKERS = (
    "do not", "does not", "never", "no ", "none ", "must not", "not perform",
    "not accepted", "not itself", "not expected", "not reachable", "cannot",
)

# Fixed stage-output labels that legitimately contain "verified"/"verify" as
# part of this command's own architecture vocabulary (what the bridge's
# verify phase produced), not a claim about reviewed_by's/requested_by's
# identity -- excluded so they cannot shadow the real identity-boundary
# check below.
_SAFE_VERIFIED_PHRASES = (
    "Verified Reviewed Approval",
    "verified reviewed approval",
)

_AFFIRMATIVE_FORBIDDEN_VERB_PATTERNS = (
    r"\bupdate\s+(?:the investigation|public\.investigations|an investigation)\b",
    r"\bapprove\s+(?:the|this|an)\s+approval\b",
    r"\breject\s+(?:the|this|an)\s+approval\b",
    r"\bconsume\s+(?:the|this|an)\s+approval\b",
    r"\bapply\s+(?:the|this)\s+(?:proposed\s+)?(?:status|confidence)\b",
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


def test_002_command_declares_review_approval(command_text):
    assert "/review-approval" in command_text
    assert "# ThreatTrace Review Approval Workflow" in command_text


def test_003_command_reads_exactly_one_json_object(command_text):
    assert "$ARGUMENTS" in command_text
    assert "exactly one JSON object" in command_text
    assert "top-level JSON value that is not an object" in command_text


# ---------------------------------------------------------------------------
# 4-9: input envelope
# ---------------------------------------------------------------------------

def test_004_requires_approval_id(command_text):
    assert "`approval_id`" in command_text


def test_005_requires_decision(command_text):
    assert "`decision`" in command_text


def test_006_requires_reviewed_by(command_text):
    assert "`reviewed_by`" in command_text


def test_007_supports_exact_approve_reject_vocabulary(command_text):
    section_start = command_text.find("### `decision`")
    section = command_text[section_start : section_start + 400]
    for value in DECISION_VALUES:
        assert f"`{value}`" in section
    assert "Never `consume`" in section


def test_008_conditionally_requires_rejection_reason(command_text):
    assert "Conditionally required:" in command_text
    assert (
        "`rejection_reason` — required only when `decision` is `reject`; "
        "must not be present at all when `decision` is `approve`."
    ) in command_text


def test_009_unknown_fields_rejected(command_text):
    assert "Reject every field this list does not name." in command_text


def test_009b_all_forbidden_fields_named(command_text):
    section_start = command_text.find("Reject every field this list does not name.")
    section = command_text[section_start : section_start + 700]
    for field in FORBIDDEN_INPUT_FIELDS:
        assert f"`{field}`" in section


# ---------------------------------------------------------------------------
# 10-11: claimed reviewer identity
# ---------------------------------------------------------------------------

def test_010_reviewed_by_described_only_as_claimed(command_text):
    section_start = command_text.find("### `reviewed_by`")
    section = command_text[section_start : section_start + 700]
    assert "claimed reviewer identity" in section

    boundary_start = command_text.find("## Claimed Identity Boundary")
    boundary_section = command_text[boundary_start : boundary_start + 600]
    assert "claimed reviewer identity" in boundary_section
    assert "claimed requester identity" in boundary_section


def test_011_reviewed_by_never_described_as_authenticated_or_verified(command_text):
    exclusion_ranges = [
        (idx, idx + len(phrase))
        for phrase in _SAFE_VERIFIED_PHRASES
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
# 12: lookup precedes transition validation
# ---------------------------------------------------------------------------

def test_012_loads_approval_before_validating_transition(command_text):
    indices = []
    search_start = 0
    for heading in STAGE_HEADINGS_IN_ORDER:
        idx = command_text.find(heading, search_start)
        assert idx != -1, f"stage heading not found: {heading}"
        indices.append(idx)
        search_start = idx + len(heading)
    assert indices == sorted(indices)

    lookup_stage_index = command_text.find("## Stage 5 — Lookup Bridge Verify")
    transition_stage_index = command_text.find("## Stage 6 — Review Eligibility and Transition Validation")
    assert 0 <= lookup_stage_index < transition_stage_index


# ---------------------------------------------------------------------------
# 13-20: lookup bridge/adapter integration
# ---------------------------------------------------------------------------

def test_013_uses_bridge_prepare_for_load_approval_record(command_text):
    stage1_start = command_text.find("## Stage 1 — Lookup Bridge Prepare")
    stage1_end = command_text.find("## Stage 2", stage1_start)
    section = command_text[stage1_start:stage1_end]
    assert '"phase": "prepare"' in section
    assert '"operation": "load_approval_record"' in section
    assert "core.approval_bridge_cli" in section


def test_014_uses_adapter_prepare_call_for_lookup(command_text):
    stage2_start = command_text.find("## Stage 2 — Lookup MCP Adapter Prepare Call")
    stage2_end = command_text.find("## Stage 3", stage2_start)
    section = command_text[stage2_start:stage2_end]
    assert '"action": "prepare_call"' in section
    assert "core.approval_mcp_adapter_cli" in section


def test_015_invokes_execute_sql_only_with_adapter_arguments(command_text):
    assert command_text.count("mcp__supabase__execute_sql") >= 2
    assert command_text.count("using exactly the `arguments` the adapter returned") >= 2


def test_016_normalizes_lookup_response_through_adapter(command_text):
    stage4_start = command_text.find("## Stage 4 — Lookup MCP Adapter Normalize Response")
    stage4_end = command_text.find("## Stage 5", stage4_start)
    section = command_text[stage4_start:stage4_end]
    assert '"action": "normalize_response"' in section
    assert '"operation": "load_approval_record"' in section


def test_017_verifies_lookup_through_bridge(command_text):
    stage5_start = command_text.find("## Stage 5 — Lookup Bridge Verify")
    stage5_end = command_text.find("## Stage 6", stage5_start)
    section = command_text[stage5_start:stage5_end]
    assert '"phase": "verify"' in section
    assert '"operation": "load_approval_record"' in section


def test_018_fails_closed_on_zero_lookup_rows(command_text):
    assert "`approval_not_found`: no approval exists with the supplied ID" in command_text
    assert "APPROVAL_NOT_FOUND" in command_text


def test_019_fails_closed_on_multiple_lookup_rows(command_text):
    stage5_start = command_text.find("## Stage 5 — Lookup Bridge Verify")
    stage5_end = command_text.find("## Stage 6", stage5_start)
    section = command_text[stage5_start:stage5_end]
    assert "contained more than one row" in section


def test_020_never_parses_raw_mcp_envelope_directly(command_text):
    assert "Do not parse, inspect, or trust the raw MCP result directly" in command_text


# ---------------------------------------------------------------------------
# 21-25: eligibility, self-review, transition plan
# ---------------------------------------------------------------------------

def test_021_requires_loaded_status_pending(command_text):
    assert "its current `status` is `pending`" in command_text
    assert "current status is not `pending`" in command_text


def test_022_prevents_claimed_requester_self_review(command_text):
    assert "SELF_REVIEW_FORBIDDEN" in command_text
    assert "the reviewer must differ from the original requester" in command_text
    assert "Never allow self-review on an approve decision." in command_text


def test_023_uses_approval_transition_cli(command_text):
    assert "core.approval_transition_cli" in command_text
    assert "core.approval_transition.validate_approval_transition" in command_text


def test_024_creates_genuine_validator_produced_transition_plan(command_text):
    assert "Call this the **genuine transition plan**." in command_text
    assert "Do not manually construct or forge a transition plan" in command_text


def test_025_does_not_accept_transition_plan_from_caller(command_text):
    section_start = command_text.find("Reject every field this list does not name.")
    section = command_text[section_start : section_start + 700]
    assert "`transition_plan`" in section
    assert "Never accept a caller-supplied transition plan or operation descriptor." in command_text


# ---------------------------------------------------------------------------
# 26-30: review-update bridge/adapter integration
# ---------------------------------------------------------------------------

def test_026_uses_bridge_prepare_for_review_transition(command_text):
    stage7_start = command_text.find("## Stage 7 — Review Bridge Prepare")
    stage7_end = command_text.find("## Stage 8", stage7_start)
    section = command_text[stage7_start:stage7_end]
    assert '"phase": "prepare"' in section
    assert '"operation": "apply_approval_review_transition"' in section


def test_027_uses_adapter_prepare_call_for_review_update(command_text):
    stage8_start = command_text.find("## Stage 8 — Review MCP Adapter Prepare Call")
    stage8_end = command_text.find("## Stage 9", stage8_start)
    section = command_text[stage8_start:stage8_end]
    assert '"action": "prepare_call"' in section


def test_028_performs_only_one_review_update(command_text):
    assert (
        "The only permitted database mutation anywhere in this command is this one "
        "conditional review-transition update on the `approvals` table." in command_text
    )
    assert "perform a second update attempt after a conflict" in command_text


def test_029_normalizes_update_response_through_adapter(command_text):
    stage10_start = command_text.find("## Stage 10 — Review MCP Adapter Normalize Response")
    stage10_end = command_text.find("## Stage 11", stage10_start)
    section = command_text[stage10_start:stage10_end]
    assert '"action": "normalize_response"' in section
    assert '"operation": "apply_approval_review_transition"' in section


def test_030_verifies_update_through_bridge(command_text):
    stage11_start = command_text.find("## Stage 11 — Review Bridge Verify")
    section = command_text[stage11_start : stage11_start + 1400]
    assert '"phase": "verify"' in section
    assert '"operation": "apply_approval_review_transition"' in section


# ---------------------------------------------------------------------------
# 31-36: fail-closed behavior on the review update
# ---------------------------------------------------------------------------

def test_031_fails_closed_on_zero_update_rows(command_text):
    assert "zero rows matched the conditional filter" in command_text
    assert "PERSISTENCE_CONFLICT" in command_text


def test_032_fails_closed_on_multiple_update_rows(command_text):
    stage11_start = command_text.find("## Stage 11 — Review Bridge Verify")
    section = command_text[stage11_start : stage11_start + 1400]
    assert "contained more than one row" in section


def test_033_fails_closed_on_transport_error(command_text):
    assert '{"kind": "transport_error"}' in command_text
    assert command_text.count("approval_transport_error") >= 2
    assert "REVIEW_MCP_CALL_FAILED" in command_text
    assert "LOOKUP_MCP_CALL_FAILED" in command_text


def test_034_fails_closed_on_binding_mismatch(command_text):
    assert "did not match the expected updated record" in command_text
    for field in (
        "approval ID", "investigation ID", "action type", "action payload",
        "requester identity", "reviewer identity", "final status", "unchanged consumption fields",
    ):
        assert field in command_text


def test_035_fails_closed_on_persistence_conflict(command_text):
    assert "code `approval_conflict`" in command_text
    assert "PERSISTENCE_CONFLICT" in command_text


def test_036_does_not_retry_automatically(command_text):
    assert "Do not automatically retry any failure in any category above." in command_text
    assert "Never retry any failure automatically" in command_text


# ---------------------------------------------------------------------------
# 37-44: mutation and SQL boundaries
# ---------------------------------------------------------------------------

def test_037_never_updates_investigations(command_text):
    assert "Never update `public.investigations`." in command_text


def test_038_never_calls_atomic_consumption_rpc(command_text):
    assert "consume_approval_and_update_investigation_state" in command_text
    assert "Never call the atomic consumption RPC." in command_text


def test_039_never_consumes_an_approval(command_text):
    assert "Never consume an approval." in command_text


def test_040_never_applies_status_or_confidence(command_text):
    assert "Never apply the proposed status or confidence to anything." in command_text


def test_041_never_changes_stored_action_type(command_text):
    assert "replace the stored `action_payload`, `action_type`, `investigation_id`, or `requested_by`" in command_text


def test_042_never_changes_stored_action_payload(command_text):
    assert "`action_payload`, `action_type`, `investigation_id`, or `requested_by`" in command_text


def test_043_never_uses_apply_migration(command_text):
    assert "Never use `apply_migration` in this workflow." in command_text
    for index in _find_all(command_text.lower(), "apply_migration"):
        preceding = command_text.lower()[max(0, index - 1200) : index]
        following = command_text.lower()[index : index + 40]
        combined = preceding + following
        assert any(marker in combined for marker in _NEGATION_MARKERS), (
            f"possible affirmative apply_migration instruction near: "
            f"{command_text[max(0, index - 20):index + 60]!r}"
        )


def test_044_never_generates_direct_sql(command_text):
    assert "Never generate SQL directly" in command_text
    assert "never interpolate" in command_text.lower()


# ---------------------------------------------------------------------------
# 45-49: success output
# ---------------------------------------------------------------------------

def test_045_reports_approved_status_correctly(command_text):
    assert 'Final Approval Status (`approved` or `rejected`)' in command_text
    assert '`status` equal to `"approved"`' in command_text


def test_046_reports_rejected_status_correctly(command_text):
    assert '`status` equal to `"rejected"`' in command_text


def test_047_states_investigation_not_updated(command_text):
    assert "A clear statement that the investigation has not been updated" in command_text


def test_048_points_approved_records_to_apply_case_update(command_text):
    assert "/apply-case-update <approval-id>" in command_text


def test_049_prevents_rejected_records_from_being_applied(command_text):
    assert (
        "state clearly that the requested case update cannot be applied, and that a new request "
        "through `/request-case-update` is required" in command_text
    )
    assert "Never claim a rejected request can still be applied." in command_text


# ---------------------------------------------------------------------------
# 50-52: examples and categories
# ---------------------------------------------------------------------------

def test_050_includes_valid_approve_and_reject_examples(command_text):
    indices = []
    search_start = 0
    for heading in EXAMPLE_HEADINGS_IN_ORDER:
        idx = command_text.find(heading, search_start)
        assert idx != -1, f"heading not found: {heading}"
        indices.append(idx)
        search_start = idx + len(heading)
    assert indices == sorted(indices)

    section_start = command_text.find("## Example Requests")
    section = command_text[section_start : command_text.find("## Safety Rules")]
    uuid_pattern = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
    )
    assert uuid_pattern.search(section)
    assert '"decision": "approve"' in section
    assert '"decision": "reject"' in section
    assert '"rejection_reason"' in section


def test_051_uses_fixed_sanitized_failure_categories_in_order(command_text):
    indices = []
    search_start = 0
    for category in FAILURE_CATEGORIES:
        heading = f"### {category}"
        idx = command_text.find(heading, search_start)
        assert idx != -1, f"category heading not found: {heading}"
        indices.append(idx)
        search_start = idx + len(heading)
    assert indices == sorted(indices)


def test_052_no_embedded_credential_url_token_or_project_reference(command_text):
    forbidden_patterns = (
        r"postgres://\S+:\S+@",
        r"https?://\S*supabase\S*",
        r"eyJ[a-zA-Z0-9_-]{10,}",
        r"sk-[a-zA-Z0-9]{10,}",
        r"service_role_key\s*[:=]\s*\S+",
    )
    for pattern in forbidden_patterns:
        assert re.search(pattern, command_text) is None
    assert (
        "Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, "
        "a project reference, an access token" in command_text
    )


# ---------------------------------------------------------------------------
# 53: strict architecture preserved
# ---------------------------------------------------------------------------

def test_053_preserves_prepare_execute_normalize_verify_architecture(command_text):
    assert "two-phase prepare/verify approval bridge" in command_text
    prepare_indices = _find_all(command_text, '"phase": "prepare"')
    verify_indices = _find_all(command_text, '"phase": "verify"')
    assert len(prepare_indices) == 2
    assert len(verify_indices) == 2
    # Lookup round trip: prepare then verify, before the review round trip's own prepare/verify.
    assert prepare_indices[0] < verify_indices[0] < prepare_indices[1] < verify_indices[1]


def test_053b_no_affirmative_forbidden_verb_outside_negation(command_text):
    for pattern in _AFFIRMATIVE_FORBIDDEN_VERB_PATTERNS:
        for match in re.finditer(pattern, command_text, flags=re.IGNORECASE):
            preceding_text = command_text[max(0, match.start() - 700) : match.start()].lower()
            assert any(marker in preceding_text for marker in _NEGATION_MARKERS), (
                f"possible affirmative instruction near: {command_text[match.start():match.start()+80]!r}"
            )


def test_053c_command_ends_with_safety_rules(command_text):
    stripped = command_text.rstrip()
    safety_index = stripped.rfind("## Safety Rules")
    assert safety_index != -1
    remainder = stripped[safety_index:]
    assert remainder.count("\n## ") == 0
    assert remainder.count("\n# ") == 0


def test_python_launcher_fallback_documented(command_text):
    assert "Try `py`" in command_text
    assert "Otherwise try `python3`" in command_text
    assert "Python 3.10 or later" in command_text


def test_all_three_cli_modules_checked_for_import(command_text):
    section_start = command_text.find("confirm the selected launcher can import all three required modules")
    section = command_text[section_start : section_start + 400]
    for module_name in ("core.approval_transition_cli", "core.approval_bridge_cli", "core.approval_mcp_adapter_cli"):
        assert module_name in section


def test_clis_invoked_through_stdin_only(command_text):
    assert "**stdin only**" in command_text
    assert command_text.count("**stdin only**") >= 3


def test_no_temporary_json_files_allowed(command_text):
    assert "create a temporary JSON file" in command_text


# ---------------------------------------------------------------------------
# 54: static-test self-boundaries
# ---------------------------------------------------------------------------

def test_054_static_tests_do_not_run_clis():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    forbidden_modules = {
        "core.approval_transition_cli",
        "core.approval_bridge_cli",
        "core.approval_mcp_adapter_cli",
        "core.approval_transition",
        "core.approval_bridge",
        "core.approval_mcp_adapter",
        "core.approval_persistence",
        "core.approval_request",
    }
    assert not (imported & forbidden_modules)


def test_054b_static_tests_do_not_call_supabase_or_mcp():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imported)
    assert not any("mcp" in name.lower() for name in imported)


def test_054c_static_tests_do_not_use_subprocess_socket_or_network():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    for forbidden in ("subprocess", "socket", "requests", "urllib", "http"):
        assert forbidden not in imported


def test_054d_static_tests_do_not_modify_any_file():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "shutil" not in imported
    assert not _has_write_mode_open_call(tree)
    assert not _has_call_to_attr(tree, {"write_text", "write_bytes", "unlink", "remove", "rename"})


def test_054e_static_tests_use_precise_parsing_not_broad_substring_only():
    tree = _this_module_ast()
    function_defs = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    assert len(function_defs) > 40
