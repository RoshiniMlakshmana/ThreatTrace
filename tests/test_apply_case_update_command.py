"""Static tests for .claude/commands/apply-case-update.md.

These tests only read the command Markdown file as text and check its
content structurally. They never execute /apply-case-update, never invoke
any project CLI, never call Supabase or MCP, never invoke the atomic
consumption function, never perform network access, never launch a
subprocess, never create a temporary file, and never modify any command
file.
"""

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMAND_PATH = REPO_ROOT / ".claude" / "commands" / "apply-case-update.md"

REQUIRED_INPUT_FIELDS = ("approval_id", "consumed_by")

FORBIDDEN_INPUT_FIELDS = (
    "investigation_id",
    "status",
    "confidence",
    "action_type",
    "action_payload",
    "requested_by",
    "requested_at",
    "reviewed_by",
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "rejection_reason",
    "consumed_at",
    "created_at",
    "expires_at",
    "approval_status",
    "transition",
    "transition_plan",
    "descriptor",
    "sql",
    "table",
    "function",
)

FAILURE_CATEGORIES = (
    "INVALID_INPUT",
    "LOOKUP_PREPARE_FAILED",
    "LOOKUP_MCP_CALL_FAILED",
    "LOOKUP_NORMALIZATION_FAILED",
    "APPROVAL_NOT_FOUND",
    "LOOKUP_VERIFICATION_FAILED",
    "CONSUMPTION_NOT_ALLOWED",
    "TRANSITION_VALIDATION_FAILED",
    "CONSUMPTION_PREPARE_FAILED",
    "CONSUMPTION_MCP_CALL_FAILED",
    "CONSUMPTION_NORMALIZATION_FAILED",
    "CONSUMPTION_VERIFICATION_FAILED",
    "PERSISTENCE_CONFLICT",
)

STAGE_HEADINGS_IN_ORDER = (
    "## Stage 1 — Lookup Bridge Prepare",
    "## Stage 2 — Lookup MCP Adapter Prepare Call",
    "## Stage 3 — Execute Through Supabase MCP (Lookup)",
    "## Stage 4 — Lookup MCP Adapter Normalize Response",
    "## Stage 5 — Lookup Bridge Verify",
    "## Stage 6 — Consumption Eligibility and Transition Validation",
    "## Stage 7 — Consumption Bridge Prepare",
    "## Stage 8 — Consumption MCP Adapter Prepare Call",
    "## Stage 9 — Execute Through Supabase MCP (Atomic Consumption)",
    "## Stage 10 — Consumption MCP Adapter Normalize Response",
    "## Stage 11 — Consumption Bridge Verify",
)

_NEGATION_MARKERS = (
    "do not", "does not", "never", "no ", "none ", "must not", "not perform",
    "not accepted", "not itself", "not expected", "not reachable", "cannot",
    "not treated", "not final",
)

# Fixed stage-output labels that legitimately contain "verified"/"verify" as
# part of this command's own architecture vocabulary, not a claim about any
# identity -- excluded so they cannot shadow the real identity-boundary
# check below.
_SAFE_VERIFIED_PHRASES = (
    "Verified Atomic Consumption Result",
    "verified atomic consumption result",
)

# A generously wide lookback/lookforward window: this document's negative
# instructions are frequently expressed as long, multi-line "must never:"
# or "Do not:" bulleted lists, where the negation-introducing line can sit
# many list items before the specific forbidden term being checked. A short
# fixed-character window would falsely flag those later list items as
# unguarded affirmative instructions.
_WIDE_WINDOW = 1500

_AFFIRMATIVE_FORBIDDEN_VERB_PATTERNS = (
    r"\bupdate\s+(?:the investigation|public\.investigations|an investigation)\b",
    r"\bupdate\s+`public\.approvals`\s+directly\b",
    r"\bapprove\s+(?:the|this|an)\s+approval\b",
    r"\breject\s+(?:the|this|an)\s+approval\b",
    r"\bconsume\s+(?:the|this|an|a)\s+(?:pending|rejected|already-consumed|consumed|approval)\b",
    r"\bapply\s+(?:the|this)\s+(?:proposed\s+)?(?:status|confidence)\b",
    r"\bcall\s+the\s+atomic\s+(?:rpc|function)\s+(?:a\s+second\s+time|more\s+than\s+once)\b",
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


def _assert_negated(command_text, index, marker_lookup_length=_WIDE_WINDOW, label=""):
    preceding = command_text.lower()[max(0, index - marker_lookup_length) : index]
    assert any(marker in preceding for marker in _NEGATION_MARKERS), (
        f"possible affirmative instruction near {label}: "
        f"{command_text[max(0, index - 20):index + 60]!r}"
    )


# ---------------------------------------------------------------------------
# 1-3: file existence and $ARGUMENTS shape
# ---------------------------------------------------------------------------

def test_001_command_file_exists_at_exact_path():
    assert COMMAND_PATH.is_file()


def test_002_command_declares_apply_case_update(command_text):
    assert "/apply-case-update" in command_text
    assert "# ThreatTrace Apply Case Update Workflow" in command_text


def test_003_command_reads_exactly_one_json_object(command_text):
    assert "$ARGUMENTS" in command_text
    assert "exactly one JSON object" in command_text
    assert "top-level JSON value that is not an object" in command_text


# ---------------------------------------------------------------------------
# 4-14: input envelope
# ---------------------------------------------------------------------------

def test_004_requires_approval_id(command_text):
    assert "`approval_id`" in command_text


def test_005_requires_consumed_by(command_text):
    assert "`consumed_by`" in command_text


def test_006_rejects_empty_consumed_by(command_text):
    assert "Reject a blank `consumed_by`" in command_text


def test_007_rejects_unknown_fields(command_text):
    assert "Reject every field this list does not name." in command_text


def _forbidden_fields_section(command_text):
    section_start = command_text.find("Reject every field this list does not name.")
    return command_text[section_start : section_start + 700]


def test_008_accepts_no_status_field(command_text):
    assert "`status`" in _forbidden_fields_section(command_text)


def test_009_accepts_no_confidence_field(command_text):
    assert "`confidence`" in _forbidden_fields_section(command_text)


def test_010_accepts_no_investigation_id_field(command_text):
    assert "`investigation_id`" in _forbidden_fields_section(command_text)


def test_011_accepts_no_action_type_field(command_text):
    assert "`action_type`" in _forbidden_fields_section(command_text)


def test_012_accepts_no_action_payload_field(command_text):
    assert "`action_payload`" in _forbidden_fields_section(command_text)


def test_013_accepts_no_consumed_at_field(command_text):
    assert "`consumed_at`" in _forbidden_fields_section(command_text)


def test_014_accepts_no_transition_plan_or_descriptor(command_text):
    section = _forbidden_fields_section(command_text)
    assert "`transition_plan`" in section
    assert "`descriptor`" in section


def test_014b_all_forbidden_fields_named(command_text):
    section = _forbidden_fields_section(command_text)
    for field in FORBIDDEN_INPUT_FIELDS:
        assert f"`{field}`" in section


# ---------------------------------------------------------------------------
# 15-17: claimed consumer identity
# ---------------------------------------------------------------------------

def test_015_consumed_by_described_only_as_claimed(command_text):
    section_start = command_text.find("### `consumed_by`")
    section = command_text[section_start : section_start + 900]
    assert "claimed consumer identity" in section

    boundary_start = command_text.find("## Claimed Identity Boundary")
    boundary_section = command_text[boundary_start : boundary_start + 600]
    assert "claimed consumer identity" in boundary_section
    assert "claimed requester identity" in boundary_section
    assert "claimed reviewer identity" in boundary_section


def test_016_consumed_by_never_described_as_authenticated_or_verified(command_text):
    exclusion_ranges = [
        (idx, idx + len(phrase))
        for phrase in _SAFE_VERIFIED_PHRASES
        for idx in _find_all(command_text, phrase)
    ]

    def _in_exclusion(pos):
        return any(start <= pos < end for start, end in exclusion_ranges)

    for term in ("authenticated", "verified", "trusted", "cryptographically proven", "service role"):
        for index in _find_all(command_text.lower(), term):
            if _in_exclusion(index):
                continue
            _assert_negated(command_text, index, label=term)


def test_017_includes_one_valid_invocation_example(command_text):
    section_start = command_text.find("## Example Request")
    section = command_text[section_start : command_text.find("## Safety Rules")]
    uuid_pattern = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
    )
    assert uuid_pattern.search(section)
    assert '"consumed_by"' in section


# ---------------------------------------------------------------------------
# 18-26: lookup bridge/adapter integration
# ---------------------------------------------------------------------------

def test_018_loads_approval_before_consumption_validation(command_text):
    indices = []
    search_start = 0
    for heading in STAGE_HEADINGS_IN_ORDER:
        idx = command_text.find(heading, search_start)
        assert idx != -1, f"stage heading not found: {heading}"
        indices.append(idx)
        search_start = idx + len(heading)
    assert indices == sorted(indices)

    lookup_verify_index = command_text.find("## Stage 5 — Lookup Bridge Verify")
    transition_stage_index = command_text.find("## Stage 6 — Consumption Eligibility and Transition Validation")
    assert 0 <= lookup_verify_index < transition_stage_index


def test_019_uses_bridge_prepare_for_load_approval_record(command_text):
    stage1_start = command_text.find("## Stage 1 — Lookup Bridge Prepare")
    stage1_end = command_text.find("## Stage 2", stage1_start)
    section = command_text[stage1_start:stage1_end]
    assert '"phase": "prepare"' in section
    assert '"operation": "load_approval_record"' in section
    assert "core.approval_bridge_cli" in section


def test_020_uses_adapter_prepare_call_for_lookup(command_text):
    stage2_start = command_text.find("## Stage 2 — Lookup MCP Adapter Prepare Call")
    stage2_end = command_text.find("## Stage 3", stage2_start)
    section = command_text[stage2_start:stage2_end]
    assert '"action": "prepare_call"' in section
    assert "core.approval_mcp_adapter_cli" in section


def test_021_invokes_lookup_only_with_adapter_arguments(command_text):
    assert command_text.count("mcp__supabase__execute_sql") >= 2
    assert "using exactly the `arguments` the adapter returned" in command_text


def test_022_normalizes_lookup_through_adapter(command_text):
    stage4_start = command_text.find("## Stage 4 — Lookup MCP Adapter Normalize Response")
    stage4_end = command_text.find("## Stage 5", stage4_start)
    section = command_text[stage4_start:stage4_end]
    assert '"action": "normalize_response"' in section
    assert '"operation": "load_approval_record"' in section


def test_023_verifies_lookup_through_bridge(command_text):
    stage5_start = command_text.find("## Stage 5 — Lookup Bridge Verify")
    stage5_end = command_text.find("## Stage 6", stage5_start)
    section = command_text[stage5_start:stage5_end]
    assert '"phase": "verify"' in section
    assert '"operation": "load_approval_record"' in section


def test_024_fails_closed_on_zero_lookup_rows(command_text):
    assert "`approval_not_found`: no approval exists with the supplied ID" in command_text
    assert "APPROVAL_NOT_FOUND" in command_text


def test_025_fails_closed_on_multiple_lookup_rows(command_text):
    stage5_start = command_text.find("## Stage 5 — Lookup Bridge Verify")
    stage5_end = command_text.find("## Stage 6", stage5_start)
    section = command_text[stage5_start:stage5_end]
    assert "contained more than one row" in section


def test_026_does_not_parse_raw_mcp_response_directly(command_text):
    assert "Do not parse, inspect, or trust the raw MCP result directly" in command_text


# ---------------------------------------------------------------------------
# 27-31: consumption eligibility
# ---------------------------------------------------------------------------

def test_027_requires_approval_to_be_approved(command_text):
    assert "its current `status` is `approved`" in command_text


def test_028_rejects_pending_approvals(command_text):
    assert "CONSUMPTION_NOT_ALLOWED" in command_text
    section_start = command_text.find("### CONSUMPTION_NOT_ALLOWED")
    section = command_text[section_start : section_start + 400]
    assert "`pending`" in section


def test_029_rejects_rejected_approvals(command_text):
    section_start = command_text.find("### CONSUMPTION_NOT_ALLOWED")
    section = command_text[section_start : section_start + 400]
    assert "`rejected`" in section


def test_030_rejects_already_consumed_approvals(command_text):
    section_start = command_text.find("### CONSUMPTION_NOT_ALLOWED")
    section = command_text[section_start : section_start + 400]
    assert "`consumed`" in section


def test_031_enforces_expiry_through_existing_validator_contract(command_text):
    assert "consumed_at` must be strictly before `expires_at`" in command_text
    section_start = command_text.find("### CONSUMPTION_NOT_ALLOWED")
    section = command_text[section_start : section_start + 400]
    assert "expired" in section


# ---------------------------------------------------------------------------
# 32-35: transition validator/CLI integration
# ---------------------------------------------------------------------------

def test_032_uses_approval_transition_cli_for_consume(command_text):
    stage6_start = command_text.find("## Stage 6 — Consumption Eligibility and Transition Validation")
    stage6_end = command_text.find("## Stage 7", stage6_start)
    section = command_text[stage6_start:stage6_end]
    assert "core.approval_transition_cli" in section
    assert '"transition": "consume"' in section


def test_033_generates_genuine_transition_plan(command_text):
    assert "Call this the **genuine consume transition plan**." in command_text
    assert "Do not manually construct or forge a transition plan" in command_text


def test_034_does_not_accept_caller_supplied_consumed_at(command_text):
    assert "`consumed_at`" in _forbidden_fields_section(command_text)
    stage6_start = command_text.find("## Stage 6 — Consumption Eligibility and Transition Validation")
    stage6_end = command_text.find("## Stage 7", stage6_start)
    section = command_text[stage6_start:stage6_end]
    assert "never with a caller-supplied `consumed_at`" in section


def test_035_does_not_manually_construct_set_fields(command_text):
    assert "never manually construct its `set_fields`" in command_text


# ---------------------------------------------------------------------------
# 36-39: atomic descriptor / stored bindings
# ---------------------------------------------------------------------------

def test_036_uses_bridge_prepare_for_apply_approval_consumption(command_text):
    stage7_start = command_text.find("## Stage 7 — Consumption Bridge Prepare")
    stage7_end = command_text.find("## Stage 8", stage7_start)
    section = command_text[stage7_start:stage7_end]
    assert '"phase": "prepare"' in section
    assert '"operation": "apply_approval_consumption"' in section


def test_037_preserves_stored_investigation_binding(command_text):
    stage7_start = command_text.find("## Stage 7 — Consumption Bridge Prepare")
    stage7_end = command_text.find("## Stage 8", stage7_start)
    section = command_text[stage7_start:stage7_end]
    assert "expected_investigation_id" in section
    assert "equal to the loaded record's own `investigation_id`" in section


def test_038_preserves_stored_action_type(command_text):
    stage7_start = command_text.find("## Stage 7 — Consumption Bridge Prepare")
    stage7_end = command_text.find("## Stage 8", stage7_start)
    section = command_text[stage7_start:stage7_end]
    assert "expected_action_type" in section


def test_039_preserves_stored_action_payload(command_text):
    stage7_start = command_text.find("## Stage 7 — Consumption Bridge Prepare")
    stage7_end = command_text.find("## Stage 8", stage7_start)
    section = command_text[stage7_start:stage7_end]
    assert "The descriptor must never contain `status` or `confidence`" in section
    assert "the stored `action_payload` remains the sole source" in section


# ---------------------------------------------------------------------------
# 40-48: atomic MCP execution boundaries
# ---------------------------------------------------------------------------

def test_040_uses_adapter_prepare_call_for_atomic_operation(command_text):
    stage8_start = command_text.find("## Stage 8 — Consumption MCP Adapter Prepare Call")
    stage8_end = command_text.find("## Stage 9", stage8_start)
    section = command_text[stage8_start:stage8_end]
    assert '"action": "prepare_call"' in section


def test_041_invokes_atomic_mutation_exactly_once(command_text):
    stage9_start = command_text.find("## Stage 9 — Execute Through Supabase MCP (Atomic Consumption)")
    stage9_end = command_text.find("## Stage 10", stage9_start)
    section = command_text[stage9_start:stage9_end]
    assert "using exactly the `arguments` the adapter returned, and only **once**" in section


def test_042_invokes_only_execute_sql_with_adapter_arguments(command_text):
    stage9_start = command_text.find("## Stage 9 — Execute Through Supabase MCP (Atomic Consumption)")
    stage9_end = command_text.find("## Stage 10", stage9_start)
    section = command_text[stage9_start:stage9_end]
    assert "mcp__supabase__execute_sql" in section


def test_043_identifies_existing_five_argument_atomic_function(command_text):
    assert "public.consume_approval_and_update_investigation_state(" in command_text
    stage8_start = command_text.find("## Stage 8 — Consumption MCP Adapter Prepare Call")
    stage8_end = command_text.find("## Stage 9", stage8_start)
    section = command_text[stage8_start:stage8_end]
    for arg_type in ("uuid", "text", "timestamptz"):
        assert arg_type in section


def test_044_never_directly_updates_approvals(command_text):
    assert "update `public.approvals` directly" in command_text


def test_045_never_directly_updates_investigations(command_text):
    assert "update `public.investigations` directly" in command_text


def test_046_never_performs_two_separate_mutations(command_text):
    assert "perform the approval consumption and the investigation update as two separate mutations" in command_text
    assert "split the atomic operation into" in command_text.lower()


def test_047_never_calls_apply_migration(command_text):
    assert "Never use `apply_migration` in this workflow." in command_text
    for index in _find_all(command_text.lower(), "apply_migration"):
        _assert_negated(command_text, index, label="apply_migration")


def test_048_never_generates_direct_sql(command_text):
    assert "Never generate SQL directly" in command_text
    assert "never interpolate" in command_text.lower()


# ---------------------------------------------------------------------------
# 49-57: normalization, verification, nineteen-column contract, fail-closed
# ---------------------------------------------------------------------------

def test_049_normalizes_atomic_response_through_adapter(command_text):
    stage10_start = command_text.find("## Stage 10 — Consumption MCP Adapter Normalize Response")
    stage10_end = command_text.find("## Stage 11", stage10_start)
    section = command_text[stage10_start:stage10_end]
    assert '"action": "normalize_response"' in section
    assert '"operation": "apply_approval_consumption"' in section


def test_050_verifies_atomic_result_through_bridge(command_text):
    stage11_start = command_text.find("## Stage 11 — Consumption Bridge Verify")
    section = command_text[stage11_start : stage11_start + 1600]
    assert '"phase": "verify"' in section
    assert '"operation": "apply_approval_consumption"' in section


def test_051_requires_nineteen_column_return_contract(command_text):
    assert "nineteen-column atomic RPC return contract" in command_text
    assert "Never accept a twentieth field anywhere in this result." in command_text
    for field in (
        "id", "investigation_id", "action_type", "action_payload", "requested_by", "requested_at",
        "status", "approved_by", "approved_at", "rejected_by", "rejected_at", "rejection_reason",
        "expires_at", "consumed_by", "consumed_at", "created_at",
    ):
        assert f"`{field}`" in command_text


def test_052_fails_closed_on_zero_atomic_rows(command_text):
    assert "zero rows matched the atomic function's own conditional filter" in command_text
    assert "PERSISTENCE_CONFLICT" in command_text


def test_053_fails_closed_on_multiple_atomic_rows(command_text):
    stage11_start = command_text.find("## Stage 11 — Consumption Bridge Verify")
    section = command_text[stage11_start : stage11_start + 1600]
    assert "contained more than one row" in section


def test_054_fails_closed_on_transport_error(command_text):
    assert '{"kind": "transport_error"}' in command_text
    assert command_text.count("approval_transport_error") >= 2
    assert "CONSUMPTION_MCP_CALL_FAILED" in command_text
    assert "LOOKUP_MCP_CALL_FAILED" in command_text


def test_055_fails_closed_on_binding_mismatch(command_text):
    assert "did not match the expected consumed record" in command_text
    for field in (
        "approval ID", "investigation ID", "action type", "action payload",
        "requester identity", "reviewer identity", "consumer identity",
    ):
        assert field in command_text


def test_056_fails_closed_on_investigation_result_mismatch(command_text):
    assert "the investigation `status`/`confidence` did not match the stored `action_payload`" in command_text


def test_057_fails_closed_on_persistence_or_replay_conflict(command_text):
    assert "code `approval_conflict`" in command_text
    assert "replayed" in command_text.lower()
    assert "PERSISTENCE_CONFLICT" in command_text


# ---------------------------------------------------------------------------
# 58-60: retry/fallback/final-authority
# ---------------------------------------------------------------------------

def test_058_never_retries_automatically(command_text):
    assert "Do not automatically retry any failure in any category above." in command_text
    assert "Never retry any failure automatically" in command_text


def test_059_never_performs_fallback_mutation(command_text):
    assert "perform a fallback mutation after zero rows, a conflict, or a transport failure" in command_text
    assert "never falls back to any other mutation path" in command_text


def test_060_treats_atomic_rpc_as_final_authority(command_text):
    assert "never treated as final authorization" in command_text.lower() or "not final authorization" in command_text.lower()
    assert "is the sole final authority" in command_text


# ---------------------------------------------------------------------------
# 61-65: success output
# ---------------------------------------------------------------------------

def test_061_reports_final_approval_status_consumed(command_text):
    assert "Final Approval Status: `consumed`" in command_text


def test_062_reports_final_investigation_status_and_confidence(command_text):
    assert "Final Investigation Status" in command_text
    assert "Final Investigation Confidence" in command_text


def test_063_reports_claimed_identities_correctly(command_text):
    output_start = command_text.find("## Required Success Output")
    output_end = command_text.find("## Required Failure Categories")
    section = command_text[output_start:output_end]
    assert "Claimed Requester Identity" in section
    assert "Claimed Reviewer Identity" in section
    assert "Claimed Consumer Identity" in section


def test_064_states_update_applied_atomically(command_text):
    assert "A clear statement that the approved case update was applied atomically" in command_text


def test_065_states_approval_cannot_be_consumed_again(command_text):
    assert "A clear statement that this approval cannot be consumed again" in command_text


# ---------------------------------------------------------------------------
# 66-70: remaining boundaries and structure
# ---------------------------------------------------------------------------

def test_066_never_approves_or_rejects_an_approval(command_text):
    assert "Never approve or reject an approval." in command_text


def test_067_never_uses_legacy_update_case_path(command_text):
    assert "Never use the legacy direct-update path `/update-case` uses." in command_text


def test_068_uses_fixed_sanitized_failure_categories_in_order(command_text):
    indices = []
    search_start = 0
    for category in FAILURE_CATEGORIES:
        heading = f"### {category}"
        idx = command_text.find(heading, search_start)
        assert idx != -1, f"category heading not found: {heading}"
        indices.append(idx)
        search_start = idx + len(heading)
    assert indices == sorted(indices)


def test_069_no_embedded_credential_url_token_or_project_reference(command_text):
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


def test_070_preserves_prepare_execute_normalize_verify_architecture(command_text):
    assert "two-phase prepare/verify approval bridge" in command_text
    prepare_indices = _find_all(command_text, '"phase": "prepare"')
    verify_indices = _find_all(command_text, '"phase": "verify"')
    assert len(prepare_indices) == 2
    assert len(verify_indices) == 2
    assert prepare_indices[0] < verify_indices[0] < prepare_indices[1] < verify_indices[1]


def test_070b_no_affirmative_forbidden_verb_outside_negation(command_text):
    for pattern in _AFFIRMATIVE_FORBIDDEN_VERB_PATTERNS:
        for match in re.finditer(pattern, command_text, flags=re.IGNORECASE):
            _assert_negated(command_text, match.start(), label=pattern)


def test_070c_command_ends_with_safety_rules(command_text):
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


def test_no_identity_separation_rule_invented_beyond_existing_contract(command_text):
    assert "does not invent any additional identity-separation rule" in command_text


# ---------------------------------------------------------------------------
# 71: static-test self-boundaries
# ---------------------------------------------------------------------------

def test_071_static_tests_do_not_run_clis():
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


def test_071b_static_tests_do_not_call_supabase_or_mcp():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imported)
    assert not any("mcp" in name.lower() for name in imported)


def test_071c_static_tests_do_not_use_subprocess_socket_or_network():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    for forbidden in ("subprocess", "socket", "requests", "urllib", "http"):
        assert forbidden not in imported


def test_071d_static_tests_do_not_modify_any_file():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "shutil" not in imported
    assert not _has_write_mode_open_call(tree)
    assert not _has_call_to_attr(tree, {"write_text", "write_bytes", "unlink", "remove", "rename"})


def test_071e_static_tests_use_precise_parsing_not_broad_substring_only():
    tree = _this_module_ast()
    function_defs = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    assert len(function_defs) > 40
