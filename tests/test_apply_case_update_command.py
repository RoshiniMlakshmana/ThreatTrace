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

# Block 6: a new Stage 6 (a purely local, no-external-call lifecycle
# eligibility check distinguishing pending/partially_approved/rejected/
# consumed, and projecting the trusted eighteen-field record down to the
# sixteen-field shape the existing Block 5 transition validator and
# consumption bridge operation still require) is inserted between the
# lookup-verify stage and the existing transition-validation stage --
# twelve stages total, not the original eleven.
STAGE_HEADINGS_IN_ORDER = (
    "## Stage 1 — Lookup Bridge Prepare",
    "## Stage 2 — Lookup MCP Adapter Prepare Call",
    "## Stage 3 — Execute Through Supabase MCP (Lookup)",
    "## Stage 4 — Lookup MCP Adapter Normalize Response",
    "## Stage 5 — Lookup Bridge Verify",
    "## Stage 6 — Local Lifecycle Eligibility Check",
    "## Stage 7 — Consumption Eligibility and Transition Validation",
    "## Stage 8 — Consumption Bridge Prepare",
    "## Stage 9 — Consumption MCP Adapter Prepare Call",
    "## Stage 10 — Execute Through Supabase MCP (Atomic Consumption)",
    "## Stage 11 — Consumption MCP Adapter Normalize Response",
    "## Stage 12 — Consumption Bridge Verify",
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
# unguarded affirmative instructions. Block 6 legitimately lengthens the
# Security Boundaries "must never:" list with several additional risk-aware
# bullets, pushing its own later items (e.g. apply_migration, "call the
# atomic RPC more than once") further from the list's own negation-
# introducing line -- the window is widened accordingly.
_WIDE_WINDOW = 1800

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

    # Block 6 legitimately and repeatedly describes the trusted approval-
    # record lookup mechanism itself (a real, correct security property of
    # that data source) as "trusted approval record" / "trusted loaded
    # record" -- a categorically different subject from any claim about
    # consumed_by's own identity, which remains never authenticated/
    # verified/trusted anywhere in this document. Any occurrence of
    # "trusted" immediately followed by one of these safe continuation
    # words describes that lookup mechanism, never consumed_by (mirrors
    # the same exclusion already established in
    # tests/test_request_case_update_command.py and
    # tests/test_review_approval_command.py).
    _safe_trusted_continuations = ("approval", "loaded", "record", "risk-aware")

    def _is_safe_trusted_usage(lowered_text, index, term):
        if term != "trusted":
            return False
        following = lowered_text[index + len(term):index + len(term) + 20].lstrip()
        return any(following.startswith(word) for word in _safe_trusted_continuations)

    for term in ("authenticated", "verified", "trusted", "cryptographically proven", "service role"):
        for index in _find_all(command_text.lower(), term):
            if _in_exclusion(index):
                continue
            if _is_safe_trusted_usage(command_text.lower(), index, term):
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
    eligibility_stage_index = command_text.find("## Stage 6 — Local Lifecycle Eligibility Check")
    transition_stage_index = command_text.find("## Stage 7 — Consumption Eligibility and Transition Validation")
    assert 0 <= lookup_verify_index < eligibility_stage_index < transition_stage_index


def test_019_uses_bridge_prepare_for_load_approval_record(command_text):
    # Block 6: the trusted lookup now loads the eighteen-field risk-aware
    # record (load_risk_aware_approval_record), never the plain Block 5
    # sixteen-field load_approval_record.
    stage1_start = command_text.find("## Stage 1 — Lookup Bridge Prepare")
    stage1_end = command_text.find("## Stage 2", stage1_start)
    section = command_text[stage1_start:stage1_end]
    assert '"phase": "prepare"' in section
    assert '"operation": "load_risk_aware_approval_record"' in section
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
    assert '"operation": "load_risk_aware_approval_record"' in section


def test_023_verifies_lookup_through_bridge(command_text):
    stage5_start = command_text.find("## Stage 5 — Lookup Bridge Verify")
    stage5_end = command_text.find("## Stage 6", stage5_start)
    section = command_text[stage5_start:stage5_end]
    assert '"phase": "verify"' in section
    assert '"operation": "load_risk_aware_approval_record"' in section


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
    # Block 6: CONSUMPTION_NOT_ALLOWED's own description grew to enumerate
    # all four non-approved statuses explicitly (pending, partially_approved,
    # rejected, consumed) -- the window is widened accordingly.
    assert "CONSUMPTION_NOT_ALLOWED" in command_text
    section_start = command_text.find("### CONSUMPTION_NOT_ALLOWED")
    section = command_text[section_start : section_start + 900]
    assert "`pending`" in section


def test_029_rejects_rejected_approvals(command_text):
    section_start = command_text.find("### CONSUMPTION_NOT_ALLOWED")
    section = command_text[section_start : section_start + 900]
    assert "`rejected`" in section


def test_030_rejects_already_consumed_approvals(command_text):
    section_start = command_text.find("### CONSUMPTION_NOT_ALLOWED")
    section = command_text[section_start : section_start + 900]
    assert "`consumed`" in section


def test_031_enforces_expiry_through_existing_validator_contract(command_text):
    assert "consumed_at` must be strictly before `expires_at`" in command_text
    section_start = command_text.find("### CONSUMPTION_NOT_ALLOWED")
    section = command_text[section_start : section_start + 900]
    assert "expired" in section


# ---------------------------------------------------------------------------
# 32-35: transition validator/CLI integration
# ---------------------------------------------------------------------------

def test_032_uses_approval_transition_cli_for_consume(command_text):
    # Block 6: consumption eligibility and transition validation is now
    # Stage 7 (Stage 6 is the new, purely local lifecycle eligibility check).
    stage7_start = command_text.find("## Stage 7 — Consumption Eligibility and Transition Validation")
    stage7_end = command_text.find("## Stage 8", stage7_start)
    section = command_text[stage7_start:stage7_end]
    assert "core.approval_transition_cli" in section
    assert '"transition": "consume"' in section


def test_033_generates_genuine_transition_plan(command_text):
    assert "Call this the **genuine consume transition plan**." in command_text
    assert "Do not manually construct or forge a transition plan" in command_text


def test_034_does_not_accept_caller_supplied_consumed_at(command_text):
    assert "`consumed_at`" in _forbidden_fields_section(command_text)
    stage7_start = command_text.find("## Stage 7 — Consumption Eligibility and Transition Validation")
    stage7_end = command_text.find("## Stage 8", stage7_start)
    section = command_text[stage7_start:stage7_end]
    assert "never with a caller-supplied `consumed_at`" in section


def test_035_does_not_manually_construct_set_fields(command_text):
    assert "never manually construct its `set_fields`" in command_text


# ---------------------------------------------------------------------------
# 36-39: atomic descriptor / stored bindings
# ---------------------------------------------------------------------------

def test_036_uses_bridge_prepare_for_apply_approval_consumption(command_text):
    stage8_start = command_text.find("## Stage 8 — Consumption Bridge Prepare")
    stage8_end = command_text.find("## Stage 9", stage8_start)
    section = command_text[stage8_start:stage8_end]
    assert '"phase": "prepare"' in section
    assert '"operation": "apply_approval_consumption"' in section


def test_037_preserves_stored_investigation_binding(command_text):
    stage8_start = command_text.find("## Stage 8 — Consumption Bridge Prepare")
    stage8_end = command_text.find("## Stage 9", stage8_start)
    section = command_text[stage8_start:stage8_end]
    assert "expected_investigation_id" in section
    assert "equal to the projected record's own `investigation_id`" in section


def test_038_preserves_stored_action_type(command_text):
    stage8_start = command_text.find("## Stage 8 — Consumption Bridge Prepare")
    stage8_end = command_text.find("## Stage 9", stage8_start)
    section = command_text[stage8_start:stage8_end]
    assert "expected_action_type" in section


def test_039_preserves_stored_action_payload(command_text):
    stage8_start = command_text.find("## Stage 8 — Consumption Bridge Prepare")
    stage8_end = command_text.find("## Stage 9", stage8_start)
    section = command_text[stage8_start:stage8_end]
    assert "The descriptor must never contain `status` or `confidence`" in section
    assert "the stored `action_payload` remains the sole source" in section


# ---------------------------------------------------------------------------
# 40-48: atomic MCP execution boundaries
# ---------------------------------------------------------------------------

def test_040_uses_adapter_prepare_call_for_atomic_operation(command_text):
    stage9_start = command_text.find("## Stage 9 — Consumption MCP Adapter Prepare Call")
    stage9_end = command_text.find("## Stage 10", stage9_start)
    section = command_text[stage9_start:stage9_end]
    assert '"action": "prepare_call"' in section


def test_041_invokes_atomic_mutation_exactly_once(command_text):
    stage10_start = command_text.find("## Stage 10 — Execute Through Supabase MCP (Atomic Consumption)")
    stage10_end = command_text.find("## Stage 11", stage10_start)
    section = command_text[stage10_start:stage10_end]
    assert "using exactly the `arguments` the adapter returned, and only **once**" in section


def test_042_invokes_only_execute_sql_with_adapter_arguments(command_text):
    stage10_start = command_text.find("## Stage 10 — Execute Through Supabase MCP (Atomic Consumption)")
    stage10_end = command_text.find("## Stage 11", stage10_start)
    section = command_text[stage10_start:stage10_end]
    assert "mcp__supabase__execute_sql" in section


def test_043_identifies_existing_five_argument_atomic_function(command_text):
    assert "public.consume_approval_and_update_investigation_state(" in command_text
    stage9_start = command_text.find("## Stage 9 — Consumption MCP Adapter Prepare Call")
    stage9_end = command_text.find("## Stage 10", stage9_start)
    section = command_text[stage9_start:stage9_end]
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
    stage11_start = command_text.find("## Stage 11 — Consumption MCP Adapter Normalize Response")
    stage11_end = command_text.find("## Stage 12", stage11_start)
    section = command_text[stage11_start:stage11_end]
    assert '"action": "normalize_response"' in section
    assert '"operation": "apply_approval_consumption"' in section


def test_050_verifies_atomic_result_through_bridge(command_text):
    stage12_start = command_text.find("## Stage 12 — Consumption Bridge Verify")
    section = command_text[stage12_start : stage12_start + 1600]
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
    stage12_start = command_text.find("## Stage 12 — Consumption Bridge Verify")
    section = command_text[stage12_start : stage12_start + 1600]
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
# Block 6, Step 15: risk-aware approval consumption
# ---------------------------------------------------------------------------


def test_loads_risk_aware_record_before_action_validation_and_consumption(command_text):
    """1. The command loads load_risk_aware_approval_record before action
    validation and consumption."""
    stage1_idx = command_text.find("## Stage 1 — Lookup Bridge Prepare")
    stage6_idx = command_text.find("## Stage 6 — Local Lifecycle Eligibility Check")
    stage7_idx = command_text.find("## Stage 7 — Consumption Eligibility and Transition Validation")
    stage8_idx = command_text.find("## Stage 8 — Consumption Bridge Prepare")
    assert -1 not in (stage1_idx, stage6_idx, stage7_idx, stage8_idx)
    assert stage1_idx < stage6_idx < stage7_idx < stage8_idx

    lookup_operation_idx = command_text.find('"operation": "load_risk_aware_approval_record"')
    transition_cli_idx = command_text.find("core.approval_transition_cli", stage7_idx)
    consume_operation_idx = command_text.find('"operation": "apply_approval_consumption"')
    assert -1 not in (lookup_operation_idx, transition_cli_idx, consume_operation_idx)
    assert lookup_operation_idx < transition_cli_idx < consume_operation_idx

    assert "Call this the **trusted approval record**." in command_text
    assert lookup_operation_idx < command_text.find("Call this the **trusted approval record**.") < stage6_idx


def test_pending_partially_approved_rejected_and_consumed_stop_before_mutation(command_text):
    """2. Pending, partially_approved, rejected, and consumed records stop
    before mutation, with partially_approved specifically requiring
    another distinct reviewer."""
    stage6_start = command_text.find("## Stage 6 — Local Lifecycle Eligibility Check")
    stage7_start = command_text.find("## Stage 7 — Consumption Eligibility and Transition Validation")
    section = command_text[stage6_start:stage7_start]

    assert "fail closed before any further stage runs unless `status` is exactly `approved`" in section
    assert "`status` is `pending`" in section
    assert "approval review is required first" in section
    assert "`status` is `partially_approved`" in section
    assert "another, distinct reviewer is still required" in section
    assert "`/apply-case-update` cannot be used yet" in section
    assert "`status` is `rejected`" in section
    assert "the request cannot be applied" in section
    assert "`status` is `consumed`" in section
    assert "it was already applied and that replay is blocked" in section

    # This is purely local -- no bridge/adapter/MCP call appears in this stage.
    assert '"phase"' not in section
    assert "mcp__supabase__execute_sql" not in section
    assert "core.approval_bridge_cli" not in section


def test_consumption_uses_only_trusted_values_and_rejects_caller_forged_fields(command_text):
    """3. The consumption operation uses only trusted approval/
    investigation/action values plus legitimate executor identity and
    generated timestamp, while caller-forged risk, lifecycle, action,
    SQL, descriptor, and RPC fields are rejected."""
    stage8_start = command_text.find("## Stage 8 — Consumption Bridge Prepare")
    stage9_start = command_text.find("## Stage 9 — Consumption MCP Adapter Prepare Call")
    section = command_text[stage8_start:stage9_start]

    assert "the same five parameters this RPC has always accepted, never a sixth" in section
    assert "the RPC re-derives its own risk-aware authorization entirely from the live" in section
    assert "never from a caller-supplied parameter" in section

    prohibited_block6_fields = (
        "risk_level", "required_approvals", "current_investigation", "current_status", "current_confidence",
        "requested_by_normalized", "existing_reviews", "approval_count", "expected_investigation_id",
        "expected_action_type", "expected_approval_status", "parameters",
    )
    block6_section_start = command_text.find("Also always reject every one of these additional Block 6 fields")
    assert block6_section_start != -1
    block6_section = command_text[block6_section_start : block6_section_start + 1600]
    for field in prohibited_block6_fields:
        assert f"`{field}`" in block6_section, f"missing forbidden Block 6 field: {field}"

    validation_section_start = command_text.find("## Request Validation")
    validation_section = command_text[validation_section_start : validation_section_start + 700]
    assert "before any Supabase operation" in validation_section


def test_one_review_and_two_review_approvals_use_same_atomic_path_without_local_counting(command_text):
    """4. Both an approved one-review record and an approved two-review
    record proceed through the same fixed atomic
    consume_approval_and_update_investigation_state path; no review
    counting or risk recalculation occurs in the command."""
    assert "public.consume_approval_and_update_investigation_state(" in command_text
    # Exactly one RPC function name is ever named as the mutation target --
    # no second, review-count-specific consumption path exists.
    assert command_text.count("consume_approval_and_update_investigation_state") >= 2
    assert "no second consumption path" in command_text.lower()

    assert (
        "A low- or medium-risk request may be consumed only after it reaches `approved` "
        "through its required one-review flow" in command_text
    )
    assert "A high- or critical-risk request may be consumed only after:" in command_text
    assert "first review moved it to `partially_approved`" in command_text
    assert "second distinct review moved it to `approved`" in command_text

    assert "This command never counts reviews itself" in command_text
    assert "never recalculates risk" in command_text.lower()
    assert "risk_level`/`required_approvals` are always read from the trusted" in command_text


def test_insufficient_review_expiry_stale_binding_concurrency_and_replay_fail_safely(command_text):
    """5. Insufficient-review authorization, expiry, stale binding,
    concurrent consumption, and replay failures stop without retry,
    fallback, repair, or success output."""
    conflict_section_start = command_text.find("### PERSISTENCE_CONFLICT")
    assert conflict_section_start != -1
    conflict_section = command_text[conflict_section_start : conflict_section_start + 1200]

    assert "zero rows matched the atomic function's own conditional filter" in conflict_section
    assert "no longer independently satisfied the live sufficient-distinct-reviews" in conflict_section
    assert "had expired" in conflict_section
    assert "no longer matched its stored investigation/action binding" in conflict_section
    assert "must not retry automatically" in conflict_section
    assert "authorization conflict without exposing which specific reviewer identity" in conflict_section

    assert "Never automatically retry a conflict or any other failure, and never reload the approval and try again automatically." in command_text
    assert "never falls back to any other mutation path" in command_text
    assert "Do not automatically retry any failure in any category above." in command_text


def test_success_output_shows_only_safe_fields_and_hides_sql_rpc_identities_and_errors(command_text):
    """6. Success output contains only safe approval, investigation,
    consumed status, risk, required-approval count, action summary,
    timestamp, and replay-protection guidance while hiding SQL, RPC
    arguments, normalized identities, reviewer identities, raw payload
    secrets, descriptors, internal errors, and credentials."""
    output_start = command_text.find("## Required Success Output")
    output_end = command_text.find("## Required Failure Categories")
    assert output_start != -1 and output_end != -1
    section = command_text[output_start:output_end]

    assert "Approval ID" in section
    assert "Investigation ID" in section
    assert "Final Approval Status: `consumed`" in section
    assert "Risk Level" in section
    assert "Required Approval Count" in section
    assert "Applied Status (only when present in the stored `action_payload`)" in section
    assert "Applied Confidence (only when present in the stored `action_payload`)" in section
    assert "Consumed At" in section
    assert "cannot be consumed again and that replay is now blocked" in section

    assert "Never display any of the following anywhere in the success or failure output" in section
    for hidden_field in (
        "requested_by_normalized", "any reviewer identity beyond the single claimed reviewer identity",
        "reviewer_identity_normalized", "the raw stored `action_payload`", "the RPC's own parameter values",
        "raw SQL", "MCP tool-call descriptor",
    ):
        assert hidden_field in section

    assert (
        "Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, "
        "a project reference, an access token" in command_text
    )
    assert "a stack trace, or an internal owner detail" in command_text


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
