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

# Block 6: the atomic multi-review RPC path replaces the old single
# conditional UPDATE, and the pipeline now performs a separate trusted
# review-history lookup and a validator-derived transition plan (via
# core.approval_multi_review_cli) before the atomic application -- the
# category set is broader, and several old lookup-only/review-only
# categories are consolidated into shared ones (MCP_CALL_FAILED,
# RESPONSE_NORMALIZATION_FAILED) reused across all three round trips,
# matching the same simpler convention already established in
# .claude/commands/request-case-update.md.
FAILURE_CATEGORIES = (
    "INVALID_INPUT",
    "APPROVAL_LOOKUP_FAILED",
    "APPROVAL_NOT_FOUND",
    "REVIEW_HISTORY_LOOKUP_FAILED",
    "TRANSITION_NOT_ALLOWED",
    "SELF_REVIEW_FORBIDDEN",
    "DUPLICATE_REVIEWER_FORBIDDEN",
    "TRANSITION_VALIDATION_FAILED",
    "REVIEW_APPLY_PREPARE_FAILED",
    "MCP_CALL_FAILED",
    "RESPONSE_NORMALIZATION_FAILED",
    "REVIEW_VERIFICATION_FAILED",
    "PERSISTENCE_CONFLICT",
)

# Block 6: five top-level stages (the first, second, and fourth each with
# five lettered sub-stages: bridge prepare, adapter prepare_call, execute,
# adapter normalize, bridge verify), not the original eleven single-
# CLI-call Block 5 stages.
STAGE_HEADINGS_IN_ORDER = (
    "## Stage 1 — Trusted Approval-Record Lookup",
    "## Stage 2 — Trusted Review-History Lookup",
    "## Stage 3 — Multi-Review Transition Plan Derivation",
    "## Stage 4 — Atomic Review Application",
    "## Stage 5 — Cross-Check the Recorded Review",
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

    # Block 6 legitimately and repeatedly describes the trusted approval-
    # record and review-history lookup mechanisms themselves (a real,
    # correct security property of those data sources) as "trusted
    # approval record" / "trusted review history" / "Trusted Approval-
    # Record Lookup" / "Trusted Review-History Lookup" -- a categorically
    # different subject from any claim about reviewed_by's own identity,
    # which remains never authenticated/verified/trusted anywhere in this
    # document. Any occurrence of "trusted" immediately followed by one of
    # these safe continuation words describes a lookup mechanism, never
    # reviewed_by, and is excluded from the negation-marker requirement
    # below on that basis alone (mirrors the same exclusion already
    # established in tests/test_request_case_update_command.py).
    _safe_trusted_continuations = ("approval", "review", "lookup")

    def _is_safe_trusted_usage(lowered_text, index, term):
        if term != "trusted":
            return False
        following = lowered_text[index + len(term):index + len(term) + 20].lstrip()
        return any(following.startswith(word) for word in _safe_trusted_continuations)

    for term in ("authenticated", "verified", "trusted", "cryptographically proven"):
        for index in _find_all(command_text.lower(), term):
            if _in_exclusion(index):
                continue
            if _is_safe_trusted_usage(command_text.lower(), index, term):
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

    lookup_stage_index = command_text.find("### Stage 1e — Approval Bridge Verify")
    transition_stage_index = command_text.find("## Stage 3 — Multi-Review Transition Plan Derivation")
    assert 0 <= lookup_stage_index < transition_stage_index


# ---------------------------------------------------------------------------
# 13-20: lookup bridge/adapter integration
# ---------------------------------------------------------------------------

def test_013_uses_bridge_prepare_for_load_approval_record(command_text):
    # Block 6: the trusted lookup now loads the eighteen-field risk-aware
    # record (load_risk_aware_approval_record), never the plain Block 5
    # sixteen-field load_approval_record.
    stage1_start = command_text.find("### Stage 1a — Approval Bridge Prepare")
    stage1_end = command_text.find("### Stage 1b", stage1_start)
    section = command_text[stage1_start:stage1_end]
    assert '"phase": "prepare"' in section
    assert '"operation": "load_risk_aware_approval_record"' in section
    assert "core.approval_bridge_cli" in section


def test_014_uses_adapter_prepare_call_for_lookup(command_text):
    stage1b_start = command_text.find("### Stage 1b — MCP Adapter Prepare Call")
    stage1b_end = command_text.find("### Stage 1c", stage1b_start)
    section = command_text[stage1b_start:stage1b_end]
    assert '"action": "prepare_call"' in section
    assert "core.approval_mcp_adapter_cli" in section


def test_015_invokes_execute_sql_only_with_adapter_arguments(command_text):
    # Block 6: three round trips (approval lookup, review-history lookup,
    # atomic review application) each execute mcp__supabase__execute_sql
    # exactly once using only the adapter's own returned arguments.
    assert command_text.count("mcp__supabase__execute_sql") >= 3
    assert command_text.count("using exactly the `arguments` the adapter returned") >= 3


def test_016_normalizes_lookup_response_through_adapter(command_text):
    stage1d_start = command_text.find("### Stage 1d — MCP Adapter Normalize Response")
    stage1d_end = command_text.find("### Stage 1e", stage1d_start)
    section = command_text[stage1d_start:stage1d_end]
    assert '"action": "normalize_response"' in section
    assert '"operation": "load_risk_aware_approval_record"' in section


def test_017_verifies_lookup_through_bridge(command_text):
    stage1e_start = command_text.find("### Stage 1e — Approval Bridge Verify")
    stage1e_end = command_text.find("## Stage 2", stage1e_start)
    section = command_text[stage1e_start:stage1e_end]
    assert '"phase": "verify"' in section
    assert '"operation": "load_risk_aware_approval_record"' in section


def test_018_fails_closed_on_zero_lookup_rows(command_text):
    assert "`approval_not_found`: no approval exists with the supplied ID" in command_text
    assert "APPROVAL_NOT_FOUND" in command_text


def test_019_fails_closed_on_multiple_lookup_rows(command_text):
    stage5_start = command_text.find("### Stage 1e — Approval Bridge Verify")
    stage5_end = command_text.find("## Stage 2", stage5_start)
    section = command_text[stage5_start:stage5_end]
    assert "contained more than one row" in section


def test_020_never_parses_raw_mcp_envelope_directly(command_text):
    assert "Do not parse, inspect, or trust the raw MCP result directly" in command_text


# ---------------------------------------------------------------------------
# 21-25: eligibility, self-review, transition plan
# ---------------------------------------------------------------------------

def test_021_requires_loaded_status_pending(command_text):
    # Block 6: a review may be recorded from either pending (single-review
    # or first-of-two) or partially_approved (second-of-two) -- never a
    # terminal status.
    assert "current status is neither `pending` nor `partially_approved`" in command_text
    assert "TRANSITION_NOT_ALLOWED" in command_text


def test_022_prevents_claimed_requester_self_review(command_text):
    assert "SELF_REVIEW_FORBIDDEN" in command_text
    assert "the reviewer must differ from the original requester" in command_text
    assert "Never allow self-review on an approve decision." in command_text


def test_023_uses_approval_transition_cli(command_text):
    # Block 6: eligibility and transition-plan derivation now go through
    # core.approval_multi_review_cli, which itself delegates to
    # core.approval_transition.validate_multi_review_transition -- never
    # the plain Block 5 core.approval_transition_cli /
    # validate_approval_transition pair.
    assert "core.approval_multi_review_cli" in command_text
    assert "core.approval_transition.validate_multi_review_transition" in command_text


def test_024_creates_genuine_validator_produced_transition_plan(command_text):
    assert "Call this the **genuine transition plan**." in command_text
    assert "Do not manually construct or forge a transition plan" in command_text


def test_025_does_not_accept_transition_plan_from_caller(command_text):
    section_start = command_text.find("Reject every field this list does not name.")
    section = command_text[section_start : section_start + 700]
    assert "`transition_plan`" in section
    # Block 6 strengthens this sentence to also name review_record, a new
    # caller-forgeable artifact this command must reject.
    assert "Never accept a caller-supplied transition plan, review record, or operation descriptor." in command_text


# ---------------------------------------------------------------------------
# 26-30: review-update bridge/adapter integration
# ---------------------------------------------------------------------------

def test_026_uses_bridge_prepare_for_review_transition(command_text):
    # Block 6: the review update is now the atomic multi-review RPC
    # operation, never the plain Block 5 conditional-update operation.
    stage4a_start = command_text.find("### Stage 4a — Approval Bridge Prepare")
    stage4a_end = command_text.find("### Stage 4b", stage4a_start)
    section = command_text[stage4a_start:stage4a_end]
    assert '"phase": "prepare"' in section
    assert '"operation": "apply_multi_review_transition"' in section


def test_027_uses_adapter_prepare_call_for_review_update(command_text):
    stage4b_start = command_text.find("### Stage 4b — MCP Adapter Prepare Call")
    stage4b_end = command_text.find("### Stage 4c", stage4b_start)
    section = command_text[stage4b_start:stage4b_end]
    assert '"action": "prepare_call"' in section


def test_028_performs_only_one_review_update(command_text):
    # Block 6: the one permitted mutation is now the atomic RPC call
    # (record_approval_review_and_promote_status), never a direct
    # conditional UPDATE of approvals.
    assert (
        "The only permitted database mutation anywhere in this command is this one "
        "atomic `record_approval_review_and_promote_status` RPC call." in command_text
    )
    assert "perform a second review-application attempt after a conflict" in command_text


def test_029_normalizes_update_response_through_adapter(command_text):
    stage4d_start = command_text.find("### Stage 4d — MCP Adapter Normalize Response")
    stage4d_end = command_text.find("### Stage 4e", stage4d_start)
    section = command_text[stage4d_start:stage4d_end]
    assert '"action": "normalize_response"' in section
    assert '"operation": "apply_multi_review_transition"' in section


def test_030_verifies_update_through_bridge(command_text):
    stage4e_start = command_text.find("### Stage 4e — Approval Bridge Verify")
    section = command_text[stage4e_start : stage4e_start + 1400]
    assert '"phase": "verify"' in section
    assert '"operation": "apply_multi_review_transition"' in section


# ---------------------------------------------------------------------------
# 31-36: fail-closed behavior on the review update
# ---------------------------------------------------------------------------

def test_031_fails_closed_on_zero_update_rows(command_text):
    # Block 6: the atomic RPC's own executor response containing zero
    # rows is the conflict signal now, never a conditional UPDATE filter.
    assert "contained zero rows" in command_text
    assert "PERSISTENCE_CONFLICT" in command_text


def test_032_fails_closed_on_multiple_update_rows(command_text):
    stage4e_start = command_text.find("### Stage 4e — Approval Bridge Verify")
    section = command_text[stage4e_start : stage4e_start + 2000]
    assert "contained more than one row" in section


def test_033_fails_closed_on_transport_error(command_text):
    # Block 6: a single shared MCP_CALL_FAILED category now covers all
    # three round trips' transport failures (matching the same simpler
    # convention already established in
    # .claude/commands/request-case-update.md), never two separate
    # LOOKUP_MCP_CALL_FAILED/REVIEW_MCP_CALL_FAILED categories.
    assert '{"kind": "transport_error"}' in command_text
    assert command_text.count("approval_transport_error") >= 3
    assert "MCP_CALL_FAILED" in command_text


def test_034_fails_closed_on_binding_mismatch(command_text):
    # Block 6: a mismatched atomic-RPC result is described in terms of the
    # genuine transition plan (updated record, review record, approval
    # count), never the old conditional-UPDATE binding-field list.
    assert "did not match the genuine plan (updated record, review record, or approval count)" in command_text


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
    # Block 6: the resulting status is one of three values now (approved,
    # partially_approved, or rejected), never just the Block 5 two-value
    # approved/rejected pair.
    assert 'Resulting Status (`approved`, `partially_approved`, or `rejected`)' in command_text
    assert "`to_status`/`result.updated_record.status` must be `approved`" in command_text


def test_046_reports_rejected_status_correctly(command_text):
    assert "`to_status`/`result.updated_record.status` must be `rejected`" in command_text


def test_047_states_investigation_not_updated(command_text):
    assert "A clear statement that the investigation has not been updated" in command_text


def test_048_points_approved_records_to_apply_case_update(command_text):
    assert "/apply-case-update <approval-id>" in command_text


def test_049_prevents_rejected_records_from_being_applied(command_text):
    assert (
        "state plainly that the request is rejected and cannot be applied, and that a new request "
        "through `/request-case-update` is required" in command_text
    )
    # Block 6: this now also covers a still-partially_approved result,
    # never just a rejected one, since neither may be applied.
    assert "never claim a rejected or still-`partially_approved` request can be applied" in command_text.lower()


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
    # Block 6: three bridge round trips now exist -- approval lookup,
    # review-history lookup, and atomic review application -- each its
    # own prepare/verify pair, never just the original two.
    assert "two-phase prepare/verify approval bridge" in command_text
    prepare_indices = _find_all(command_text, '"phase": "prepare"')
    verify_indices = _find_all(command_text, '"phase": "verify"')
    assert len(prepare_indices) == 3
    assert len(verify_indices) == 3
    # Each round trip's own prepare precedes its own verify, and all three
    # round trips appear in strict lookup -> lookup -> application order.
    assert (
        prepare_indices[0] < verify_indices[0]
        < prepare_indices[1] < verify_indices[1]
        < prepare_indices[2] < verify_indices[2]
    )


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
    # Block 6: no standalone core.approval_transition_cli invocation
    # remains in this workflow -- it is replaced in this import-check
    # list by core.approval_multi_review_cli, the module Stage 3 actually
    # invokes. The set is still exactly three modules.
    section_start = command_text.find("confirm the selected launcher can import all three required modules")
    section = command_text[section_start : section_start + 400]
    for module_name in ("core.approval_multi_review_cli", "core.approval_bridge_cli", "core.approval_mcp_adapter_cli"):
        assert module_name in section


def test_clis_invoked_through_stdin_only(command_text):
    assert "**stdin only**" in command_text
    assert command_text.count("**stdin only**") >= 3


def test_no_temporary_json_files_allowed(command_text):
    assert "create a temporary JSON file" in command_text


# ---------------------------------------------------------------------------
# Block 6, Step 13: risk-aware multi-review transitions
# ---------------------------------------------------------------------------


def test_loads_risk_aware_record_before_reviews_and_before_transition_validation(command_text):
    """1. The command loads the risk-aware approval record before loading
    reviews and before transition validation."""
    stage1_idx = command_text.find("## Stage 1 — Trusted Approval-Record Lookup")
    stage2_idx = command_text.find("## Stage 2 — Trusted Review-History Lookup")
    stage3_idx = command_text.find("## Stage 3 — Multi-Review Transition Plan Derivation")
    assert stage1_idx != -1 and stage2_idx != -1 and stage3_idx != -1
    assert stage1_idx < stage2_idx < stage3_idx

    lookup_operation_idx = command_text.find('"operation": "load_risk_aware_approval_record"')
    reviews_operation_idx = command_text.find('"operation": "load_approval_reviews"')
    # core.approval_multi_review_cli is legitimately named earlier too (the
    # launcher import-check list, the request-validation explanation) --
    # the real ordering claim is about its actual Stage 3 invocation,
    # searched for starting only from Stage 3's own heading.
    multi_review_cli_idx = command_text.find("core.approval_multi_review_cli", stage3_idx)
    assert -1 not in (lookup_operation_idx, reviews_operation_idx, multi_review_cli_idx)
    assert lookup_operation_idx < reviews_operation_idx < multi_review_cli_idx

    assert "Call this the **trusted approval record**." in command_text
    trusted_record_idx = command_text.find("Call this the **trusted approval record**.")
    assert stage1_idx < trusted_record_idx < stage2_idx


def test_loads_reviews_from_persistence_never_accepts_caller_existing_reviews(command_text):
    """2. The command loads existing reviews from persistence and never
    accepts caller-supplied existing_reviews."""
    stage2_start = command_text.find("## Stage 2 — Trusted Review-History Lookup")
    stage3_start = command_text.find("## Stage 3 — Multi-Review Transition Plan Derivation")
    assert stage2_start != -1 and stage3_start != -1
    section = command_text[stage2_start:stage3_start]

    assert '"operation": "load_approval_reviews"' in section
    assert "never from a caller-supplied list" in section
    assert "Call this the **trusted review history**." in section
    assert "Do not alter, deduplicate, reorder, synthesize, or remove any entry in it" in section

    # existing_reviews is explicitly named as a rejected top-level input
    # field, with an explanation of exactly why.
    block6_section_start = command_text.find("Also always reject every one of these additional Block 6 fields")
    block6_section = command_text[block6_section_start : block6_section_start + 1200]
    assert "`existing_reviews`" in block6_section
    assert "a caller-supplied review history could otherwise be used to forge" in command_text.lower()


def test_multi_review_cli_receives_only_trusted_record_reviews_and_legitimate_transition_request(command_text):
    """3. The multi-review CLI receives exactly the trusted current
    record, trusted reviews, and legitimate transition request without
    caller-forged transition fields."""
    stage3_start = command_text.find("## Stage 3 — Multi-Review Transition Plan Derivation")
    stage4_start = command_text.find("## Stage 4 — Atomic Review Application")
    assert stage3_start != -1 and stage4_start != -1
    section = command_text[stage3_start:stage4_start]

    assert "core.approval_multi_review_cli" in section

    # Both the approve and reject envelopes use exactly current_record,
    # existing_reviews, transition_request, in that order.
    for envelope_marker in ('"current_record": "<the trusted approval record from Stage 1e>"',):
        assert envelope_marker in section
    envelope_start = section.find('"current_record": "<the trusted approval record from Stage 1e>"')
    envelope_block = section[envelope_start : envelope_start + 250]
    assert envelope_block.find('"current_record"') < envelope_block.find('"existing_reviews"') < envelope_block.find('"transition_request"')

    # transition_request never contains approval_id, reviewed_at, or any
    # other forged field -- only decision/reviewed_by[/rejection_reason].
    assert (
        "`transition_request` never contains `approval_id`, `reviewed_at`, or any other field"
        in section
    )
    assert "this command never adds to it" in section
    assert "this command never generates or overrides that timestamp" in section

    # The CLI, not this command, derives every plan field.
    assert "This command never independently derives `from_status`, `to_status`, `approval_count_before`, `approval_count_after`, `reviewer_identity_normalized`, `review_record`, or `set_fields`" in section


def test_one_review_approval_moves_pending_to_approved_with_apply_guidance(command_text):
    """4. One-review approval moves pending → approved and provides
    /apply-case-update guidance."""
    assert (
        "when `required_approvals` is `1`, `to_status`/`result.updated_record.status` must be `approved` "
        "and `approval_count` must be `1`"
    ) in command_text

    guidance_start = command_text.find("Next-action guidance:")
    guidance_end = command_text.find("Never claim an approved request has already updated the investigation.")
    guidance_section = command_text[guidance_start:guidance_end]
    assert "**One-review approval**" in guidance_section
    one_review_idx = guidance_section.find("**One-review approval**")
    one_review_line = guidance_section[one_review_idx : one_review_idx + 250]
    assert "now `approved`" in one_review_line
    assert "/apply-case-update <approval-id>" in one_review_line


def test_two_review_approval_first_then_second_reviewer_with_guidance_only_after_second(command_text):
    """5. A two-review approval: first distinct reviewer moves pending →
    partially_approved; second distinct reviewer moves partially_approved
    → approved; apply guidance appears only after the second review."""
    assert (
        "when `required_approvals` is `2` and `approval_count_before` was `0`, "
        "`to_status`/`result.updated_record.status` must be `partially_approved` and `approval_count` must be `1`"
    ) in command_text
    assert (
        "when `required_approvals` is `2` and `approval_count_before` was `1`, "
        "`to_status`/`result.updated_record.status` must be `approved` and `approval_count` must be `2`"
    ) in command_text

    guidance_start = command_text.find("Next-action guidance:")
    guidance_end = command_text.find("Never claim an approved request has already updated the investigation.")
    guidance_section = command_text[guidance_start:guidance_end]

    first_idx = guidance_section.find("**First review of a two-review approval**")
    second_idx = guidance_section.find("**Second review of a two-review approval**")
    assert first_idx != -1 and second_idx != -1 and first_idx < second_idx

    first_line = guidance_section[first_idx : second_idx]
    assert "partially_approved" in first_line
    assert "one additional, distinct reviewer is still required" in first_line
    assert "Do not suggest `/apply-case-update` yet." in first_line
    assert "/apply-case-update <approval-id>" not in first_line

    second_line = guidance_section[second_idx : second_idx + 350]
    assert "now `approved`" in second_line
    assert "both required distinct reviewers have approved" in second_line
    assert "/apply-case-update <approval-id>" in second_line


def test_self_approval_duplicate_reviewer_expiry_terminal_and_forged_fields_fail_safely(command_text):
    """6. Requester self-approval, duplicate reviewer, expired approval,
    terminal status, and prohibited caller fields fail before mutation or
    fail safely on concurrent conflict without retry."""
    assert "SELF_REVIEW_FORBIDDEN" in command_text
    assert "DUPLICATE_REVIEWER_FORBIDDEN" in command_text
    assert (
        "reporting that the claimed reviewer identity has already recorded an approve review "
        "against this approval" in command_text
    )
    assert "TRANSITION_NOT_ALLOWED" in command_text
    assert "a terminal approval can never receive another review" in command_text
    # Expiry/chronology failures fall under the generic transition-
    # validation category, exactly like every other non-status,
    # non-identity multi-review validator failure.
    assert "a chronology/expiry failure" in command_text
    assert "TRANSITION_VALIDATION_FAILED" in command_text

    # Every Block 6 prohibited field fails locally, before Stage 1 (the
    # first external Supabase/MCP operation), never after.
    prohibited_block6_fields = (
        "risk_level", "required_approvals", "requested_by_normalized", "existing_reviews",
        "reviewer_identity_normalized", "from_status", "to_status", "approval_count_before",
        "approval_count_after", "review_record", "set_fields",
    )
    block6_section_start = command_text.find("Also always reject every one of these additional Block 6 fields")
    block6_section = command_text[block6_section_start : block6_section_start + 1500]
    for field in prohibited_block6_fields:
        assert f"`{field}`" in block6_section, f"missing forbidden Block 6 field: {field}"
    validation_section_start = command_text.find("## Request Validation")
    validation_section = command_text[validation_section_start : validation_section_start + 700]
    assert "before any Supabase or MCP operation" in validation_section

    # A concurrent conflict (including a concurrent duplicate reviewer)
    # fails safely, with no retry and no fallback.
    assert "a concurrently added duplicate-normalized reviewer" in command_text
    assert "PERSISTENCE_CONFLICT" in command_text
    assert "No review was recorded." in command_text
    assert "never followed by a fallback direct update or insert" in command_text
    assert "never an automatic re-lookup or re-attempt within this same run" in command_text


def test_rejection_guidance_and_output_hides_sql_normalized_identity_payload_descriptors_and_errors(command_text):
    """7. Rejection from pending or partially_approved produces rejected
    guidance, while success and failure output hide SQL, normalized
    identity, raw payload, descriptors, internal errors, and
    credentials."""
    assert (
        "A valid reject decision must move" not in command_text  # sanity: no stale Block 5-only phrasing survives
    )
    reject_section_start = command_text.find("- **Rejection** (resulting status `rejected`)")
    assert reject_section_start != -1
    reject_line = command_text[reject_section_start : reject_section_start + 300]
    assert "rejected and cannot be applied" in reject_line
    assert "/request-case-update" in reject_line

    # TRANSITION_NOT_ALLOWED explicitly still permits a reject from either
    # pending or partially_approved -- only a terminal status is blocked.
    assert "neither `pending` nor `partially_approved`" in command_text

    hidden_section_start = command_text.find("Never display any of the following anywhere in the success or failure output")
    assert hidden_section_start != -1
    hidden_section = command_text[hidden_section_start : hidden_section_start + 700]
    for hidden_field in (
        "requested_by_normalized", "reviewer_identity_normalized", "the raw stored `action_payload`",
        "the RPC's own parameter values", "raw SQL", "MCP tool-call descriptor",
    ):
        assert hidden_field in hidden_section

    assert (
        "Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, "
        "a project reference, an access token" in command_text
    )
    assert "a stack trace, or an internal owner detail" in command_text


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
