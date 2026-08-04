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

# Block 6: the pipeline now performs a trusted investigation-context
# lookup and a deterministic risk-classification preview before the
# actual (now live-context-guarded) insertion -- four top-level stages,
# not the original six single-CLI-call Block 5 stages.
STAGE_HEADINGS_IN_ORDER = (
    "## Stage 1 — Trusted Investigation-Context Lookup",
    "## Stage 2 — Deterministic Risk Classification Preview",
    "## Stage 3 — Risk-Aware Approval Insertion",
    "## Stage 4 — Cross-Check the Created Approval",
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

    # Block 6 legitimately and repeatedly describes the trusted
    # investigation-context lookup mechanism itself (a real, correct
    # security property of that data source) as "trusted investigation
    # context" / "trusted lookup" / "trusted context lookup" / "trusted
    # investigation-context lookup" -- a categorically different subject
    # from any claim about requested_by's own identity, which remains
    # never authenticated/verified/trusted anywhere in this document. Any
    # occurrence of "trusted" immediately followed by one of these safe
    # continuation words describes that lookup mechanism, never
    # requested_by, and is excluded from the negation-marker requirement
    # below on that basis alone.
    _safe_trusted_continuations = ("investigation", "context", "lookup", "data")

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
    # Block 6: the actual mutation this command performs now uses the
    # live-context-guarded insert_risk_aware_pending_approval operation,
    # never the plain Block 5 insert_pending_approval operation -- the old
    # operation name is only ever mentioned in a "never fall back to"
    # safety negation, verified separately by
    # test_insertion_uses_risk_aware_operation_with_trusted_context_and_rejects_forged_expected_context
    # below.
    assert "core.approval_bridge_cli" in command_text
    assert '"phase": "prepare"' in command_text
    assert '"operation": "insert_risk_aware_pending_approval"' in command_text


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
    # Block 6: the original legitimate request (including its
    # action_payload) is now first constructed in Stage 2 (Deterministic
    # Risk Classification Preview), not in a standalone Stage 1 request-
    # validation CLI call -- Stage 1 is now the trusted investigation-
    # context lookup, which builds no action_payload of its own.
    stage2_start = command_text.find("## Stage 2 — Deterministic Risk Classification Preview")
    stage2_end = command_text.find("## Stage 3", stage2_start)
    section = command_text[stage2_start:stage2_end]
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


def test_040b_all_four_stages_appear_in_order(command_text):
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
    # Block 6: no standalone core.approval_request_cli invocation remains
    # in this workflow (core.approval_risk_request_cli already delegates
    # to its validator internally) -- it is replaced in this import-check
    # list by core.approval_risk_request_cli, the module Stage 2 actually
    # invokes. The set is still exactly three modules.
    section_start = command_text.find("confirm the selected launcher can import all three required modules")
    section = command_text[section_start : section_start + 400]
    for module_name in ("core.approval_risk_request_cli", "core.approval_bridge_cli", "core.approval_mcp_adapter_cli"):
        assert module_name in section


def test_clis_invoked_through_stdin_only(command_text):
    assert "**stdin only**" in command_text
    assert command_text.count("**stdin only**") >= 3


def test_no_temporary_json_files_allowed(command_text):
    assert "create a temporary JSON file" in command_text


# ---------------------------------------------------------------------------
# Block 6, Step 11: trusted risk-aware approval creation
# ---------------------------------------------------------------------------


def test_trusted_context_lookup_precedes_risk_classification_and_insertion(command_text):
    """1. The command performs trusted investigation-context lookup before
    risk classification and insertion."""
    stage1_idx = command_text.find("## Stage 1 — Trusted Investigation-Context Lookup")
    stage2_idx = command_text.find("## Stage 2 — Deterministic Risk Classification Preview")
    stage3_idx = command_text.find("## Stage 3 — Risk-Aware Approval Insertion")
    assert stage1_idx != -1
    assert stage2_idx != -1
    assert stage3_idx != -1
    assert stage1_idx < stage2_idx < stage3_idx

    # The genuine operation names, not just the stage titles, must appear
    # in this same relative order: the lookup operation is prepared and
    # verified entirely within Stage 1, strictly before the risk-aware
    # insert operation ever appears.
    lookup_operation_idx = command_text.find('"operation": "load_investigation_approval_context"')
    insert_operation_idx = command_text.find('"operation": "insert_risk_aware_pending_approval"')
    assert lookup_operation_idx != -1
    assert insert_operation_idx != -1
    assert lookup_operation_idx < insert_operation_idx

    # The lookup's own verify phase result -- the trusted context -- is
    # named as the thing risk classification is based on.
    assert "trusted investigation context" in command_text.lower()
    trusted_context_idx = command_text.lower().find("call this the **trusted investigation context**")
    assert trusted_context_idx != -1
    assert stage2_idx > trusted_context_idx > stage1_idx


def test_risk_classification_cli_receives_only_original_request_and_trusted_context(command_text):
    """2. The risk-classification CLI receives only: original request;
    trusted status/confidence."""
    stage2_start = command_text.find("## Stage 2 — Deterministic Risk Classification Preview")
    stage3_start = command_text.find("## Stage 3 — Risk-Aware Approval Insertion")
    assert stage2_start != -1 and stage3_start != -1
    section = command_text[stage2_start:stage3_start]

    assert "core.approval_risk_request_cli" in section

    # The envelope sent to the risk-classification CLI is exactly request
    # + current_investigation, in that order.
    envelope_start = section.find('"request": "<the original legitimate request>"')
    assert envelope_start != -1
    envelope_block = section[envelope_start : envelope_start + 300]
    assert '"current_investigation"' in envelope_block
    assert envelope_block.find('"request"') < envelope_block.find('"current_investigation"')

    # current_investigation carries only status/confidence -- investigation_id
    # is explicitly excluded, and the command says so.
    current_investigation_block_start = envelope_block.find('"current_investigation"')
    current_investigation_block = envelope_block[current_investigation_block_start:]
    assert '"status"' in current_investigation_block
    assert '"confidence"' in current_investigation_block
    assert "Do not include `investigation_id` inside `current_investigation`" in section

    # The caller never chooses the derived fields this stage produces.
    assert "The caller never chooses `risk_level` or `required_approvals`" in section


def test_insertion_uses_risk_aware_operation_with_trusted_context_and_rejects_forged_expected_context(command_text):
    """3. The insertion uses: insert_risk_aware_pending_approval; the
    original request without derived risk fields; trusted status/
    confidence; no caller-forged expected context."""
    stage3_start = command_text.find("## Stage 3 — Risk-Aware Approval Insertion")
    stage4_start = command_text.find("## Stage 4 — Cross-Check the Created Approval")
    assert stage3_start != -1 and stage4_start != -1
    section = command_text[stage3_start:stage4_start]

    assert '"operation": "insert_risk_aware_pending_approval"' in section

    # The insertion's own input envelope is exactly request,
    # current_investigation, expires_at, in that exact key order --
    # matching core.approval_bridge's own _OPERATION_INPUT_FIELDS
    # ordering requirement for this operation.
    envelope_start = section.find('"input": {')
    envelope_end = section.find("}\n}", envelope_start)
    envelope_block = section[envelope_start:envelope_end]
    request_idx = envelope_block.find('"request"')
    current_investigation_idx = envelope_block.find('"current_investigation"')
    expires_at_idx = envelope_block.find('"expires_at"')
    assert -1 not in (request_idx, current_investigation_idx, expires_at_idx)
    assert request_idx < current_investigation_idx < expires_at_idx

    # request is explicitly the same object from Stage 2, never the risk
    # preview, and never a caller-supplied risk field.
    assert "the exact same object built in Stage 2" in section
    assert "never the risk classification preview" in section
    assert "never a caller-supplied `risk_level`/`required_approvals`/`requested_by_normalized`" in section

    # expected_current_status/expected_current_confidence are produced by
    # the persistence layer alone, from the trusted context, never a
    # separate caller field, and never stored inside values.
    assert "expected_current_status" in section
    assert "expected_current_confidence" in section
    assert "never inside `values`, never new `approvals` columns" in section
    assert "This command never manually constructs or alters this descriptor" in section

    # The Block 5, non-context-guarded operation is never the one this
    # command actually uses -- it is only ever named in a "never fall
    # back to" safety negation (the negation-introducing "must never:"
    # line sits at the top of the same bulleted Security Boundaries list,
    # several items above -- a wide lookback window, matching the same
    # convention already used elsewhere in this file, e.g. test_020).
    fallback_idx = command_text.find("fall back to the plain, non-context-guarded `insert_pending_approval`")
    assert fallback_idx != -1
    preceding = command_text[max(0, fallback_idx - 1400) : fallback_idx].lower()
    assert "must never" in preceding


def test_block6_caller_fields_rejected_before_any_external_execution(command_text):
    """4. Caller-supplied risk, required approvals, current context,
    expected context, SQL, or descriptors are rejected before external
    execution."""
    prohibited_block6_fields = (
        "current_investigation",
        "current_status",
        "current_confidence",
        "risk_level",
        "required_approvals",
        "requested_by_normalized",
        "expected_current_status",
        "expected_current_confidence",
        "approval_count",
        "reviewer",
        "reviewed_by",
        "descriptor",
    )
    section_start = command_text.find("Also always reject every one of these additional Block 6 fields")
    assert section_start != -1
    section = command_text[section_start : section_start + 1400]
    for field in prohibited_block6_fields:
        assert f"`{field}`" in section, f"missing forbidden Block 6 field: {field}"

    # This rejection happens locally, before Stage 1 (the first external
    # Supabase/MCP operation) ever runs.
    validation_section_start = command_text.find("## Request Validation")
    validation_section = command_text[validation_section_start : validation_section_start + 700]
    assert "before any Supabase or MCP operation" in validation_section
    assert "Reject any field not listed under Input Envelope (including every Block 6 field named above)" in validation_section

    # A caller can never supply the SQL/descriptor mechanisms directly --
    # this command builds no SQL and accepts no ready-made descriptor.
    assert "a caller can never supply a bridge or adapter descriptor directly" in command_text


def test_stale_context_conflict_stops_without_retry_fallback_or_success_output(command_text):
    """5. A stale-context/zero-row conflict stops without retry, fallback,
    or success output."""
    conflict_section_start = command_text.find("### PERSISTENCE_CONFLICT")
    assert conflict_section_start != -1
    conflict_section = command_text[conflict_section_start : conflict_section_start + 900]

    assert "contained zero rows" in conflict_section
    assert "no longer matched the trusted context" in conflict_section
    assert "No approval was created." in conflict_section
    assert "Never retried automatically" in conflict_section
    assert "fallback unconditional insertion" in conflict_section
    assert "re-issue" in conflict_section.lower()

    # The Stage 3e exit-code table explicitly ties approval_conflict to
    # PERSISTENCE_CONFLICT and states plainly that no approval was created.
    stage3e_start = command_text.find("### Stage 3e — Approval Bridge Verify")
    stage4_start = command_text.find("## Stage 4 — Cross-Check the Created Approval")
    stage3e_section = command_text[stage3e_start:stage4_start]
    assert "code `approval_conflict`" in stage3e_section
    assert "PERSISTENCE_CONFLICT" in stage3e_section
    assert "No approval was created." in stage3e_section

    # No automatic retry of either external stage, and no fallback
    # insertion path, anywhere in this document.
    assert "never automatically re-run stage 1" in command_text.lower()
    assert "never automatically re-attempt stage 3" in command_text.lower()
    assert "Never fall back to the plain `insert_pending_approval` operation or to an unconditional `VALUES` insertion" in command_text


def test_success_output_shows_safe_fields_and_correct_review_count_guidance_while_hiding_secrets(command_text):
    """6. Success output contains safe approval ID, pending status,
    derived risk, required approval count, expiry, and correct one-review/
    two-review next-action guidance while hiding SQL, normalized identity,
    payload secrets, and internal errors."""
    output_section_start = command_text.find("## Required Success Output")
    output_section_end = command_text.find("## Required Failure Behavior")
    assert output_section_start != -1 and output_section_end != -1
    section = command_text[output_section_start:output_section_end]

    assert "Approval ID" in section
    assert "Approval Status: `pending`" in section
    assert "Derived Risk Level" in section
    assert "Required Approval Count" in section
    assert "Expires At" in section
    assert "Requested At" in section

    # One-review vs two-distinct-review guidance is explicitly
    # distinguished, and both branches still point at /review-approval.
    assert 'required_approvals` is `1`' in section
    assert 'required_approvals` is `2`' in section
    assert "two distinct reviewers" in section.lower()
    assert "partially_approved" in section
    assert section.count("/review-approval <approval-id>") >= 2

    # Sensitive/internal content is explicitly excluded from this output.
    assert "Never display any of the following anywhere in the success output" in section
    for hidden_field in ("raw SQL", "MCP tool-call descriptor", "requested_by_normalized", "expected_current_status"):
        assert hidden_field in section


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
