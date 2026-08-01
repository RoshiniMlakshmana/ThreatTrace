"""Static tests for .claude/commands/decision-review.md.

These tests only read the command Markdown file as text and check its
content. They never execute /decision-review, never invoke any project
CLI, never call Supabase, never perform network access, never launch a
subprocess, never create a temporary file, and never modify any command
file.
"""

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMAND_PATH = REPO_ROOT / ".claude" / "commands" / "decision-review.md"

REQUIRED_INPUT_FIELDS = (
    "investigation_id",
    "supporting_evidence_ids",
    "contradicting_evidence_ids",
    "current_assessment",
    "decision_status",
)

OPTIONAL_INPUT_FIELDS = (
    "unresolved_assumptions",
    "evidence_gaps",
    "strengthen_conditions",
    "weaken_conditions",
    "reversal_conditions",
    "recommended_next_evidence",
    "limitations",
)

REJECTED_INPUT_FIELDS = (
    "hypothesis_id",
    "generated_at",
    "confidence",
    "trust_level",
    "investigation_status",
    "evidence_records",
    "approval",
    "execute",
    "persist",
)

DECISION_STATUSES = (
    "supported",
    "partially_supported",
    "contradicted",
    "inconclusive",
    "insufficient_evidence",
)

FINAL_PREVIEW_HEADINGS_IN_ORDER = (
    "# Decision Review",
    "## Decision Context",
    "## Supporting Evidence",
    "## Contradicting Evidence",
    "## Context Warnings",
    "## Current Assessment",
    "## Why the Current Assessment Holds",
    "## Unresolved Assumptions",
    "## Evidence Gaps",
    "## What Would Strengthen the Assessment",
    "## What Would Weaken the Assessment",
    "## What Would Reverse the Assessment",
    "## Recommended Next Evidence",
    "## Limitations",
    "## Analyst Next Step",
)

# Affirmative write/mutate/execute verbs that must never be used as an
# instruction telling the command to actually perform a write, mutation,
# approval, containment, or execution action. They may still appear inside
# negative safety prose ("do not X", "no X occurs", "never X").
_AFFIRMATIVE_FORBIDDEN_VERB_PATTERNS = (
    r"\binsert\s+(?:the|a|one|evidence|the record|the row)\b",
    r"\bupdate\s+(?:the|an|the investigation|the record)\b",
    r"\bdelete\s+(?:the|an|the record|the row)\b",
    r"\bupsert\b",
    r"\bpersist\s+(?:the|this|it|evidence|the analysis)\b",
    r"\bapprove\s+(?:the|this|it)\b",
    r"\bcontain\s+(?:the|this|host|it)\b",
)

_NEGATION_MARKERS = ("do not", "does not", "never", "no ", "none ", "must not", "not perform")


@pytest.fixture(scope="module")
def command_text():
    return COMMAND_PATH.read_text(encoding="utf-8")


def _heading_index(text, heading):
    index = text.find("\n" + heading + "\n")
    if index == -1:
        index = text.find(heading + "\n")
    return index


def _this_module_ast():
    source = Path(__file__).read_text(encoding="utf-8")
    return ast.parse(source)


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


# ---------------------------------------------------------------------------
# 1-6: file existence and input-envelope shape
# ---------------------------------------------------------------------------

def test_001_command_file_exists():
    assert COMMAND_PATH.is_file()


def test_002_command_uses_arguments(command_text):
    assert "$ARGUMENTS" in command_text


def test_003_input_is_exactly_one_json_object(command_text):
    assert "exactly one JSON object" in command_text or "exactly one JSON value" in command_text
    assert "not an object" in command_text or "top-level value that is not a JSON object" in command_text


def test_004_exact_required_input_fields_documented(command_text):
    for field in REQUIRED_INPUT_FIELDS:
        assert f"`{field}`" in command_text


def test_005_exact_optional_input_fields_documented(command_text):
    for field in OPTIONAL_INPUT_FIELDS:
        assert f"`{field}`" in command_text


def test_006_unknown_fields_rejected(command_text):
    assert "Reject every field this list does not name" in command_text


# ---------------------------------------------------------------------------
# 7-13: rejected fields, evidence selection, overlap
# ---------------------------------------------------------------------------

def test_007_hypothesis_id_rejected_from_analyst_input(command_text):
    assert "`hypothesis_id`" in command_text
    assert "hypothesis_id" in REJECTED_INPUT_FIELDS
    section = command_text[command_text.find("Reject every field this list does not name"):]
    assert "`hypothesis_id`" in section[: section.find("## Request Validation")]


def test_008_generated_at_rejected_from_analyst_input(command_text):
    section = command_text[command_text.find("Reject every field this list does not name"):]
    assert "`generated_at`" in section[: section.find("## Request Validation")]


def test_009_supporting_ids_are_analyst_selected(command_text):
    assert "explicitly present and a JSON array composed only of valid UUID strings" in command_text


def test_010_contradicting_ids_are_analyst_selected(command_text):
    assert "### `contradicting_evidence_ids`" in command_text
    assert "Apply the identical rules" in command_text


def test_011_empty_evidence_lists_allowed(command_text):
    assert command_text.count("An empty list is valid.") >= 2


def test_012_duplicate_ids_rejected(command_text):
    assert "Reject duplicates within the list" in command_text
    assert "Reject duplicate evidence IDs within either list" in command_text


def test_013_cross_group_overlap_rejected(command_text):
    assert "the two groups must be disjoint" in command_text


# ---------------------------------------------------------------------------
# 14-20: assessment, status, collections, secrets
# ---------------------------------------------------------------------------

def test_014_current_assessment_is_analyst_supplied(command_text):
    assert "This value is entirely analyst-authored" in command_text
    assert "never generate a replacement for it" in command_text


def test_015_decision_status_is_analyst_supplied(command_text):
    assert "This value is entirely analyst-supplied" in command_text
    assert "never calculate it" in command_text


def test_016_all_five_decision_statuses_documented(command_text):
    for status in DECISION_STATUSES:
        assert f"`{status}`" in command_text


def test_017_seven_optional_collections_documented(command_text):
    section_start = command_text.find("### Optional reasoning collections")
    assert section_start != -1
    section = command_text[section_start : section_start + 1200]
    for field in OPTIONAL_INPUT_FIELDS:
        assert f"`{field}`" in section


def test_018_omitted_optional_collections_become_empty_lists(command_text):
    assert "omitted (in which case it becomes `[]`)" in command_text


def test_019_secret_scanning_limited_to_analyst_authored_reasoning(command_text):
    assert "scan only `current_assessment` and the seven optional reasoning collections" in command_text
    assert "Do not scan the evidence IDs, the investigation ID" in command_text


def test_020_secret_values_are_not_echoed(command_text):
    assert "Do not echo the matched value." in command_text
    assert "Do not echo the complete request." in command_text


# ---------------------------------------------------------------------------
# 21-26: pre-Supabase ordering and investigation query
# ---------------------------------------------------------------------------

def test_021_request_validation_occurs_before_supabase(command_text):
    assert "before any Supabase operation" in command_text
    validation_index = command_text.find("## Request Validation")
    supabase_index = command_text.find("## Supabase Read-Only Lookup")
    assert 0 <= validation_index < supabase_index


def test_022_investigation_query_is_read_only(command_text):
    assert "## Supabase Read-Only Lookup" in command_text
    assert "this workflow never inserts, updates, or deletes any record" in command_text


def test_023_investigation_query_requests_only_id_status_confidence(command_text):
    section_start = command_text.find("### Investigation query")
    section = command_text[section_start : section_start + 600]
    assert "`id`" in section
    assert "`status`" in section
    assert "`confidence`" in section


def test_024_query_failure_distinguished_from_not_found(command_text):
    assert '"Investigation lookup failed."' in command_text
    assert '"Investigation not found."' in command_text


def test_025_malformed_investigation_response_rejected(command_text):
    assert '"Investigation lookup returned malformed data."' in command_text


def test_026_multiple_investigation_rows_rejected(command_text):
    assert '"Investigation lookup returned multiple records."' in command_text


# ---------------------------------------------------------------------------
# 27-38: evidence query
# ---------------------------------------------------------------------------

def test_027_evidence_query_is_read_only(command_text):
    section_start = command_text.find("### Evidence query")
    section = command_text[section_start : section_start + 2000]
    assert "read query" in section


def test_028_one_filtered_evidence_query_is_specified(command_text):
    assert "exactly **one** filtered read query" in command_text


def test_029_evidence_query_scoped_by_investigation_id(command_text):
    assert "`investigation_id` equals the canonical investigation ID" in command_text


def test_030_evidence_query_scoped_by_selected_ids(command_text):
    assert "`id` is in the complete selected-ID set" in command_text


def test_031_evidence_query_requests_only_six_required_fields(command_text):
    section_start = command_text.find("Request only the six fields")
    section = command_text[section_start : section_start + 400]
    for field in ("id", "investigation_id", "trust_level", "confidence", "assertion_type", "supports_hypothesis"):
        assert f"`{field}`" in section


def test_032_details_not_requested(command_text):
    section_start = command_text.find("### Evidence query")
    section = command_text[section_start : section_start + 2500]
    assert "Never request `details`" in section


def test_033_provenance_not_requested(command_text):
    section_start = command_text.find("### Evidence query")
    section = command_text[section_start : section_start + 2500]
    assert "`provenance`" in section
    assert "Never request `details`, `provenance`" in section


def test_034_empty_id_selection_skips_evidence_query(command_text):
    assert "skip the evidence query entirely" in command_text


def test_035_missing_evidence_rejected(command_text):
    assert '"One or more selected evidence records were not found."' in command_text


def test_036_duplicate_returned_evidence_rejected(command_text):
    assert '"Evidence lookup returned duplicate records."' in command_text


def test_037_unrequested_evidence_rejected(command_text):
    assert '"Evidence lookup returned unrequested records."' in command_text


def test_038_cross_investigation_evidence_rejected(command_text):
    assert '"Evidence belongs to a different investigation."' in command_text


# ---------------------------------------------------------------------------
# 39-43: safe error/transport handling
# ---------------------------------------------------------------------------

def test_039_raw_database_errors_not_printed(command_text):
    assert "Never print a raw database error" in command_text


def test_040_python_launcher_fallback_documented(command_text):
    assert "Try `py`" in command_text
    assert "Otherwise try `python3`" in command_text
    assert "Python 3.10 or later" in command_text


def test_041_all_three_cli_module_names_appear(command_text):
    for module_name in ("core.decision_context_cli", "core.decision_warning_formatter_cli", "core.decision_analysis_cli"):
        assert module_name in command_text


def test_042_clis_invoked_through_stdin_only(command_text):
    assert "**stdin only**" in command_text
    assert command_text.count("**stdin only**") >= 3


def test_043_no_temporary_json_files_allowed(command_text):
    assert "create a temporary JSON file" in command_text


# ---------------------------------------------------------------------------
# 44-46: stage ordering
# ---------------------------------------------------------------------------

def test_044_context_cli_runs_first(command_text):
    stage1_index = command_text.find("## Stage 1 — Decision-Context CLI")
    stage2_index = command_text.find("## Stage 2 — Warning-Formatter CLI")
    stage3_index = command_text.find("## Stage 3 — Decision-Analysis CLI")
    assert 0 <= stage1_index < stage2_index < stage3_index


def test_045_warning_cli_runs_after_context(command_text):
    stage1_index = command_text.find("## Stage 1 — Decision-Context CLI")
    stage2_index = command_text.find("## Stage 2 — Warning-Formatter CLI")
    assert 0 <= stage1_index < stage2_index


def test_046_analysis_cli_runs_after_context(command_text):
    stage1_index = command_text.find("## Stage 1 — Decision-Context CLI")
    stage3_index = command_text.find("## Stage 3 — Decision-Analysis CLI")
    assert 0 <= stage1_index < stage3_index
    assert "Only build this stage's request after Stage 1" in command_text


# ---------------------------------------------------------------------------
# 47-52: context CLI input/output shape
# ---------------------------------------------------------------------------

def test_047_context_input_has_exactly_five_fields(command_text):
    stage1_index = command_text.find("## Stage 1 — Decision-Context CLI")
    section = command_text[stage1_index : stage1_index + 1200]
    for field in ("investigation_id", "investigation", "supporting_evidence_ids", "contradicting_evidence_ids", "evidence_records"):
        assert f'"{field}"' in section


def test_048_context_output_exact_top_level_shape_documented(command_text):
    assert "Require the parsed object to contain exactly these top-level fields" in command_text
    for field in ("`investigation`", "`supporting_evidence`", "`contradicting_evidence`", "`warnings`"):
        assert field in command_text


def test_049_context_investigation_shape_documented(command_text):
    assert "Require `investigation` to contain exactly `id`, `status`, `confidence`" in command_text


def test_050_context_evidence_summary_shape_documented(command_text):
    assert (
        "Require every entry of `supporting_evidence` and `contradicting_evidence` to contain exactly "
        "`id`, `trust_level`, `confidence`, `assertion_type`, `supports_hypothesis`" in command_text
    )


def test_051_context_warning_shape_documented(command_text):
    assert "Require every entry of `warnings` to contain exactly `evidence_id`, `code`" in command_text


def test_052_context_evidence_order_checked(command_text):
    assert "in the same order" in command_text
    assert "no evidence ID appears in both `supporting_evidence` and `contradicting_evidence`" in command_text


# ---------------------------------------------------------------------------
# 53-56: warning formatter stage
# ---------------------------------------------------------------------------

def test_053_warning_formatter_receives_context_warnings_only(command_text):
    assert 'Take only `validated_context["warnings"]` — nothing else' in command_text


def test_054_warning_output_exact_shape_documented(command_text):
    assert "Require every entry to contain exactly `evidence_id`, `code`, `explanation`" in command_text


def test_055_warning_order_checked(command_text):
    section_start = command_text.find("## Stage 2 — Warning-Formatter CLI")
    section = command_text[section_start : section_start + 3000]
    assert "array order is unchanged" in section


def test_056_warning_explanation_mapping_not_duplicated_in_command_prose(command_text):
    assert "Do not recreate or duplicate the warning-code-to-explanation mapping" in command_text
    # None of the eight fixed explanation strings should be reproduced verbatim here.
    forbidden_explanations = (
        "Source trust for this evidence has not been recorded.",
        "Source trust for this evidence is recorded as low.",
        "Confidence for this evidence has not been recorded.",
        "This evidence is recorded as an interpretation, not a direct observation.",
        "This evidence is recorded as a hypothesis, not a direct observation.",
        "This evidence is recorded as a recommendation, not a direct observation.",
        "This evidence's stored supports_hypothesis value conflicts with its assigned group.",
        "This evidence's supports_hypothesis value was not specified.",
    )
    for explanation in forbidden_explanations:
        assert explanation not in command_text


# ---------------------------------------------------------------------------
# 57-66: analysis handoff
# ---------------------------------------------------------------------------

def test_057_analysis_investigation_id_comes_from_validated_context(command_text):
    assert '`investigation_id` from `validated_context["investigation"]["id"]`' in command_text


def test_058_analysis_supporting_ids_come_from_validated_context(command_text):
    assert '`supporting_evidence_ids` rebuilt from `validated_context["supporting_evidence"]`' in command_text


def test_059_analysis_contradicting_ids_come_from_validated_context(command_text):
    assert '`contradicting_evidence_ids` rebuilt from `validated_context["contradicting_evidence"]`' in command_text


def test_060_raw_request_ids_are_not_reused_for_analysis_handoff(command_text):
    assert "Never reuse the raw request's evidence-ID lists for this handoff" in command_text


def test_061_hypothesis_id_is_hardcoded_null_for_analysis(command_text):
    assert "Always send `hypothesis_id` as `null`" in command_text


def test_062_generated_at_is_omitted_from_analysis_input(command_text):
    assert "Never include `generated_at` in the request; the validator generates it." in command_text


def test_063_analysis_exact_output_shape_documented(command_text):
    section_start = command_text.find("Require the parsed object to contain exactly these fields")
    section = command_text[section_start : section_start + 900]
    for field in (
        "investigation_id",
        "hypothesis_id",
        "current_assessment",
        "decision_status",
        "supporting_evidence_ids",
        "contradicting_evidence_ids",
        "unresolved_assumptions",
        "evidence_gaps",
        "strengthen_conditions",
        "weaken_conditions",
        "reversal_conditions",
        "recommended_next_evidence",
        "limitations",
        "generated_at",
    ):
        assert f"`{field}`" in section


def test_064_caller_decision_status_equality_checked(command_text):
    assert "`decision_status` equals the analyst-supplied status" in command_text


def test_065_caller_current_assessment_equality_checked(command_text):
    assert "`current_assessment` equals the trimmed analyst value" in command_text


def test_066_generated_timestamp_is_checked(command_text):
    assert "`generated_at` is a nonblank UTC timestamp ending in `Z`" in command_text


# ---------------------------------------------------------------------------
# 67-70: no generation/calculation
# ---------------------------------------------------------------------------

def test_067_no_model_reasoning_generation(command_text):
    assert "Do not call an AI model" in command_text


def test_068_no_decision_status_calculation(command_text):
    assert "never calculate it and never replace it with a computed value" in command_text


def test_069_no_confidence_calculation(command_text):
    assert "No confidence calculation." in command_text


def test_070_no_trust_modification(command_text):
    assert "No trust modification." in command_text


# ---------------------------------------------------------------------------
# 71-79: final preview structure
# ---------------------------------------------------------------------------

def test_071_final_preview_occurs_only_after_all_stages_succeed(command_text):
    assert "Only display the preview below after Stage 1, Stage 2, and Stage 3 have all fully succeeded" in command_text


def test_072_exact_final_section_headings_appear_in_order(command_text):
    indices = []
    search_start = 0
    for heading in FINAL_PREVIEW_HEADINGS_IN_ORDER:
        idx = command_text.find(heading, search_start)
        assert idx != -1, f"heading not found: {heading}"
        indices.append(idx)
        search_start = idx + len(heading)
    assert indices == sorted(indices)


def test_073_supporting_evidence_fields_documented(command_text):
    section_start = command_text.find("## Supporting Evidence")
    section = command_text[section_start : section_start + 500]
    for field in ("Evidence ID", "Source Trust", "Evidence Confidence", "Assertion Type", "Stored supports_hypothesis Value"):
        assert field in section


def test_074_contradicting_evidence_fields_documented(command_text):
    section_start = command_text.find("## Contradicting Evidence")
    section = command_text[section_start : section_start + 400]
    assert "Use the same fields as Supporting Evidence" in section


def test_075_warning_advisory_statement_exists(command_text):
    assert "Warnings are advisory metadata checks and are not proof of maliciousness." in command_text


def test_076_current_assessment_is_labeled_not_persisted(command_text):
    assert command_text.count("Analyst supplied — not persisted") >= 2


def test_077_why_section_does_not_generate_causal_prose(command_text):
    section_start = command_text.find("## Why the Current Assessment Holds")
    section = command_text[section_start : section_start + 500]
    assert "Do not generate narrative reasoning here" in section
    assert "ThreatTrace did not generate a causal explanation" in section


def test_078_all_seven_reasoning_sections_exist(command_text):
    for heading in (
        "## Unresolved Assumptions",
        "## Evidence Gaps",
        "## What Would Strengthen the Assessment",
        "## What Would Weaken the Assessment",
        "## What Would Reverse the Assessment",
        "## Recommended Next Evidence",
        "## Limitations",
    ):
        assert heading in command_text


def test_079_empty_list_display_behavior_documented(command_text):
    assert command_text.count("None supplied.") >= 7


# ---------------------------------------------------------------------------
# 80-89: safety statements and no-confirmation
# ---------------------------------------------------------------------------

def test_080_no_write_statement_exists(command_text):
    assert "No decision-analysis record was written." in command_text


def test_081_no_investigation_mutation_statement_exists(command_text):
    assert "No investigation status or confidence changed." in command_text


def test_082_no_approval_statement_exists(command_text):
    assert "No approval occurred." in command_text


def test_083_no_containment_execution_statement_exists(command_text):
    assert "No containment or execution occurred." in command_text


def test_084_exactly_one_next_command_is_recommended(command_text):
    assert "Recommend exactly one existing command" in command_text
    assert "Never recommend more than one command." in command_text


def test_085_query_branch_documented(command_text):
    assert "recommend `/query`" in command_text


def test_086_case_summary_branch_documented(command_text):
    assert "recommend `/case-summary`" in command_text


def test_087_automatic_command_execution_prohibited(command_text):
    assert "never invoke it automatically" in command_text


def test_088_no_confirmation_phrase_required(command_text):
    assert "## No Confirmation Phrase" in command_text
    assert "This command performs no write of any kind" in command_text


def test_089_add_evidence_not_requested_as_a_gate(command_text):
    section_start = command_text.find("## No Confirmation Phrase")
    section = command_text[section_start : section_start + 500]
    assert '"Add evidence"' in section
    assert "do not request the phrase" in section


# ---------------------------------------------------------------------------
# 90-100: error categories and prohibited behaviors
# ---------------------------------------------------------------------------

def test_090_error_categories_exist(command_text):
    for heading in (
        "### Request error",
        "### Database error",
        "### Context-validation error",
        "### Warning-formatting error",
        "### Analysis-validation error",
        "### Internal tooling error",
    ):
        assert heading in command_text


def test_091_partial_preview_prohibited_after_failure(command_text):
    assert command_text.count("Never present a partial") + command_text.count("No partial preview may ever be labeled valid") >= 1


def test_092_raw_evidence_details_prohibited(command_text):
    assert "No raw evidence details or provenance ever appear in the preview." in command_text


def test_093_provenance_prohibited(command_text):
    assert "provenance" in command_text.lower()
    assert "No raw evidence details or provenance" in command_text


def test_094_database_write_operations_prohibited(command_text):
    assert "No database writes of any kind." in command_text


def test_095_investigation_updates_prohibited(command_text):
    assert "No investigation mutation" in command_text


def test_096_evidence_insertions_prohibited(command_text):
    assert "No evidence record was inserted or modified." in command_text


def test_097_decision_persistence_prohibited(command_text):
    assert "not persisted" in command_text


def test_098_approval_behavior_prohibited(command_text):
    assert "No approval action of any kind." in command_text


def test_099_containment_behavior_prohibited(command_text):
    assert "No containment action of any kind." in command_text


def test_100_red_team_execution_prohibited(command_text):
    assert "No Red Team execution of any kind." in command_text


# ---------------------------------------------------------------------------
# 101-106: static-test self-boundaries
# ---------------------------------------------------------------------------

def test_101_static_tests_do_not_run_clis():
    # AST-based (not raw substring search): a raw substring search would
    # trivially "find" these module names inside this very test's own
    # assertion strings. Checking actual import statements avoids that
    # self-referential false positive.
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    forbidden_modules = {
        "core.decision_context_cli",
        "core.decision_warning_formatter_cli",
        "core.decision_analysis_cli",
    }
    assert not (imported & forbidden_modules)


def test_102_static_tests_do_not_call_supabase():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imported)


def test_103_static_tests_do_not_use_subprocess():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "subprocess" not in imported


def test_104_static_tests_avoid_broad_forbidden_word_assertions(command_text):
    # Every affirmative-verb pattern that would instruct the command to
    # actually perform a write/mutate/approve/contain action must never
    # match this document -- the document only ever uses those verbs
    # inside negative safety prose ("do not", "never", "no ...").
    import re

    for pattern in _AFFIRMATIVE_FORBIDDEN_VERB_PATTERNS:
        for match in re.finditer(pattern, command_text, flags=re.IGNORECASE):
            preceding_text = command_text[max(0, match.start() - 60) : match.start()].lower()
            assert any(marker in preceding_text for marker in _NEGATION_MARKERS), (
                f"possible affirmative write instruction near: {command_text[match.start():match.start()+80]!r}"
            )


def test_105_command_ends_with_safety_rules(command_text):
    stripped = command_text.rstrip()
    safety_index = stripped.rfind("## Safety Rules")
    assert safety_index != -1
    # No further heading should follow "## Safety Rules".
    remainder = stripped[safety_index:]
    assert remainder.count("\n## ") == 0
    assert remainder.count("\n# ") == 0


def test_106_static_tests_do_not_modify_any_file():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)

    assert "shutil" not in imported
    assert not _has_write_mode_open_call(tree)
    assert not _has_call_to_attr(tree, {"write_text", "write_bytes", "unlink", "remove", "rename"})


# ---------------------------------------------------------------------------
# Additional affirmative-instruction-language robustness checks
# ---------------------------------------------------------------------------

def test_no_affirmative_execute_instruction_outside_safety_prose(command_text):
    import re

    for match in re.finditer(r"\bexecute\b", command_text, flags=re.IGNORECASE):
        preceding_text = command_text[max(0, match.start() - 40) : match.start()].lower()
        following_text = command_text[match.start() : match.start() + 60].lower()
        combined = preceding_text + following_text
        assert any(marker in combined for marker in _NEGATION_MARKERS), (
            f"possible affirmative execute instruction near: {command_text[match.start():match.start()+80]!r}"
        )
