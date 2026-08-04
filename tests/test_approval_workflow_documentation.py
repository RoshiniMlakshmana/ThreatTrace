"""Static tests for the Block 5 approval-gated case-update documentation
and routing updates: README.md, SECURITY.md, docs/architecture.md,
docs/demo-walkthrough.md, .claude/commands/triage-case.md, and
.claude/commands/purple-loop.md -- plus the Block 6 risk-aware
multi-review approval documentation: README.md's project-status update
and docs/block6-risk-aware-approvals.md.

These tests only read repository text files and check their content
structurally. They never execute a ThreatTrace command, never invoke any
project CLI, never call Supabase or MCP, never execute SQL or an RPC,
never access the network, never launch a shell command, and never modify
any file.

64 tests are defined for the Block 5 specification, plus 4 additional
tests for Block 6's closure documentation (68 total).
"""

import ast
import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

README_PATH = REPO_ROOT / "README.md"
SECURITY_PATH = REPO_ROOT / "SECURITY.md"
ARCHITECTURE_PATH = REPO_ROOT / "docs" / "architecture.md"
DEMO_PATH = REPO_ROOT / "docs" / "demo-walkthrough.md"
TRIAGE_PATH = REPO_ROOT / ".claude" / "commands" / "triage-case.md"
PURPLE_LOOP_PATH = REPO_ROOT / ".claude" / "commands" / "purple-loop.md"
BLOCK6_PATH = REPO_ROOT / "docs" / "block6-risk-aware-approvals.md"

ALL_MODIFIED_PATHS = (
    README_PATH, SECURITY_PATH, ARCHITECTURE_PATH, DEMO_PATH, TRIAGE_PATH, PURPLE_LOOP_PATH,
)

UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


@pytest.fixture(scope="module")
def readme_text():
    return README_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def security_text():
    return SECURITY_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def architecture_text():
    return ARCHITECTURE_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def demo_text():
    return DEMO_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def triage_text():
    return TRIAGE_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def purple_loop_text():
    return PURPLE_LOOP_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def block6_text():
    return BLOCK6_PATH.read_text(encoding="utf-8")


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


def _extract_json_after(text, prefix):
    idx = text.find(prefix)
    assert idx != -1, f"prefix not found: {prefix!r}"
    start = text.find("{", idx)
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise AssertionError(f"no balanced JSON object found after {prefix!r}")


def _command_list_section(text, heading, next_heading_or_marker):
    start = text.find(heading)
    assert start != -1, f"heading not found: {heading}"
    end = text.find(next_heading_or_marker, start + len(heading))
    assert end != -1, f"end marker not found after {heading}: {next_heading_or_marker}"
    return text[start:end]


# ---------------------------------------------------------------------------
# 1-4: general boundaries
# ---------------------------------------------------------------------------

def test_001_all_six_files_exist():
    for path in ALL_MODIFIED_PATHS:
        assert path.is_file(), f"missing file: {path}"


def test_002_test_module_reads_only_repository_text_files():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert imported <= {"ast", "json", "re", "pathlib", "pytest"}


def test_003_test_module_performs_no_network_mcp_supabase_sql_rpc_or_shell_execution():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    forbidden = {
        "subprocess", "socket", "requests", "urllib", "http",
        "supabase", "core.approval_bridge_cli", "core.approval_mcp_adapter_cli",
        "core.approval_transition_cli", "core.approval_request_cli",
    }
    assert not (imported & forbidden)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("execute", "executemany", "system", "popen")


def test_004_documentation_contains_no_embedded_credentials_tokens_urls_or_project_references():
    forbidden_patterns = (
        r"postgres://\S+:\S+@",
        r"https?://\S*supabase\.co\S*",
        r"eyJ[a-zA-Z0-9_-]{10,}",
        r"sk-[a-zA-Z0-9]{10,}",
        r"service_role_key\s*[:=]\s*\S+",
    )
    for path in ALL_MODIFIED_PATHS:
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            assert re.search(pattern, text) is None, f"forbidden pattern {pattern!r} found in {path}"


# ---------------------------------------------------------------------------
# 5-17: README
# ---------------------------------------------------------------------------

def test_005_readme_documents_request_case_update(readme_text):
    assert "`/request-case-update`" in readme_text


def test_006_readme_documents_review_approval(readme_text):
    assert "`/review-approval`" in readme_text


def test_007_readme_documents_apply_case_update(readme_text):
    assert "`/apply-case-update`" in readme_text


def test_008_readme_labels_update_case_deprecated(readme_text):
    assert "Deprecated" in readme_text
    row_index = readme_text.find("| `/update-case` |")
    assert row_index != -1
    row = readme_text[row_index : readme_text.find("\n", row_index)]
    assert "Deprecated" in row
    assert "static" in row.lower()


def test_009_three_commands_appear_in_lifecycle_order(readme_text):
    section_start = readme_text.find("## Approval-Gated Case Updates")
    section = readme_text[section_start : section_start + 400]
    indices = []
    search_start = 0
    for name in ("/request-case-update", "/review-approval", "/apply-case-update"):
        idx = section.find(name, search_start)
        assert idx != -1, f"not found in order block: {name}"
        indices.append(idx)
        search_start = idx + len(name)
    assert indices == sorted(indices)


def test_010_request_described_as_creating_pending_approval(readme_text):
    assert "creates one pending approval" in readme_text


def test_011_review_described_as_approve_reject(readme_text):
    assert "lets a reviewer approve or reject that pending approval" in readme_text


def test_012_apply_described_as_atomic(readme_text):
    assert "atomically consumes an approved, unconsumed approval" in readme_text


def test_013_request_stated_not_to_update_investigation(readme_text):
    section_start = readme_text.find("`/request-case-update` creates one pending approval")
    section = readme_text[section_start : section_start + 300]
    assert "It does not update the investigation." in section


def test_014_review_stated_not_to_update_investigation(readme_text):
    section_start = readme_text.find("`/review-approval` lets a reviewer")
    section = readme_text[section_start : section_start + 300]
    assert "It does not update the investigation." in section


def test_015_direct_case_updates_stated_disabled(readme_text):
    assert "never applied directly" in readme_text
    assert "direct-write behavior is unavailable" in readme_text


def test_016_typed_confirmation_not_authorization(readme_text):
    assert "typed confirmation was never authorization" in readme_text


def test_017_readme_contains_valid_json_examples_for_all_three_commands(readme_text):
    request_json = json.loads(_extract_json_after(readme_text, "/request-case-update {"))
    review_json = json.loads(_extract_json_after(readme_text, "/review-approval {"))
    apply_json = json.loads(_extract_json_after(readme_text, "/apply-case-update {"))
    assert "investigation_id" in request_json and "requested_by" in request_json
    assert "approval_id" in review_json and "decision" in review_json and "reviewed_by" in review_json
    assert "approval_id" in apply_json and "consumed_by" in apply_json


# ---------------------------------------------------------------------------
# 18-29: SECURITY.md
# ---------------------------------------------------------------------------

def test_018_security_documents_approval_gated_case_updates(security_text):
    assert "## Approval-Gated Case Updates" in security_text


def test_019_security_prohibits_direct_investigation_updates(security_text):
    section_start = security_text.find("## Approval-Gated Case Updates")
    section = security_text[section_start : section_start + 400]
    assert "never applied directly" in section


def test_020_security_names_atomic_consumption_rpc(security_text):
    assert "consume_approval_and_update_investigation_state" in security_text


def test_021_security_states_public_lacks_rpc_execution(security_text):
    section_start = security_text.find("## Approval-Gated Case Updates")
    section = security_text[section_start : section_start + 1600]
    assert "`PUBLIC`, `anon`, and `authenticated` cannot execute the atomic RPC." in section


def test_022_security_states_anon_lacks_rpc_execution(security_text):
    section_start = security_text.find("## Approval-Gated Case Updates")
    section = security_text[section_start : section_start + 1600]
    assert "`anon`" in section and "cannot execute the atomic RPC" in section


def test_023_security_states_authenticated_lacks_rpc_execution(security_text):
    section_start = security_text.find("## Approval-Gated Case Updates")
    section = security_text[section_start : section_start + 1600]
    assert "`authenticated`" in section and "cannot execute the atomic RPC" in section


def test_024_security_states_service_role_retains_rpc_execution(security_text):
    assert "Only `service_role` (and the function owner) retain `EXECUTE` permission on it." in security_text


def test_025_security_states_identities_are_claimed(security_text):
    assert "caller-supplied **claimed identities**" in security_text


def test_026_security_does_not_claim_identities_authenticated(security_text):
    section_start = security_text.find("caller-supplied **claimed identities**")
    section = security_text[section_start : section_start + 200]
    assert "none of them is authenticated" in section


def test_027_security_documents_atomic_approval_consumption(security_text):
    assert "consumes the approval and updates the investigation together in the same database transaction" in security_text


def test_028_security_documents_replay_prevention(security_text):
    assert "Every replay attempt fails closed as a persistence conflict" in security_text


def test_029_security_documents_rpc_as_final_authority_against_toctou(security_text):
    assert "final authority against TOCTOU" in security_text


# ---------------------------------------------------------------------------
# 30-43: architecture
# ---------------------------------------------------------------------------

def test_030_architecture_documents_all_three_approval_commands(architecture_text):
    section_start = architecture_text.find("## Approval-Gated Case Update Architecture (Block 5)")
    assert section_start != -1
    section = architecture_text[section_start : section_start + 800]
    for name in ("/request-case-update", "/review-approval", "/apply-case-update"):
        assert name in section


def test_031_architecture_shows_commands_in_correct_order(architecture_text):
    section_start = architecture_text.find("## Approval-Gated Case Update Architecture (Block 5)")
    section = architecture_text[section_start : section_start + 800]
    indices = []
    search_start = 0
    for name in ("/request-case-update", "/review-approval", "/apply-case-update"):
        idx = section.find(name, search_start)
        assert idx != -1
        indices.append(idx)
        search_start = idx + len(name)
    assert indices == sorted(indices)


def test_032_architecture_documents_approval_request_validator(architecture_text):
    assert "approval request validator" in architecture_text


def test_033_architecture_documents_transition_validator(architecture_text):
    assert "transition validator" in architecture_text
    assert "consume transition validator" in architecture_text


def test_034_architecture_documents_persistence_layer(architecture_text):
    section_start = architecture_text.find("## Approval-Gated Case Update Architecture (Block 5)")
    section = architecture_text[section_start : architecture_text.find("## Data and Filesystem Boundaries")]
    assert "persistence descriptor" in section
    assert "persistence function" in section


def test_035_architecture_documents_approval_bridge(architecture_text):
    assert "core.approval_bridge" in architecture_text


def test_036_architecture_documents_mcp_adapter(architecture_text):
    assert "core.approval_mcp_adapter" in architecture_text


def test_037_architecture_requires_adapter_produced_execute_sql_arguments(architecture_text):
    section_start = architecture_text.find("## Approval-Gated Case Update Architecture (Block 5)")
    section = architecture_text[section_start : architecture_text.find("## Data and Filesystem Boundaries")]
    assert "mcp__supabase__execute_sql" in section
    assert "converts only an already-verified, allowlisted descriptor into one fixed SQL template" in section


def test_038_architecture_identifies_atomic_rpc_as_final_mutation(architecture_text):
    section_start = architecture_text.find("## Approval-Gated Case Update Architecture (Block 5)")
    section = architecture_text[section_start : architecture_text.find("## Data and Filesystem Boundaries")]
    assert "consume_approval_and_update_investigation_state" in section
    assert "is the final authority" in section


def test_039_architecture_states_stored_action_payload_is_update_source(architecture_text):
    assert "The stored `action_payload` on the approval record is the exclusive source of the applied `status`/`confidence`" in architecture_text


def test_040_architecture_documents_exactly_nineteen_returned_fields(architecture_text):
    assert "returns exactly nineteen fields" in architecture_text
    assert "`investigation_status`" in architecture_text
    assert "`investigation_confidence`" in architecture_text
    assert "`investigation_updated_at`" in architecture_text


def test_041_architecture_documents_prepare_execute_normalize_verify(architecture_text):
    section_start = architecture_text.find("### Two-Phase Tool Architecture")
    section = architecture_text[section_start : section_start + 300]
    assert "Prepare" in section
    assert "normalize" in section
    assert "verify" in section


def test_042_architecture_prohibits_direct_investigation_updates(architecture_text):
    assert "it never updates `public.investigations` through any other path" in architecture_text


def test_043_architecture_excludes_update_case_from_mutation_architecture(architecture_text):
    assert "`/update-case` is not part of this mutation architecture." in architecture_text


# ---------------------------------------------------------------------------
# 44-54: demo walkthrough
# ---------------------------------------------------------------------------

def test_044_old_direct_update_case_narrative_absent(demo_text):
    assert "via `/update-case`" not in demo_text
    assert "updated to **medium** via" not in demo_text


def test_045_demo_contains_valid_request_example(demo_text):
    parsed = json.loads(_extract_json_after(demo_text, "/request-case-update {"))
    assert "investigation_id" in parsed
    assert "requested_by" in parsed


def test_046_demo_contains_valid_review_example(demo_text):
    matches = [m.start() for m in re.finditer(re.escape("/review-approval {"), demo_text)]
    assert matches
    approve_json = json.loads(_extract_json_after(demo_text, "/review-approval {"))
    assert "approval_id" in approve_json
    assert "decision" in approve_json


def test_047_demo_contains_valid_apply_example(demo_text):
    parsed = json.loads(_extract_json_after(demo_text, "/apply-case-update {"))
    assert "approval_id" in parsed
    assert "consumed_by" in parsed


def test_048_demo_examples_appear_in_lifecycle_order(demo_text):
    section_start = demo_text.find("## 4. Confidence and Severity")
    section = demo_text[section_start : demo_text.find("## 5. Red Team Routing")]
    request_index = section.find("/request-case-update {")
    review_index = section.find("/review-approval {")
    apply_index = section.find("/apply-case-update {")
    assert 0 <= request_index < review_index < apply_index


def test_049_demo_example_uuids_are_syntactically_valid(demo_text):
    request_json = json.loads(_extract_json_after(demo_text, "/request-case-update {"))
    review_json = json.loads(_extract_json_after(demo_text, "/review-approval {"))
    apply_json = json.loads(_extract_json_after(demo_text, "/apply-case-update {"))
    assert UUID_PATTERN.match(request_json["investigation_id"])
    assert UUID_PATTERN.match(review_json["approval_id"])
    assert UUID_PATTERN.match(apply_json["approval_id"])


def test_050_demo_identities_labeled_claimed(demo_text):
    assert "claimed requester identity" in demo_text
    assert "claimed reviewer identity" in demo_text
    assert "claimed consumer identity" in demo_text


def test_051_demo_request_stage_states_investigation_unchanged(demo_text):
    assert "The investigation is not updated at this point." in demo_text


def test_052_demo_review_stage_states_investigation_unchanged(demo_text):
    assert "The investigation is still not updated." in demo_text


def test_053_demo_apply_stage_states_atomic(demo_text):
    assert "This single atomic operation marks the approval `consumed`" in demo_text


def test_054_demo_includes_rejected_request_path(demo_text):
    assert "### If the Reviewer Had Rejected Instead" in demo_text
    section_start = demo_text.find("### If the Reviewer Had Rejected Instead")
    section = demo_text[section_start:]
    assert "the investigation would remain completely unchanged" in section
    assert "rejected approval could never be applied" in section


# ---------------------------------------------------------------------------
# 55-59: triage-case.md
# ---------------------------------------------------------------------------

def _triage_step_12_section(triage_text):
    return _command_list_section(triage_text, "12. Recommend the next ThreatTrace command", "## Required Output")


def test_055_triage_recommends_request_for_proposed_change(triage_text):
    section = _triage_step_12_section(triage_text)
    assert "recommend `/request-case-update`" in section


def test_056_triage_recommends_review_for_pending_approval(triage_text):
    section = _triage_step_12_section(triage_text)
    assert "recommend `/review-approval`" in section


def test_057_triage_recommends_apply_for_approved_request(triage_text):
    section = _triage_step_12_section(triage_text)
    assert "recommend `/apply-case-update`" in section


def test_058_triage_does_not_automatically_invoke_or_chain_commands(triage_text):
    assert "never execute, invoke, or chain it automatically" in triage_text
    assert "Never invoke or chain `/request-case-update`, `/review-approval`, or `/apply-case-update` automatically" in triage_text


def test_059_triage_does_not_recommend_update_case_as_mutation_command(triage_text):
    section = _triage_step_12_section(triage_text)
    possible_commands_start = section.find("Possible commands include:")
    possible_commands_section = section[possible_commands_start : section.find("When triage identifies")]
    assert "/update-case" not in possible_commands_section
    assert "never recommend it as a way to change status or confidence" in section


# ---------------------------------------------------------------------------
# 60-64: purple-loop.md
# ---------------------------------------------------------------------------

def _purple_loop_step_6_section(purple_loop_text):
    return _command_list_section(purple_loop_text, "6. Route the recommendation", "7. Never execute")


def test_060_purple_loop_recommends_request_for_proposed_change(purple_loop_text):
    section = _purple_loop_step_6_section(purple_loop_text)
    assert "Proposed change" in section
    assert "/request-case-update" in section


def test_061_purple_loop_recommends_review_for_pending_approval(purple_loop_text):
    section = _purple_loop_step_6_section(purple_loop_text)
    assert "Pending approval" in section
    assert "/review-approval" in section


def test_062_purple_loop_recommends_apply_for_approved_request(purple_loop_text):
    section = _purple_loop_step_6_section(purple_loop_text)
    assert "Approved approval" in section
    assert "/apply-case-update" in section


def test_063_purple_loop_does_not_automatically_invoke_or_chain_commands(purple_loop_text):
    assert "Never execute, invoke, or chain another command automatically" in purple_loop_text
    assert "Never invoke or chain `/request-case-update`, `/review-approval`, or `/apply-case-update` automatically" in purple_loop_text


def test_064_purple_loop_contains_no_direct_case_update_path(purple_loop_text):
    section = _purple_loop_step_6_section(purple_loop_text)
    route_list_start = section.find("- /threat-hunt")
    route_list_end = section.find("Case-update routing follows")
    route_list = section[route_list_start:route_list_end]
    assert "/update-case" not in route_list
    assert "deprecated static guidance and must never be recommended as a way to change status or confidence" in purple_loop_text


# ---------------------------------------------------------------------------
# 65-68: Block 6 risk-aware multi-review approval closure documentation
# ---------------------------------------------------------------------------


def test_065_readme_marks_block_6_complete_and_links_to_block6_document(readme_text):
    assert "Block 6" in readme_text
    assert "is complete" in readme_text
    assert "[docs/block6-risk-aware-approvals.md](docs/block6-risk-aware-approvals.md)" in readme_text


def test_066_block6_document_contains_risk_mapping_and_both_lifecycles(block6_text):
    assert "| low | 1 |" in block6_text
    assert "| medium | 1 |" in block6_text
    assert "| high | 2 |" in block6_text
    assert "| critical | 2 |" in block6_text
    assert "pending → approved → consumed" in block6_text
    assert "pending → partially_approved → approved → consumed" in block6_text


def test_067_block6_document_covers_required_security_boundaries(block6_text):
    assert "trusted" in block6_text.lower()
    assert "TOCTOU" in block6_text
    assert "self-review" in block6_text
    assert "Duplicate reviewer blocked" in block6_text
    assert "Immutable review history" in block6_text
    assert "record_approval_review_and_promote_status" in block6_text
    assert "consume_approval_and_update_investigation_state" in block6_text
    assert "Partial approval cannot execute" in block6_text
    assert "Replay protection" in block6_text


def test_068_block6_document_contains_live_evidence_limitations_and_roadmap(block6_text):
    assert "## Live Supabase Verification" in block6_text
    assert "### One-review scenario" in block6_text
    assert "### Two-review scenario" in block6_text
    assert "duplicate" in block6_text.lower() and "blocked before any mutation" in block6_text
    assert "replay attempt" in block6_text.lower() and "blocked before any mutation" in block6_text
    assert "restored the database to exactly its pre-test state" in block6_text
    assert "claimed and deterministically normalized, not yet cryptographically authenticated" in block6_text
    assert "## Next: Block 7 — Shadow Execution / Digital Twin" in block6_text
