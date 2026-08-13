"""Tests for core.analyst_feedback -- the pure, deterministic structured
analyst feedback collection layer (Block 13).

No Supabase, MCP, file, subprocess, network, Hayabusa, or AI/model access
occurs anywhere in this file; every input is a plain in-memory value, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time(). No tool is ever executed and no prior security-policy
function (Block 8/9/10/Mutation-Freeze/evaluation lab) is ever called.
"""

import copy
import inspect

import core.analyst_feedback as analyst_feedback_module
from core.analyst_feedback import (
    ANALYST_DECISIONS,
    ERROR_CATEGORIES,
    TARGET_TYPES,
    AnalystFeedbackError,
    create_analyst_feedback,
)

SUBMITTED_AT = "2026-01-01T00:00:00Z"

_RESULT_FIELDS = {
    "feedback_version", "target_type", "target_reference", "analyst_decision", "error_category",
    "rationale", "evidence_reference", "corrected_value", "submitted_at", "feedback_persisted",
    "automatic_learning_performed",
}


def _feedback(**overrides):
    kwargs = {
        "target_type": "investigation_decision",
        "target_reference": "investigation-123",
        "analyst_decision": "agree",
        "error_category": None,
        "rationale": None,
        "evidence_reference": None,
        "corrected_value": None,
        "submitted_at": SUBMITTED_AT,
    }
    kwargs.update(overrides)
    return create_analyst_feedback(**kwargs)


def _disagree_feedback(**overrides):
    kwargs = {
        "target_type": "investigation_decision",
        "target_reference": "investigation-123",
        "analyst_decision": "disagree",
        "error_category": "false_positive",
        "rationale": "The supporting evidence does not establish this classification.",
        "evidence_reference": None,
        "corrected_value": None,
        "submitted_at": SUBMITTED_AT,
    }
    kwargs.update(overrides)
    return create_analyst_feedback(**kwargs)


def _assert_raises(**kwargs):
    try:
        create_analyst_feedback(**kwargs)
        assert False, f"expected AnalystFeedbackError for kwargs={kwargs!r}"
    except AnalystFeedbackError:
        pass


# ---------------------------------------------------------------------------
# Successful creation
# ---------------------------------------------------------------------------


def test_001_agree_investigation_target():
    result = _feedback()
    assert result["analyst_decision"] == "agree"
    assert result["target_type"] == "investigation_decision"
    assert result["error_category"] is None
    assert result["rationale"] is None
    assert set(result) == _RESULT_FIELDS


def test_002_disagree_investigation_target():
    result = _disagree_feedback()
    assert result["analyst_decision"] == "disagree"
    assert result["error_category"] == "false_positive"
    assert result["rationale"]


def test_003_insufficient_evidence():
    result = _feedback(analyst_decision="insufficient_evidence")
    assert result["analyst_decision"] == "insufficient_evidence"
    assert result["error_category"] is None


def test_004_policy_target():
    result = _feedback(
        target_type="security_policy_decision",
        target_reference="gateway:apply_approval_consumption:call-1",
        corrected_value="deny",
    )
    assert result["target_type"] == "security_policy_decision"
    assert result["corrected_value"] == "deny"


def test_005_evaluation_target():
    result = _feedback(
        target_type="evaluation_result",
        target_reference="evaluate:emergency_freeze_bypass:identity_agent:coordinator_agent",
        corrected_value="fail",
    )
    assert result["target_type"] == "evaluation_result"
    assert result["corrected_value"] == "fail"


def test_006_optional_corrected_value_present():
    result = _feedback(corrected_value="contradicted")
    assert result["corrected_value"] == "contradicted"


def test_007_optional_corrected_value_absent():
    result = _feedback()
    assert result["corrected_value"] is None


def test_008_optional_evidence_references_present():
    result = _feedback(evidence_reference=["evidence-a", "evidence-b"])
    assert result["evidence_reference"] == ["evidence-a", "evidence-b"]


def test_009_optional_evidence_references_absent():
    result = _feedback()
    assert result["evidence_reference"] is None


def test_010_deterministic_repeated_result():
    first = _feedback()
    second = _feedback()
    assert first == second


# ---------------------------------------------------------------------------
# Conditional disagreement contract
# ---------------------------------------------------------------------------


def test_011_disagree_requires_error_category():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="disagree",
        error_category=None, rationale="some rationale", evidence_reference=None,
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


def test_012_disagree_requires_rationale():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="disagree",
        error_category="false_positive", rationale=None, evidence_reference=None,
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


def test_013_disagree_with_both_works():
    result = _disagree_feedback()
    assert result["error_category"] == "false_positive"
    assert result["rationale"]


def test_014_agree_with_error_category_rejected():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="agree",
        error_category="false_positive", rationale=None, evidence_reference=None,
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


def test_015_insufficient_evidence_with_error_category_rejected():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="insufficient_evidence",
        error_category="missing_evidence", rationale=None, evidence_reference=None,
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


def test_016_blank_disagreement_rationale_rejected():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="disagree",
        error_category="false_positive", rationale="   ", evidence_reference=None,
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


def test_017_blank_rationale_rejected_even_on_agree():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="agree",
        error_category=None, rationale="   ", evidence_reference=None,
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


def test_018_non_string_rationale_rejected():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="agree",
        error_category=None, rationale=123, evidence_reference=None,
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


def test_019_agree_with_non_blank_rationale_is_allowed():
    result = _feedback(rationale="Consistent with the collected evidence.")
    assert result["rationale"] == "Consistent with the collected evidence."


# ---------------------------------------------------------------------------
# Vocabulary validation
# ---------------------------------------------------------------------------


def test_020_every_valid_target_type_accepted():
    for target_type in TARGET_TYPES:
        result = _feedback(target_type=target_type, target_reference="ref")
        assert result["target_type"] == target_type


def test_021_invalid_target_type_rejected():
    for bad_value in ("approval_request", "approval_decision", "action_review", "", None, 123):
        _assert_raises(
            target_type=bad_value, target_reference="x", analyst_decision="agree",
            error_category=None, rationale=None, evidence_reference=None,
            corrected_value=None, submitted_at=SUBMITTED_AT,
        )


def test_022_every_valid_analyst_decision_accepted():
    for analyst_decision in ("agree", "insufficient_evidence"):
        result = _feedback(analyst_decision=analyst_decision)
        assert result["analyst_decision"] == analyst_decision
    disagree_result = _disagree_feedback()
    assert disagree_result["analyst_decision"] == "disagree"


def test_023_invalid_analyst_decision_rejected():
    for bad_value in ("allow", "require_approval", "deny", "pass", "fail", "not_applicable", "partially_agree", ""):
        _assert_raises(
            target_type="investigation_decision", target_reference="x", analyst_decision=bad_value,
            error_category=None, rationale=None, evidence_reference=None,
            corrected_value=None, submitted_at=SUBMITTED_AT,
        )


def test_024_every_valid_error_category_accepted():
    for error_category in ERROR_CATEGORIES:
        result = _disagree_feedback(error_category=error_category)
        assert result["error_category"] == error_category


def test_025_invalid_error_category_rejected():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="disagree",
        error_category="not_a_real_category", rationale="rationale text", evidence_reference=None,
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


# ---------------------------------------------------------------------------
# corrected_value domain validation
# ---------------------------------------------------------------------------


def test_026_investigation_valid_decision_status_accepted():
    from core.decision_analysis import DECISION_STATUSES
    for status in DECISION_STATUSES:
        result = _feedback(target_type="investigation_decision", corrected_value=status)
        assert result["corrected_value"] == status


def test_027_investigation_invalid_corrected_value_rejected():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="agree",
        error_category=None, rationale=None, evidence_reference=None,
        corrected_value="allow", submitted_at=SUBMITTED_AT,
    )


def test_028_policy_allow_accepted():
    result = _feedback(target_type="security_policy_decision", corrected_value="allow")
    assert result["corrected_value"] == "allow"


def test_029_policy_require_approval_accepted():
    result = _feedback(target_type="security_policy_decision", corrected_value="require_approval")
    assert result["corrected_value"] == "require_approval"


def test_030_policy_deny_accepted():
    result = _feedback(target_type="security_policy_decision", corrected_value="deny")
    assert result["corrected_value"] == "deny"


def test_031_policy_evaluation_value_rejected():
    _assert_raises(
        target_type="security_policy_decision", target_reference="x", analyst_decision="agree",
        error_category=None, rationale=None, evidence_reference=None,
        corrected_value="pass", submitted_at=SUBMITTED_AT,
    )


def test_032_evaluation_pass_accepted():
    result = _feedback(target_type="evaluation_result", corrected_value="pass")
    assert result["corrected_value"] == "pass"


def test_033_evaluation_fail_accepted():
    result = _feedback(target_type="evaluation_result", corrected_value="fail")
    assert result["corrected_value"] == "fail"


def test_034_evaluation_not_applicable_accepted():
    result = _feedback(target_type="evaluation_result", corrected_value="not_applicable")
    assert result["corrected_value"] == "not_applicable"


def test_035_evaluation_policy_value_rejected():
    _assert_raises(
        target_type="evaluation_result", target_reference="x", analyst_decision="agree",
        error_category=None, rationale=None, evidence_reference=None,
        corrected_value="deny", submitted_at=SUBMITTED_AT,
    )


def test_036_corrected_value_non_string_rejected():
    _assert_raises(
        target_type="evaluation_result", target_reference="x", analyst_decision="agree",
        error_category=None, rationale=None, evidence_reference=None,
        corrected_value=123, submitted_at=SUBMITTED_AT,
    )


def test_037_corrected_value_allowed_alongside_disagree():
    result = _disagree_feedback(corrected_value="contradicted")
    assert result["corrected_value"] == "contradicted"


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------


def test_038_valid_target_reference_accepted():
    result = _feedback(target_reference="investigation-abc-123")
    assert result["target_reference"] == "investigation-abc-123"


def test_039_blank_target_reference_rejected():
    for bad_value in ("", "   "):
        _assert_raises(
            target_type="investigation_decision", target_reference=bad_value, analyst_decision="agree",
            error_category=None, rationale=None, evidence_reference=None,
            corrected_value=None, submitted_at=SUBMITTED_AT,
        )


def test_040_non_string_target_reference_rejected():
    for bad_value in (None, 123, ["ref"], {}):
        _assert_raises(
            target_type="investigation_decision", target_reference=bad_value, analyst_decision="agree",
            error_category=None, rationale=None, evidence_reference=None,
            corrected_value=None, submitted_at=SUBMITTED_AT,
        )


def test_041_evidence_reference_none_accepted():
    result = _feedback(evidence_reference=None)
    assert result["evidence_reference"] is None


def test_042_evidence_reference_valid_single_item_list():
    result = _feedback(evidence_reference=["evidence-1"])
    assert result["evidence_reference"] == ["evidence-1"]


def test_043_evidence_reference_multiple_items():
    result = _feedback(evidence_reference=["evidence-1", "evidence-2", "evidence-3"])
    assert result["evidence_reference"] == ["evidence-1", "evidence-2", "evidence-3"]


def test_044_evidence_reference_empty_list_rejected():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="agree",
        error_category=None, rationale=None, evidence_reference=[],
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


def test_045_evidence_reference_blank_element_rejected():
    for bad_list in (["evidence-1", ""], ["evidence-1", "   "], [""]):
        _assert_raises(
            target_type="investigation_decision", target_reference="x", analyst_decision="agree",
            error_category=None, rationale=None, evidence_reference=bad_list,
            corrected_value=None, submitted_at=SUBMITTED_AT,
        )


def test_046_evidence_reference_non_list_rejected():
    for bad_value in ("evidence-1", 123, {"id": "evidence-1"}):
        _assert_raises(
            target_type="investigation_decision", target_reference="x", analyst_decision="agree",
            error_category=None, rationale=None, evidence_reference=bad_value,
            corrected_value=None, submitted_at=SUBMITTED_AT,
        )


def test_047_evidence_reference_non_string_element_rejected():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="agree",
        error_category=None, rationale=None, evidence_reference=["evidence-1", 123],
        corrected_value=None, submitted_at=SUBMITTED_AT,
    )


def test_048_caller_evidence_list_not_mutated_or_aliased():
    original = ["evidence-1", "evidence-2"]
    snapshot = copy.deepcopy(original)

    result = _feedback(evidence_reference=original)

    assert original == snapshot
    assert result["evidence_reference"] is not original
    result["evidence_reference"].append("injected")
    assert original == snapshot


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------


def test_049_valid_submitted_at_accepted():
    result = _feedback(submitted_at="2026-06-15T08:30:00Z")
    assert result["submitted_at"] == "2026-06-15T08:30:00Z"


def test_050_malformed_submitted_at_rejected():
    for bad_value in ("not-a-timestamp", "", None, 123, "2026-01-01T00:00:00"):
        _assert_raises(
            target_type="investigation_decision", target_reference="x", analyst_decision="agree",
            error_category=None, rationale=None, evidence_reference=None,
            corrected_value=None, submitted_at=bad_value,
        )


def test_051_timezone_naive_submitted_at_rejected():
    _assert_raises(
        target_type="investigation_decision", target_reference="x", analyst_decision="agree",
        error_category=None, rationale=None, evidence_reference=None,
        corrected_value=None, submitted_at="2026-01-01T00:00:00",
    )


def test_052_deterministic_timestamp_handling():
    first = _feedback(submitted_at=SUBMITTED_AT)
    second = _feedback(submitted_at=SUBMITTED_AT)
    assert first["submitted_at"] == second["submitted_at"] == SUBMITTED_AT


def test_053_no_default_now_when_submitted_at_supplied():
    # There is no way to omit submitted_at at all -- it is a required
    # keyword-only parameter with no default -- so this confirms only
    # that the exact supplied value is echoed back unchanged.
    result = _feedback(submitted_at="2030-12-31T23:59:59Z")
    assert result["submitted_at"] == "2030-12-31T23:59:59Z"


# ---------------------------------------------------------------------------
# Honesty fields
# ---------------------------------------------------------------------------


def test_054_feedback_persisted_always_false():
    for analyst_decision in ("agree", "disagree", "insufficient_evidence"):
        if analyst_decision == "disagree":
            result = _disagree_feedback()
        else:
            result = _feedback(analyst_decision=analyst_decision)
        assert result["feedback_persisted"] is False


def test_055_automatic_learning_performed_always_false():
    for analyst_decision in ("agree", "disagree", "insufficient_evidence"):
        if analyst_decision == "disagree":
            result = _disagree_feedback()
        else:
            result = _feedback(analyst_decision=analyst_decision)
        assert result["automatic_learning_performed"] is False


def test_056_no_authentication_field_present():
    result = _feedback()
    forbidden_fields = {"analyst_id", "analyst_name", "reviewer_identity", "user_id", "feedback_id"}
    assert forbidden_fields.isdisjoint(result)


def test_057_result_field_set_exact():
    result = _feedback()
    assert set(result) == _RESULT_FIELDS


# ---------------------------------------------------------------------------
# Purity / structural boundary
# ---------------------------------------------------------------------------


def test_058_module_never_reads_clock_env_filesystem_network_mcp_database():
    # Only the executable code is inspected, not the module docstring --
    # the docstring itself names "subprocess"/"Supabase"/etc. in prose to
    # explain that this module never performs them, which would otherwise
    # trip this same substring check.
    full_source = inspect.getsource(analyst_feedback_module)
    source = full_source.split("from __future__", 1)[1]
    forbidden_substrings = (
        "datetime.now",
        "utcnow",
        "time.time",
        "os.environ",
        "os.getenv",
        "open(",
        "Path(",
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "mcp__",
        "random.",
        "uuid.uuid",
    )
    for forbidden in forbidden_substrings:
        assert forbidden not in source, f"forbidden substring found: {forbidden!r}"


def test_059_module_never_invokes_prior_security_policy_functions():
    full_source = inspect.getsource(analyst_feedback_module)
    source = full_source.split("from __future__", 1)[1]
    forbidden_calls = (
        "evaluate_tool_call(",
        "evaluate_agent_tool_call(",
        "evaluate_mutation_freeze(",
        "create_decision_binding(",
        "verify_decision_binding(",
        "evaluate_ai_security_case(",
    )
    for forbidden in forbidden_calls:
        assert forbidden not in source, f"forbidden call found: {forbidden!r}"


def test_060_module_only_imports_plain_vocabularies_not_functions():
    full_source = inspect.getsource(analyst_feedback_module)
    source = full_source.split("from __future__", 1)[1]
    assert "from core.agent_gateway import DECISIONS" in source
    assert "from core.decision_analysis import DECISION_STATUSES" in source
    # A code comment legitimately explains why core.ai_asset_registry's
    # vocabulary is mirrored locally rather than imported -- only an
    # actual import statement for any of these four modules is forbidden.
    forbidden_import_statements = (
        "import core.agent_identity_policy",
        "from core.agent_identity_policy",
        "import core.mutation_freeze",
        "from core.mutation_freeze",
        "import core.decision_binding",
        "from core.decision_binding",
        "import core.ai_asset_registry",
        "from core.ai_asset_registry",
    )
    for forbidden in forbidden_import_statements:
        assert forbidden not in source, f"forbidden import found: {forbidden!r}"
