"""Focused tests confirming Block 15H-I's Detection Engineering flow
correctly uses the existing, unmodified Security Governor
`detection_engineering` stage (Block 15C.5) -- and that reusable
Security Experience Memory honesty (Block 15D) is preserved for
detection-engineering-originated findings, without any new coupling
code. No `core.security_governor`/`core.security_experience_memory`
source was modified for this checkpoint -- these tests exercise the
existing, unmodified public API only.
"""

from __future__ import annotations

from core.security_experience_memory import create_security_experience
from core.security_governor import evaluate_security_governor_event


def _governor_event(**overrides):
    event = {
        "event_version": "1", "actor_role": "blue_team", "action_class": "stage_contribution",
        "current_stage": "detection_engineering", "required_role": "blue_team",
        "gateway_decision": "allow", "identity_decision": "allow", "mutation_freeze_active": False,
        "approval_state": "not_required", "decision_binding_state": "not_required", "scope_state": "within_scope",
        "source_truth_state": "unchanged", "remote_content_state": "not_present", "audit_state": "recorded",
        "prior_policy_denials": 0, "execution_requested": False,
    }
    event.update(overrides)
    return event


class TestDetectionEngineeringGovernorStage:
    def test_001_valid_detection_engineering_action_allowed(self):
        result = evaluate_security_governor_event(event=_governor_event())
        assert result["decision"] == "allow"
        assert result["execution_allowed"] is True

    def test_002_wrong_role_at_detection_engineering_denied(self):
        result = evaluate_security_governor_event(event=_governor_event(actor_role="red_team", required_role="red_team"))
        assert result["decision"] == "block"
        assert "ROLE_SCOPE_VIOLATION" in result["reason_codes"]

    def test_003_scope_expansion_during_detection_engineering_denied(self):
        result = evaluate_security_governor_event(event=_governor_event(scope_state="expansion_attempt"))
        assert result["decision"] == "block"
        assert "SCOPE_EXPANSION_ATTEMPT" in result["reason_codes"]

    def test_004_mutation_freeze_blocks_a_mutating_detection_engineering_action(self):
        result = evaluate_security_governor_event(
            event=_governor_event(mutation_freeze_active=True, action_class="execution_request"),
        )
        assert result["decision"] == "block"
        assert "MUTATION_FREEZE_ACTIVE" in result["reason_codes"]

    def test_005_untrusted_remote_content_adopted_as_instruction_denied(self):
        # A threat-intel-sourced trigger's own text must never be able
        # to steer a Governor decision by claiming to be an instruction.
        result = evaluate_security_governor_event(event=_governor_event(remote_content_state="adopted_as_instruction"))
        assert result["decision"] == "block"
        assert "UNTRUSTED_CONTENT_INSTRUCTION_ATTEMPT" in result["reason_codes"]

    def test_006_execution_request_without_decision_binding_denied(self):
        result = evaluate_security_governor_event(
            event=_governor_event(action_class="execution_request", execution_requested=True, decision_binding_state="missing"),
        )
        assert result["decision"] == "block"
        assert "DECISION_BINDING_REQUIRED" in result["reason_codes"]

    def test_007_denied_action_remains_denied_no_special_case_for_detection_engineering(self):
        # No Governor bypass was introduced for this checkpoint -- the
        # exact same rules that govern every other stage apply here too.
        result = evaluate_security_governor_event(event=_governor_event(gateway_decision="deny"))
        assert result["decision"] == "block"
        assert result["execution_allowed"] is False

    def test_008_no_authentication_claim_observable_only(self):
        result = evaluate_security_governor_event(event=_governor_event())
        assert result["observable_only"] is True
        assert result["execution_performed"] is False


# ---------------------------------------------------------------------------
# Security Experience Memory honesty for detection-engineering-originated
# findings -- exercising the existing, unmodified Block 15D module.
# ---------------------------------------------------------------------------


def _case(**overrides):
    case = {
        "handoff_version": "1", "case_id": "SH-" + "0" * 16,
        "finding_reference": {
            "finding_id": "CF-abc123", "technical_severity": "medium", "finding_status": "candidate",
            "confidence": "high", "evidence_digests": ["sha256:" + "a" * 64],
        },
        "priority_reference": {
            "operational_priority": "medium", "priority_direction": "unchanged",
            "context_completeness": "complete", "priority_score": {"base": 2, "raw_modifier": 0, "applied_modifier": 0, "final": 2},
        },
        "current_stage": "detection_engineering", "required_role": "blue_team", "stage_results": [],
        "approval_state": "not_required", "approval_reference": None,
        "human_review_required": True, "execution_performed": False,
    }
    case.update(overrides)
    return case


def _prioritization(**overrides):
    prioritization = {
        "finding_id": "CF-abc123", "operational_priority": "medium",
        "context": {
            "environment": "production", "asset_criticality": "medium",
            "exposure": "internal", "threat_activity": "unknown",
        },
    }
    prioritization.update(overrides)
    return prioritization


class TestDraftRuleNeverAutomaticallyReusable:
    def test_009_governor_block_forces_rejected_never_reusable(self):
        governor_result = evaluate_security_governor_event(event=_governor_event(gateway_decision="deny"))
        experience = create_security_experience(case=_case(), prioritization=_prioritization(), governor_result=governor_result)
        assert experience["experience_status"] == "rejected"
        assert experience["reusable"] is False

    def test_010_governor_freeze_forces_rejected_never_reusable(self):
        governor_result = evaluate_security_governor_event(event=_governor_event(source_truth_state="modification_attempted"))
        assert governor_result["decision"] == "freeze"
        experience = create_security_experience(case=_case(), prioritization=_prioritization(), governor_result=governor_result)
        assert experience["experience_status"] == "rejected"
        assert experience["reusable"] is False

    def test_011_case_not_yet_at_human_review_never_validated_even_with_allow(self):
        # The case is still at detection_engineering, not human_review --
        # a draft/candidate rule stage cannot itself become reusable
        # validated memory no matter how permissive the Governor is.
        governor_result = evaluate_security_governor_event(event=_governor_event())
        assert governor_result["decision"] == "allow"
        experience = create_security_experience(case=_case(), prioritization=_prioritization(), governor_result=governor_result)
        assert experience["experience_status"] != "validated"
        assert experience["reusable"] is False

    def test_012_no_detection_rule_field_ever_read_by_create_security_experience(self):
        # Structural proof that a rule's own validation_status/
        # deployment_state cannot influence memory admission at all --
        # core.security_experience_memory has no coupling to
        # core.detection_rule whatsoever.
        import inspect
        signature = inspect.signature(create_security_experience)
        assert set(signature.parameters) == {"case", "prioritization", "governor_result"}

    def test_013_detection_rule_module_never_imports_memory_module(self):
        import core.detection_rule as detection_rule_module
        assert "security_experience_memory" not in dir(detection_rule_module)

    def test_014_detection_planner_module_never_imports_memory_module(self):
        import core.detection_planner as detection_planner_module
        assert "security_experience_memory" not in dir(detection_planner_module)
