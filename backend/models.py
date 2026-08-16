"""Pure, deterministic Run + Event contracts for the ThreatTrace Live
Platform backend (Block 15J-K).

This module performs no I/O of any kind -- no clock access, no network,
no filesystem, no randomness. Every timestamp is a required,
caller-supplied value (already captured by the caller's own clock),
exactly like every other timestamp-accepting function in this project
(`core.pipeline_orchestrator.measure_duration_minutes`,
`core.bug_bounty_evidence_normalization.normalize_bug_bounty_evidence`).

## Run history is in-memory runtime state, not an audit record

A `run` built here is a live progress snapshot for this backend
process's own lifetime only. It is never persisted, never a
tamper-evident audit trail (compare `core.tamper_evident_audit`, which
this module never imports or claims to be), and is lost entirely when
the backend restarts. `backend.run_store` is the only place a `run`
dict actually lives; this module only defines its shape and validates
transitions.

## Events never carry raw secrets or unbounded content

`build_event`'s `sanitized_payload` is deliberately bounded (see
`MAX_PAYLOAD_BYTES`) and defensively scanned for a fixed denylist of
key-name substrings (`cookie`, `token`, `authorization`, `password`,
`secret`, `api_key`, `apikey`, `credential`, `private_prompt`,
`chain_of_thought`) -- raised as `EVENT_PAYLOAD_FORBIDDEN_KEY` if any
nested key matches, case-insensitively. This is defense in depth: the
orchestrator that calls `build_event` is itself responsible for never
constructing a payload containing a raw HTTP body, cookie, token,
credential, private prompt, or chain-of-thought text in the first
place -- only bounded, already-summarized counts/ids/decisions ever
belong in a `sanitized_payload`.

## Local-only target policy lives here, not in `core.bug_bounty_scope`

`validate_local_only_target` is a Block 15J-K-specific policy layer
that this project's existing `core.bug_bounty_scope` deliberately does
not implement (that module supports any name-based origin an analyst
lists). For this checkpoint's live backend, every Bug Bounty run target
must resolve to exactly the hostname `"localhost"` -- not `127.0.0.1`
(a raw IP, already rejected by `core.bug_bounty_scope` itself in v1),
not any public or LAN hostname/IP, not `file://`/`ftp://`/`javascript:`.
This function never reaches into `core.bug_bounty_scope`'s own URL
parser; it owns a small, independent, conservative check, following
this project's established "each module owns its own copy of a shape
it shares in spirit with another module" convention.

`RunModelError`, `EventModelError`, `build_run`, `apply_run_transition`,
`build_event`, and `validate_local_only_target` are this module's
public symbols (plus its fixed vocabulary constants).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

RUN_MODEL_VERSION = "1"
EVENT_MODEL_VERSION = "1"

RUN_TYPES = frozenset({"bug_bounty", "detection"})

RUN_STATUSES = frozenset({
    "created",
    "planning",
    "awaiting_policy",
    "awaiting_governor",
    "running",
    "normalizing",
    "correlating",
    "prioritizing",
    "generating_detection",
    "awaiting_human_review",
    "completed",
    "blocked",
    "failed",
    "cancelled",
})

TERMINAL_STATUSES = frozenset({"completed", "blocked", "failed", "cancelled"})

EVENT_TYPES = frozenset({
    "run_created",
    "run_started",
    "planner_started",
    "planner_completed",
    "tool_policy_evaluated",
    "governor_evaluated",
    "tool_started",
    "tool_completed",
    "tool_failed",
    "http_assessment_completed",
    "evidence_normalized",
    "finding_correlated",
    "canonical_finding_created",
    "context_prioritization_started",
    "context_prioritized",
    "handoff_transition",
    "threat_intel_ingested",
    "threat_intel_normalized",
    "threat_intel_review_started",
    "threat_intel_review_completed",
    "threat_hunt_started",
    "threat_hunt_completed",
    "telemetry_evaluated",
    "detection_plan_created",
    "detection_rule_created",
    "detection_rule_validated",
    "detection_engineering_started",
    "detection_engineering_completed",
    "red_validation_started",
    "red_validation_completed",
    "purple_remediation_started",
    "purple_remediation_completed",
    "human_review_required",
    "human_review_recorded",
    "run_blocked",
    "run_failed",
    "run_cancelled",
    "run_completed",
})

STAGES = frozenset({
    "intake",
    "planning",
    "tool_policy",
    "governor",
    "tool_execution",
    "normalization",
    "correlation",
    "prioritization",
    "threat_intel",
    "threat_hunt",
    "detection_engineering",
    "red_validation",
    "purple_remediation",
    "human_review",
    "complete",
})

SOURCE_COMPONENTS = frozenset({
    "orchestrator",
    "bug_bounty_scope",
    "bug_bounty_tool_policy",
    "security_governor",
    "bug_bounty_assessment",
    "bug_bounty_crawler",
    "bug_bounty_evidence_normalization",
    "bug_bounty_finding_correlation",
    "bug_bounty_final_report",
    "threat_intelligence",
    "context_prioritization",
    "security_handoff",
    "bug_bounty_threat_intel_review",
    "bug_bounty_threat_hunt_review",
    "bug_bounty_purple_remediation",
    "security_experience_memory",
    "detection_trigger",
    "detection_telemetry",
    "detection_planner",
    "detection_rule",
    "detection_rule_deduplication",
    "detection_rule_validation",
    "detection_engineering_report",
})

MAX_SUMMARY_LENGTH = 300
MAX_PAYLOAD_BYTES = 8192

_FORBIDDEN_PAYLOAD_KEY_SUBSTRINGS = (
    "cookie", "token", "authorization", "password", "secret",
    "api_key", "apikey", "credential", "private_prompt", "chain_of_thought",
)

_RUN_FIELD_DEFAULTS: dict[str, Any] = {
    "target_summary": None,
    "current_stage": "created",
    "requested_tools": (),
    "permitted_tools": (),
    "executed_tools": (),
    "finding_count": 0,
    "canonical_finding_count": 0,
    "detection_trigger_count": 0,
    "rule_candidate_count": 0,
    "governor_decisions": (),
    "human_review_required": False,
    "limitations": (),
    "error_summary": None,
    "cancellation_requested": False,
    "report": None,
    "attack_surface": None,
    "lifecycle": None,
}

_RUN_MUTABLE_FIELDS = frozenset(_RUN_FIELD_DEFAULTS) | {"status", "current_stage", "started_at", "completed_at"}


class RunModelError(ValueError):
    """Raised when a supplied run-construction/transition input is
    structurally invalid.

    Every message begins with one of a fixed set of stable codes,
    including `INVALID_RUN_ID`, `INVALID_RUN_TYPE`, `INVALID_TIMESTAMP`,
    `INVALID_STATUS`, `INVALID_FIELD`, `TERMINAL_RUN`,
    `REENTER_CREATED`.

    Never raised because a run ends up `"blocked"`/`"failed"`/
    `"cancelled"`, or because zero findings/rules were produced -- every
    one of those is a normal, honestly-recorded outcome, never an error.
    """


class EventModelError(ValueError):
    """Raised when a supplied event-construction input is structurally
    invalid, including a `sanitized_payload` that is oversized, not
    JSON-serializable, or contains a forbidden key.

    Every message begins with one of a fixed set of stable codes,
    including `INVALID_RUN_ID`, `INVALID_EVENT_TYPE`, `INVALID_STAGE`,
    `INVALID_SOURCE_COMPONENT`, `INVALID_SUMMARY`, `INVALID_SEQUENCE`,
    `INVALID_TIMESTAMP`, `INVALID_PAYLOAD`, `PAYLOAD_TOO_LARGE`,
    `PAYLOAD_FORBIDDEN_KEY`.
    """


def _raise_run(code: str, detail: str) -> None:
    raise RunModelError(f"{code}: {detail}")


def _raise_event(code: str, detail: str) -> None:
    raise EventModelError(f"{code}: {detail}")


def _require_nonblank_string(value: Any, raiser: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raiser(code, f"{field_name!r} must be a non-blank string")
    return value


# ---------------------------------------------------------------------------
# Run contract
# ---------------------------------------------------------------------------


def build_run(*, run_id: Any, run_type: Any, created_at: Any) -> dict[str, Any]:
    """Deterministically build one new run record in status
    `"created"`. Performs no I/O; `created_at` must already have been
    captured by the caller's own clock.

    All parameters are required and keyword-only. `run_id` must be a
    non-blank string (the opaque identifier `backend.run_store` already
    generated -- this function never generates one itself). `run_type`
    must be one of `RUN_TYPES`.

    Returns a new dict containing exactly the run contract's fields:
    `run_model_version`, `run_id`, `run_type`, `created_at`,
    `started_at` (`None`), `completed_at` (`None`), `status`
    (`"created"`), `target_summary` (`None`), `current_stage`
    (`"created"`), `requested_tools`/`permitted_tools`/`executed_tools`
    (empty lists), `finding_count`/`canonical_finding_count`/
    `detection_trigger_count`/`rule_candidate_count` (`0`),
    `governor_decisions` (empty list), `human_review_required`
    (`False`), `limitations` (empty list), `error_summary` (`None`),
    `cancellation_requested` (`False`), `report` (`None`), `attack_surface`
    (`None`), `lifecycle` (`None` -- populated only for a Full Security
    Lifecycle run; a plain Bug-Bounty-only run never sets this).
    """
    validated_run_id = _require_nonblank_string(run_id, _raise_run, "INVALID_RUN_ID", "run_id")
    if not isinstance(run_type, str) or run_type not in RUN_TYPES:
        _raise_run("INVALID_RUN_TYPE", "run_type must be one of RUN_TYPES")
    validated_created_at = _require_nonblank_string(created_at, _raise_run, "INVALID_TIMESTAMP", "created_at")

    run: dict[str, Any] = {
        "run_model_version": RUN_MODEL_VERSION,
        "run_id": validated_run_id,
        "run_type": run_type,
        "created_at": validated_created_at,
        "started_at": None,
        "completed_at": None,
        "status": "created",
    }
    for field_name, default in _RUN_FIELD_DEFAULTS.items():
        run[field_name] = list(default) if isinstance(default, tuple) else default
    return run


def apply_run_transition(*, run: Any, new_status: Any, timestamp: Any = None, **field_updates: Any) -> dict[str, Any]:
    """Deterministically apply one status transition (plus optional
    field updates) to an already-built `run`, returning a **new** dict
    -- `run` itself is never mutated. Performs no I/O; `timestamp`, when
    supplied, must already have been captured by the caller's own clock.

    `run` must be a mapping shaped like `build_run`'s own return value.
    `new_status` must be one of `RUN_STATUSES`, and can never *re-enter*
    `"created"` from any other status (only `build_run` produces that
    status) -- however, passing `new_status="created"` while `run`'s
    current status is already `"created"` is allowed as a genuine no-op,
    specifically so `backend.run_store.RunStore.update_fields` can
    update fields (e.g. `cancellation_requested`) on a run the
    orchestrator's background thread has not yet picked up. A `run`
    whose current `status` is already terminal (see `TERMINAL_STATUSES`)
    can never be transitioned at all -- either violation raises
    `RunModelError` (`REENTER_CREATED`/`TERMINAL_RUN`). `timestamp` is optional; when
    `new_status` is `"running"` (the first non-planning/policy/governor
    execution status) it is commonly used by the caller to set
    `started_at`, and when `new_status` is terminal it is commonly used
    to set `completed_at` -- but this function never infers that
    itself; the caller must pass `started_at`/`completed_at` explicitly
    via `field_updates` if they want them set.

    `field_updates` may set any of `_RUN_MUTABLE_FIELDS` -- `run_id`,
    `run_type`, `run_model_version`, and `created_at` can never be
    changed after creation and raise `INVALID_FIELD` if supplied.

    Never raises because a run is being transitioned to `"blocked"`/
    `"failed"`/`"cancelled"`, or because `field_updates` records zero
    findings/rules -- every one of those is a normal, honestly-recorded
    outcome.
    """
    if not isinstance(run, Mapping):
        _raise_run("INVALID_RUN_ID", "run must be a mapping")

    current_status = run.get("status")
    if current_status in TERMINAL_STATUSES:
        _raise_run("TERMINAL_RUN", f"run is already in terminal status {current_status!r}")

    if not isinstance(new_status, str) or new_status not in RUN_STATUSES:
        _raise_run("INVALID_STATUS", "new_status must be one of RUN_STATUSES")
    if new_status == "created" and current_status != "created":
        _raise_run("REENTER_CREATED", "a run can never transition back into 'created'")

    for field_name in field_updates:
        if field_name not in _RUN_MUTABLE_FIELDS:
            _raise_run("INVALID_FIELD", f"{field_name!r} is not a mutable run field")

    updated = dict(run)
    updated["status"] = new_status
    for field_name, value in field_updates.items():
        updated[field_name] = value
    return updated


# ---------------------------------------------------------------------------
# Event contract
# ---------------------------------------------------------------------------


def _validate_sanitized_payload(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        _raise_event("INVALID_PAYLOAD", "sanitized_payload must be a mapping or None")

    try:
        serialized = json.dumps(value, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        _raise_event("INVALID_PAYLOAD", "sanitized_payload must be JSON-serializable")

    if len(serialized.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        _raise_event("PAYLOAD_TOO_LARGE", f"sanitized_payload exceeds {MAX_PAYLOAD_BYTES} bytes")

    def _scan_keys(node: Any) -> None:
        if isinstance(node, Mapping):
            for key, nested in node.items():
                key_lower = str(key).lower()
                if any(forbidden in key_lower for forbidden in _FORBIDDEN_PAYLOAD_KEY_SUBSTRINGS):
                    _raise_event("PAYLOAD_FORBIDDEN_KEY", f"sanitized_payload contains a forbidden key: {key!r}")
                _scan_keys(nested)
        elif isinstance(node, list):
            for item in node:
                _scan_keys(item)

    _scan_keys(value)
    return dict(value)


def build_event(
    *,
    run_id: Any,
    event_type: Any,
    sequence: Any,
    timestamp: Any,
    stage: Any,
    source_component: Any,
    summary: Any,
    sanitized_payload: Any = None,
) -> dict[str, Any]:
    """Deterministically build one structured event. Performs no I/O of
    any kind -- `sequence` must already have been assigned by the
    caller (see `backend.event_bus.EventBus.publish`, the only intended
    caller of this function), and `timestamp` must already have been
    captured by the caller's own clock.

    All parameters except `sanitized_payload` (default `None`, treated
    as `{}`) are required and keyword-only. `event_type` must be one of
    `EVENT_TYPES`. `sequence` must be a positive int. `stage` must be
    one of `STAGES`. `source_component` must be one of
    `SOURCE_COMPONENTS`. `summary` must be a non-blank string; it is
    truncated (never silently dropped) to `MAX_SUMMARY_LENGTH`
    characters with a trailing `"..."` marker if longer.
    `sanitized_payload`, when supplied, must be a JSON-serializable
    mapping no larger than `MAX_PAYLOAD_BYTES` once serialized, and must
    not contain any key matching the fixed denylist documented in the
    module docstring (checked recursively) -- raises `EventModelError`
    otherwise. This function never inspects payload *values* for
    secrets; only the caller constructing `sanitized_payload` is
    responsible for never including a raw HTTP body, cookie, token, API
    key, credential, private prompt, or chain-of-thought text in it.

    Returns a new dict containing exactly `event_model_version`,
    `event_id` (`f"EVT-{run_id}-{sequence}"` -- deterministic and
    unique per run, never random), `run_id`, `event_type`, `timestamp`,
    `sequence`, `stage`, `source_component`, `summary` (bounded),
    `sanitized_payload` (a new dict, independent of any input mapping).
    """
    validated_run_id = _require_nonblank_string(run_id, _raise_event, "INVALID_RUN_ID", "run_id")

    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        _raise_event("INVALID_EVENT_TYPE", "event_type must be one of EVENT_TYPES")

    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        _raise_event("INVALID_SEQUENCE", "sequence must be a positive int")

    validated_timestamp = _require_nonblank_string(timestamp, _raise_event, "INVALID_TIMESTAMP", "timestamp")

    if not isinstance(stage, str) or stage not in STAGES:
        _raise_event("INVALID_STAGE", "stage must be one of STAGES")

    if not isinstance(source_component, str) or source_component not in SOURCE_COMPONENTS:
        _raise_event("INVALID_SOURCE_COMPONENT", "source_component must be one of SOURCE_COMPONENTS")

    validated_summary = _require_nonblank_string(summary, _raise_event, "INVALID_SUMMARY", "summary")
    if len(validated_summary) > MAX_SUMMARY_LENGTH:
        validated_summary = validated_summary[: MAX_SUMMARY_LENGTH - 3] + "..."

    validated_payload = _validate_sanitized_payload(sanitized_payload)

    return {
        "event_model_version": EVENT_MODEL_VERSION,
        "event_id": f"EVT-{validated_run_id}-{sequence}",
        "run_id": validated_run_id,
        "event_type": event_type,
        "timestamp": validated_timestamp,
        "sequence": sequence,
        "stage": stage,
        "source_component": source_component,
        "summary": validated_summary,
        "sanitized_payload": validated_payload,
    }


# ---------------------------------------------------------------------------
# Local-only target policy
# ---------------------------------------------------------------------------

_ALLOWED_LOCAL_HOSTNAME = "localhost"
_ALLOWED_SCHEME = "http"


def validate_local_only_target(target: Any) -> str:
    """Deterministically confirm `target` is an `http://localhost[:port]/...`
    URL, and return it unchanged. Performs no I/O, no DNS resolution --
    only string parsing.

    Rejects (raises `RunModelError` with code `INVALID_TARGET`)
    anything else: a non-string/blank value, a non-`http` scheme
    (`https`, `file://`, `ftp://`, `javascript:`, ...), userinfo, a raw
    IP host (including the loopback IP `127.0.0.1` itself -- only the
    name `"localhost"` is accepted, matching `core.bug_bounty_scope`'s
    own v1 name-only-scoping limitation), any public or LAN hostname,
    or a fragment. This is a strictly *narrower* boundary than
    `core.bug_bounty_scope.create_bug_bounty_scope` (which accepts any
    well-formed name-based origin an analyst lists) -- this checkpoint's
    live backend only ever scans the local Juice Shop research
    container, never an analyst-chosen arbitrary target.
    """
    if not isinstance(target, str) or not target.strip():
        _raise_run("INVALID_TARGET", "target must be a non-blank string")

    try:
        parsed = urlsplit(target.strip())
    except ValueError:
        _raise_run("INVALID_TARGET", "target could not be parsed as a URL")

    if parsed.scheme.lower() != _ALLOWED_SCHEME:
        _raise_run("INVALID_TARGET", "target must use the 'http' scheme (local-only research target)")
    if "@" in parsed.netloc:
        _raise_run("INVALID_TARGET", "target must not contain userinfo")
    if parsed.fragment:
        _raise_run("INVALID_TARGET", "target must not contain a fragment")

    try:
        hostname = parsed.hostname
    except ValueError:
        hostname = None
        _raise_run("INVALID_TARGET", "target host could not be parsed")

    if not hostname or hostname.lower() != _ALLOWED_LOCAL_HOSTNAME:
        _raise_run(
            "INVALID_TARGET",
            "target host must be exactly 'localhost' -- this checkpoint's live backend never scans a "
            "public host, a LAN host/IP, or the raw loopback IP",
        )

    return target.strip()


# ---------------------------------------------------------------------------
# Demo target alias (self-hosted Docker deployment)
# ---------------------------------------------------------------------------

DEMO_TARGET_ENV_VAR = "THREATTRACE_DEMO_TARGET"
DEMO_TARGET_DISPLAY_ALIAS = "http://localhost:3000/"


def resolve_execution_target(*, display_target: str, env: Any = None) -> str:
    """Map the one fixed, hardcoded demo alias (`http://localhost:3000/`
    -- what a browser/user submits) to the real internal execution
    target the self-hosted Docker deployment actually needs to reach
    (`http://juice-shop:3000`, the Docker Compose service name),
    **only** when the operator has explicitly configured
    `THREATTRACE_DEMO_TARGET`. Performs no I/O -- pure string
    comparison.

    This function must only ever be called on a `display_target` that
    has *already* passed `validate_local_only_target` -- it never
    performs that check itself, and never weakens it. It is a strictly
    *narrower*, additive mapping on top of that already-enforced
    boundary: it recognizes exactly one fixed alias string, never an
    arbitrary hostname, and never a caller-supplied mapping. A
    `display_target` of any other shape (including any other
    `localhost` port) passes through unchanged.

    Absent `THREATTRACE_DEMO_TARGET` (the default -- host-native
    deployment, no Docker-network translation needed), this function is
    a pure no-op: it always returns `display_target` unchanged. This is
    the mechanism `docker-compose.yml`'s `threattrace` service uses
    (`THREATTRACE_DEMO_TARGET: "http://juice-shop:3000"`) to let a user
    open the dashboard, submit the familiar `http://localhost:3000/`
    they can also open directly in a browser, and have the backend
    actually reach the demo target by its real Docker DNS service name
    -- see `docs/docker-self-hosted-deployment.md` for the full
    display-target-vs-execution-target model.
    """
    active_env = env if env is not None else os.environ
    configured = (active_env.get(DEMO_TARGET_ENV_VAR) or "").strip()
    if not configured:
        return display_target
    if display_target.rstrip("/") != DEMO_TARGET_DISPLAY_ALIAS.rstrip("/"):
        return display_target
    return configured
