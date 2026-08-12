"""Pure, deterministic Decision-to-Execution Binding correlator (Block 10).

This module answers one question only: *do these exact proposed tool
arguments, and this exact already-produced Block 9 identity-policy
decision, still agree with each other right now?* It never decides
whether a proposed tool call is itself permitted -- that remains
`core.agent_identity_policy.evaluate_agent_tool_call`'s (and, beneath
it, `core.agent_gateway.evaluate_tool_call`'s) own concern, consumed
here strictly as an already-produced result, never recomputed.

A Decision Binding is deliberately **unsigned**. SHA-256 is used here
only for deterministic content correlation -- detecting an ordinary or
accidental mismatch between what was originally decided and what is
being checked again later. A Decision Binding is NOT, and this module
never claims it to be:

- execution authorization;
- an execution permit;
- a capability token;
- an authenticated token;
- a secure token.

Because it is unsigned, anyone holding the binding's plain field values
can recompute a matching `binding_digest` -- this module never claims
tamper-proofing against a party who can see and reconstruct the
binding's own content. It provides no authentication, no cryptographic
origin verification, no authorization, no replay protection, and no
one-time-use enforcement; verifying the same still-valid binding twice
always returns the same `"valid"` outcome, since this module keeps no
state between calls.

This module does not:

- classify a tool, look up an agent, look up a role, evaluate a
  capability, evaluate an allowlist, or narrow a policy decision --
  every one of those remains `core.agent_identity_policy`'s and
  `core.agent_gateway`'s own concern. This module never imports either
  of those modules; it consumes only a plain, duck-typed mapping shaped
  like their already-produced result;
- execute the proposed tool, call MCP, construct SQL, or perform any
  I/O of any kind;
- read the system clock, an environment variable, or the filesystem;
- generate a random value of any kind;
- create, approve, reject, review, or consume an approval;
- retain any state between calls -- `create_decision_binding` and
  `verify_decision_binding` are each a single pure computation over
  their own arguments alone, and neither call has any memory of a
  previous call.

`create_decision_binding` and `verify_decision_binding` are this
module's only public functions. Neither ever raises an exception for a
structurally invalid or policy-refused input -- every such condition is
represented in the returned mapping through an explicit
`binding_outcome` / `verification_outcome` field instead, exactly like
`core.agent_gateway.evaluate_tool_call` represents an unknown tool
through `decision` rather than an exception. Both results always carry
`identity_authenticated: False` and `execution_performed: False`, and
`verify_decision_binding`'s result additionally always carries
`replay_protection_provided: False`.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

DECISION_BINDING_VERSION = "1"

# Maximum permitted lifetime of one Decision Binding, in seconds. Fixed by
# design; never accepted as a caller-supplied override.
MAX_BINDING_LIFETIME_SECONDS = 300

_FINAL_DECISIONS = frozenset({"allow", "require_approval", "deny"})
_CREATED_POLICY_DECISIONS = frozenset({"allow", "require_approval"})

# ---------------------------------------------------------------------------
# Fixed, closed creation-refusal vocabulary, checked in this exact order.
# Creation returns the single, first-matching refusal reason rather than an
# accumulated list -- creation is a single go/no-go gate, not a multi-rule
# report.
# ---------------------------------------------------------------------------

CREATION_REFUSAL_CODES = (
    "INVALID_IDENTITY_RESULT_STRUCTURE",
    "IDENTITY_RESULT_DENIED",
    "ARGUMENTS_NOT_A_MAPPING",
    "ARGUMENTS_NOT_CANONICALIZABLE",
    "INVALID_APPROVAL_REFERENCE",
    "INVALID_ISSUED_AT",
    "INVALID_EXPIRES_AT",
    "EXPIRY_NOT_AFTER_ISSUED",
    "LIFETIME_EXCEEDS_MAXIMUM",
)

_CREATION_REFUSAL_MESSAGE = MappingProxyType({
    "INVALID_IDENTITY_RESULT_STRUCTURE": (
        "identity_policy_result is not a structurally valid Block 9 identity-policy result."
    ),
    "IDENTITY_RESULT_DENIED": (
        "identity_policy_result's final_decision is deny; no binding can be created for a denied request."
    ),
    "ARGUMENTS_NOT_A_MAPPING": "arguments must be a mapping.",
    "ARGUMENTS_NOT_CANONICALIZABLE": (
        "arguments contains a value that cannot be canonically serialized "
        "(an unsupported type, a non-string object key, or a NaN/Infinity number)."
    ),
    "INVALID_APPROVAL_REFERENCE": "approval_reference must be a non-blank string when supplied.",
    "INVALID_ISSUED_AT": "issued_at must be an aware datetime or an aware ISO-8601 string.",
    "INVALID_EXPIRES_AT": "expires_at must be an aware datetime or an aware ISO-8601 string.",
    "EXPIRY_NOT_AFTER_ISSUED": "expires_at must be strictly after issued_at.",
    "LIFETIME_EXCEEDS_MAXIMUM": f"Binding lifetime must not exceed {MAX_BINDING_LIFETIME_SECONDS} seconds.",
})

# ---------------------------------------------------------------------------
# Fixed, closed verification rule vocabulary -- accumulated, like
# `core.agent_gateway.evaluate_tool_call`'s own `matched_rules`, rather than
# stopping at the first failure, so a caller sees every reason a binding is
# invalid at once.
# ---------------------------------------------------------------------------

VERIFICATION_RULE_ORDER = (
    "MALFORMED_BINDING",
    "MALFORMED_FRESH_IDENTITY_RESULT",
    "MALFORMED_ARGUMENTS",
    "MALFORMED_VERIFICATION_TIME",
    "BINDING_DIGEST_MISMATCH",
    "AGENT_MISMATCH",
    "TOOL_MISMATCH",
    "GATEWAY_DECISION_MISMATCH",
    "POLICY_DECISION_MISMATCH",
    "ARGUMENT_DIGEST_MISMATCH",
    "APPROVAL_REFERENCE_CHANGED",
    "ISSUED_EXPIRY_RELATIONSHIP_INVALID",
    "LIFETIME_EXCEEDS_MAXIMUM",
    "BINDING_EXPIRED",
    "BINDING_VALID",
    "CLAIMED_IDENTITY_NOT_AUTHENTICATED",
    "EXECUTION_NOT_PERFORMED",
    "REPLAY_PROTECTION_NOT_PROVIDED",
)

_BLOCKING_VERIFICATION_CODES = frozenset({
    "MALFORMED_BINDING",
    "MALFORMED_FRESH_IDENTITY_RESULT",
    "MALFORMED_ARGUMENTS",
    "MALFORMED_VERIFICATION_TIME",
    "BINDING_DIGEST_MISMATCH",
    "AGENT_MISMATCH",
    "TOOL_MISMATCH",
    "GATEWAY_DECISION_MISMATCH",
    "POLICY_DECISION_MISMATCH",
    "ARGUMENT_DIGEST_MISMATCH",
    "APPROVAL_REFERENCE_CHANGED",
    "ISSUED_EXPIRY_RELATIONSHIP_INVALID",
    "LIFETIME_EXCEEDS_MAXIMUM",
    "BINDING_EXPIRED",
})

_VERIFICATION_RULE_SEVERITY = MappingProxyType({
    code: ("blocking" if code in _BLOCKING_VERIFICATION_CODES else "informational")
    for code in VERIFICATION_RULE_ORDER
})

_VERIFICATION_RULE_MESSAGE = MappingProxyType({
    "MALFORMED_BINDING": "The supplied binding is not a structurally valid Decision Binding produced by this module.",
    "MALFORMED_FRESH_IDENTITY_RESULT": "The supplied fresh Block 9 identity-policy result is not structurally valid.",
    "MALFORMED_ARGUMENTS": "The supplied arguments could not be canonically serialized for comparison.",
    "MALFORMED_VERIFICATION_TIME": "verification_time must be an aware datetime or an aware ISO-8601 string.",
    "BINDING_DIGEST_MISMATCH": (
        "Recomputing binding_digest from the binding's own stored fields did not match the stored binding_digest."
    ),
    "AGENT_MISMATCH": "The bound canonical agent does not match the fresh Block 9 result's canonical agent.",
    "TOOL_MISMATCH": "The bound canonical tool does not match the fresh Block 9 result's canonical tool.",
    "GATEWAY_DECISION_MISMATCH": "The bound gateway decision does not match the fresh Block 9 result's gateway decision.",
    "POLICY_DECISION_MISMATCH": "The bound policy decision does not match the fresh Block 9 result's final decision.",
    "ARGUMENT_DIGEST_MISMATCH": "The supplied arguments do not recompute to the bound argument digest.",
    "APPROVAL_REFERENCE_CHANGED": (
        "The bound approval reference does not match the approval reference supplied for verification."
    ),
    "ISSUED_EXPIRY_RELATIONSHIP_INVALID": "The binding's own expires_at is not strictly after its own issued_at.",
    "LIFETIME_EXCEEDS_MAXIMUM": (
        f"The binding's own lifetime exceeds the maximum of {MAX_BINDING_LIFETIME_SECONDS} seconds."
    ),
    "BINDING_EXPIRED": "The binding has expired relative to the supplied verification_time.",
    "BINDING_VALID": "All correlation and freshness checks passed for the supplied verification_time.",
    "CLAIMED_IDENTITY_NOT_AUTHENTICATED": (
        "This verification never authenticates any identity; it only compares claimed, unsigned content."
    ),
    "EXECUTION_NOT_PERFORMED": "This verification only evaluates the binding. No tool was executed.",
    "REPLAY_PROTECTION_NOT_PROVIDED": (
        "This module performs no stateful replay tracking; a still-valid binding can be verified more than once."
    ),
})

_IDENTITY_RESULT_REQUIRED_FIELDS = (
    "canonical_agent_id",
    "agent_role",
    "canonical_tool_name",
    "gateway_decision",
    "final_decision",
    "identity_authenticated",
    "execution_performed",
)

_BINDING_REQUIRED_FIELDS = (
    "decision_binding_version",
    "binding_outcome",
    "canonical_agent_id",
    "agent_role",
    "canonical_tool_name",
    "gateway_decision",
    "policy_decision",
    "argument_digest",
    "approval_reference",
    "issued_at",
    "expires_at",
    "identity_authenticated",
    "execution_performed",
    "binding_digest",
)

# ---------------------------------------------------------------------------
# Deterministic canonical-JSON argument/binding digesting. Strict: it
# rejects a non-JSON-compatible value, a non-string object key, and a
# NaN/Infinity number rather than silently coercing any of them, and never
# mutates the value it is given.
# ---------------------------------------------------------------------------


class _CanonicalizationError(Exception):
    """Internal-only signal that a value could not be canonicalized."""


def _canonicalize(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise _CanonicalizationError("NaN and Infinity are not canonical JSON values")
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    if value is None:
        return None
    if isinstance(value, Mapping):
        canonical: dict[str, Any] = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise _CanonicalizationError("object keys must be strings")
            canonical[key] = _canonicalize(nested)
        return canonical
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    raise _CanonicalizationError(f"unsupported value type: {type(value).__name__}")


def _canonical_json_digest(value: Any) -> str | None:
    try:
        canonical = _canonicalize(value)
    except _CanonicalizationError:
        return None
    text = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Narrow, private input validators -- each module in this project owns its
# own copy of this exact validation shape rather than sharing one.
# ---------------------------------------------------------------------------


def _try_parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_optional_approval_reference(value: Any) -> tuple[bool, str | None]:
    """`approval_reference` is treated as an opaque identifier: any
    non-blank string is accepted verbatim. Block 10 does not consume any
    upstream object (e.g. a Block 6 approval record) whose contract would
    guarantee a UUID shape, so no such shape is required or assumed here.
    Whitespace is inspected only to reject a blank string -- the value
    itself is never stripped, reformatted, or otherwise reinterpreted.
    """
    if value is None:
        return True, None
    if not isinstance(value, str):
        return False, None
    if not value.strip():
        return False, None
    return True, value


def _extract_identity_policy_fields(value: Any) -> dict[str, Any] | None:
    """Structurally validate a claimed Block 9 identity-policy result.

    This only checks shape and type -- the exact fields
    `create_decision_binding`/`verify_decision_binding` themselves read --
    never a policy value's correctness. It never calls
    `core.agent_identity_policy` or `core.agent_gateway`; it accepts any
    duck-typed mapping with this shape.
    """
    if not isinstance(value, Mapping):
        return None
    for field in _IDENTITY_RESULT_REQUIRED_FIELDS:
        if field not in value:
            return None

    canonical_agent_id = value["canonical_agent_id"]
    agent_role = value["agent_role"]
    canonical_tool_name = value["canonical_tool_name"]
    gateway_decision = value["gateway_decision"]
    final_decision = value["final_decision"]
    identity_authenticated = value["identity_authenticated"]
    execution_performed = value["execution_performed"]

    if canonical_agent_id is not None and not isinstance(canonical_agent_id, str):
        return None
    if agent_role is not None and not isinstance(agent_role, str):
        return None
    if canonical_tool_name is not None and not isinstance(canonical_tool_name, str):
        return None
    if gateway_decision is not None and not isinstance(gateway_decision, str):
        return None
    if not isinstance(final_decision, str) or final_decision not in _FINAL_DECISIONS:
        return None
    if identity_authenticated is not False:
        return None
    if execution_performed is not False:
        return None

    if final_decision != "deny" and (
        canonical_agent_id is None or agent_role is None or canonical_tool_name is None
    ):
        return None

    return {
        "canonical_agent_id": canonical_agent_id,
        "agent_role": agent_role,
        "canonical_tool_name": canonical_tool_name,
        "gateway_decision": gateway_decision,
        "final_decision": final_decision,
    }


def _build_binding_payload(
    *,
    canonical_agent_id: str,
    agent_role: str,
    canonical_tool_name: str,
    gateway_decision: str,
    policy_decision: str,
    argument_digest: str,
    approval_reference: str | None,
    issued_at: str,
    expires_at: str,
) -> dict[str, Any]:
    return {
        "decision_binding_version": DECISION_BINDING_VERSION,
        "binding_outcome": "created",
        "canonical_agent_id": canonical_agent_id,
        "agent_role": agent_role,
        "canonical_tool_name": canonical_tool_name,
        "gateway_decision": gateway_decision,
        "policy_decision": policy_decision,
        "argument_digest": argument_digest,
        "approval_reference": approval_reference,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "identity_authenticated": False,
        "execution_performed": False,
    }


def _extract_binding_fields(value: Any) -> dict[str, Any] | None:
    """Structurally validate a claimed Decision Binding and recompute
    nothing -- it only extracts and type-checks the fields verification
    itself needs, including parsing `issued_at`/`expires_at` back into
    aware datetimes.
    """
    if not isinstance(value, Mapping):
        return None
    for field in _BINDING_REQUIRED_FIELDS:
        if field not in value:
            return None

    if value.get("decision_binding_version") != DECISION_BINDING_VERSION:
        return None
    if value.get("binding_outcome") != "created":
        return None

    canonical_agent_id = value["canonical_agent_id"]
    agent_role = value["agent_role"]
    canonical_tool_name = value["canonical_tool_name"]
    gateway_decision = value["gateway_decision"]
    policy_decision = value["policy_decision"]
    argument_digest = value["argument_digest"]
    approval_reference = value["approval_reference"]
    issued_at = value["issued_at"]
    expires_at = value["expires_at"]
    identity_authenticated = value["identity_authenticated"]
    execution_performed = value["execution_performed"]
    binding_digest = value["binding_digest"]

    for non_blank_field in (canonical_agent_id, agent_role, canonical_tool_name, gateway_decision):
        if not isinstance(non_blank_field, str) or not non_blank_field:
            return None
    if policy_decision not in _CREATED_POLICY_DECISIONS:
        return None
    if not isinstance(argument_digest, str) or not argument_digest.startswith("sha256:"):
        return None
    if approval_reference is not None and not isinstance(approval_reference, str):
        return None
    if not isinstance(issued_at, str) or not isinstance(expires_at, str):
        return None
    if identity_authenticated is not False:
        return None
    if execution_performed is not False:
        return None
    if not isinstance(binding_digest, str) or not binding_digest.startswith("sha256:"):
        return None

    issued_dt = _try_parse_timestamp(issued_at)
    if issued_dt is None:
        return None
    expires_dt = _try_parse_timestamp(expires_at)
    if expires_dt is None:
        return None

    return {
        "canonical_agent_id": canonical_agent_id,
        "agent_role": agent_role,
        "canonical_tool_name": canonical_tool_name,
        "gateway_decision": gateway_decision,
        "policy_decision": policy_decision,
        "argument_digest": argument_digest,
        "approval_reference": approval_reference,
        "issued_at": issued_at,
        "issued_dt": issued_dt,
        "expires_at": expires_at,
        "expires_dt": expires_dt,
        "binding_digest": binding_digest,
    }


def _recompute_binding_digest(binding_fields: Mapping[str, Any]) -> str | None:
    payload = _build_binding_payload(
        canonical_agent_id=binding_fields["canonical_agent_id"],
        agent_role=binding_fields["agent_role"],
        canonical_tool_name=binding_fields["canonical_tool_name"],
        gateway_decision=binding_fields["gateway_decision"],
        policy_decision=binding_fields["policy_decision"],
        argument_digest=binding_fields["argument_digest"],
        approval_reference=binding_fields["approval_reference"],
        issued_at=binding_fields["issued_at"],
        expires_at=binding_fields["expires_at"],
    )
    return _canonical_json_digest(payload)


def _refused(code: str) -> dict[str, Any]:
    return {
        "decision_binding_version": DECISION_BINDING_VERSION,
        "binding_outcome": "refused",
        "canonical_agent_id": None,
        "agent_role": None,
        "canonical_tool_name": None,
        "gateway_decision": None,
        "policy_decision": None,
        "argument_digest": None,
        "approval_reference": None,
        "issued_at": None,
        "expires_at": None,
        "binding_digest": None,
        "refusal_reason": {"code": code, "message": _CREATION_REFUSAL_MESSAGE[code]},
        "identity_authenticated": False,
        "execution_performed": False,
    }


def create_decision_binding(
    *,
    identity_policy_result: Any,
    arguments: Any,
    issued_at: Any,
    expires_at: Any,
    approval_reference: Any = None,
) -> dict[str, Any]:
    """Deterministically correlate one already-produced Block 9
    identity-policy result with the exact proposed tool arguments, an
    optional approval reference, and an explicit issued/expiry time
    window, into one unsigned Decision Binding.

    All parameters are keyword-only. `identity_policy_result` must be a
    mapping shaped like `core.agent_identity_policy.evaluate_agent_tool_call`'s
    own return value; this function never calls that function itself, never
    looks up an agent, and never reclassifies a tool -- `canonical_agent_id`,
    `agent_role`, `canonical_tool_name`, `gateway_decision`, and
    `final_decision` are read verbatim from it. `arguments` is the exact
    proposed tool arguments to bind by content, hashed with a strict
    canonical-JSON SHA-256 digest; it is never mutated and never echoed back
    in the result. `issued_at`/`expires_at` must each be an aware `datetime`
    or aware ISO-8601 string; this function never reads the system clock
    itself. `approval_reference`, if supplied, is treated as an opaque
    identifier and must be a non-blank string; it is never parsed,
    normalized, or reinterpreted.

    Returns a new dict containing exactly `decision_binding_version`,
    `binding_outcome` (`"created"` or `"refused"`), `canonical_agent_id`,
    `agent_role`, `canonical_tool_name`, `gateway_decision`,
    `policy_decision`, `argument_digest`, `approval_reference`, `issued_at`,
    `expires_at`, `binding_digest`, `refusal_reason`,
    `identity_authenticated` (always `False`), `execution_performed`
    (always `False`). On `"refused"`, every field except
    `decision_binding_version`, `binding_outcome`, `refusal_reason`,
    `identity_authenticated`, `execution_performed` is `None`.
    `binding_digest` is the SHA-256 digest of the canonical JSON of every
    other binding field -- never a digest of itself.

    Never raises for a structurally invalid or policy-refused input --
    creation refuses (via `refusal_reason`) when `identity_policy_result`
    is not structurally valid, represents a final `deny` decision,
    `arguments` is not a canonicalizable mapping, `approval_reference` is
    supplied but blank, `issued_at`/`expires_at` is malformed,
    `expires_at` is not strictly after `issued_at`, or the resulting
    lifetime exceeds `MAX_BINDING_LIFETIME_SECONDS`. `CREATION_REFUSAL_CODES`
    lists every possible `refusal_reason["code"]`, checked in that exact
    order, and creation reports only the first one that applies.
    """
    identity_fields = _extract_identity_policy_fields(identity_policy_result)
    if identity_fields is None:
        return _refused("INVALID_IDENTITY_RESULT_STRUCTURE")

    if identity_fields["final_decision"] == "deny":
        return _refused("IDENTITY_RESULT_DENIED")

    if not isinstance(arguments, Mapping):
        return _refused("ARGUMENTS_NOT_A_MAPPING")

    argument_digest = _canonical_json_digest(arguments)
    if argument_digest is None:
        return _refused("ARGUMENTS_NOT_CANONICALIZABLE")

    reference_ok, canonical_reference = _validate_optional_approval_reference(approval_reference)
    if not reference_ok:
        return _refused("INVALID_APPROVAL_REFERENCE")

    issued_dt = _try_parse_timestamp(issued_at)
    if issued_dt is None:
        return _refused("INVALID_ISSUED_AT")

    expires_dt = _try_parse_timestamp(expires_at)
    if expires_dt is None:
        return _refused("INVALID_EXPIRES_AT")

    if expires_dt <= issued_dt:
        return _refused("EXPIRY_NOT_AFTER_ISSUED")

    if (expires_dt - issued_dt).total_seconds() > MAX_BINDING_LIFETIME_SECONDS:
        return _refused("LIFETIME_EXCEEDS_MAXIMUM")

    payload = _build_binding_payload(
        canonical_agent_id=identity_fields["canonical_agent_id"],
        agent_role=identity_fields["agent_role"],
        canonical_tool_name=identity_fields["canonical_tool_name"],
        gateway_decision=identity_fields["gateway_decision"],
        policy_decision=identity_fields["final_decision"],
        argument_digest=argument_digest,
        approval_reference=canonical_reference,
        issued_at=_format_timestamp(issued_dt),
        expires_at=_format_timestamp(expires_dt),
    )

    result = dict(payload)
    result["binding_digest"] = _canonical_json_digest(payload)
    result["refusal_reason"] = None
    return result


def verify_decision_binding(
    *,
    binding: Any,
    fresh_identity_policy_result: Any,
    arguments: Any,
    verification_time: Any,
    approval_reference: Any = None,
) -> dict[str, Any]:
    """Deterministically verify one previously created Decision Binding
    against a freshly-produced Block 9 identity-policy result, the
    proposed arguments being checked again, an explicit verification
    time, and (if one was originally bound) the current approval
    reference.

    All parameters are keyword-only. `binding` must be a mapping shaped
    like `create_decision_binding`'s own `"created"` return value.
    `fresh_identity_policy_result` must be a mapping shaped like
    `core.agent_identity_policy.evaluate_agent_tool_call`'s own return
    value -- this function never calls that function, never
    re-evaluates policy, and never looks up an agent or tool itself; the
    caller alone is responsible for supplying an up-to-date result.
    `arguments` is hashed with the same strict canonical-JSON SHA-256
    digest `create_decision_binding` uses, and compared to the binding's
    own stored `argument_digest`. `verification_time` must be an aware
    `datetime` or aware ISO-8601 string; this function never reads the
    system clock itself.

    Returns a new dict containing exactly `decision_binding_version`,
    `verification_outcome` (`"valid"` or `"invalid"`), `canonical_agent_id`,
    `canonical_tool_name`, `policy_decision` (each read from the binding
    when it could be parsed, else `None`), `matched_verification_rules`,
    `verified_at`, `identity_authenticated` (always `False`),
    `execution_performed` (always `False`), `replay_protection_provided`
    (always `False`).

    `matched_verification_rules` accumulates every rule in
    `VERIFICATION_RULE_ORDER` that applies, in that fixed order -- unlike
    `create_decision_binding`, verification is a report, not a single
    go/no-go gate. At minimum this checks: the binding's own structure and
    version; recomputing `binding_digest` from the binding's own stored
    fields; the bound canonical agent/tool against the fresh Block 9
    result; the bound `gateway_decision` (Block 8's own decision) and the
    bound `policy_decision` (Block 9's own `final_decision`) each against
    their fresh Block 9 result counterpart -- two independent
    comparisons, since a fresh result could re-narrow `final_decision`
    without its `gateway_decision` changing, or vice versa, and this
    function never evaluates either value itself, only correlates what
    the caller supplies; the supplied `arguments` against the bound
    `argument_digest`; the bound `approval_reference` against the supplied
    one (only when one was originally bound); the binding's own
    issued/expiry relationship and maximum lifetime; and whether the
    binding has expired relative to `verification_time`.
    `verification_outcome` is `"invalid"` whenever any blocking rule
    matched, and `"valid"` otherwise. Never raises for any malformed input;
    a malformed `binding`, `fresh_identity_policy_result`, `arguments`, or
    `verification_time` is reported as an `"invalid"` outcome through
    `matched_verification_rules` instead.
    """
    matched_verification_rules: list[dict[str, Any]] = []

    def _emit(code: str) -> None:
        matched_verification_rules.append({
            "code": code,
            "severity": _VERIFICATION_RULE_SEVERITY[code],
            "message": _VERIFICATION_RULE_MESSAGE[code],
            "affects_decision": code in _BLOCKING_VERIFICATION_CODES,
        })

    def _emit_closing_rules() -> None:
        _emit("CLAIMED_IDENTITY_NOT_AUTHENTICATED")
        _emit("EXECUTION_NOT_PERFORMED")
        _emit("REPLAY_PROTECTION_NOT_PROVIDED")

    def _outcome() -> str:
        blocking = any(rule["code"] in _BLOCKING_VERIFICATION_CODES for rule in matched_verification_rules)
        return "invalid" if blocking else "valid"

    def _result(
        canonical_agent_id: str | None,
        canonical_tool_name: str | None,
        policy_decision: str | None,
        verified_at: str | None,
    ) -> dict[str, Any]:
        return {
            "decision_binding_version": DECISION_BINDING_VERSION,
            "verification_outcome": _outcome(),
            "canonical_agent_id": canonical_agent_id,
            "canonical_tool_name": canonical_tool_name,
            "policy_decision": policy_decision,
            "matched_verification_rules": matched_verification_rules,
            "verified_at": verified_at,
            "identity_authenticated": False,
            "execution_performed": False,
            "replay_protection_provided": False,
        }

    binding_fields = _extract_binding_fields(binding)
    if binding_fields is None:
        _emit("MALFORMED_BINDING")
        _emit_closing_rules()
        return _result(None, None, None, None)

    identity_fields = _extract_identity_policy_fields(fresh_identity_policy_result)

    fresh_argument_digest = None
    if isinstance(arguments, Mapping):
        fresh_argument_digest = _canonical_json_digest(arguments)

    verification_dt = _try_parse_timestamp(verification_time)

    if identity_fields is None:
        _emit("MALFORMED_FRESH_IDENTITY_RESULT")
    if fresh_argument_digest is None:
        _emit("MALFORMED_ARGUMENTS")
    if verification_dt is None:
        _emit("MALFORMED_VERIFICATION_TIME")

    if identity_fields is None or fresh_argument_digest is None or verification_dt is None:
        _emit_closing_rules()
        return _result(
            binding_fields["canonical_agent_id"],
            binding_fields["canonical_tool_name"],
            binding_fields["policy_decision"],
            None,
        )

    if _recompute_binding_digest(binding_fields) != binding_fields["binding_digest"]:
        _emit("BINDING_DIGEST_MISMATCH")

    if binding_fields["canonical_agent_id"] != identity_fields["canonical_agent_id"]:
        _emit("AGENT_MISMATCH")

    if binding_fields["canonical_tool_name"] != identity_fields["canonical_tool_name"]:
        _emit("TOOL_MISMATCH")

    if binding_fields["gateway_decision"] != identity_fields["gateway_decision"]:
        _emit("GATEWAY_DECISION_MISMATCH")

    if binding_fields["policy_decision"] != identity_fields["final_decision"]:
        _emit("POLICY_DECISION_MISMATCH")

    if binding_fields["argument_digest"] != fresh_argument_digest:
        _emit("ARGUMENT_DIGEST_MISMATCH")

    _, normalized_fresh_reference = _validate_optional_approval_reference(approval_reference)
    if approval_reference is not None and normalized_fresh_reference is None:
        # Supplied but blank: guaranteed not to equal any bound reference,
        # so this is always reported as a mismatch.
        normalized_fresh_reference = object()
    if (
        binding_fields["approval_reference"] is not None
        and binding_fields["approval_reference"] != normalized_fresh_reference
    ):
        _emit("APPROVAL_REFERENCE_CHANGED")

    if binding_fields["expires_dt"] <= binding_fields["issued_dt"]:
        _emit("ISSUED_EXPIRY_RELATIONSHIP_INVALID")

    if (binding_fields["expires_dt"] - binding_fields["issued_dt"]).total_seconds() > MAX_BINDING_LIFETIME_SECONDS:
        _emit("LIFETIME_EXCEEDS_MAXIMUM")

    if verification_dt >= binding_fields["expires_dt"]:
        _emit("BINDING_EXPIRED")

    if not any(rule["code"] in _BLOCKING_VERIFICATION_CODES for rule in matched_verification_rules):
        _emit("BINDING_VALID")

    _emit_closing_rules()

    return _result(
        binding_fields["canonical_agent_id"],
        binding_fields["canonical_tool_name"],
        binding_fields["policy_decision"],
        _format_timestamp(verification_dt),
    )
