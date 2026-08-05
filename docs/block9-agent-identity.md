# Block 9 — Agent Identity and Least Privilege

**The Block 9 MVP is complete.** It is a stateless, deterministic identity-and-capability layer that sits on top of Block 8: given a claimed agent identity and a proposed tool call, it resolves that claim against a fixed, immutable registry, applies a fixed role and a fixed per-agent capability check, and narrows Block 8's own decision accordingly. Identity here is **claimed, never authenticated** — a registry match proves only that the caller typed a string equal to a known registry key, nothing more. The engine never executes a tool, under any decision, including `allow`. Actual execution, whatever form it eventually takes, remains a separate, independently controlled boundary this MVP never crosses.

## Problem and Purpose

Block 8 answers *is this proposed tool call generally safe to consider at all?* It does not answer *which agent is making this request*, or *does that specific claimed agent have the least-privilege capability to request it*. Without that second question, any caller able to name a recognized tool inherits whatever Block 8 itself would allow for that tool — regardless of who or what is actually asking.

Block 9 closes that gap for a defined set of risks:

- unknown claimed agents;
- disabled agents;
- caller-selected roles;
- caller-selected capabilities;
- tool-allowlist bypass;
- role operation-class bypass;
- mutation requests outside an agent's assigned capability;
- agent substitution;
- alias or letter-case confusion;
- attempts to override a Block 8 denial;
- an identity result mistaken for authentication;
- a policy result mistaken for execution.

No AI/LLM model decides agent identity, role, capability, tool permission, or the final policy outcome anywhere in this MVP. Every decision is a plain, deterministic comparison against fixed, in-code data — the same input always produces the same result, forever.

## The Four-Layer Project Story

| Block | Question it answers |
|---|---|
| Block 8 | May an AI agent even attempt this proposed tool call in the first place? |
| Block 9 | Does this specific claimed agent have the least-privilege capability to request that tool? |
| Block 6 | Is this sensitive case mutation authorized? |
| Block 7 | What would this authorized case update actually change? |

```
agent proposes tool call
  → Block 9 resolves claimed agent and capability
  → Block 8 classifies the proposed tool
  → Block 9 narrows the gateway outcome
  → a permitted mutation may require Block 6 approval
  → Block 7 may preview the approved change
  → actual execution remains a separate boundary
```

Implementation order is exact and one-directional:

1. Block 9 validates and resolves the claimed identity first.
2. Unknown and disabled claimed agents are denied **before** Block 8 is ever consulted.
3. Only a known, enabled claimed agent's request is evaluated through Block 8.
4. Block 9 applies role and capability narrowing to Block 8's own result afterward.

Block 9 never automatically invokes Block 6 or Block 7 — `require_approval` only names the existing Block 6 workflow as the required next step; it never submits a request to it, and it never calls into Block 7's simulation engine.

## Architecture

```
Agent / Caller
    |
    v
/evaluate-agent-tool-call
    |
    v
Claimed agent ID + tool + arguments
    |
    v
Pinned UTC evaluated_at
    |
    v
agent_identity_policy_cli
    |
    v
Pure evaluate_agent_tool_call
    |
    +--> Immutable Agent Registry
    |
    +--> Immutable Role Ceilings
    |
    +--> Block 8 evaluate_tool_call
    |
    +--> Agent Tool Allowlist
    |
    +--> Mutation-Request Capability
    |
    v
Fifteen-Field Identity-Aware Report
    |
    v
No Authentication
No Execution
```

- the caller supplies only a claimed agent ID, a tool name, and an argument mapping;
- `evaluated_at` is pinned once by the command boundary, never by the caller, and never read from the system clock by the engine itself;
- roles and capabilities come only from the fixed, in-code agent registry — never from the caller;
- tool classification, operation class, and the gateway decision come only from `core.agent_gateway.evaluate_tool_call`, called unchanged;
- the final decision comes only from deterministic policy — never from the caller, and never from a model;
- the registry stores no callable, module path, import target, SQL, RPC function, or secret — nothing in this MVP can ever dynamically select or invoke code from caller input;
- no new database operation, table, schema, migration, RPC, bridge, or adapter was added anywhere in this Block.

## Claimed Identity Is Not Authentication

`agent_id` is a caller-supplied string, nothing more. The registry performs **exact string resolution only** — trimmed of surrounding whitespace, case-sensitive, never casefolded, never aliased, never fuzzy-matched. `canonical_agent_id` in a report means only that the claimed value matched a fixed registry key exactly. `identity_authenticated` is always `false`, in every report this MVP can ever produce.

The system performs no:

- login;
- token validation;
- session validation;
- certificate validation;
- cryptographic verification;
- workload-identity check;
- identity-provider lookup.

**What registry resolution provides:** deterministic role assignment, deterministic capability assignment, a reproducible policy decision, and least-privilege restriction on top of Block 8 — with no caller-selected role or capability ever accepted.

**What it does not provide:** proof of who actually sent the request; proof that a genuine, running instance of that agent sent it; prevention of one caller claiming another registered agent's ID; cryptographic binding of any kind; a session identity; or an organizational ownership model.

Impersonation — one caller typing another registered agent's ID — remains an explicitly documented limitation of this MVP, not something this design claims to prevent.

## Fixed Roles

Exactly five roles exist:

- `observer`
- `analyst`
- `investigation_coordinator`
- `approval_reviewer`
- `disabled`

| Role | Permitted operation classes |
|---|---|
| `observer` | `read_only` |
| `analyst` | `read_only`, `state_mutation`, `approval_mutation` |
| `investigation_coordinator` | `read_only`, `state_mutation`, `approval_mutation` |
| `approval_reviewer` | `read_only` |
| `disabled` | none |

A mutation-permitting operation class is never *directly* allowed by role alone — a role that includes `state_mutation`/`approval_mutation` in its ceiling only makes a `require_approval` outcome reachable at all; whether it is actually preserved still depends on the specific agent's own `mutation_request_allowed` flag. No role, including a future one, may ever permit `schema_mutation`, `external_side_effect`, or `prohibited`, and no role can ever override a Block 8 `deny`. No `administrator` role exists in this MVP — every scenario the design needed is coverable by the five roles above, and an extra role is one more place a privilege escalation could accidentally be defined.

## Immutable Agent Registry

The registry is fixed in code, immutable, stored through `MappingProxyType`, composed of frozen dataclass entries, and uses `frozenset` for every capability set. Matching is exact-name, case-sensitive, trim-only, default-deny, alias-free, and fuzzy-match-free.

| Agent | Role | Enabled | Tool count | Mutation requests |
|---|---|---|---|---|
| `observer_agent` | `observer` | `true` | 1 | `false` |
| `analyst_agent` | `analyst` | `true` | 3 | `false` |
| `coordinator_agent` | `investigation_coordinator` | `true` | 3 | `true` |
| `reviewer_agent` | `approval_reviewer` | `true` | 2 | `false` |
| `disabled_agent` | `disabled` | `false` | 0 | `false` |

The complete per-agent tool allowlists are intentionally not published here — a caller can already ask, per request, whether a specific tool is permitted (`safe_capability_summary.requested_tool_allowed`), without this document or any report ever disclosing the full list.

These five synthetic IDs are demonstration policy identities only — fixed, functional, obviously synthetic names chosen to exercise the role/capability model, never real people, real teams, or authenticated services.

The registry stores no passwords, tokens, keys, certificates, secrets, authorization phrases, callables, module paths, import targets, SQL, RPC functions, or other executable references — only descriptive policy metadata.

## Combined Capability Model

A known, enabled claimed agent must pass **both**:

1. the agent's role operation-class ceiling permits the tool's operation class;
2. the tool is present in that specific agent's own canonical-tool allowlist.

When Block 8 itself returns `require_approval`, a third check also applies:

3. the specific agent's own `mutation_request_allowed` flag is `true`.

This combined model is deliberately stricter than either alternative alone. Role-only authorization would let any agent with a mutation-capable role reach every mutation-capable tool Block 8 ever registers, present or future — an unwanted default. Tool-allowlist-only authorization would let an allowlisted tool bypass a role's own operation-class ceiling entirely. Together:

- adding a new tool to Block 8's own registry never automatically grants it to any existing agent — it must be added to that agent's own allowlist explicitly;
- an allowlisted tool still cannot bypass its agent's role operation-class ceiling;
- a mutation-capable role still cannot submit a mutation request unless that specific agent's own `mutation_request_allowed` flag permits it.

## Integration with Block 8

Exact evaluation order:

1. structural identity-aware input validation;
2. exact agent-registry lookup;
3. unknown-agent short-circuit — denied without ever calling Block 8;
4. disabled-agent short-circuit — denied without ever calling Block 8;
5. a known, enabled claimed agent's request is evaluated through `core.agent_gateway.evaluate_tool_call` exactly once;
6. Block 9 consumes Block 8's own `canonical_tool_name`, `operation_class`, and `decision` verbatim;
7. the agent's role and per-agent capabilities narrow that result;
8. one combined identity-aware report is returned.

Block 9 never duplicates the Block 8 tool registry, never reclassifies a tool, never rebuilds Block 8's own policy rules, and can never widen what Block 8 already decided. Unknown and disabled claimed agents never receive `canonical_tool_name` or `operation_class` disclosure — a caller who cannot even resolve to a known agent learns nothing about whether the requested tool exists, is enabled, or what class it belongs to.

## Decision Vocabulary

| Final decision | Meaning |
|---|---|
| `allow` | Block 8 allowed the call and the known, enabled claimed agent passed both the role and tool-capability checks. It may proceed only to a separate execution boundary. |
| `require_approval` | Block 8 required approval and the known, enabled claimed agent is permitted to submit that mutation request. No approval is created automatically. |
| `deny` | Identity resolution, agent enablement, Block 8, the role ceiling, the tool allowlist, or the mutation-request policy prevented the request. |

All three are equally valid, successful policy reports. `deny` is never a CLI transport failure. `require_approval` never creates an approval. `allow` never executes the tool. No decision authenticates the caller. `execution_performed` remains `false` for every decision, without exception.

## Gateway-to-Final Monotonicity

| Block 8 gateway decision | Permitted Block 9 final decisions |
|---|---|
| `deny` | `deny` only |
| `require_approval` | `require_approval` or `deny` |
| `allow` | `allow` or `deny` |
| `null` (unknown/disabled agent) | `deny` only |

Block 9 may never promote:

- `deny` → `require_approval`;
- `deny` → `allow`;
- `require_approval` → `allow`.

Identity policy is strictly a narrowing layer on top of Block 8's own decision — never a privilege-expansion layer, under any circumstance.

## Fixed Identity-Rule Order

Every evaluation walks this exact, ten-code order, and only ever emits the rules that actually apply:

1. `UNKNOWN_AGENT`
2. `AGENT_DISABLED`
3. `GATEWAY_DENIED`
4. `OPERATION_CLASS_NOT_PERMITTED`
5. `TOOL_NOT_IN_AGENT_ALLOWLIST`
6. `MUTATION_REQUEST_NOT_PERMITTED`
7. `GATEWAY_APPROVAL_REQUIRED`
8. `IDENTITY_POLICY_ALLOWED`
9. `CLAIMED_IDENTITY_NOT_AUTHENTICATED`
10. `EXECUTION_NOT_PERFORMED`

Each rule carries a fixed severity, a fixed message, and a fixed decision-effect flag. No message ever interpolates a raw agent ID, tool name, argument value, SQL, path, or exception detail — every message is a constant string. Rules are deterministic and nothing here is generated, ranked, or worded dynamically by an LLM. Exactly ten rules exist — there is no invented eleventh rule anywhere in the committed engine. `EXECUTION_NOT_PERFORMED` appears in every normal report, without exception. `CLAIMED_IDENTITY_NOT_AUTHENTICATED` appears in every report for a known, enabled agent — never for an unknown or disabled one, since there is no resolved identity in those cases to caveat.

## Result Contract

Every evaluation returns exactly fifteen top-level fields:

1. `identity_policy_version`
2. `canonical_agent_id`
3. `agent_role`
4. `identity_authenticated`
5. `canonical_tool_name`
6. `operation_class`
7. `gateway_decision`
8. `final_decision`
9. `eligible_for_execution`
10. `requires_approval`
11. `matched_identity_rules`
12. `safe_capability_summary`
13. `required_next_action`
14. `evaluated_at`
15. `execution_performed`

`identity_policy_version` is always `"1"`. `identity_authenticated` is always `false`. `execution_performed` is always `false`. The three final decisions each carry one fixed, exact combination of the remaining fields:

### `allow`

- `eligible_for_execution` = `true`;
- `requires_approval` = `false`;
- `required_next_action` = `proceed_to_separate_execution_boundary`.

### `require_approval`

- `eligible_for_execution` = `false`;
- `requires_approval` = `true`;
- `required_next_action` = `submit_to_approval_workflow`.

### `deny`

- `eligible_for_execution` = `false`;
- `requires_approval` = `false`;
- `required_next_action` = `do_not_execute`.

A report that does not match this table exactly, that is malformed, missing a field, carries an extra field, or violates gateway-to-final monotonicity always fails closed at the command boundary — it is never repaired, completed, or reinterpreted by hand.

## Safe Capability Summary

`safe_capability_summary` contains exactly five fields:

- `role`;
- `requested_tool_allowed`;
- `requested_operation_class_permitted`;
- `mutation_request_allowed`;
- `allowed_tool_count`.

It reports only information relevant to the *current* request — never the complete tool allowlist and never a complete capability set. `allowed_tool_count` is a coarse integer count only, never a list of names. Unknown and disabled agents always receive a fixed summary of `null`/`false` values. `mutation_request_allowed` is `null` whenever the mutation-decision stage was never actually reached — for example, when an earlier role-ceiling or allowlist denial already made the flag irrelevant — so its presence or absence in a report is itself meaningful, not incidental.

## Structural Validation vs. Policy Denial

`AgentIdentityPolicyError` is raised only for structurally invalid input:

- a non-string claimed agent ID;
- a blank agent ID;
- an oversized agent ID;
- an agent ID containing prohibited control or executable-looking syntax;
- a non-string or blank tool name;
- non-mapping `arguments`;
- a malformed `evaluated_at`;
- a timezone-naive `evaluated_at`;
- a structural Block 8 validation error surfaced while evaluating a known, enabled agent's request.

Every other outcome is a normal, successful `deny` report, never an exception:

- an unknown agent;
- a disabled agent;
- a Block 8 denial;
- an operation class outside the role's ceiling;
- a tool outside the agent's allowlist;
- a mutation request the agent is not permitted to submit.

## Security and Safe-Output Controls

This MVP is structurally protected against:

- caller-selected roles;
- caller-selected capabilities;
- caller-selected enabled status;
- caller-selected authentication status;
- case-normalization privilege escalation (matching is case-sensitive, never casefolded);
- alias confusion (no alias table exists anywhere);
- agent substitution;
- an automatic fallback to `coordinator_agent` or any other more-privileged agent;
- role substitution;
- capability addition;
- tool substitution;
- overriding a Block 8 `deny`;
- mutation access without the specific agent's own permission;
- generic SQL, schema mutation, or external side effects (Block 8 already denies these unconditionally, and no role's ceiling ever includes them);
- LLM-generated authorization of any kind;
- a result mistaken for authentication;
- a result mistaken for execution.

No report ever exposes a raw unknown agent ID, raw `arguments`, a complete tool allowlist, a complete capability set, a secret, a credential, a token, a UUID value, SQL, a filesystem path, an authorization phrase, an environment value, a registry internal beyond the five safe `safe_capability_summary` fields, a descriptor, an MCP payload, an RPC parameter, a stack trace, or an exception class name.

## No-Retry and No-Fallback Behavior

After any denial or failure, this MVP never:

- retries automatically;
- alters the claimed agent ID's letter case;
- selects an alias;
- substitutes `coordinator_agent`, or any other registered agent, for the one the caller named;
- substitutes a more-privileged agent generally;
- enables a disabled agent;
- modifies a role;
- adds a capability the registry does not already grant;
- removes an argument;
- changes the requested tool;
- falls back directly to raw Block 8 as a bypass;
- switches to raw MCP;
- switches to direct or hand-written SQL;
- invokes Hayabusa;
- invokes an approval workflow automatically;
- manually executes the requested operation through any path.

## Advisory Block 6 Integration

`require_approval` returns `required_next_action: submit_to_approval_workflow` and nothing more. This is **advisory only**: no approval is created, `/request-case-update` is never automatically invoked, `/review-approval` is never automatically invoked, and `/apply-case-update` is never automatically invoked. Block 6 must still independently validate any future approval request entirely on its own rules. An existing approval never authenticates the claimed agent, and an existing approval never causes Block 9 to execute a tool.

## Local Five-Scenario Demonstration

A local, non-mutating demonstration exercised five identity-aware outcomes end to end through the real `core.agent_identity_policy_cli` boundary — no Supabase, MCP, SQL, RPC, Hayabusa, approval workflow, or external process ever ran, and no requested tool was ever executed.

### Analyst read-only allow

`analyst_agent` requested a permitted read-only lookup. Gateway decision `allow`, final decision `allow`. The identity policy allowed the request; the claimed identity remained unauthenticated throughout; the lookup itself was never executed.

### Observer allowlist denial

`observer_agent` requested a read-only tool outside its own allowlist. Gateway decision `allow`, final decision `deny`, with `TOOL_NOT_IN_AGENT_ALLOWLIST`. Block 9 narrowed Block 8's own `allow` to `deny`; no capability was added to widen it back; no tool was substituted; the lookup was never executed.

### Analyst mutation denial

`analyst_agent` requested a mutation it lacks the capability flag for. Gateway decision `require_approval`, final decision `deny`, with `MUTATION_REQUEST_NOT_PERMITTED`. No approval was created and no mutation was executed.

### Coordinator mutation request

`coordinator_agent` requested the same mutation, with its own `mutation_request_allowed` flag set. Gateway decision `require_approval`, final decision `require_approval`, with `GATEWAY_APPROVAL_REQUIRED`. No approval was created, no approval workflow was invoked, and no mutation was executed.

### Unknown claimed agent

An unregistered claimed agent ID requested a recognized tool. Gateway decision `null`, final decision `deny`, with `UNKNOWN_AGENT`. Block 8 was never reached; the raw unknown claimed identity was never disclosed in the report; no known agent was substituted in its place.

Across all five scenarios: every report contained exactly fifteen fields; every `safe_capability_summary` contained exactly five fields; each scenario used one separately pinned, aware UTC `evaluated_at` value; `identity_authenticated` was `false` in every report; `execution_performed` was `false` in every report; no raw demonstration UUID, no raw unknown agent ID, no arguments, no SQL, no path, no credential, no token, no full allowlist, and no registry internal appeared anywhere in any report; no authentication, session, approval, tool, database, or external operation occurred at any point; and the repository remained completely unchanged.

## Automated Verification

- **3,900+ automated tests** pass across the full project suite.
- **One test is intentionally skipped** on the current Windows environment: `tests/test_hayabusa_validation.py::test_evtx_symlink_rejected`, because symlink creation on this host requires additional permission or Developer Mode. This is an environment limitation, not a product defect.
- Coverage includes: the fixed role vocabulary; role-ceiling enforcement; the immutable agent registry; known-agent resolution; unknown-agent denial; disabled-agent denial; exact case-sensitive matching with no aliases; Block 8 integration; per-agent tool allowlists; operation-class restrictions; mutation-request restrictions; monotonic decision narrowing; the fixed ten-rule ordering; the fifteen-field output contract; the five-field safe capability summary; claimed-identity honesty; sensitive-output suppression; determinism; input nonmutation; the CLI's strict JSON envelope; command-level safety; and no-retry/no-fallback behavior at every layer.

## Presentation Walkthrough

1. Explain Block 8 versus Block 9 — general tool-call safety versus a specific claimed agent's least-privilege capability.
2. Submit `analyst_agent` with a permitted read-only request.
3. Show gateway `allow` and final `allow`.
4. Highlight `identity_authenticated: false`.
5. Highlight `execution_performed: false`.
6. Submit `observer_agent` with a read-only tool outside its allowlist.
7. Show Block 9 narrowing `allow` to `deny`.
8. Submit `analyst_agent` with a mutation.
9. Show `require_approval` narrowed to `deny`.
10. Submit `coordinator_agent` with the same mutation.
11. Show final `require_approval`, never a direct `allow`.
12. Confirm no approval was created.
13. Submit an unknown agent.
14. Show the gateway-related fields as `null` and the `UNKNOWN_AGENT` rule.
15. Explain that actual execution, whenever it happens, remains a separate, independently controlled boundary this MVP never crosses.

## Limitations

- Identity is claimed, not authenticated.
- A registered agent ID can be impersonated by any caller who knows or guesses it.
- The registry is static and lives in code — adding or changing an agent requires a code change.
- No sessions exist.
- No cryptographic binding exists between a claimed identity and a request.
- No signed requests exist.
- No workload identity exists.
- No external identity provider exists.
- Decisions are stateless.
- Decisions are not persisted anywhere.
- No execution binding exists between a decision and whatever happens afterward.
- No organization or user ownership model exists on top of agents.
- No database-backed identity audit trail exists in this MVP.
- Capability coverage is limited to whatever tools Block 8's own fixed registry already knows about.
- No aliases are supported for any registered agent ID.
- No graphical dashboard exists yet; the interface remains command-driven.

## Future Authentication Roadmap

The following are explicitly deferred and **not implemented** anywhere in this MVP:

- signed agent tokens;
- service identities;
- workload identity;
- short-lived credentials;
- certificate binding;
- request signing;
- key rotation;
- session expiry;
- external identity-provider integration;
- cryptographic decision-to-execution binding.

This document does not imply that any partial form of authentication currently exists — every item above remains future work, deliberately out of scope for this claim-based MVP.

## Next Block

Block 9 is complete. **Block 10** will begin with a separate, read-only architecture audit — its exact scope must be selected and confirmed before any implementation begins. This document does not invent or implement Block 10.
