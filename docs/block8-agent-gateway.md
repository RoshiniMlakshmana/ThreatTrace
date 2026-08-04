# Block 8 — AI Agent Gateway / Runtime Firewall

**The Block 8 MVP is complete.** It is a stateless, deterministic policy evaluator: given a proposed AI-agent tool call, it decides — before anything executes — whether that call may proceed, must go through approval, or is denied outright. It never executes the tool it evaluates. Actual execution, whatever form it eventually takes, remains a separate, independently controlled boundary this MVP never crosses.

## Problem and Purpose

An AI agent operating inside a system like ThreatTrace can propose a tool call that is unknown, over-privileged, state-mutating, schema-changing, a generic code/SQL execution path, an external side effect, structurally malformed, or an attempt to smuggle a caller-chosen policy outcome through an ordinary-looking argument. Left unchecked, any one of these can turn a helpful agent into an unsafe one.

Block 8 creates one deterministic boundary between four distinct moments:

1. an agent **proposes** a tool call;
2. **policy** decides whether it may proceed at all;
3. **approval** is required wherever the call actually mutates something;
4. a wholly separate **execution boundary** — never this MVP — is the only place anything real ever happens.

The policy decision itself is never made by an LLM. It is a fixed, closed rule set evaluated deterministically against a fixed, immutable tool registry — the same input always produces the same decision, forever.

## The Three-Layer Project Story

| Block | Question it answers |
|---|---|
| Block 6 | Is this sensitive action authorized? |
| Block 7 | What would this authorized action actually change? |
| Block 8 | May an AI agent even attempt this proposed tool call in the first place? |

```
agent proposes tool call
  → Block 8 evaluates policy
  → a mutation may require Block 6 approval
  → an approved case update may use the Block 7 preview
  → actual execution remains a separate boundary
```

Block 8 never automatically invokes Block 6 or Block 7 — `require_approval` only names the existing Block 6 workflow as the required next step; it never submits a request to it, and it never calls into Block 7's simulation engine.

## Architecture

```
Agent / Caller
    |
    v
/evaluate-tool-call
    |
    v
Pinned UTC evaluated_at
    |
    v
agent_gateway_cli
    |
    v
Pure evaluate_tool_call
    |
    +--> Immutable Tool Registry
    |
    +--> Argument Validation
    |
    +--> Fixed Policy Rules
    |
    v
Twelve-Field Decision Report
    |
    v
No Execution
```

- the caller supplies only a tool name and an argument mapping;
- `evaluated_at` is pinned once by the command boundary, never by the caller, and never read from the system clock by the engine itself;
- `operation_class` comes only from the fixed registry — never from the caller;
- the final `decision` comes only from the deterministic policy engine — never from the caller, and never from a model;
- the registry stores no callable, module path, import name, SQL template, or RPC function — nothing in this MVP can ever dynamically select or invoke code from caller input;
- no new database operation, table, RPC, or SQL template was added anywhere in this Block.

## Decision Vocabulary

| Decision | Meaning |
|---|---|
| `allow` | The recognized read-only request passed policy and may proceed only to a separate execution boundary. |
| `require_approval` | The recognized mutation passed structural policy but requires the separate, existing approval workflow first. |
| `deny` | The request is unknown, disabled, malformed, prohibited, schema-changing, generic-execution, or externally side-effecting. |

All three are equally valid, successful decision reports. `deny` is never a CLI transport failure. `require_approval` never creates an approval by itself. `allow` never executes the tool. `execution_performed` is `false` in every one of them, without exception.

## Operation Classes

Six fixed classes, mapped to policy deterministically:

| Operation class | Policy |
|---|---|
| `read_only` | `allow` |
| `state_mutation` | `require_approval` |
| `approval_mutation` | `require_approval` |
| `schema_mutation` | `deny` |
| `external_side_effect` | `deny` |
| `prohibited` | `deny` |

An unknown tool has no trusted operation class at all — it is denied outright, never assigned a class by inference or guesswork.

## Immutable Tool Registry

The registry is fixed in code, immutable, and composed of frozen entries. Matching is exact-name and case-sensitive, default-deny, alias-free, and fuzzy-match-free. No entry ever stores a callable, a module path, a SQL template, an RPC function, or a dynamic import target — only descriptive policy metadata.

| Tool | Policy |
|---|---|
| `load_risk_aware_approval_record` | allowed, read-only |
| `load_investigation_approval_context` | allowed, read-only |
| `apply_approval_consumption` | requires approval |
| `load_approval_record` | disabled (legacy) |
| `apply_migration` | denied — schema mutation |
| `execute_sql` | denied — generic execution |
| `run_evtx_analysis` | denied — external side effect |

Registry membership alone never executes or exposes the underlying tool — it is purely a policy classification.

## Argument Validation

Two independent validation levels:

**Command envelope validation** (`/evaluate-tool-call`) — exactly one tool-name token, exactly one JSON object, and one timestamp pinned by the command itself. The command layer never decides whether a tool is known, enabled, or policy-compliant.

**Engine policy validation** (`core.agent_gateway`) — arguments must be a mapping; keys must be strings; required fields must exist; unknown fields are denied; globally prohibited policy/control fields are denied; UUID-typed fields use canonical UUID validation; nested mappings and lists are rejected; strings longer than 4096 characters are rejected; a caller-chosen policy outcome supplied as an argument is always rejected, never silently accepted. Raw argument values are never echoed back in any report.

An arbitrary, attacker-controlled unknown argument name is represented only by the safe marker `<unknown>` — never echoed. A globally prohibited but well-known canonical field name (e.g. `risk_level`) may be listed safely, since it comes from this project's own fixed vocabulary, never from caller-controlled text. Malformed tool-specific arguments always produce a `deny` report — never an attempt to execute anything with partially valid input.

## Fixed Policy-Rule Order

Every evaluation walks this exact, fourteen-code order, and only ever emits the rules that actually apply:

1. `UNKNOWN_TOOL`
2. `TOOL_DISABLED`
3. `MALFORMED_ARGUMENTS`
4. `MISSING_ARGUMENT`
5. `UNKNOWN_ARGUMENT`
6. `PROHIBITED_ARGUMENT`
7. `SCHEMA_MUTATION_DENIED`
8. `GENERIC_SQL_TOOL_DENIED`
9. `EXTERNAL_SIDE_EFFECT_DENIED`
10. `MUTATION_REQUIRES_APPROVAL`
11. `APPROVAL_MUTATION_RESTRICTED`
12. `READ_ONLY_TOOL_ALLOWED`
13. `SENSITIVE_ARGUMENT_SUPPRESSED`
14. `EXECUTION_NOT_PERFORMED`

Every rule's message is a fixed constant — nothing is generated dynamically, and no LLM produces or reorders them. An earlier denial category always prevents a later `allow` or `require_approval` rule from ever appearing in the same report. `EXECUTION_NOT_PERFORMED` appears in every normal decision report, without exception.

## Result Contract

Every evaluation returns exactly twelve top-level fields:

1. `gateway_version`
2. `canonical_tool_name`
3. `operation_class`
4. `decision`
5. `eligible_for_execution`
6. `requires_approval`
7. `matched_rules`
8. `safe_argument_summary`
9. `blocked_argument_fields`
10. `required_next_action`
11. `evaluated_at`
12. `execution_performed`

`gateway_version` is always `"1"`. `execution_performed` is always `false`. The three decisions each carry one fixed, exact combination of the remaining fields:

| `decision` | `eligible_for_execution` | `requires_approval` | `required_next_action` |
|---|---|---|---|
| `allow` | `true` | `false` | `proceed_to_separate_execution_boundary` |
| `require_approval` | `false` | `true` | `submit_to_approval_workflow` |
| `deny` | `false` | `false` | `do_not_execute` |

A report that does not match this table exactly, or that is malformed, missing a field, or carries an extra field, always fails closed at the command boundary — it is never repaired, completed, or reinterpreted by hand.

## Safe-Output Controls

`safe_argument_summary` contains only the fixed markers `present`, `absent`, `redacted` — never an actual value. `blocked_argument_fields` contains only canonical, fixed, prohibited field names and/or the literal marker `<unknown>` — never an attacker-controlled field name. No report ever exposes a raw unknown tool name, a raw argument value, a UUID, SQL, migration content, a filesystem path, an authorization phrase, an identity, a credential, a token, an environment value, a descriptor, an MCP payload, an RPC parameter, a stack trace, or an exception class name.

## Policy Precedence

```
1. structurally invalid engine input   → AgentGatewayError
2. unknown tool                        → deny
3. disabled tool                       → deny
4. argument violation                  → deny
5. schema / prohibited / external-side-effect operation → deny
6. state or approval mutation          → require_approval
7. read-only operation                 → allow
```

The engine never falls back to execution at any stage. It never repairs a tool name through an alias or a case change, never silently removes an offending argument, never substitutes a different, known tool for the one actually named, and never retries a denied operation through generic SQL or a raw MCP call.

## Advisory Block 6 Integration

The MVP's approval integration is deliberately **advisory only**: a `require_approval` decision returns `required_next_action: submit_to_approval_workflow` and nothing more. The gateway itself never creates an approval, and `/request-case-update` is never automatically invoked. The underlying action must still independently satisfy every one of Block 6's own rules on its own merits — an existing approval never causes the gateway to execute a tool, and the gateway's `allow`/`require_approval` decision is never treated as Block 6 authorization by itself.

## Local Three-Decision Demonstration

A local, non-mutating demonstration exercised all three decisions end to end through the real `core.agent_gateway_cli` boundary — no Supabase, MCP, SQL, RPC, Hayabusa, approval workflow, or external process ever ran.

### Allow scenario

A recognized, read-only approval lookup produced `decision: allow`, matched rules `READ_ONLY_TOOL_ALLOWED` and `EXECUTION_NOT_PERFORMED`, in that order. No lookup was actually executed.

### Require-approval scenario

A recognized approval-mutating call produced `decision: require_approval`, matched rules `MUTATION_REQUIRES_APPROVAL`, `APPROVAL_MUTATION_RESTRICTED`, and `EXECUTION_NOT_PERFORMED`, in that order. No approval was created, and no mutation was executed.

### Deny scenario

A generic-SQL tool call produced `decision: deny`, matched rules `GENERIC_SQL_TOOL_DENIED`, `SENSITIVE_ARGUMENT_SUPPRESSED`, and `EXECUTION_NOT_PERFORMED`, in that order. The query value was redacted, and no SQL was executed.

Across all three: every report contained exactly twelve fields; every `evaluated_at` was a pinned, aware UTC value; `execution_performed` was `false` in every case; no requested tool, database call, MCP call, RPC, Hayabusa action, approval workflow, or external process ever executed; and the repository remained completely unchanged. The raw demonstration UUID, the raw query string, and any temporary file paths used are intentionally not reproduced here.

## Automated Verification

- **3,900+ automated tests** pass across the full project suite.
- **One test is intentionally skipped** on the current Windows environment: `tests/test_hayabusa_validation.py::test_evtx_symlink_rejected`, because symlink creation on this host requires additional permission or Developer Mode. This is an environment limitation, not a product defect.
- Coverage includes: immutable registry behavior; every `allow`/`require_approval`/`deny` decision path; default denial of unknown tools; denial of disabled tools; denial of schema-mutating and generic-SQL tools; denial of external-side-effect tools; the full argument-validation rule set; the fixed fourteen-rule ordering; safe-output suppression; deterministic, repeatable results; input nonmutation; the CLI's strict JSON envelope; the command's no-execution boundaries; and failure/no-fallback behavior at every layer.

## Presentation Walkthrough

1. Submit a recognized read-only lookup.
2. Show the `allow` decision.
3. Highlight `execution_performed: false`.
4. Submit a recognized mutation.
5. Show `require_approval` and its advisory next action.
6. Confirm no approval was created.
7. Submit a generic SQL request.
8. Show `deny` and its redacted arguments.
9. Show the fixed matched rules.
10. Explain that actual execution, whenever it happens, is a separate, independently controlled boundary this MVP never crosses.

## Limitations

- The gateway is advisory — it is not a harness-level interception mechanism that can physically prevent a tool call from happening; it is the trusted decision a calling command is expected to consult and obey.
- Decisions are stateless and are not persisted anywhere.
- No decision is cryptographically or otherwise bound to a later execution attempt.
- No cryptographic caller or agent identity is enforced anywhere in this MVP.
- Tool coverage is limited to the fixed, in-code registry — anything not registered is simply unknown and denied.
- No aliases are supported for any registered tool name.
- No external agent-orchestration integration exists yet.
- `require_approval` never automatically constructs or submits a Block 6 request.
- External-side-effect tools are denied outright in this MVP rather than conditionally allowed under any circumstance.
- No graphical dashboard exists yet; the interface remains command-driven.

## Next: Block 9 — Agent Identity and Least Privilege

Block 9 will focus on:

- canonical agent identities;
- agent roles;
- scoped tool capabilities;
- least-privilege permissions;
- per-agent tool allowlists;
- identity-aware policy decisions;
- separation of claimed and authenticated identity;
- safe capability-denial explanations.

Block 9 is not implemented as part of Block 8 or this document.
