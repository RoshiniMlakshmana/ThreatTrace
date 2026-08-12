---
description: Look up or list declared AI assets, or run a deterministic security evaluation case against one, through the read-only AI Asset Registry / Security Evaluation Lab
argument-hint: "{operation: \"lookup\"|\"list\"|\"evaluate\", ...}"
---

# ThreatTrace AI Security Lab Workflow

`/ai-security-lab` is the Combined Block 11-12 AI Asset Inventory, Provenance & Security Evaluation Lab boundary. It answers two things only:

- *what AI/security-agent-related assets are declared in this repository, and where?* (`lookup` / `list`)
- *for one defined deterministic evaluation case, did the existing ThreatTrace security primitive behave as expected for this registered asset?* (`evaluate`)

by consulting the existing, already-committed, deterministic measurement layer (`core.ai_asset_registry`, reached only through `core.ai_asset_registry_cli`) — and nothing else. This command is strictly a transport adapter and is strictly a **reporting/evaluation surface**, never a production security gate:

Caller operation + inputs → command-level envelope validation → `core.ai_asset_registry_cli` → deterministic inventory or evaluation result

`/ai-security-lab` never authenticates a model, a prompt, or an agent; never cryptographically verifies provenance; never certifies AI safety; never executes an attack or a tool; never provides runtime enforcement; never guarantees attack prevention; never modifies the inventory or any policy; never persists an evaluation result; and never calls Supabase, MCP, or the network. `lookup`/`list`/`evaluate` are the only three operations this command ever performs, and every one of them is read-only.

## What This Lab Is — and Is Not

This lab is a **deterministic, local, read-only measurement layer** over already-completed security primitives. It is:

- **not** a production allow/deny policy engine;
- **not** an authorization layer;
- **not** an execution boundary;
- **not** an agent-authentication layer;
- **not** proof that a repository-declared asset matches what is actually deployed at runtime;
- **not** cryptographic or authenticated provenance of any kind — every inventory entry's provenance is `"repository_declared"` only, meaning this repository declares the asset at the stated location, nothing more;
- **not** an AI safety certification of any kind.

Block 8 (Agent Gateway), Block 9 (Agent Identity Policy), the Emergency Mutation Freeze, and Block 10 (Decision Binding) remain the project's only production security-decision primitives, unchanged and unmodified by this command. This lab only *observes* them.

## Evaluation Input

$ARGUMENTS

## Stage 0 — Command-Level Input Shape Validation

`$ARGUMENTS` must be exactly one JSON object. Perform every check below, in order, before Stage 1 — before any CLI invocation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one parsed JSON value.
4. Reject a top-level value that is not a JSON object.
5. Require an `"operation"` field equal to exactly `"lookup"`, `"list"`, or `"evaluate"`. Reject any other value, including a missing one.
6. For `"lookup"`: require exactly `operation`, `asset_id`. Reject a missing or extra field.
7. For `"list"`: require exactly `operation`, `asset_type`. `asset_type` is a required key whose value may be `null` or a string. Reject a missing or extra field.
8. For `"evaluate"`: require exactly `operation`, `case_type`, `asset_id`. Reject a missing or extra field.

This command performs **no semantic validation of `asset_id`, `asset_type`, or `case_type` beyond confirming the envelope has the right keys.** It never decides whether an `asset_id` is well-formed, whether an `asset_type` is one of the six recognized types, or whether a `case_type` is one of the five recognized evaluation cases — every one of those is always decided later, entirely by `core.ai_asset_registry`, reached only through `core.ai_asset_registry_cli`. Every value is passed through completely unchanged, never lowercased, trimmed-and-reinterpreted, or repaired.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Before continuing, confirm the selected launcher can import `core.ai_asset_registry_cli`. If no launcher can be selected, or the import check fails, stop and report `AI_SECURITY_LAB_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke the CLI through **stdin only**, exactly following the safe invocation pattern already established by `/evaluate-tool-call`, `/evaluate-agent-tool-call`, and `/create-decision-binding`. Never pass JSON through command-line arguments, never create a temporary JSON file, never interpolate caller content directly into executable shell code, and never write request data to disk.

## Stage 1 — Invoke the AI Asset Registry CLI

Send the caller's validated envelope through **stdin only**, completely unchanged (the exact same `operation`, and `asset_id`/`asset_type`/`case_type` fields the caller supplied, in any order), to `py -m core.ai_asset_registry_cli` (or the equivalent selected launcher). Never call `core.ai_asset_registry` directly, never call `core.agent_gateway`, `core.agent_identity_policy`, `core.mutation_freeze`, or `core.decision_binding` directly, and never reimplement any inventory or evaluation logic in this document — the CLI and the core it wraps already own that orchestration entirely.

### AI Asset Registry CLI exit handling

- **0**: success — the result is complete regardless of whether it is an inventory `found: true`/`found: false` result or an evaluation `"pass"`/`"fail"`/`"not_applicable"` outcome; all of these are normal, successful results. Continue to the output validation below.
- **2**: a deterministic command/CLI-envelope or core structural-validation failure — stop and report `AI_SECURITY_LAB_VALIDATION_FAILED`.
- **1**: an unexpected internal failure — stop and report `AI_SECURITY_LAB_INTERNAL_FAILURE`.
- **any other code**: stop and report `AI_SECURITY_LAB_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled result. A security evaluation `"fail"` is a **legitimate, successful evaluation result** — it means the tested property did not behave as expected, never that the CLI itself failed.

### AI Asset Registry CLI success-output validation

Require stdout to be exactly one JSON object.

For a `lookup`/`list` result, require exactly the fields `core.ai_asset_registry.lookup_ai_asset`/`list_ai_assets` always return (`inventory_version`, `asset_id`, `asset_type`, `found`, `name`, `enabled`, `declared_in`, `provenance` for `lookup`; `inventory_version`, `asset_type`, `count`, `assets` for `list`, where each entry in `assets` has the same shape as a `lookup` result).

For an `evaluate` result, require exactly the fields `core.ai_asset_registry.evaluate_ai_security_case` always returns: `evaluation_version`, `case_type`, `asset_id`, `asset_found`, `evaluation_outcome`, `expected_property`, `observed_decision`, `observed_evidence`, `execution_performed`. Require `evaluation_outcome` to be exactly one of `pass`, `fail`, `not_applicable` — never `allow`, `require_approval`, or `deny`; those values may only ever appear inside `observed_decision`, as evidence of a real, separately-observed Block 8/9 policy decision. Require `execution_performed` to equal exactly `false`.

If the result is missing a required field, contains an unrecognized field, has an `evaluation_outcome` outside the fixed three-value set, or has `execution_performed` other than `false`: stop, report `AI_SECURITY_LAB_VALIDATION_FAILED`, and never display the result as if it were successful. Do not repair, complete, or reinterpret a malformed result by hand.

Call the fully validated result the **AI security lab result**.

## Required Output

Produce, only after the AI security lab result passes every check above:

### For a `lookup` or `list` result

- Asset ID(s) and `asset_type`
- `found` (for `lookup`) or `count` (for `list`)
- `name`, `enabled`, `declared_in` for each asset
- Provenance, labeled explicitly as **"repository-declared provenance"** — meaning only that this repository declares the asset at the stated location. Never label it verified provenance, authenticated provenance, or cryptographic provenance, and never imply that a repository declaration equals actual runtime deployment state.
- When `found` is `false` (or `count` is `0`), state plainly that no such asset is currently registered — this is a normal result, never an error.

### For an `evaluate` result

Display:

- `case_type`
- `asset_id` and `asset_found`
- `evaluation_outcome`
- `expected_property`
- `observed_decision` (when not `null` — a real, separately-observed Block 8/9 policy decision, shown only as evidence, never as the evaluation's own outcome)
- `observed_evidence` (every item's `code`/`severity`/`message`, exactly as returned)
- **`execution_performed: false`**

State clearly, for every `evaluate` result regardless of outcome:

> "`pass` means only that the tested deterministic security property behaved as expected for this defined evaluation case. It does not mean ThreatTrace or any AI system is secure, that a model or prompt is authentic, that an attack is impossible, or that runtime enforcement occurred."

### When `evaluation_outcome` is `"fail"`

State clearly that the tested property did not behave as expected for this case — a normal, valid evaluation result, never a CLI or command failure. Display the same evidence as any other outcome. Never retry automatically, never substitute a different asset or case to force a `"pass"`.

### When `evaluation_outcome` is `"not_applicable"`

State clearly that the requested registered asset does not participate meaningfully in the requested case type — never a crash, never a fabricated pass or fail.

Never display:

- a raw exception message, exception class name, traceback, or internal stack detail;
- a claim that any asset's provenance was authenticated, verified, or cryptographically proven;
- a claim that a passing evaluation certifies AI safety, guarantees security, or guarantees real-world attack prevention;
- a claim that any tool, model, prompt, or agent was executed or authenticated by this command;
- a raw internal construction of the CLI command or its stdin envelope.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw exception message, exception class name, traceback, or internal detail in any of them.

### AI_SECURITY_LAB_CLI_UNAVAILABLE

The Python launcher or `core.ai_asset_registry_cli` import check failing before any stage below runs.

### AI_SECURITY_LAB_VALIDATION_FAILED

Stage 0 rejecting malformed JSON, non-object top-level JSON, an invalid/missing `operation`, or a missing/unknown envelope field for the selected operation; or Stage 1 reporting CLI exit code 2, or the CLI success-output validation failing.

### AI_SECURITY_LAB_INTERNAL_FAILURE

Stage 1 reporting CLI exit code 1 or any other unexpected code.

Do not automatically retry any failure in any category above.

## Security Boundaries

This command must never:

- authenticate a model, a prompt, or an agent, under any circumstance;
- cryptographically verify, sign, or HMAC any asset's provenance;
- describe inventory provenance as anything other than **repository-declared**;
- certify AI safety, guarantee security, or guarantee real-world attack prevention because an evaluation returned `"pass"`;
- execute an attack, a tool, or any external process;
- provide or claim runtime enforcement of any kind;
- modify the AI asset inventory, any registry, or any production policy;
- persist an evaluation result anywhere;
- call Supabase, MCP, or any database, directly or indirectly;
- make a network request of any kind;
- accept a caller-supplied `evaluation_outcome`, `observed_decision`, `observed_evidence`, `found`, `enabled`, `provenance`, or `execution_performed` as a command-level override;
- treat `evaluation_outcome: "fail"` as a command or CLI failure;
- treat `found: false` or `count: 0` as an error;
- reimplement any Block 8, Block 9, Emergency Mutation Freeze, Block 10, inventory, or evaluation-applicability rule of its own;
- imply that a repository declaration equals actual runtime deployment state.

The only process this command ever executes is the one committed, deterministic adapter: `py -m core.ai_asset_registry_cli` (or the equivalent selected launcher), invoked exactly once per command invocation.

## Example Invocations

```json
{"operation": "lookup", "asset_id": "identity_agent:coordinator_agent"}
```

```json
{"operation": "list", "asset_type": "gateway_tool"}
```

```json
{"operation": "evaluate", "case_type": "emergency_freeze_bypass", "asset_id": "identity_agent:coordinator_agent"}
```

## Safety Rules

- Accept exactly one JSON object with exactly the fields required for the selected `operation`. Never accept a caller-supplied override of any core-owned output field.
- Never call `core.ai_asset_registry`, `core.agent_gateway`, `core.agent_identity_policy`, `core.mutation_freeze`, or `core.decision_binding` directly — only `core.ai_asset_registry_cli`, exactly once.
- Never authenticate a model, prompt, or agent, and never describe a registry match or provenance record as authenticated, verified, or cryptographically proven.
- Never claim a passing evaluation certifies AI safety or guarantees real-world security.
- Never execute a tool, an attack, or any external process, under any evaluation outcome.
- Never modify the inventory, any policy, or persist any evaluation result.
- Never call Supabase, MCP, or the network.
- Never treat `"fail"` or `"not_applicable"` as a command failure, and never attempt a fallback to force `"pass"`.
- Never retry any stage automatically, and never fall back to a substitute asset or case after a failure.
- Never expose a raw exception message, exception class name, traceback, or internal detail.
