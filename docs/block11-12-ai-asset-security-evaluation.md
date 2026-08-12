# Combined Block 11–12 — AI Asset Inventory, Provenance & Security Evaluation Lab

**The Combined Block 11–12 MVP is complete.** It is a pure, deterministic, local, read-only measurement layer with two coupled responsibilities: declaring what AI/security-agent-related assets exist in this repository (inventory/provenance), and observing whether an already-completed security primitive behaves as expected for one of those registered assets (security evaluation). It is not a production policy engine — Blocks 8, 9, the Emergency Mutation Freeze, and Block 10 remain the project's only production security-decision primitives, unmodified by this block.

## 1. Purpose

Blocks 11 (AI Asset Inventory & Provenance) and Block 12 (AI Security Evaluation Lab) were originally separate roadmap items but were deliberately merged into one MVP because the two concerns are directly coupled:

- **Inventory/provenance** answers: *what AI/security-agent-related assets are declared in this repository, and where?*
- **Evaluation** answers: *did a defined deterministic security property behave as expected for a registered asset?*

An evaluation case cannot be meaningfully expressed without referencing a stable, registered asset ID — the evaluation layer's own input contract is `case_type` + `asset_id`. Splitting inventory and evaluation into two independent blocks would have forced either a premature interface between two brand-new modules or duplicated asset-shape constants, for no real separation-of-concerns benefit. Merging them into one module keeps the coupling explicit and the implementation small.

## 2. Architecture

```
AI Asset Registry (core.ai_asset_registry)
        |
        +--> lookup_ai_asset(asset_id)   -----> inventory result
        |
        +--> list_ai_assets(asset_type)  -----> inventory listing
        |
        +--> evaluate_ai_security_case(case_type, asset_id)
                    |
                    v
        [calls the real, unmodified pure functions from:]
                    |
        Block 8 (core.agent_gateway.evaluate_tool_call)
        Block 9 (core.agent_identity_policy.evaluate_agent_tool_call)
        Emergency Mutation Freeze (core.mutation_freeze.evaluate_mutation_freeze)
        Block 10 (core.decision_binding.create_decision_binding / verify_decision_binding)
                    |
                    v
        observed evidence (real rule codes from the underlying block)
                    |
                    v
        evaluation_outcome: "pass" | "fail" | "not_applicable"
```

This block is **observational/measurement-oriented only**. It calls the real public functions of Blocks 8/9/10/Mutation-Freeze with real, valid, well-formed arguments and reports their real, unmodified results back — it never wraps, monkeypatches, or alters their contracts, and it introduces **no new production `allow`/`deny` gate**. It is not another production policy layer.

## 3. Implemented files

| File | Role |
|---|---|
| `core/ai_asset_registry.py` | Pure inventory + evaluation engine |
| `tests/test_ai_asset_registry.py` | Core tests (58 tests) |
| `core/ai_asset_registry_cli.py` | Stdin/stdout JSON adapter around the three core functions |
| `tests/test_ai_asset_registry_cli.py` | CLI adapter tests (34 tests) |
| `.claude/commands/ai-security-lab.md` | Claude Code command wrapping the CLI |
| `docs/block11-12-ai-asset-security-evaluation.md` | This document |

No other file exists for this block.

## 4. Actual asset inventory

Verified directly against the repository at implementation time — not assumed:

| Asset type | Count |
|---|---:|
| `gateway_tool` | 7 |
| `identity_agent` | 5 |
| `claude_subagent` | 2 |
| `claude_command` | 20 |
| `claude_skill` | 1 |
| `mcp_server` | 2 |
| **Total** | **37** |

**Correction note:** the earlier architecture audit (Step 1) initially reported 23 `claude_command` files and a total of 40 assets. Before implementing Checkpoint A, this was re-derived directly from the repository (`Glob` against `.claude/commands/*.md`, both flat and recursive) and found to be **20**, not 23 — a counting slip in that earlier audit, not an actual repository change (confirmed via `git log`/`git status` showing no relevant commits between the audit and implementation). The implemented registry uses the verified repository state throughout: **37 assets total**. The stale count of 40 does not appear anywhere in the implementation or in this document.

## 5. Asset contract

Every registered asset has exactly six fields: `asset_id`, `asset_type`, `name`, `declared_in`, `enabled`, `provenance`.

`asset_id` uses the stable, deterministic format `<asset_type>:<canonical_name>` — for example `identity_agent:observer_agent`, `gateway_tool:apply_approval_consumption`, `claude_subagent:purple-team`.

`enabled`:

- an **actual boolean** where the repository's own Block 8/9 registry data explicitly contains an `enabled` field (`gateway_tool` and `identity_agent` assets only — e.g. `gateway_tool:load_approval_record` and `identity_agent:disabled_agent` both correctly report `enabled: false`, matching their real, disabled registry entries);
- **`null`** for every other asset type (`claude_subagent`, `claude_command`, `claude_skill`, `mcp_server`) — none of these carries an authoritative enabled/disabled field anywhere in the repository, so `null` is reported rather than inferring `true` from mere file presence.

## 6. Provenance semantics

Every registered asset's `provenance` carries exactly one tier: `"repository_declared"`. This means, and only means: **this repository declares the asset at the stated location** — nothing more. It is never described as, and never means:

- authenticated provenance;
- verified runtime deployment state;
- cryptographically verified origin;
- signed provenance.

Checkpoint A deliberately did **not** invent versions, hashes, digests, timestamps, or exact model IDs for any asset. No such authoritative metadata exists for any of these 37 assets in this repository today — inventing one would have violated the project's established honesty discipline (the same discipline Block 10 applies to its own unsigned SHA-256 digests: never claim more than what is actually true).

## 7. Why there is no model/prompt inventory

A significant repository finding from the Step 1 audit, reconfirmed during implementation: **ThreatTrace's current Python core contains no live LLM/model-provider integration.** This is directly evidenced by `tests/test_decision_context.py`'s own negative-assertion tests (`assert "openai" not in source.lower()`, `assert "anthropic" not in source.lower()`) — leakage guards proving absence, not a hidden integration elsewhere. A repo-wide search for `prompt injection`, `jailbreak`, `guardrail`, and `excessive agency` returned zero hits anywhere in the repository, including documentation.

The `.claude/agents/*.md`, `.claude/commands/*.md`, and `.claude/skills/**/SKILL.md` files exist as real, checked-in repository/harness assets — and are inventoried as `claude_subagent`/`claude_command`/`claude_skill` — but there is no ThreatTrace **Python** prompt-to-model runtime surface anywhere that this project's own code executes. Because of this, this MVP does **not** invent first-class `model`, `llm`, `prompt`, or `guardrail` asset types — doing so would mean inventing an asset category with nothing real behind it.

## 8. Inventory API

`lookup_ai_asset(*, asset_id)` and `list_ai_assets(*, asset_type=None)` are both pure, deterministic, local functions operating over a fixed, in-code, `MappingProxyType`-frozen registry:

- no filesystem scanning, no Git calls, no clock reads, no environment reads, no network, no Supabase/database, no MCP, at runtime;
- a well-formed but unregistered `asset_id` returns `found: false` with every other field `null` — a normal result, never an exception;
- a malformed structural input (non-string/blank `asset_id`, an unrecognized `asset_type` filter) raises the typed `AIAssetRegistryError`.

## 9. Evaluation case types

Exactly five `case_type` values are supported, each observing exactly one already-completed security primitive:

| `case_type` | Observes |
|---|---|
| `unregistered_asset` | Block 8's `UNKNOWN_TOOL` / Block 9's `UNKNOWN_AGENT` denial of an unregistered tool or agent identifier |
| `identity_privilege_bypass` | Block 9's least-privilege allowlist denial for a known low-privilege agent requesting a tool outside its allowlist |
| `mutation_policy_bypass` | Block 8's mutation gate — a mutation-capable tool never resolving directly to `allow` |
| `emergency_freeze_bypass` | The Emergency Mutation Freeze's `MUTATION_FREEZE_ACTIVE` narrowing of an eligible mutation-capable request to `deny` |
| `decision_binding_substitution` | Block 10's `ARGUMENT_DIGEST_MISMATCH` detection of a substituted argument during verification |

Prompt injection, jailbreak, and excessive-agency case types are **not implemented** — per §7, there is no ThreatTrace prompt/model runtime surface for them to evaluate, and this MVP does not invent a vulnerable subsystem merely to have something to test.

## 10. Representative-case scope

**This is an explicit, deliberate MVP limitation, not an oversight.** Each of the four asset-scoped case types (`identity_privilege_bypass`, `mutation_policy_bypass`, `emergency_freeze_bypass`, `decision_binding_substitution`) evaluates exactly **one** deterministic, already-established reference scenario against exactly **one** canonical registered asset:

- `identity_privilege_bypass` → `identity_agent:observer_agent` only (the documented "observer allowlist denial" scenario from `docs/block9-agent-identity.md`);
- `mutation_policy_bypass` → `gateway_tool:apply_approval_consumption` only (the registry's one enabled `approval_mutation` tool);
- `emergency_freeze_bypass` and `decision_binding_substitution` → `identity_agent:coordinator_agent` only (the one registered agent whose mutation request reaches a bindable, `require_approval` decision).

Every other registered asset correctly returns `evaluation_outcome: "not_applicable"` for that case type. A passing case demonstrates **the defined property behaved correctly for that one representative scenario** — it does not mean every asset in the same category was exhaustively evaluated, and this document, the CLI, and the Claude command all state this explicitly rather than implying broader coverage.

## 11. Decision Binding substitution evaluation

`decision_binding_substitution` was corrected during implementation to keep the evaluated action and the bound action **exactly aligned**:

- one real registered tool, `apply_approval_consumption`, is evaluated through the real Block 9 path with its real, valid argument schema — exactly one field, `approval_id`;
- the **exact same** `{"approval_id": <fixed UUID>}` object used for that Block 9 evaluation is then bound via `create_decision_binding` — never a separately-constructed, richer object;
- verification substitutes a **second fixed, valid UUID** for `approval_id` (never a random one, never a nested structure the tool's real schema does not accept) and expects `verification_outcome: "invalid"` with `ARGUMENT_DIGEST_MISMATCH` present.

A nested synthetic argument was intentionally **not** used: `core.decision_binding`'s own 49 dedicated tests already prove nested-object canonicalization and nested-substitution detection exhaustively. For this merged evaluation lab, consistency between "what was actually evaluated" and "what was actually bound" is the more important property to demonstrate — bolting on an unrelated nested field only for the binding step would have weakened that end-to-end alignment without adding any coverage Block 10's own tests don't already provide.

## 12. Evaluation result contract

Every evaluation result contains exactly nine fields: `evaluation_version`, `case_type`, `asset_id`, `asset_found`, `evaluation_outcome`, `expected_property`, `observed_decision`, `observed_evidence`, `execution_performed`.

`evaluation_outcome` is restricted to exactly `pass`, `fail`, `not_applicable`. **`allow`, `require_approval`, and `deny` are production policy decisions and never appear as an `evaluation_outcome`** — they may only ever appear inside `observed_decision`, as evidence of a real, separately-observed Block 8/9 policy result (e.g. `observed_decision: "deny"` for `unregistered_asset`). `decision_binding_substitution` correctly leaves `observed_decision: null`, since its observed artifact is Block 10's own `verification_outcome` vocabulary (`"valid"`/`"invalid"`), a different concept never conflated with a policy decision.

## 13. Meaning of pass/fail/not_applicable

**`pass`** — the tested deterministic property behaved as expected.

**`fail`** — the tested property did not behave as expected. This is a valid, normal evaluation result, never an exception. Honestly: at the current validated repository state, every real, applicable deterministic security control behaves correctly, so neither the core nor the CLI test suite fabricates a genuine production-policy failure just to demonstrate `"fail"` — doing so would require monkeypatching a real Block 8/9/10/Mutation-Freeze function, which both test suites explicitly avoid for evaluation-case tests. The `"fail"` vocabulary remains fully present in the implementation and would surface immediately if a future change to any of those blocks introduced a real regression.

**`not_applicable`** — the requested registered asset does not participate meaningfully in the requested evaluation case (§10) — never a crash, never a fabricated pass or fail.

## 14. Relationship to completed security blocks

- **Block 8** provides Agent Gateway policy — *is this proposed tool call generally safe to consider at all?*
- **Block 9** provides claimed-identity, least-privilege narrowing on top of Block 8.
- **Emergency Mutation Freeze** provides a policy-evaluation-time administrative mutation-freeze narrowing on top of Block 9.
- **Block 10** provides exact-argument/policy-decision correlation (Decision Binding) between an already-produced policy result and later re-verification.
- **Combined Blocks 11–12** observe and measure those four controls, using registered assets as the unit of reference. This block does not replace, narrow, widen, or duplicate any of them — it only reports on what they already do.

## 15. Security honesty / limitations

A passing evaluation does **not** provide: AI safety certification; a guarantee of security; a real-world attack-prevention guarantee; authentication (of a model, prompt, or agent); execution; runtime enforcement; cryptographic provenance; model authenticity; or prompt authenticity. `execution_performed` is always `false` in every evaluation result this block can ever produce — no evaluation case ever executes a tool, calls MCP, calls Supabase, or performs any I/O. The evaluation lab runs deterministic, local, in-process evaluations only.

## 16. CLI

`core/ai_asset_registry_cli.py`, invoked as:

```
py -m core.ai_asset_registry_cli
```

Supports three operations via a top-level `"operation"` field: `lookup` (`{operation, asset_id}`), `list` (`{operation, asset_type}` — `asset_type` required, `null` or a supported type string), `evaluate` (`{operation, case_type, asset_id}`). JSON via stdin only; deterministic sorted JSON via stdout only; no `argparse`, no `sys.argv` parsing, no filesystem/network/database/Supabase/MCP access, no system-clock read. Exit `0` for every successfully handled outcome — including inventory `found: false` and evaluation `"fail"`/`"not_applicable"` — exit `2` for envelope/input validation failures (including the core's own typed `AIAssetRegistryError`), exit `1` for unexpected internal failures.

## 17. Claude command

`/ai-security-lab` is a thin, user-facing surface around `core.ai_asset_registry_cli` — it validates only the outer JSON envelope needed to invoke the CLI, sends the caller's input through stdin unchanged, and displays the CLI's own result. It adds no policy or evaluation semantics of its own, and explicitly labels inventory provenance as repository-declared (never verified/authenticated/cryptographic) and evaluation `"pass"` as meaning only that the tested property behaved as expected for that one defined case — never that ThreatTrace or any AI system is secure.

## 18. Tests

As committed and re-verified at the close of this checkpoint:

- **`tests/test_ai_asset_registry.py` — 58 tests** (inventory counts/lookup/listing/provenance/non-fabrication/non-aliasing, and all five evaluation case types' pass/not_applicable/cross-cutting behavior).
- **`tests/test_ai_asset_registry_cli.py` — 34 tests** (envelope dispatch for all three operations, exit-code behavior, structural no-external-access checks, and a check that the CLI never imports Blocks 8/9/10/Mutation-Freeze directly).
- **Core + CLI combined — 92 tests.**
- **Bounded regression** (`tests/test_agent_gateway.py` + `tests/test_agent_identity_policy.py` + `tests/test_decision_binding.py` + `tests/test_decision_binding_cli.py` + `tests/test_mutation_freeze.py` + `tests/test_ai_asset_registry.py` + `tests/test_ai_asset_registry_cli.py`) — **257 tests**, all passing together.

These counts reflect the repository as validated at the close of this checkpoint; they are not projected or assumed.

## 19. Future possibilities

Listed strictly as **future possibilities, not implemented, not currently planned or approved**:

- persistent inventory (a database/Supabase-backed store, rather than the fixed in-code registry);
- signed or otherwise cryptographically verified provenance;
- exact model/provider/version metadata, if and when such authoritative data actually exists for an asset;
- a prompt/model runtime inventory, if ThreatTrace ever gains an actual Python prompt-to-model execution surface;
- additional representative evaluation cases beyond the current five;
- broader per-asset coverage within each existing case type (evaluating every applicable agent/tool, not just one canonical scenario);
- evaluation history/trending over time.

None of the above is implemented, and this document does not describe any partial implementation of them.
