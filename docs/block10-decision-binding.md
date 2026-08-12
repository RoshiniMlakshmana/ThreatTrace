# Block 10 — Decision Binding

**The Block 10 MVP is complete.** It is a stateless, deterministic, unsigned correlator that sits *after* Block 9: given an already-produced Block 9 identity-policy result and the exact proposed tool arguments, it produces a **Decision Binding** — a content correlation artifact that can later be checked, against a fresh Block 9 result and the arguments actually being presented, for exact agreement. Block 10 never runs Block 8 or Block 9 itself, never authenticates anyone, and never executes a tool, under any outcome.

## 1. Purpose

Blocks 8 and 9 can evaluate a proposed tool call and produce a policy decision — `allow`, `require_approval`, or `deny` — for a specific agent, tool, and argument set, at a specific moment. But that decision, on its own, is just a report. Nothing before Block 10 ties the decision to the *exact* arguments it was made for, in a way a later step can re-check.

Concretely, without Block 10, this substitution is undetectable by anything downstream of Block 9:

```
Evaluate:   tool = update_investigation_state, arguments = A   →  allow
Present later:   tool = update_investigation_state, arguments = B   →  (still "allowed"?)
```

If a policy decision for arguments `A` is silently reused, reinterpreted, or re-presented against different arguments `B`, nothing in Blocks 8/9 alone would catch the substitution — both decisions were genuinely `allow`, just for different content. Block 10 closes this gap by producing a deterministic, content-addressed correlation between the decision and the exact arguments it covers, so a later step can detect the mismatch.

**This is not authorization.** A Decision Binding does not decide whether a request is permitted — that already happened in Block 9. Block 10 only answers *does what I'm looking at right now still match what was originally decided?*

## 2. Architecture

```
Block 8 Agent Gateway (evaluate_tool_call)
        |
        v
Block 9 Agent Identity / Least Privilege (evaluate_agent_tool_call)
        |
        v
   [already-produced Block 9 result]
        |
        v
Decision Binding creation  (create_decision_binding)
        |
        v
   [unsigned Decision Binding, caller-held]
        |
        .  ... time passes; a fresh Block 9 evaluation is performed elsewhere ...
        |
        v
   [fresh Block 9 result]
        |
        v
Decision Binding verification  (verify_decision_binding)
        |
        v
   verification_outcome: "valid" | "invalid"
```

Block 10 **receives** an already-produced Block 9 result as a plain, duck-typed mapping — it never imports `core.agent_gateway` or `core.agent_identity_policy`, never calls either module's evaluation function, and never re-derives a `gateway_decision` or `final_decision` itself. Everything Block 10 knows about policy, it was told, once, by the caller.

Implemented components (nothing beyond this list exists for Block 10):

| File | Role |
|---|---|
| `core/decision_binding.py` | Pure creation/verification engine — `create_decision_binding`, `verify_decision_binding` |
| `tests/test_decision_binding.py` | Core engine tests (49 tests) |
| `core/decision_binding_cli.py` | Stdin/stdout JSON adapter around the two core functions |
| `tests/test_decision_binding_cli.py` | CLI adapter tests (27 tests) |
| `.claude/commands/create-decision-binding.md` | Creation-only Claude Code command wrapping the CLI |

There is no `verify-decision-binding.md` command and no Block 10 execution layer — both remain out of scope for this MVP.

## 3. Creation Contract

`create_decision_binding(*, identity_policy_result, arguments, issued_at, expires_at, approval_reference=None)` binds together, into one unsigned artifact:

- the caller-supplied Block 9 result's `canonical_agent_id`;
- `agent_role` — for any `allow`/`require_approval` result this must be non-null (the structural check requires it), so every `"created"` binding always carries a populated agent role alongside the canonical agent and tool;
- `canonical_tool_name`;
- `gateway_decision` (Block 8's own decision, read from the supplied result);
- `policy_decision` (Block 9's own `final_decision`, read from the supplied result);
- the exact proposed `arguments`, reduced to a canonical-JSON SHA-256 `argument_digest` — never the raw arguments themselves;
- an optional `approval_reference`;
- caller-supplied `issued_at`;
- caller-supplied `expires_at`.

The result always carries `binding_outcome`: either `"created"` or `"refused"`. A `"refused"` outcome is a **normal, deterministic evaluation result** — never an exception, never a CLI failure — reported through a fixed `refusal_reason.code` from `CREATION_REFUSAL_CODES` (9 fixed codes, checked in order, first match wins: a structurally invalid Block 9 result, a `final_decision` of `deny`, non-mapping or non-canonicalizable `arguments`, a blank/non-string `approval_reference`, a malformed `issued_at`/`expires_at`, `expires_at` not strictly after `issued_at`, or a requested lifetime exceeding the maximum).

The approved maximum binding lifetime is **300 seconds** (`MAX_BINDING_LIFETIME_SECONDS`) — `expires_at` more than 300 seconds after `issued_at` is refused (`LIFETIME_EXCEEDS_MAXIMUM`).

`issued_at` and `expires_at` are **entirely caller-supplied** (an aware `datetime` or aware ISO-8601 string). `core.decision_binding` performs **no clock read of any kind, anywhere** — there is no fallback, no default duration, and no internally generated timestamp in this module.

## 4. Verification Contract

`verify_decision_binding(*, binding, fresh_identity_policy_result, arguments, verification_time, approval_reference=None)` receives:

- the previously created Decision Binding;
- a **fresh, caller-supplied Block 9 identity-policy result** — Block 10 never re-runs Block 9 to obtain this; the caller must supply a genuinely re-evaluated result;
- the proposed `arguments` being checked, right now;
- a caller-supplied `verification_time`;
- the current `approval_reference`, when one was originally bound.

Verification accumulates every applicable rule from a fixed, 18-code `VERIFICATION_RULE_ORDER` (unlike creation, which stops at the first refusal, verification is a full report). The relevant correlation checks include:

- recomputing `binding_digest` from the binding's own stored fields (`BINDING_DIGEST_MISMATCH`);
- the bound canonical agent against the fresh result's canonical agent (`AGENT_MISMATCH`);
- the bound canonical tool against the fresh result's canonical tool (`TOOL_MISMATCH`);
- the bound `gateway_decision` against the fresh result's `gateway_decision` (`GATEWAY_DECISION_MISMATCH`) — checked **independently** of the final-decision check, since a fresh result could re-narrow `final_decision` without its `gateway_decision` changing, or vice versa;
- the bound `policy_decision` against the fresh result's `final_decision` (`POLICY_DECISION_MISMATCH`);
- the supplied `arguments`, re-digested, against the bound `argument_digest` (`ARGUMENT_DIGEST_MISMATCH`);
- the bound `approval_reference` against the one supplied for verification, only when one was originally bound (`APPROVAL_REFERENCE_CHANGED`);
- the binding's own `issued_at`/`expires_at` relationship and 300-second maximum lifetime;
- whether the binding has expired relative to `verification_time` (`BINDING_EXPIRED`).

`verification_outcome` is `"valid"` when no blocking rule matched, `"invalid"` otherwise. **`"valid"` means only that the supplied values correlate under this stateless, unsigned contract at this moment** — it does not mean the action is authorized, and it does not mean anything was, or will be, executed. Verifying the same still-valid binding twice always returns `"valid"` twice — this module keeps no state between calls, so it cannot and does not detect reuse.

## 5. Canonical Argument Hashing

Both `argument_digest` and `binding_digest` are computed by the same strict canonicalization routine:

- every mapping is recursively canonicalized, with every key required to be a string;
- every list is recursively canonicalized, element by element, in order — list order is significant;
- `bool`, `int`, `str`, and `None` pass through unchanged; `bool` and `int`/`str` are never conflated (`True` and `"True"` digest differently);
- `float` values are checked for `NaN`/`Infinity` and **refused** if present — never silently coerced;
- any other Python type (a `set`, a `tuple`, an arbitrary object) is **refused** as non-canonicalizable, rather than guessed at;
- the canonical form is serialized with `json.dumps(..., sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)` — sorted keys at every nesting level, compact separators, full UTF-8 (no `\uXXXX` escaping);
- the digest is `"sha256:" + hexdigest` of that UTF-8 text.

Caller-supplied `arguments` are never mutated by this process — canonicalization always builds a fresh structure and never edits the caller's own object in place.

`argument_digest` is an **unsigned SHA-256 content-correlation digest**. It proves that two argument sets are byte-for-byte equivalent after canonicalization — nothing about who produced them, whether they were authorized, or where they came from. It is not a cryptographic authorization primitive.

## 6. Binding Digest

`binding_digest` is computed over the canonical JSON of every *other* Decision Binding field — `decision_binding_version`, `binding_outcome`, `canonical_agent_id`, `agent_role`, `canonical_tool_name`, `gateway_decision`, `policy_decision`, `argument_digest`, `approval_reference`, `issued_at`, `expires_at` — explicitly **excluding `binding_digest` itself**. There is no circular hashing: the payload used to compute the digest never contains the digest field. Verification recomputes this exact same digest from the binding's own stored fields and compares it to the stored `binding_digest`.

**Trust limitation, stated plainly:** because the artifact is unsigned, a party who can see and reconstruct the binding's own plain field values can also recompute a matching `binding_digest` from scratch. Digest verification therefore detects an *accidental* or *ordinary* content mismatch reliably — it is **not** proof of trusted origin, and it is **not** resistant to a party deliberately constructing a self-consistent, forged artifact. This is a direct consequence of the deliberate design decision not to sign or HMAC the artifact in this MVP (see §8, §13).

## 7. Approval Reference

`approval_reference` is:

- optional (`None` is always valid);
- **opaque** — any non-blank string is accepted verbatim (`"approval-123"`, `"case-review-A"`, a UUID string, or any other non-blank string);
- rejected only when it is an empty string, a whitespace-only string, or a non-string value.

It is **never parsed, normalized, reformatted, or assumed to be a UUID**. Block 10 does not load, validate, or re-evaluate any Block 6 approval object — it only correlates the exact reference string supplied at creation against the one supplied at verification, when one was originally bound. If no reference was ever bound, a caller-supplied verification-time reference is never treated as a mismatch.

## 8. Trust Boundary / Security Honesty

Block 10 currently provides:

- deterministic, unsigned content correlation between a policy decision and exact proposed arguments;
- exact-argument mismatch detection (via canonical SHA-256 digesting);
- fresh-policy-result correlation (a stale or substituted Block 9 result is detected independently, on both `gateway_decision` and `final_decision`);
- bounded lifetime validation (300-second maximum, enforced both at creation and again at verification);
- stateless verification (no database, no cache, no in-process memory between calls).

Block 10 does **not** provide:

- agent authentication;
- authorization of any kind;
- execution permission;
- execution — no tool is ever executed by either function, under any outcome;
- signature or HMAC integrity;
- proof of trusted origin;
- tamper-proofing against a caller able to reconstruct a self-consistent unsigned artifact;
- one-time-use enforcement;
- replay prevention;
- nonce storage or any other replay state;
- database or file persistence — a Decision Binding exists only in the value returned to the caller;
- runtime enforcement of any kind.

Every result this module produces carries `identity_authenticated: False` and `execution_performed: False`; every verification result additionally carries `replay_protection_provided: False` — always, regardless of outcome.

This artifact is called a **Decision Binding**, and only that, throughout the codebase and this document. It is never called a capability token, a secure token, an authenticated token, execution authorization, or an execution permit.

## 9. CLI

`core/decision_binding_cli.py` is a thin stdin/stdout JSON adapter, invoked as:

```
py -m core.decision_binding_cli
```

It supports exactly two operations, selected by a top-level `"operation"` field in the JSON object read from stdin:

- `"create"` — five further fields: `identity_policy_result`, `arguments`, `issued_at`, `expires_at`, `approval_reference`;
- `"verify"` — five further fields: `binding`, `fresh_identity_policy_result`, `arguments`, `verification_time`, `approval_reference`.

Every field's value is passed to the corresponding core function unchanged — the CLI performs only envelope shape validation (unordered, set-based field-name checking; JSON key order never affects validity), never semantic validation of any field's content. Output is deterministic: `json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n"` to stdout, exactly once. There is no `argparse`, no command-line-argument input, no file input, and no network, database, Supabase, or MCP access anywhere in this module. Like the core it wraps, the CLI never reads the system clock — `issued_at`, `expires_at`, and `verification_time` are always caller-supplied.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Any successfully handled evaluation — includes `binding_outcome == "created"`, `binding_outcome == "refused"`, `verification_outcome == "valid"`, and `verification_outcome == "invalid"` alike. |
| `2` | A CLI input/envelope failure (malformed JSON, non-object top level, invalid/missing `operation`, or a missing/unknown field for the selected operation). |
| `1` | An unexpected internal failure. |

`refused` and `invalid` are **security evaluation outcomes**, not CLI processing errors — they are reported on exit `0`, exactly like `deny` is a normal, successful outcome in Blocks 8 and 9.

## 10. Claude Code Command

`/create-decision-binding` is **creation-only**. It:

- accepts the caller-supplied Block 9 result, exact arguments, explicit `issued_at`/`expires_at`, and an optional `approval_reference`, as one JSON object;
- validates only the envelope shape (exact field set present, no caller-supplied `operation`) — it performs no type or structural check on `identity_policy_result` or `arguments` beyond confirming each key is present, letting `core.decision_binding` produce its own graceful `refused` outcome (`INVALID_IDENTITY_RESULT_STRUCTURE` / `ARGUMENTS_NOT_A_MAPPING`) for a malformed value;
- constructs the exact CLI envelope, adding only the fixed literal `"operation": "create"`;
- invokes `core.decision_binding_cli` through stdin, exactly once;
- presents the returned result, labeling `argument_digest`/`binding_digest` explicitly as unsigned content-correlation digests, and stating plainly that no binding was persisted and nothing was executed.

It does **not**: run Block 8; run Block 9; execute a tool; authenticate an identity; persist anything; generate a timestamp of any kind; provide replay protection. `/verify-decision-binding` does not exist — verification has no Claude Code command in this MVP.

## 11. Example

1. A caller already holds a Block 9 result for agent `coordinator_agent`, tool `update_investigation_state`, decided `allow`, for arguments representing **state A**.
2. `/create-decision-binding` (or a direct `create_decision_binding` call) produces a Decision Binding — `binding_outcome: "created"` — binding that decision to the SHA-256 digest of state A.
3. Later, verification is invoked with:
   - a fresh Block 9 result matching the original agent, tool, `gateway_decision`, and `final_decision`;
   - arguments identical to state A.

   Result: `verification_outcome: "valid"`.
4. If, instead, one nested field inside the arguments differs from state A — even a single value changed one level deep — the recomputed argument digest no longer matches the bound one:

   Result: `verification_outcome: "invalid"`, with `ARGUMENT_DIGEST_MISMATCH` among the matched rules.

A `"valid"` outcome in step 3 does not execute `update_investigation_state`, does not authorize its execution, and does not itself trigger any further action — it only confirms that the arguments now being examined are the exact ones the original decision covered.

## 12. Tests and Validation

As committed:

- **`tests/test_decision_binding.py` — 49 tests**, covering creation success, canonicalization (key order, nesting, Unicode, numeric type distinctions, NaN/Infinity rejection, non-mutation), all 9 creation refusal codes, verification success and every verification rule (including the independent `GATEWAY_DECISION_MISMATCH` check, a dedicated populated-agent/tool `deny` structural case, and expiry-boundary behavior), and the honesty fields (`identity_authenticated`, `execution_performed`, `replay_protection_provided`) across every outcome.
- **`tests/test_decision_binding_cli.py` — 27 tests**, covering the adapter boundary specifically: envelope dispatch for both operations, key-order independence, exact pass-through of every field (verified by monkeypatching the core functions and inspecting captured kwargs), exit-code behavior for `created`/`refused`/`valid`/`invalid`/malformed input/unexpected failure, deterministic sorted output, and a structural check that the CLI module never imports Block 8, Block 9, the system clock, or any external system.
- **Bounded Block 8/9/10 regression — 118 tests** (`tests/test_agent_gateway.py` + `tests/test_agent_identity_policy.py` + `tests/test_decision_binding.py` + `tests/test_decision_binding_cli.py`), all passing together, confirming Block 10's addition did not disturb Block 8 or Block 9.

These counts reflect the repository as committed at the time this document was written; they are not projected or assumed.

## 13. Remaining Limitation / Future Hardening

**Replay protection is intentionally not provided by this stateless MVP.** Because `verify_decision_binding` keeps no state between calls, a still-valid, unsigned binding can be presented for verification any number of times within its lifetime window and will report `"valid"` every time. This is a deliberate, documented scope boundary for this MVP — not an oversight.

Possible future hardening, listed strictly as **future possibilities, not implemented, not currently planned or approved**:

- authenticated (not merely claimed) identity feeding Block 9, and by extension Block 10;
- signed or HMAC-protected Decision Binding artifacts, closing the "caller can reconstruct a self-consistent artifact" gap described in §6;
- a trusted issuance boundary (a component other than the caller minting the binding);
- stateful replay prevention (nonce/consumption tracking);
- an actual execution-boundary enforcement layer that consumes a `"valid"` verification result as a precondition for real execution — no such layer exists anywhere in the project today.

None of the above is implemented, and this document does not describe any partial implementation of them.
