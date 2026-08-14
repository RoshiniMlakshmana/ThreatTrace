# Block 15G-B — Nmap + Nuclei Tool Adapters

Status: implemented and validated. Not committed. As of Block 15G-B.2,
`nmap` 7.991 and `nuclei` v3.11.1 are installed, the `bug_bounty_assessment`
Governor gap is closed (§4 below, and `core.security_governor`'s own
"Governor operational stage vs. Security Handoff stage" docstring
section), and both adapters have completed real, successful live scans
against the local Juice Shop container via `execute_bug_bounty_tool`.

## 1. Purpose

Block 15G-A built the LLM Bug Bounty Planner and the Tool Permission
Policy, but left every tool_id except `http_assessor` unimplemented. Block
15G-B adds the first two real external-tool adapters — **Nmap** (bounded
TCP reconnaissance) and **Nuclei** (bounded, safe-profile known-pattern
scanning) — plus the single execution boundary
(`core.bug_bounty_tool_execution`) that is now the only place in the
codebase where either adapter can ever actually run.

```
Analyst
   |
LLM Bug Bounty Planner            (.claude/agents/bug-bounty-planner.md)
   |
Tool Permission Policy            (core.bug_bounty_tool_policy)
   |
Security Governor boundary        (core.security_governor -- supplied, not synthesized)
   |
Tool Adapter                      (core.bug_bounty_tool_execution)
   |-- HTTP Assessor               (existing, untouched, own orchestration path)
   |-- Nmap        <- NEW          (adapters.bug_bounty_nmap)
   +-- Nuclei      <- NEW          (adapters.bug_bounty_nuclei)
   |
Structured Tool Result
```

## 2. Analyst permission boundary

Unchanged from Block 15G-A. `core.bug_bounty_tool_execution` never
re-derives or trusts a caller-supplied permission boolean — it calls the
real, unmodified `core.bug_bounty_tool_policy.evaluate_tool_permission`
itself, exactly once per call, over the caller's own `permissions`/
`tool_request`. `analyst_permitted` and `profile_permitted` remain two
independent AND-ed gates; `nmap`/`nuclei` still require both an explicit
`allowed_tools` entry and a profile ceiling that includes them (`recon`
and above for `nmap`; `safe_dast` and above for `nuclei`).

## 3. Planner relationship

The LLM planner (`.claude/agents/bug-bounty-planner.md`) is unmodified by
this block. It still only *proposes* a structured plan — it has no tool
access beyond `Read`, never calls `execute_bug_bounty_tool`, and never
generates a raw command. Now that `nmap`/`nuclei` are `implemented: True`
in `TOOL_CATALOG`, a planner-proposed step using either tool can reach
`policy_status: "PERMITTED"` for the first time (previously always
`ADAPTER_UNAVAILABLE`) — but reaching `PERMITTED` in
`core.bug_bounty_planner`'s validation output still never executes
anything; it only means the *next* stage (this block's execution
boundary) is now capable of running it, given an explicit Governor
`allow`.

## 4. Governor gate

`core.bug_bounty_tool_execution.execute_bug_bounty_tool` requires a
caller-supplied `governor_result` shaped exactly like
`core.security_governor.evaluate_security_governor_event`'s own return
value (validated structurally — exact ten-field set, `decision` in the
real five-value vocabulary, `execution_allowed` a bool). Execution is
permitted only when `execution_allowed is True` **and** `decision` is not
one of `block`/`freeze`/`require_review`. Under the Governor's own real
semantics `execution_allowed` is `True` only when `decision == "allow"`,
so in practice this is equivalent to requiring `decision == "allow"`
outright; the module checks both explicitly rather than relying on that
invariant. **This module never calls `evaluate_security_governor_event`
itself and never fabricates a passing result** — the caller must already
have obtained one from a real Governor evaluation.

**Block 15G-B.2 update:** the first real end-to-end validation attempt
(against real, installed Nmap/Nuclei binaries) discovered that no
honestly-constructed Governor event for `actor_role: "bug_bounty"` could
ever pass — `core.security_governor`'s stage/role vocabulary had no
stage mapped to the `bug_bounty` role it already declared, so every such
event hit `STAGE_BYPASS_ATTEMPT`/`ROLE_SCOPE_VIOLATION` regardless of
being otherwise legitimate. Block 15G-B.2 closed this gap by adding a
`bug_bounty_assessment` **Governor operational stage** (→
`required_role: "bug_bounty"`) to `core.security_governor.STAGES`/
`REQUIRED_ROLE_BY_STAGE` — see that module's own docstring section
"Governor operational stage vs. Security Handoff stage" for the full
rationale. Nothing about approval, Decision Binding, mutation freeze,
scope, source-truth protection, the untrusted-remote-content boundary,
or audit requirements was changed or exempted for Bug Bounty — the gap
was purely "no stage existed to evaluate it under," not a missing
exemption.

## 5. Execution boundary

`core.bug_bounty_tool_execution.execute_bug_bounty_tool(*, permissions,
tool_request, governor_result, execution_config) -> dict` is the **only**
function in the codebase that can cause `adapters.bug_bounty_nmap` or
`adapters.bug_bounty_nuclei` to run. Flow, in order:

1. Validate `governor_result`'s shape and `execution_config`'s shape
   (structural — raises `BugBountyToolExecutionError` on failure).
2. Call the real `evaluate_tool_permission(permissions=..., tool_request=...)`
   (wraps `BugBountyToolPolicyError` as `BugBountyToolExecutionError` on
   structurally invalid input).
3. If `execution_permitted` is `False` → return `POLICY_DENIED`, no
   subprocess.
4. If the Governor does not allow → return `GOVERNOR_DENIED`, no
   subprocess.
5. If `tool_id` has no entry in the closed adapter registry → return
   `NO_ADAPTER_REGISTERED`, no subprocess.
6. Call the registered adapter. If it raises its own adapter-specific
   structural error (e.g. too many ports) → return
   `ADAPTER_REJECTED_REQUEST`, no subprocess.
7. Otherwise return the adapter's real structured result, with
   `execution_permitted: True`.

Every non-`True` path returns `tool_result: None` and
`execution_performed: False` — never raises for a normal denied outcome.

## 6. Closed adapter registry

```python
_ADAPTER_REGISTRY = MappingProxyType({
    "nmap": _run_nmap_adapter,
    "nuclei": _run_nuclei_adapter,
})
```

A fixed Python literal — never built from a `tool_id` string or any other
caller-supplied value, and immutable at runtime (`MappingProxyType`).
`http_assessor` is **deliberately not registered here**: its own existing
orchestration path (`core.bug_bounty_assessment` +
`adapters.bug_bounty_http`) is untouched by this block, and a policy-
permitted `http_assessor` request through this newer boundary resolves to
`NO_ADAPTER_REGISTERED` rather than silently falling through to a
different code path.

## 7. Nmap scope

`adapters.bug_bounty_nmap.run_nmap_scan` answers exactly: is one
analyst-approved host reachable through a requested, scoped TCP port
check, and what service/version does Nmap report for each open port? It
never performs discovery across a range, OS fingerprinting, NSE
scripting, or UDP scanning.

## 8. Nmap port restrictions

Exactly one bare host per invocation — no CIDR, no wildcard, no comma/
space-separated multiple hosts, no hostfile (`_validate_scan_target`
rejects all of these). At most `MAX_PORTS_PER_SCAN = 20` explicit ports
per invocation — never `-p-`, never a full range. This is enforced
*independently of and in addition to* whatever `core.bug_bounty_tool_policy`
already approved for the request's `ports`/`allowed_ports`, since the
policy layer bounds authorization, not per-invocation Nmap ergonomics.

## 9. Nmap XML parsing

The fixed command always requests `-oX -` (XML on stdout, per Nmap's own
documented recommendation for programmatic use); this adapter never
parses Nmap's human-readable terminal output. Parsing uses the standard
library's `xml.etree.ElementTree`; a malformed document is reported as
`status: "failed"`, never raised as an exception. Only `port`, `protocol`,
`state`, `service`, `product`, `version` are ever extracted; every
free-text field is bounded to 256 characters and redacted to
`"[REDACTED]"` if it contains a credential-like marker (`authorization:`,
`cookie:`, `api_key`, `password`, `bearer `, etc.).

## 10. Nmap limitations (v1, documented honestly)

- No NSE scripts, no OS detection, no UDP scanning, no timing/evasion
  flags beyond the fixed `-T3`.
- `-Pn` is always used (host discovery is skipped, host is treated as
  up) — chosen for determinism against containerized/local targets where
  ICMP may be filtered; this means an actually-unreachable host is only
  detected via each requested port's own `state`, not via a separate
  "host down" signal.
- `-sT` (TCP connect scan) is used rather than a raw-socket `-sS` SYN
  scan, so it does not require elevated privileges — also more
  deterministic across the mixed Windows/WSL/Docker environment this
  project runs in.
- `network_requests_performed` is always `None` — Nmap does not reliably
  report a packet/request count this project would treat as trustworthy.

## 11. Nuclei safe profile

`adapters.bug_bounty_nuclei.run_nuclei_scan` uses **one fixed, adapter-
controlled profile** — there is no `template_id`/`tags` parameter
anywhere in its signature, satisfying the spec's instruction that if
planner-selected template IDs cannot be safely allowlisted yet, a single
fixed safe profile must be used instead:

- Template directories: `http/` and `ssl/` only (`-t http/ -t ssl/`).
- `-etags fuzz` — fuzzing templates excluded.
- `-ni` — OAST/interactsh polling disabled.
- No `-headless`, `-code`/`-enable-code-templates`, `-secret-file`
  (authentication), `-cloud-upload`, or `-uncover` flag is ever passed —
  every one of those capabilities is opt-in in Nuclei itself, so simply
  never including the enabling flag keeps the invocation safe by
  omission.
- `-rl 10 -c 5` — fixed, conservative rate limit and concurrency (§15).
- `-jsonl -silent` — structured output only.

## 12. Nuclei template restrictions

Restricted to the `http/` and `ssl/` template directories only; `code/`,
`javascript/`, `file/`, `headless/`, and workflow-based aggressive chains
are never reachable because they are never passed as a `-t` argument and
no code path lets a caller add one.

## 13. Nuclei OAST disabled

`-ni` (`-no-interactsh`) is always present in the fixed command vector —
no interactsh/OAST callback server is ever configured or contacted.

## 14. Nuclei fuzzing disabled

`-etags fuzz` is always present — every template tagged `fuzz` is
excluded from the run, in addition to the `http/`/`ssl/` directory
restriction already excluding most non-HTTP fuzzing surfaces.

## 15. Rate limiting

`NUCLEI_RATE_LIMIT = 10` requests/second and `NUCLEI_CONCURRENCY = 5` —
both far below Nuclei's own higher defaults (150 rps / 25 concurrency),
chosen as a conservative value appropriate for a first integration
against a local, authorized target. Neither is caller-configurable;
raising either requires a future, explicitly-reviewed checkpoint.

## 16. Structured output

Nmap: XML via `-oX -`, parsed with `xml.etree.ElementTree`. Nuclei:
JSON-Lines via `-jsonl`, parsed line-by-line with `json.loads`; a
malformed individual line is skipped, never treated as a fatal error for
the whole scan. Neither adapter ever scrapes colorized/human-readable
terminal text.

## 17. Tool-not-installed behavior

Both adapters call `shutil.which("nmap"/"nuclei")` before ever
constructing a command. If the executable cannot be found — or if
launching it raises `OSError` even after being found (e.g. a stale PATH
entry) — the adapter returns `status: "tool_not_installed"`,
`execution_performed: False`, without ever calling `subprocess.run`.
Neither adapter downloads, installs, or falls back to any other command.

## 18. Timeouts

Each adapter enforces its own `process_timeout_seconds` ceiling
(`adapters.bug_bounty_nmap.MAX_PROCESS_TIMEOUT_SECONDS = 60`,
`adapters.bug_bounty_nuclei.MAX_PROCESS_TIMEOUT_SECONDS = 90` — Nuclei's
is slightly higher since even a bounded two-directory template run can
take longer than a <=20-port TCP connect scan). A caller may request a
lower value; requesting a higher one raises
`BugBountyNmapAdapterError`/`BugBountyNucleiAdapterError`
(`INVALID_EXECUTION_CONFIG`). `subprocess.run(..., timeout=...)` only
ever terminates the one child process this adapter itself started — no
other process is ever touched.

## 19. Output bounds

`MAX_OUTPUT_BYTES = 1_048_576` (1 MiB) for both adapters, with the same
caller-may-lower-never-raise rule. Captured stdout beyond
`max_output_bytes` is dropped before parsing and `output_truncated: True`
is reported. Raw stderr is never placed in `error_detail` or any other
result field — only a short, fixed, safe description string.

## 20. Evidence sanitation

Neither adapter ever stores raw stdout/stderr in its returned result —
the only trace of the captured output is a local SHA-256 content digest
in `evidence_references` (`nmap_xml_sha256:...` /
`nuclei_jsonl_sha256:...`), mirroring the local-content-correlation-
digest pattern documented in `adapters.bug_bounty_http`. Every free-text
field (`state`/`service`/`product`/`version` for Nmap;
`title`/`severity`/`matcher` for Nuclei) is bounded to 256 characters and
redacted to `"[REDACTED]"` if it contains a credential-like marker.
Nuclei's `classification` field only ever echoes `cve-id`/`cwe-id`
values Nuclei's own template metadata reported — neither adapter ever
invents a CVE/CWE identifier.

## 21. Tool observation semantics

Both adapters return a `tool_result_version: "1"` contract with
`tool_id`, `request_id`, `target`, `status` (`completed`/`failed`/
`tool_not_installed`/`timeout`), `observations`, `evidence_references`,
`network_requests_performed` (always `None`), `output_truncated`,
`error_detail`, `execution_performed`. `execution_performed` reflects
whether a real process was actually started (`True` even for a timed-out
process, since it was genuinely launched; `False` only when the
executable could not be found and no process was ever started) — it is
never a proxy for "found something."

## 22. Why results are not final findings

A Nmap/Nuclei tool result is a raw, sanitized *observation* — never a
canonical ThreatTrace finding. No correlation, deduplication, severity
re-scoring, or automatic promotion into `core.context_prioritization` (or
any other downstream consumer) happens anywhere in this block. Block
15G-D is explicitly reserved for an Evidence Normalizer + Finding
Correlator + Final Bug Bounty Report layer that would consume these tool
results; nothing in this block writes to it.

## 23. Juice Shop validation

Environment audit (`shutil.which` / PowerShell `Get-Command`, run before
any code was written): **neither `nmap` nor `nuclei` is installed** in
this development environment. No live scan was therefore performed
against `threattrace-juice-shop` (`127.0.0.1:3000`) — both adapters would
correctly report `status: "tool_not_installed"` if invoked here. All 131
adapter/execution-boundary tests use a mocked `subprocess.run`/
`shutil.which`, per the spec's explicit "no real external scan in unit
tests" instruction. No public target was ever referenced, configured, or
scanned anywhere in this block.

## 24. LLM does not execute commands

Unchanged guarantee from Block 15G-A, now reinforced by construction at
the execution layer too: `.claude/agents/bug-bounty-planner.md` has no
tool access beyond `Read`; `core.bug_bounty_planner` performs no I/O;
`core.bug_bounty_tool_execution` is a `core.*` module with zero LLM/MCP
access; only the two adapter modules perform subprocess I/O, and both
build their argument vectors exclusively from validated, structured,
non-caller-free-text fields (`target`, `ports`, `request_id`,
`execution_config`) — never from an LLM-generated string.

## 25. Security honesty

Verified by direct search of the new production diff (adapters + the new
core module):

- `subprocess` appears only in `adapters/bug_bounty_nmap.py` and
  `adapters/bug_bounty_nuclei.py`, always as `subprocess.run(argv,
  shell=False, ...)` with a list `argv` — never `shell=True`.
- No `os.system`, `eval(`, or `exec(` anywhere in the new files.
- No Nmap/Nuclei/ZAP/Burp invocation anywhere in `core/` — the only
  `core.*` module touched for execution
  (`core/bug_bounty_tool_execution.py`) never itself calls
  `subprocess`; it only calls the two adapters' public functions.
- No network scanning happens outside the two adapter modules — neither
  `core.bug_bounty_planner` nor `core.bug_bounty_tool_policy` was
  modified to perform any I/O (`core.bug_bounty_tool_policy` only had
  two `TOOL_CATALOG` boolean flags flipped).
- No database/Supabase/MCP import anywhere in any new or modified file.

## 26. Next step: correlation/report pipeline

Deferred to a future checkpoint (Block 15G-C/D):

- Real ZAP/Burp DAST adapters, authenticated testing, and controlled
  validation remain unimplemented (`TOOL_CATALOG` entries for `zap`,
  `burp_dast`, `authenticated_testing`, `controlled_validation` are still
  `implemented: False`).
- An Evidence Normalizer + Finding Correlator that turns raw Nmap/Nuclei
  `observations` (plus the existing `http_assessor` findings) into
  canonical ThreatTrace findings, and a Final Bug Bounty Report layer on
  top of that.
- Real, live-tool validation against the local Juice Shop container, once
  `nmap`/`nuclei` are actually installed in a development or CI
  environment — the honest `tool_not_installed` path exercised in this
  block should be re-verified against a real `status: "completed"` run
  at that point.
- Wiring `core.bug_bounty_tool_execution` into whatever orchestrator
  ultimately drives an end-to-end analyst-approved plan → execution
  loop (this block adds the boundary function itself, not its caller).
