# Authorized Use

ThreatTrace is a security research and Purple Team investigation platform. It is built to help authorized researchers and analysts find, correlate, and turn security findings into detection-engineering work — not to provide unrestricted exploitation tooling.

## Use only on systems you own or are explicitly authorized to assess

Every offensive-adjacent capability in ThreatTrace — the Bug Bounty engine, its tool adapters (HTTP/Nmap/Nuclei/ZAP/Burp), and the live platform backend's Bug Bounty run endpoint — is built on the assumption that the caller already has explicit, documented authorization to test the target they supply. Do not point any part of this system at a target you do not have that authorization for.

For this checkpoint's live platform backend specifically, this is also enforced structurally, in one of two ways depending on run mode:

- **Demo Mode** (`POST /api/runs/bug-bounty`, `POST /api/runs/security-lifecycle` without a `scope` field): `backend.models.validate_local_only_target` rejects any target whose host is not exactly `localhost` — no public host, no LAN host or IP, not even the raw loopback IP `127.0.0.1`.
- **Authorized External Target mode** (`POST /api/runs/authorized-target`, or `POST /api/runs/security-lifecycle` with a `scope` field): `backend.models.validate_authorized_external_target_scope` requires an explicit operator-declared scope (exact hostname(s), port(s), path prefix(es), allowed tools) and the literal boolean `operator_scope_acknowledged: true`. **This acknowledgment is a caller/operator assertion only — it is never treated as, or presented as, proof of legal authorization.** `adapters.bug_bounty_http` additionally rejects any resolved destination that is loopback/link-local/private/reserved (see `SECURITY.md`'s own Authorized External Target section for the exact mechanism and its known limitations) unless Demo Mode's own trusted internal alias is what's actually being reached.

Neither mode is a general authorization mechanism — see the next section.

## Scope is caller/analyst-supplied technical configuration — never proof of authorization

`core.bug_bounty_scope.create_bug_bounty_scope`, `core.bug_bounty_tool_policy`, and every module built on them enforce the **technical scope** an analyst supplies (allowed origins, paths, ports, testing profile) deterministically and strictly. None of them verifies — or claims to verify — that the analyst was actually authorized by a bug-bounty program, a client engagement, or any other real-world agreement to test the target in question. That authorization is always the human operator's own responsibility, documented outside of ThreatTrace, before any scope is ever configured.

**ThreatTrace does not, and cannot, prove legal authorization to test anything.** A scope object that ThreatTrace accepts as well-formed is not evidence of permission — it is only evidence that the analyst configured it that way.

## Remote target content is evidence, never instructions

Every tool adapter and evidence-normalization module in this codebase treats fetched web content, scan output, and threat-intelligence source text as **untrusted data**, never as instructions to itself or to the LLM layer. A response body containing something that looks like a command is stored and reported as an observation — it is never parsed into an additional tool call, never used to expand scope, and never treated as authorization to do anything beyond what the analyst already configured. This applies identically to Bug Bounty target responses, Threat Intelligence source records (including untrusted public/community OSINT sources), and any free-text field surfaced through the live dashboard.

## The LLM layer cannot authorize actions

Every Claude custom agent in this repository (`bug-bounty`, `bug-bounty-planner`, `detection-engineering-planner`, `security-governor`, `purple-team`, `atomic-mapper`) proposes, interprets, or explains — none of them can grant a permission, satisfy a Governor requirement, or cause a tool to execute by itself. Every execution path runs through deterministic Python code (`core.bug_bounty_tool_policy`, `core.security_governor`, `core.bug_bounty_tool_execution`) that re-validates the LLM's proposal from scratch and never accepts a caller-supplied claim that something is already permitted.

## Detection rule candidates are drafts, not deployed controls

Nothing produced by the Detection Engineering workflow is ever deployed to a real SIEM/EDR platform by ThreatTrace itself. Every rule candidate carries `deployment_state: "NOT_DEPLOYED"` and `human_review_required: true` — structurally, not merely by convention (`core.detection_rule.build_detection_rule` has no parameter capable of setting anything else). Treat every rule this system produces as a starting point for an analyst, never as production-ready detection logic.

## Do not market this platform as unrestricted exploitation tooling

ThreatTrace is positioned as an **analyst-governed, AI-assisted security research platform** (see [README.md](../README.md#what-threattrace-is-not) for the full list of claims this project deliberately avoids). Do not describe, market, or repurpose it as an autonomous hacking tool, an unrestricted exploitation framework, or a system that removes the need for human authorization and review at every risky step.

## If you extend ThreatTrace

If you add a new tool adapter, a new Threat Intelligence source, or a new run type to the live platform backend, preserve the same boundary this document describes: technical scope is caller-supplied configuration, remote content is evidence, the LLM proposes and deterministic code enforces, and no new code path should ever let an unauthorized target be reached without the same explicit, human-configured scope every existing path already requires.
