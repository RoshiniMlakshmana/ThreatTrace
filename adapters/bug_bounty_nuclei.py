"""Real, bounded Nuclei safe-profile scanning adapter (Block 15G-B;
Nuclei Reliability Step 1 profile/reliability rework; Step 1B phased
architecture rework; Step 1C medium-coverage + technology-directed
rework).

## Step 1C: valuable medium coverage + live technology-aware selection

Step 1B measured that `http/exposures/` at medium severity alone (140
templates) takes **~66.24s real** -- much heavier per-template than the
`high,critical` tier (94 templates, ~15.2s) -- and directly found a
real condition there (`prometheus-metrics`, a publicly exposed
`/metrics` endpoint). `http/misconfiguration/`'s medium tier, by
contrast, is cheap (171 templates, ~13.1s measured; combined with its
own `high,critical` tier in one phase, 551 templates measured ~36.4s
real -- matching the sum almost exactly). Step 1C's response, driven
entirely by these real numbers:

- `misconfiguration`'s severity widened in place to `medium,high,
  critical` (cheap enough to fold into the existing phase, budget
  raised 35s -> 55s).
- A new, separate `exposures_medium` phase (severity `medium` only,
  same `http/exposures/` directory) carries the expensive part alone,
  with its own real, measured, generously-margined budget (100s vs.
  ~66.24s measured, ~1.5x). Kept separate from the fast `exposures`
  (`high,critical`) phase deliberately: if the expensive medium phase
  times out, the fast phase's already-completed results are unaffected
  (see the existing `"partial"` aggregate-status guarantee).
- A new `technology_directed` phase, tag-only (no directory
  restriction), applicable **only** when `select_nuclei_phases`'s
  `detected_technologies` argument maps to at least one tag in the
  closed `_TECHNOLOGY_TAG_MAP` -- otherwise `skipped_not_applicable`,
  never a fallback to the whole template tree. `backend.orchestrator`
  derives `detected_technologies` from `http_assessor`'s own already-
  produced `information_disclosure` findings (reusing existing
  evidence text, never a new header-capture code path) -- see that
  module for the extraction logic. **Disclosed honestly**: this
  project's own authorized Juice Shop target does not expose a
  `Server`/`X-Powered-By` header at all (verified directly), so this
  phase resolves to `skipped_not_applicable` in every real validation
  run against it -- the wiring and fallback path are real and tested,
  but positive technology-directed narrowing has not been demonstrated
  against the one target available in this environment.
- `MAX_PROCESS_TIMEOUT_SECONDS` raised from Step 1B's 90s to **230s**,
  driven almost entirely by `exposures_medium`'s own 100s budget --
  the sum of every QUICK phase budget is 210s (25+100+55+20+10).

This is this project's own established practice, followed again here:
runtime bounds only ever grow with a specific, measured, per-phase
justification, never a blanket "make the timeout bigger."

This is the **second** of two real external-tool adapters this block
adds. Like `adapters.bug_bounty_nmap`, this is a boundary module -- it
performs real subprocess I/O so `core.bug_bounty_tool_execution` (the
single execution boundary that calls it) and every other `core.*` module
never have to.

## Every executable command is built from closed, deterministic inputs

`_build_phase_command` is the only place an argument vector is ever
assembled, and it accepts only a resolved executable path, one
already-validated target URL, and one closed `_PHASE_IDS` member --
never a caller-supplied flag, template path, template ID, or raw tag
string. Execution always uses a list argument vector and `shell=False`
(via `subprocess.Popen`).

## Step 1B: why Step 1's single-command `bounded_web_v1` still timed out

Step 1 cut the template selection from 11,175 to 779 templates
(`http/exposures/` + `http/misconfiguration/` + `ssl/`, severity
medium+) and measured a ~31s *theoretical* floor at `-rl 25`. The real,
authorized, local validation run still timed out at ~76.5s with zero
results. Step 1B root-caused this properly with direct, bounded,
local-only timing experiments against the same authorized Juice Shop
target (never the full Bug Bounty workflow -- direct Nuclei CLI calls
only):

- `http/exposures/` alone, severity medium+ (232 templates): **did not
  finish in 60s**.
- `http/exposures/`, severity high+critical only (94 templates):
  completed in **~15.2s** (measured, `EXIT=0`) -- and genuinely
  discovered a real condition (`prometheus-metrics`, a publicly
  accessible `/metrics` endpoint leaking internal application
  telemetry) via this exact bounded, authorized, local timing
  experiment.
- `http/misconfiguration/`, severity critical only (41 templates):
  completed in **~3.1s**.
- `http/misconfiguration/`, severity high+critical (380 templates):
  completed in **~23.2s**.
- `http/exposures/` + `http/misconfiguration/` combined, severity
  high+critical (474 templates): completed in **~38.2s** -- consistent
  with the sum of the two measured above, confirming no adverse
  interaction from combining directories.
- `ssl/`, severity medium+: only **2 templates** total, and the current
  target (`http://juice-shop:3000`) is plain HTTP -- a direct local
  probe confirmed no TLS listener (`https://juice-shop:3000` fails to
  connect). SSL templates were contributing essentially nothing to this
  target while still being included in every scan.

Conclusion: the real driver of runtime was never raw template *count*
so much as the **medium-severity tier specifically** (which is where
Nuclei's exposure/misconfig checks get much heavier -- larger response
bodies, more path variants) -- not an evenly-distributed per-template
cost. `severity=high,critical` alone, without changing directories at
all, is what actually made the workload finish reliably.

## Phased execution, not one monolithic command

Nuclei now runs as up to three independently-bounded phases per scan,
each a separate `subprocess.Popen` invocation with its own dynamically
allocated slice of the overall runtime budget (see `_run_nuclei_phases`):

1. **`exposures`** -- `http/exposures/`, severity `high,critical`.
2. **`misconfiguration`** -- `http/misconfiguration/`, severity
   `high,critical`.
3. **`ssl`** -- `ssl/`, severity `medium,high,critical`; **skipped
   entirely** (`skipped_not_applicable`, zero budget spent) unless the
   target's own URL scheme is `https` -- determined from the exact same
   already-validated target string, never from live reconnaissance, so
   this can never expand scope. See `_is_https_target`.

Each phase's own budget is a fixed constant (`_PHASE_BUDGET_SECONDS`),
measured with real headroom over the timings above (`exposures`: 25s
budget vs. ~15.2s measured; `misconfiguration`: 35s budget vs. ~23.2s
measured), but the *actual* per-phase timeout is
`min(fixed_phase_budget, remaining_overall_budget)` -- a phase that
finishes early returns its unused time to the phases still queued,
rather than each phase getting a rigid, wasteful, independent slice.

A later phase timing out or failing **never discards an earlier phase's
already-completed observations** -- see "Aggregate status" below.

## One fixed QUICK profile is what the orchestrator actually calls

`run_nuclei_scan`'s signature still has no parameter for a template
path, template ID, tag, or profile name -- there is no caller-facing
way to select anything else. `QUICK_PROFILE_NAME` (`"quick_phased_v1"`)
is what every live Bug Bounty run uses today.

`STANDARD_PROFILE_PHASES` is also defined and fully unit-tested (wider
coverage -- adds the `medium` severity tier back for `exposures`/
`misconfiguration`, i.e. Step 1's original 779-template selection) but
is **not** wired to any live call site this step -- the orchestrator
never requests it, and no new parameter was added to reach it, since
Step 1's own real validation proved that severity tier does not
reliably complete within any reasonable Bug Bounty budget. It exists as
a defined, tested, available configuration for a future, deliberate
decision to expose it -- never silently substituted for QUICK.

## Technology-aware narrowing (Step 1C: live, wired end to end)

`select_nuclei_phases(target=..., detected_technologies=...)` is a
real, closed, deterministic function: a fixed `_TECHNOLOGY_TAG_MAP`
(`express`, `nodejs`, `node.js`, `angular`) contributes extra `-tags`
to `PHASE_TECHNOLOGY_DIRECTED` only for a recognized technology --
never to `exposures`/`misconfiguration`/`ssl`, which always run their
own fixed, technology-independent selection. `backend.orchestrator`
extracts `detected_technologies` via `_detect_technologies_from_
http_assessor`, which reuses `http_assessor`'s own already-produced
`information_disclosure` findings (a lowercase substring match against
each finding's `reproduction_summary` text) -- never a new header-
capture code path, never a change to `core.bug_bounty_assessment`'s
output contract. An unrecognized or absent technology leaves
`PHASE_TECHNOLOGY_DIRECTED` `skipped_not_applicable`, never a fallback
to the entire template tree. **Disclosed honestly**: this project's own
authorized Juice Shop target does not expose a `Server`/`X-Powered-By`
header at all, so positive technology-directed narrowing cannot be
demonstrated live against the only target available in this
environment -- only its correct `skipped_not_applicable` fallback path
can be. The mechanism itself is real, wired, and covered by dedicated
tests (`TestTechnologyDirectedPhase` in `tests/test_bug_bounty_nuclei_
adapter.py`; `TestTechnologyDetection` in `tests/test_backend_
orchestrator.py`), independent of what any single target happens to
expose.

## Every command is built from closed, deterministic inputs (continued)

- `-etags fuzz,dos,intrusive,bruteforce,headless` on every phase --
  unchanged from Step 1, never enabled to chase more findings.
- `-duc` (`-disable-update-check`) on every phase -- unchanged from
  Step 1.
- `-dr` (`-disable-redirects`) on every phase -- unchanged from Step 1.
- `-timeout <NUCLEI_REQUEST_TIMEOUT_SECONDS>` / `-retries
  <NUCLEI_RETRIES>` / `-mhe <NUCLEI_MAX_HOST_ERROR>` -- unchanged from
  Step 1.
- `-rl <NUCLEI_RATE_LIMIT>` / `-c <NUCLEI_CONCURRENCY>` -- unchanged
  from Step 1 (still well under Nuclei's own much higher defaults;
  still justified only because the target is always local and
  already-authorized).
- `-jsonl -silent` -- structured JSON-Lines output only, per phase.

## Timeout no longer discards partial results (unchanged from Step 1)

`_run_nuclei_process` (per-phase) still drives the child via
`subprocess.Popen` with a graceful-`terminate()`-then-bounded-grace-
then-`kill()` sequence, always reaping via a final `communicate()`, so
a phase that overruns its own slice of the budget still returns
whatever valid JSON-Lines output it had already flushed.

## Aggregate status -- never discards an earlier phase's real findings

`STATUS_VALUES` now includes `"partial"` alongside the existing
`"completed"`/`"timeout"`/`"failed"`/`"tool_not_installed"` -- a
genuinely new, honest outcome: at least one phase produced real
evidence (completed cleanly, or timed out with `partial_results`) while
at least one other applicable phase did not complete. `_aggregate_
phase_status` computes this deterministically from the per-phase
results; see its own docstring for the exact rule. A later phase's
timeout/failure is never allowed to convert an earlier phase's genuine
`observations` into an empty result.

## Observability, without inventing statistics Nuclei doesn't expose

`nuclei_version` is probed once per scan (best-effort, independently
bounded, no network activity). `templates_selected_count` is now
reported **per phase** (via the same `-tl` dry-run technique as Step 1,
scoped to that phase's exact directory/severity/tag selection) as well
as summed into a top-level `templates_selected_count` for backward
compatibility with Step 1's own contract. `phases` in the returned
result is a list of per-phase telemetry dicts (`phase_id`, `status`,
`templates_selected_count`, `elapsed_seconds`, `observation_count`,
`partial_results`) -- exactly the "templates by phase" / "phases
attempted" / "phases completed" observability this step adds. Nuclei's
own per-template request counts remain deliberately unreported --
Nuclei does not reliably expose them in `-jsonl -silent` mode, and
guessing one was rejected again this step.

## Tool result is not a finding

Exactly like `adapters.bug_bounty_nmap`, a result this module returns is
a raw tool observation, never a canonical ThreatTrace finding.

`BugBountyNucleiAdapterError`, `run_nuclei_scan`, and
`select_nuclei_phases` are this module's public functions (plus
`QUICK_PROFILE_NAME`, `STANDARD_PROFILE_NAME`, `PHASE_IDS`,
`PHASE_STATUS_VALUES`, `STATUS_VALUES`, `NUCLEI_RATE_LIMIT`,
`NUCLEI_CONCURRENCY`, `NUCLEI_REQUEST_TIMEOUT_SECONDS`, `NUCLEI_RETRIES`,
`NUCLEI_MAX_HOST_ERROR`, `NUCLEI_EXCLUDED_TAGS`,
`NUCLEI_TERMINATION_GRACE_SECONDS`, `MAX_PROCESS_TIMEOUT_SECONDS`,
`MAX_OUTPUT_BYTES`, and `TOOL_RESULT_VERSION`).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

TOOL_RESULT_VERSION = "3"
NUCLEI_EXECUTABLE_NAME = "nuclei"

# ---------------------------------------------------------------------------
# Closed phase catalogue. Never caller-selectable, never built from a
# tag/directory/template-id string a caller supplies -- every value below
# is a fixed Python literal.
# ---------------------------------------------------------------------------

PHASE_EXPOSURES = "exposures"
PHASE_EXPOSURES_MEDIUM = "exposures_medium"
PHASE_MISCONFIGURATION = "misconfiguration"
PHASE_TECHNOLOGY_DIRECTED = "technology_directed"
PHASE_SSL = "ssl"
PHASE_IDS = (PHASE_EXPOSURES, PHASE_EXPOSURES_MEDIUM, PHASE_MISCONFIGURATION, PHASE_TECHNOLOGY_DIRECTED, PHASE_SSL)

QUICK_PROFILE_NAME = "quick_phased_v2"
STANDARD_PROFILE_NAME = "standard_phased_v1"

# Real, measured (see module docstring) directory/severity selection per
# phase for the QUICK profile -- what every live Bug Bounty run actually
# uses today. PHASE_TECHNOLOGY_DIRECTED has no fixed directory -- its
# selection is entirely tag-driven (see select_nuclei_phases), so it is
# deliberately absent from this table.
_QUICK_PHASE_DIRECTORIES: Mapping[str, tuple[str, ...]] = {
    PHASE_EXPOSURES: ("http/exposures/",),
    PHASE_EXPOSURES_MEDIUM: ("http/exposures/",),
    PHASE_MISCONFIGURATION: ("http/misconfiguration/",),
    PHASE_SSL: ("ssl/",),
}
_QUICK_PHASE_SEVERITIES: Mapping[str, tuple[str, ...]] = {
    PHASE_EXPOSURES: ("high", "critical"),
    PHASE_EXPOSURES_MEDIUM: ("medium",),
    # Step 1C: folded medium back into the single misconfiguration phase
    # (551 templates combined measured ~36.4s real -- misconfiguration's
    # medium tier is cheap, unlike exposures') -- see module docstring.
    PHASE_MISCONFIGURATION: ("medium", "high", "critical"),
    PHASE_SSL: ("medium", "high", "critical"),
    PHASE_TECHNOLOGY_DIRECTED: ("info", "low", "medium", "high", "critical"),
}

# STANDARD widens exposures/misconfiguration back to Step 1's original
# medium+ tier -- defined and fully tested, but never wired to any live
# call site this step (see module docstring).
_STANDARD_PHASE_SEVERITIES: Mapping[str, tuple[str, ...]] = {
    PHASE_EXPOSURES: ("medium", "high", "critical"),
    PHASE_EXPOSURES_MEDIUM: ("medium",),
    PHASE_MISCONFIGURATION: ("medium", "high", "critical"),
    PHASE_SSL: ("medium", "high", "critical"),
    PHASE_TECHNOLOGY_DIRECTED: ("info", "low", "medium", "high", "critical"),
}

# Closed, deterministic technology-name -> Nuclei-tag mapping (Step 1C).
# Reused verbatim by select_nuclei_phases to build PHASE_TECHNOLOGY_
# DIRECTED's tag selection -- never a directory restriction, since a
# technology-specific template can live anywhere in the template tree.
# Every entry here was independently verified (local, network-free -tl
# count) to resolve to a small, fast, bounded template set (see module
# docstring) before being added -- never added speculatively.
_TECHNOLOGY_TAG_MAP: Mapping[str, tuple[str, ...]] = {
    "express": ("express", "nodejs"),
    "nodejs": ("nodejs",),
    "node.js": ("nodejs",),
    "angular": ("angular",),
}

# Fixed per-phase runtime budgets (seconds) -- real headroom over the
# measured timings in the module docstring: exposures ~15.2s measured
# (25s budget, ~1.6x margin); exposures_medium ~66.24s measured (100s
# budget, ~1.5x margin -- this is the expensive phase that carries most
# of Step 1C's "valuable medium coverage" cost, including the real
# prometheus-metrics exposure this project's own timing experiments
# found); misconfiguration (medium+high+critical combined) ~36.4s
# measured (55s budget, ~1.5x margin); technology_directed ~untested
# directly (29 templates across the closed technology map's tags,
# comparable to misconfiguration's per-template speed, 20s budget is
# generous); ssl ~untested directly (2 templates, usually
# skipped_not_applicable anyway). A phase's *actual* timeout is
# min(this value, whatever overall budget remains when that phase
# starts) -- see run_nuclei_scan.
_PHASE_BUDGET_SECONDS: Mapping[str, float] = {
    PHASE_EXPOSURES: 25.0,
    PHASE_EXPOSURES_MEDIUM: 100.0,
    PHASE_MISCONFIGURATION: 55.0,
    PHASE_TECHNOLOGY_DIRECTED: 20.0,
    PHASE_SSL: 10.0,
}

# Only PHASE_SSL requires the target itself to be HTTPS -- determined
# from the exact already-validated target string's own scheme (never
# from live reconnaissance/scanner output), so this can never expand
# scope. See _is_https_target.
_PHASE_REQUIRES_HTTPS: Mapping[str, bool] = {
    PHASE_EXPOSURES: False,
    PHASE_EXPOSURES_MEDIUM: False,
    PHASE_MISCONFIGURATION: False,
    PHASE_TECHNOLOGY_DIRECTED: False,
    PHASE_SSL: True,
}

NUCLEI_EXCLUDED_TAGS = ("fuzz", "dos", "intrusive", "bruteforce", "headless")
NUCLEI_RATE_LIMIT = 25
NUCLEI_CONCURRENCY = 10
NUCLEI_REQUEST_TIMEOUT_SECONDS = 5
NUCLEI_RETRIES = 1
NUCLEI_MAX_HOST_ERROR = 5

# Bounded grace period between a graceful SIGTERM and a forceful SIGKILL
# on a phase's runtime-budget overrun. Short and fixed -- never
# caller-configurable.
NUCLEI_TERMINATION_GRACE_SECONDS = 5.0

# Independent, short, best-effort timeouts for the observability probes
# below -- never allowed to consume a meaningful share of any phase's
# own runtime budget, and never allowed to fail the scan itself.
_VERSION_PROBE_TIMEOUT_SECONDS = 5.0
_TEMPLATE_COUNT_PROBE_TIMEOUT_SECONDS = 10.0

# Conservative bound for the WHOLE phased scan (all phases + probes
# combined), against a local/authorized target. A caller may request a
# lower value; never a higher one. Step 1C: sum of QUICK's own phase
# budgets is 210s (25+100+55+20+10, see _PHASE_BUDGET_SECONDS) -- the
# large jump from Step 1B's 90s is real, measured, and driven almost
# entirely by exposures_medium's own 100s budget (the phase carrying
# "valuable medium coverage," measured at ~66.24s real -- see module
# docstring). 230s retains real margin for probe overhead and
# process-startup cost across up to five separate subprocess
# invocations, without exceeding it blindly.
MAX_PROCESS_TIMEOUT_SECONDS = 230
MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB, per phase

STATUS_VALUES = frozenset({"completed", "partial", "timeout", "failed", "tool_not_installed"})
PHASE_STATUS_VALUES = frozenset({
    "completed", "timeout", "failed", "skipped_not_applicable", "skipped_budget_exhausted",
})

_NUCLEI_VERSION_PATTERN = re.compile(r"Version:\s*v?(\S+)")

_EXECUTION_CONFIG_VERSION = "1"
_EXECUTION_CONFIG_REQUIRED_FIELDS = ("execution_config_version", "process_timeout_seconds", "max_output_bytes")

_FREE_TEXT_MAX_LENGTH = 256
_REDACTION_MARKERS = (
    "authorization:", "cookie:", "set-cookie:", "api_key", "apikey", "password", "bearer ",
)


class BugBountyNucleiAdapterError(ValueError):
    """Raised when a supplied `target`/`execution_config` is structurally
    invalid -- not a bare `http(s)` URL, or an `execution_config` that
    exceeds a hardcoded safety ceiling.

    Never raised for a real scan outcome (missing executable, a phase
    timeout, a non-zero exit, malformed output) -- every one of those is
    a normal, successfully returned result with a `status` field, not an
    error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyNucleiAdapterError(f"{code}: {detail}")


def _require_nonblank_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise("INVALID_INPUT", f"{field_name!r} must be a non-blank string")
    return value.strip()


def _sanitize_free_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in _REDACTION_MARKERS):
        return "[REDACTED]"
    return text[:_FREE_TEXT_MAX_LENGTH]


def _sanitize_string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    sanitized = [_sanitize_free_text(item) for item in value if isinstance(item, str)]
    sanitized = [item for item in sanitized if item]
    return sanitized or None


# ---------------------------------------------------------------------------
# Target / execution_config validation -- private, local, additive on top
# of whatever core.bug_bounty_tool_policy already approved.
# ---------------------------------------------------------------------------


def _validate_scan_target(target: Any) -> str:
    candidate = _require_nonblank_string(target, "target")
    parsed = urlsplit(candidate)
    if parsed.scheme not in ("http", "https"):
        _raise("INVALID_TARGET", "target must be an http(s) URL")
    if not parsed.hostname:
        _raise("INVALID_TARGET", "target must include a hostname")
    return candidate


def _is_https_target(target: str) -> bool:
    """Reads only the already-validated target string's own scheme --
    never live reconnaissance, never scanner output. This is why a
    protocol-gated phase can never be used to expand scope: it can only
    ever narrow (skip a phase), and the fact it examines was already
    fully authorized before this adapter ever saw it."""
    return urlsplit(target).scheme == "https"


def _validate_execution_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_EXECUTION_CONFIG_REQUIRED_FIELDS):
        _raise("INVALID_EXECUTION_CONFIG", "execution_config must contain exactly the three required fields")
    if value.get("execution_config_version") != _EXECUTION_CONFIG_VERSION:
        _raise("INVALID_EXECUTION_CONFIG", "execution_config_version must be '1'")

    timeout = value.get("process_timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        _raise("INVALID_EXECUTION_CONFIG", "process_timeout_seconds must be a positive number")
    if timeout > MAX_PROCESS_TIMEOUT_SECONDS:
        _raise("INVALID_EXECUTION_CONFIG", f"process_timeout_seconds must not exceed {MAX_PROCESS_TIMEOUT_SECONDS}")

    max_output = value.get("max_output_bytes")
    if isinstance(max_output, bool) or not isinstance(max_output, int) or max_output <= 0:
        _raise("INVALID_EXECUTION_CONFIG", "max_output_bytes must be a positive int")
    if max_output > MAX_OUTPUT_BYTES:
        _raise("INVALID_EXECUTION_CONFIG", f"max_output_bytes must not exceed {MAX_OUTPUT_BYTES}")

    return {
        "execution_config_version": _EXECUTION_CONFIG_VERSION,
        "process_timeout_seconds": timeout,
        "max_output_bytes": max_output,
    }


# ---------------------------------------------------------------------------
# Deterministic phase planning -- Phase 3's `select_nuclei_templates`
# concept, closed and testable. No LLM, no title-text guessing, no
# target-provided template names, no filesystem access beyond the fixed
# template directories Nuclei itself already ships.
# ---------------------------------------------------------------------------


def select_nuclei_phases(*, target: str, detected_technologies: Any = None, profile: str = QUICK_PROFILE_NAME) -> list[dict[str, Any]]:
    """Deterministically plan which of `PHASE_IDS` apply to `target`, and
    with what extra tags, for `profile` (`QUICK_PROFILE_NAME` or
    `STANDARD_PROFILE_NAME`). Performs no I/O and executes nothing.

    `detected_technologies` is an optional iterable of lowercase
    technology name strings; each recognized entry in the fixed, closed
    `_TECHNOLOGY_TAG_MAP` contributes tags to `PHASE_TECHNOLOGY_
    DIRECTED` only (never `exposures`/`misconfiguration`/`ssl`, which
    always run their own fixed, technology-independent selection).
    `PHASE_TECHNOLOGY_DIRECTED` is `applicable` **only** when at least
    one recognized technology contributed a tag -- an unrecognized or
    absent technology means that phase is `skipped_not_applicable`,
    never a fallback to the entire template tree. Real, live technology
    detection is wired from `http_assessor`'s own already-produced
    `information_disclosure` findings (see `backend.orchestrator`); it
    resolves to nothing detected for any target that doesn't disclose a
    recognized `Server`/`X-Powered-By` value (this project's own
    authorized Juice Shop target is one such case -- see module
    docstring for why this is disclosed rather than hidden).

    Returns a list of `{"phase_id", "applicable", "directories",
    "severities", "extra_tags"}` dicts, one per `PHASE_IDS` entry, in
    `PHASE_IDS` order. `directories` is always `()` for `PHASE_
    TECHNOLOGY_DIRECTED` (tag-driven only, spans the whole template
    tree, never directory-restricted) and for any other phase when
    `applicable` is `False`.
    """
    if profile not in (QUICK_PROFILE_NAME, STANDARD_PROFILE_NAME):
        _raise("INVALID_PROFILE", f"profile must be one of {QUICK_PROFILE_NAME!r}/{STANDARD_PROFILE_NAME!r}")
    severities_by_phase = _QUICK_PHASE_SEVERITIES if profile == QUICK_PROFILE_NAME else _STANDARD_PHASE_SEVERITIES

    technologies = detected_technologies or ()
    extra_tags: set[str] = set()
    for tech in technologies:
        if isinstance(tech, str):
            extra_tags.update(_TECHNOLOGY_TAG_MAP.get(tech.strip().lower(), ()))
    sorted_extra_tags = tuple(sorted(extra_tags))

    is_https = _is_https_target(target)

    plan: list[dict[str, Any]] = []
    for phase_id in PHASE_IDS:
        if phase_id == PHASE_TECHNOLOGY_DIRECTED:
            applicable = bool(sorted_extra_tags)
            plan.append({
                "phase_id": phase_id,
                "applicable": applicable,
                "directories": (),
                "severities": severities_by_phase[phase_id] if applicable else (),
                "extra_tags": sorted_extra_tags if applicable else (),
            })
            continue
        applicable = is_https if _PHASE_REQUIRES_HTTPS[phase_id] else True
        plan.append({
            "phase_id": phase_id,
            "applicable": applicable,
            "directories": _QUICK_PHASE_DIRECTORIES[phase_id] if applicable else (),
            "severities": severities_by_phase[phase_id] if applicable else (),
            "extra_tags": (),
        })
    return plan


# ---------------------------------------------------------------------------
# Command construction -- the only place a Nuclei argument vector is
# ever assembled, per phase. Always a list (never a shell string).
# ---------------------------------------------------------------------------


def _phase_template_selection_args(phase_plan: Mapping[str, Any]) -> list[str]:
    """The template-selection portion of one phase's plan only -- shared
    verbatim between that phase's real scan command and its own
    `-tl` template-count probe."""
    argv: list[str] = []
    for directory in phase_plan["directories"]:
        argv += ["-t", directory]
    argv += ["-severity", ",".join(phase_plan["severities"])]
    excluded_tags = NUCLEI_EXCLUDED_TAGS
    argv += ["-etags", ",".join(excluded_tags)]
    if phase_plan["extra_tags"]:
        argv += ["-tags", ",".join(phase_plan["extra_tags"])]
    return argv


def _build_phase_command(*, nuclei_path: str, target: str, phase_plan: Mapping[str, Any]) -> list[str]:
    argv = [nuclei_path, "-u", target] + _phase_template_selection_args(phase_plan)
    argv += [
        "-ni",
        "-duc",
        "-dr",
        "-timeout", str(NUCLEI_REQUEST_TIMEOUT_SECONDS),
        "-retries", str(NUCLEI_RETRIES),
        "-mhe", str(NUCLEI_MAX_HOST_ERROR),
        "-rl", str(NUCLEI_RATE_LIMIT),
        "-c", str(NUCLEI_CONCURRENCY),
        "-jsonl",
        "-silent",
    ]
    return argv


def _find_nuclei_executable() -> str | None:
    return shutil.which(NUCLEI_EXECUTABLE_NAME)


def _digest_reference(raw_bytes: bytes) -> str:
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return f"nuclei_jsonl_sha256:{digest}"


# ---------------------------------------------------------------------------
# Observability probes -- each independently bounded and best-effort;
# neither is ever allowed to raise out of run_nuclei_scan, and neither
# performs any network activity.
# ---------------------------------------------------------------------------


def _probe_nuclei_version(nuclei_path: str) -> str | None:
    try:
        completed = subprocess.run(
            [nuclei_path, "-version"], shell=False, capture_output=True, timeout=_VERSION_PROBE_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    text = (completed.stdout or b"").decode("utf-8", errors="replace") + (completed.stderr or b"").decode("utf-8", errors="replace")
    match = _NUCLEI_VERSION_PATTERN.search(text)
    return match.group(1) if match else None


def _probe_phase_template_count(nuclei_path: str, phase_plan: Mapping[str, Any]) -> int | None:
    if not phase_plan["applicable"]:
        return 0
    argv = [nuclei_path] + _phase_template_selection_args(phase_plan) + ["-tl"]
    try:
        completed = subprocess.run(argv, shell=False, capture_output=True, timeout=_TEMPLATE_COUNT_PROBE_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if completed.returncode != 0:
        return None
    lines = (completed.stdout or b"").decode("utf-8", errors="replace").splitlines()
    return sum(1 for line in lines if line.strip())


# ---------------------------------------------------------------------------
# Process execution -- Popen-based (not subprocess.run) specifically so a
# runtime-budget overrun can still recover whatever valid stdout the
# child process had already written and flushed before termination.
# Unchanged from Step 1, reused per phase.
# ---------------------------------------------------------------------------


def _run_nuclei_process(argv: list[str], *, timeout_seconds: float) -> tuple[int | None, bytes, bytes, bool]:
    """Run `argv` to completion or until `timeout_seconds` elapses.

    Returns `(returncode, stdout, stderr, timed_out)`. `returncode` is
    `None` only when the process was terminated/killed on timeout.
    `stdout`/`stderr` reflect whatever was actually captured -- on the
    graceful-terminate path this can be a genuine, non-empty, partial
    JSON-Lines payload if Nuclei had already written matches before the
    runtime budget expired.
    """
    process = subprocess.Popen(argv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return process.returncode, stdout or b"", stderr or b"", False
    except subprocess.TimeoutExpired:
        pass

    # Graceful termination first (SIGTERM), bounded grace period to let
    # Nuclei flush any buffered output and exit cleanly.
    process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=NUCLEI_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        # Graceful termination did not succeed in time -- force kill, then
        # always perform one final communicate() to reap the process and
        # drain whatever remains in the pipes. No orphan process, no
        # unreaped zombie, no unread buffered output left behind.
        process.kill()
        stdout, stderr = process.communicate()
    return None, stdout or b"", stderr or b"", True


# ---------------------------------------------------------------------------
# JSON-Lines parsing -- structured only, never terminal-text scraping.
# Malformed individual lines are skipped, never treated as a fatal error
# for the whole phase.
# ---------------------------------------------------------------------------


def _normalize_classification(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    cve_id = _sanitize_string_list(value.get("cve-id"))
    cwe_id = _sanitize_string_list(value.get("cwe-id"))
    if cve_id is None and cwe_id is None:
        return None
    return {"cve_id": cve_id, "cwe_id": cwe_id}


def _normalize_nuclei_record(record: Mapping[str, Any]) -> dict[str, Any]:
    template_id = record.get("template-id") or record.get("templateID")
    info = record.get("info") if isinstance(record.get("info"), Mapping) else {}
    matched_at = record.get("matched-at") or record.get("matched_at") or record.get("host")

    return {
        "type": "known_pattern_match",
        "template_id": _sanitize_free_text(template_id),
        "title": _sanitize_free_text(info.get("name")),
        "severity": _sanitize_free_text(info.get("severity")),
        "target": _sanitize_free_text(matched_at),
        "matcher": _sanitize_free_text(record.get("matcher-name")),
        "classification": _normalize_classification(info.get("classification")),
    }


def _parse_nuclei_jsonl(raw_bytes: bytes) -> list[dict[str, Any]]:
    text = raw_bytes.decode("utf-8", errors="replace")
    observations: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        observations.append(_normalize_nuclei_record(record))
    return observations


# ---------------------------------------------------------------------------
# Per-phase execution.
# ---------------------------------------------------------------------------


def _run_one_phase(
    *, nuclei_path: str, target: str, phase_plan: Mapping[str, Any], timeout_seconds: float, max_output_bytes: int,
) -> dict[str, Any]:
    phase_id = phase_plan["phase_id"]

    if not phase_plan["applicable"]:
        return {
            "phase_id": phase_id, "status": "skipped_not_applicable",
            "templates_selected_count": 0, "elapsed_seconds": 0.0,
            "observations": [], "observation_count": 0, "partial_results": False,
            "evidence_reference": None, "output_truncated": False, "stderr_summary": None,
        }

    if timeout_seconds <= 0:
        return {
            "phase_id": phase_id, "status": "skipped_budget_exhausted",
            "templates_selected_count": _probe_phase_template_count(nuclei_path, phase_plan),
            "elapsed_seconds": 0.0, "observations": [], "observation_count": 0, "partial_results": False,
            "evidence_reference": None, "output_truncated": False, "stderr_summary": None,
        }

    templates_selected_count = _probe_phase_template_count(nuclei_path, phase_plan)
    argv = _build_phase_command(nuclei_path=nuclei_path, target=target, phase_plan=phase_plan)

    phase_started_at = time.monotonic()
    returncode, raw_stdout, raw_stderr, timed_out = _run_nuclei_process(argv, timeout_seconds=timeout_seconds)
    elapsed_seconds = time.monotonic() - phase_started_at

    output_truncated = len(raw_stdout) > max_output_bytes
    bounded_stdout = raw_stdout[:max_output_bytes]
    stderr_summary = _sanitize_free_text((raw_stderr or b"").decode("utf-8", errors="replace"))
    evidence_reference = _digest_reference(bounded_stdout) if bounded_stdout else None

    if timed_out:
        observations = _parse_nuclei_jsonl(bounded_stdout)
        return {
            "phase_id": phase_id, "status": "timeout",
            "templates_selected_count": templates_selected_count, "elapsed_seconds": elapsed_seconds,
            "observations": observations, "observation_count": len(observations),
            "partial_results": bool(observations),
            "evidence_reference": evidence_reference, "output_truncated": output_truncated,
            "stderr_summary": stderr_summary,
        }

    if returncode != 0:
        return {
            "phase_id": phase_id, "status": "failed",
            "templates_selected_count": templates_selected_count, "elapsed_seconds": elapsed_seconds,
            "observations": [], "observation_count": 0, "partial_results": False,
            "evidence_reference": evidence_reference, "output_truncated": output_truncated,
            "stderr_summary": stderr_summary,
        }

    observations = _parse_nuclei_jsonl(bounded_stdout)
    return {
        "phase_id": phase_id, "status": "completed",
        "templates_selected_count": templates_selected_count, "elapsed_seconds": elapsed_seconds,
        "observations": observations, "observation_count": len(observations), "partial_results": False,
        "evidence_reference": evidence_reference, "output_truncated": output_truncated,
        "stderr_summary": stderr_summary,
    }


def _aggregate_phase_status(phase_results: list[dict[str, Any]]) -> str:
    """Deterministic aggregate status from real per-phase results only.

    `skipped_not_applicable` phases (e.g. `ssl` on a plain-HTTP target)
    are excluded from this computation entirely -- they were correctly
    never attempted, not a failure of any kind.

    - Every applicable phase `completed` -> `"completed"`.
    - At least one applicable phase produced real evidence (`completed`,
      or `timeout`/`skipped_budget_exhausted` with `observation_count >
      0`) but not all of them did -> `"partial"` -- this is the rule
      that guarantees an earlier phase's genuine findings are never
      discarded because a later phase timed out or failed.
    - No applicable phase produced anything AND at least one timed out
      -> `"timeout"`.
    - No applicable phase produced anything and none timed out (i.e. at
      least one genuinely failed) -> `"failed"`.
    - No applicable phases existed at all (every phase was
      `skipped_not_applicable`) -> `"completed"` (there was truthfully
      nothing to fail).
    """
    applicable = [p for p in phase_results if p["status"] != "skipped_not_applicable"]
    if not applicable:
        return "completed"

    completed = [p for p in applicable if p["status"] == "completed"]
    if len(completed) == len(applicable):
        return "completed"

    any_evidence = any(p["observation_count"] > 0 for p in applicable)
    if any_evidence or completed:
        return "partial"

    if any(p["status"] == "timeout" for p in applicable):
        return "timeout"
    return "failed"


# ---------------------------------------------------------------------------
# Result contract.
# ---------------------------------------------------------------------------


def _build_result(
    *,
    request_id: str,
    target: str,
    status: str,
    observations: list[dict[str, Any]],
    evidence_references: list[str],
    output_truncated: bool,
    error_detail: str | None,
    execution_performed: bool,
    partial_results: bool = False,
    runtime_duration_seconds: float | None = None,
    profile_name: str | None = None,
    nuclei_version: str | None = None,
    templates_selected_count: int | None = None,
    stderr_summary: str | None = None,
    phases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "tool_result_version": TOOL_RESULT_VERSION,
        "tool_id": "nuclei",
        "request_id": request_id,
        "target": target,
        "status": status,
        "observations": observations,
        "evidence_references": evidence_references,
        "network_requests_performed": None,
        "output_truncated": output_truncated,
        "error_detail": error_detail,
        "execution_performed": execution_performed,
        "partial_results": partial_results,
        "runtime_duration_seconds": runtime_duration_seconds,
        "profile_name": profile_name,
        "nuclei_version": nuclei_version,
        "templates_selected_count": templates_selected_count,
        "stderr_summary": stderr_summary,
        # Step 1B addition -- per-phase telemetry, never discarded even
        # when the overall status is "partial"/"timeout"/"failed".
        "phases": phases if phases is not None else [],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_nuclei_scan(*, target: Any, request_id: Any, execution_config: Any, detected_technologies: Any = None) -> dict[str, Any]:
    """Run one bounded, phased Nuclei scan under the fixed `QUICK_
    PROFILE_NAME` profile (see module docstring), and return a
    structured, sanitized tool result. Never invoked directly by the LLM
    planner -- only `core.bug_bounty_tool_execution` calls this, and only
    after it has re-evaluated the real tool permission policy and
    confirmed a Security Governor `allow` decision.

    `detected_technologies` (Step 1C, optional, defaults to `None`) is
    forwarded unmodified to `select_nuclei_phases` -- see that
    function's own docstring for the closed, deterministic mapping and
    the honest disclosure about what it does and doesn't detect for
    this project's own authorized target today. This is still not a
    caller-selectable template/tag/flag surface: an unrecognized or
    absent value always resolves to the same fixed generic phase set.

    Raises `BugBountyNucleiAdapterError` for a structurally invalid
    `target`/`request_id`/`execution_config`. Never raises for a real
    scan outcome.

    Runs up to five independently-bounded phases (`exposures`,
    `exposures_medium`, `misconfiguration`, `technology_directed`,
    `ssl`) via `select_nuclei_phases`/`_run_one_phase`, each drawing
    from a shared, dynamically-shrinking overall budget
    (`execution_config['process_timeout_seconds']`) -- a phase that
    finishes early leaves more budget for the phases still queued.
    `ssl` is skipped (`skipped_not_applicable`, zero budget spent)
    unless `target`'s own scheme is `https`; `technology_directed` is
    skipped unless `detected_technologies` maps to at least one tag.

    Returns a dict containing every field Step 1 returned (`status` now
    drawn from the widened `STATUS_VALUES`, which adds `"partial"`) plus
    `phases` -- a list of per-phase telemetry dicts (`phase_id`,
    `status` from `PHASE_STATUS_VALUES`, `templates_selected_count`,
    `elapsed_seconds`, `observation_count`, `partial_results`). `status`
    is computed by `_aggregate_phase_status`: `"completed"` only when
    every applicable phase completed; `"partial"` when some but not all
    applicable phases produced real evidence -- an earlier phase's
    genuine findings are never discarded because a later phase timed
    out or failed; `"timeout"`/`"failed"` only when nothing was
    recovered from any phase.
    """
    validated_target = _validate_scan_target(target)
    validated_request_id = _require_nonblank_string(request_id, "request_id")
    validated_config = _validate_execution_config(execution_config)

    nuclei_path = _find_nuclei_executable()
    if nuclei_path is None:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="tool_not_installed",
            observations=[], evidence_references=[], output_truncated=False, error_detail=None,
            execution_performed=False, profile_name=QUICK_PROFILE_NAME,
        )

    nuclei_version = _probe_nuclei_version(nuclei_path)
    phase_plans = select_nuclei_phases(
        target=validated_target, detected_technologies=detected_technologies, profile=QUICK_PROFILE_NAME,
    )

    overall_started_at = time.monotonic()
    remaining_budget = float(validated_config["process_timeout_seconds"])
    max_output_bytes = validated_config["max_output_bytes"]

    phase_results: list[dict[str, Any]] = []
    for phase_plan in phase_plans:
        phase_id = phase_plan["phase_id"]
        phase_timeout = min(_PHASE_BUDGET_SECONDS[phase_id], remaining_budget) if phase_plan["applicable"] else 0.0
        try:
            result = _run_one_phase(
                nuclei_path=nuclei_path, target=validated_target, phase_plan=phase_plan,
                timeout_seconds=phase_timeout, max_output_bytes=max_output_bytes,
            )
        except OSError:
            result = {
                "phase_id": phase_id, "status": "failed", "templates_selected_count": None,
                "elapsed_seconds": 0.0, "observations": [], "observation_count": 0, "partial_results": False,
                "evidence_reference": None, "output_truncated": False, "stderr_summary": None,
            }
        phase_results.append(result)
        remaining_budget -= result["elapsed_seconds"]

    runtime_duration_seconds = time.monotonic() - overall_started_at

    all_observations: list[dict[str, Any]] = []
    evidence_references: list[str] = []
    output_truncated = False
    for result in phase_results:
        all_observations.extend(result["observations"])
        if result["evidence_reference"]:
            evidence_references.append(result["evidence_reference"])
        output_truncated = output_truncated or result["output_truncated"]

    total_templates = sum(
        result["templates_selected_count"] for result in phase_results
        if isinstance(result["templates_selected_count"], int)
    ) if any(isinstance(r["templates_selected_count"], int) for r in phase_results) else None

    aggregate_status = _aggregate_phase_status(phase_results)
    partial_results = aggregate_status == "partial"

    error_detail = None
    if aggregate_status == "timeout":
        error_detail = "one or more nuclei phases did not complete within their runtime budget"
    elif aggregate_status == "failed":
        error_detail = "one or more nuclei phases exited with a non-zero status"

    stderr_summaries = [r["stderr_summary"] for r in phase_results if r["stderr_summary"]]

    phases_telemetry = [
        {
            "phase_id": r["phase_id"], "status": r["status"],
            "templates_selected_count": r["templates_selected_count"],
            "elapsed_seconds": r["elapsed_seconds"], "observation_count": r["observation_count"],
            "partial_results": r["partial_results"],
        }
        for r in phase_results
    ]

    return _build_result(
        request_id=validated_request_id, target=validated_target, status=aggregate_status,
        observations=all_observations, evidence_references=evidence_references,
        output_truncated=output_truncated, error_detail=error_detail, execution_performed=True,
        partial_results=partial_results, runtime_duration_seconds=runtime_duration_seconds,
        profile_name=QUICK_PROFILE_NAME, nuclei_version=nuclei_version,
        templates_selected_count=total_templates,
        stderr_summary=stderr_summaries[0] if stderr_summaries else None,
        phases=phases_telemetry,
    )
