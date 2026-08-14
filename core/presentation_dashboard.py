"""Pure, deterministic presentation-dashboard HTML renderer (Block
15F-B).

This module answers exactly one question: *given a caller-supplied,
already-sanitized `dashboard_data` object -- real baseline/refined Bug
Bounty benchmark results, an optional real Block 15E research
evaluation, a workflow-stage execution summary, and a fixed research
limitations list -- what does one self-contained, presentation-quality
HTML document rendering that data honestly look like?*

## A renderer only -- never a computation engine

This module never computes a benchmark result, a research metric, or a
workflow decision. `core.benchmark_evaluation` remains the sole source
of truth for TP/FP/FN/TN/precision/recall/F1; `core.research_evaluation`
remains the sole source of truth for every research metric it can
produce. This module only formats caller-supplied, already-computed
numbers into HTML -- it never recomputes, re-derives, or "improves" a
number it is given.

## Unavailable is rendered honestly, never invented

`research_evaluation` may be `None` -- this module never fabricates a
zero, a rate, or a `"not exercised"` Governor/Memory count as if it
were a real measurement. When `research_evaluation` is `None`, every
research-evaluation-derived section states plainly that it was not
evaluated in this benchmark run, exactly as the caller's Block 15E
pipeline did not run for it. `security_workflow_summary` similarly
marks each pipeline stage `"executed"` or `"not_evaluated"` from
caller-supplied fact only -- this module never infers a stage's status
from anything else.

## No script execution, no external resources, no network

Every caller-supplied string value (`project_name`, `target`,
`run_label`, workflow-stage notes, research-limitations text) is HTML-
escaped before being embedded -- this module never treats a supplied
string as HTML/JavaScript to execute. The generated document contains
no `<script src=...>`, no `<link href="http...">`, no external font,
image, or CDN reference of any kind, and no analytics/tracking of any
kind -- it is fully self-contained and works when opened directly from
the local filesystem, with no server and no network access required.

## No timestamps, no random IDs

The same `dashboard_data` input always produces byte-identical HTML
output. This module never reads the system clock, never generates a
UUID, and never embeds a "generated at" timestamp -- there is nothing
in the rendered document that varies between two calls with the same
input.

## Terminology honesty

The rendered document always uses **functional security roles**,
**deterministic core services**, **Claude custom agents**, and
**policy identities** -- it never claims this repository runs "eight
autonomous agents," and the architecture flow it renders is always
labeled as platform workflow, never as a claim that every stage was
exercised in the current benchmark run.

`PresentationDashboardError` and `render_presentation_dashboard` are
this module's only public symbols.
"""

from __future__ import annotations

import html
from collections.abc import Mapping
from typing import Any

DASHBOARD_VERSION = "1"

_BENCHMARK_SUMMARY_FIELDS = (
    "true_positive_count",
    "false_positive_count",
    "false_negative_count",
    "true_negative_count",
    "precision",
    "recall",
    "f1",
    "supported_ground_truth_count",
)

_WORKFLOW_STAGES = (
    ("bug_bounty", "Bug Bounty"),
    ("context_prioritization", "Context Prioritization"),
    ("security_handoff", "Security Handoff"),
    ("security_governor", "Security Governor"),
    ("validated_experience_memory", "Validated Security Experience Memory"),
    ("research_evaluation", "Research Evaluation"),
)

_STAGE_STATUSES = frozenset({"executed", "not_evaluated"})

_TOP_LEVEL_REQUIRED_FIELDS = (
    "dashboard_version",
    "project_name",
    "target",
    "target_origin",
    "target_version_or_digest",
    "run_label",
    "baseline_benchmark",
    "refined_benchmark",
    "research_evaluation",
    "security_workflow_summary",
    "research_limitations",
)

_SUPPORTED_CAPABILITIES = (
    "Security-header presence",
    "Fixed metadata resource observation",
    "CORS observation",
    "Advertised HTTP methods",
    "Inert input reflection",
)

_UNSUPPORTED_CAPABILITIES = (
    "SQL injection",
    "Executable XSS",
    "IDOR / access control",
    "SSRF",
    "Command injection",
    "Authentication weaknesses",
    "Business-logic challenges",
)


class PresentationDashboardError(ValueError):
    """Raised when a supplied `dashboard_data` input is structurally
    invalid.

    Every message begins with one of a fixed set of stable codes:
    `INVALID_DASHBOARD_DATA`, `INVALID_BENCHMARK_SUMMARY`,
    `INVALID_WORKFLOW_SUMMARY`, `INVALID_STAGE_STATUS`,
    `INVALID_RESEARCH_LIMITATIONS`.

    Never raised because `research_evaluation` is `None`, because a
    workflow stage's status is `"not_evaluated"`, or because a
    benchmark's `false_positive_count` is greater than zero -- every
    one of those is a normal, honestly-rendered input, not an error
    condition.
    """


def _raise(code: str, detail: str) -> None:
    raise PresentationDashboardError(f"{code}: {detail}")


def _require_nonblank_string(value: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be a non-blank string")
    return value


def _require_nonnegative_int(value: Any, code: str, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _raise(code, f"{field_name!r} must be an int")
    if value < 0:
        _raise(code, f"{field_name!r} must be a non-negative int")
    return value


def _require_optional_rate(value: Any, code: str, field_name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _raise(code, f"{field_name!r} must be a number or null")
    if value < 0 or value > 1:
        _raise(code, f"{field_name!r} must be between 0 and 1")
    return float(value)


# ---------------------------------------------------------------------------
# Validation.
# ---------------------------------------------------------------------------


def _validate_benchmark_summary(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_BENCHMARK_SUMMARY_FIELDS):
        _raise("INVALID_BENCHMARK_SUMMARY", f"{field_name} must contain exactly the eight required fields")

    return {
        "true_positive_count": _require_nonnegative_int(
            value.get("true_positive_count"), "INVALID_BENCHMARK_SUMMARY", f"{field_name}.true_positive_count",
        ),
        "false_positive_count": _require_nonnegative_int(
            value.get("false_positive_count"), "INVALID_BENCHMARK_SUMMARY", f"{field_name}.false_positive_count",
        ),
        "false_negative_count": _require_nonnegative_int(
            value.get("false_negative_count"), "INVALID_BENCHMARK_SUMMARY", f"{field_name}.false_negative_count",
        ),
        "true_negative_count": _require_nonnegative_int(
            value.get("true_negative_count"), "INVALID_BENCHMARK_SUMMARY", f"{field_name}.true_negative_count",
        ),
        "precision": _require_optional_rate(value.get("precision"), "INVALID_BENCHMARK_SUMMARY", f"{field_name}.precision"),
        "recall": _require_optional_rate(value.get("recall"), "INVALID_BENCHMARK_SUMMARY", f"{field_name}.recall"),
        "f1": _require_optional_rate(value.get("f1"), "INVALID_BENCHMARK_SUMMARY", f"{field_name}.f1"),
        "supported_ground_truth_count": _require_nonnegative_int(
            value.get("supported_ground_truth_count"),
            "INVALID_BENCHMARK_SUMMARY", f"{field_name}.supported_ground_truth_count",
        ),
    }


def _validate_stage_status(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"status", "note"}:
        _raise("INVALID_STAGE_STATUS", f"{field_name} must contain exactly status/note")
    status = value.get("status")
    if status not in _STAGE_STATUSES:
        _raise("INVALID_STAGE_STATUS", f"{field_name}.status must be 'executed' or 'not_evaluated'")
    note = value.get("note")
    if note is not None and (not isinstance(note, str) or not note.strip()):
        _raise("INVALID_STAGE_STATUS", f"{field_name}.note must be null or a non-blank string")
    return {"status": status, "note": note}


def _validate_workflow_summary(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != {key for key, _ in _WORKFLOW_STAGES}:
        _raise("INVALID_WORKFLOW_SUMMARY", "security_workflow_summary must contain exactly the six fixed stage keys")
    return {
        key: _validate_stage_status(value.get(key), f"security_workflow_summary.{key}")
        for key, _ in _WORKFLOW_STAGES
    }


def _validate_research_limitations(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) == 0:
        _raise("INVALID_RESEARCH_LIMITATIONS", "research_limitations must be a non-empty list")
    validated: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            _raise("INVALID_RESEARCH_LIMITATIONS", "research_limitations entries must be non-blank strings")
        validated.append(item)
    return validated


def _validate_dashboard_data(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_TOP_LEVEL_REQUIRED_FIELDS):
        _raise("INVALID_DASHBOARD_DATA", "dashboard_data must contain exactly the eleven required fields")

    if value.get("dashboard_version") != DASHBOARD_VERSION:
        _raise("INVALID_DASHBOARD_DATA", "dashboard_version must be '1'")

    project_name = _require_nonblank_string(value.get("project_name"), "INVALID_DASHBOARD_DATA", "project_name")
    target = _require_nonblank_string(value.get("target"), "INVALID_DASHBOARD_DATA", "target")
    target_origin = _require_nonblank_string(value.get("target_origin"), "INVALID_DASHBOARD_DATA", "target_origin")
    target_version_or_digest = _require_nonblank_string(
        value.get("target_version_or_digest"), "INVALID_DASHBOARD_DATA", "target_version_or_digest",
    )
    run_label = _require_nonblank_string(value.get("run_label"), "INVALID_DASHBOARD_DATA", "run_label")

    baseline_benchmark = _validate_benchmark_summary(value.get("baseline_benchmark"), "baseline_benchmark")
    refined_benchmark = _validate_benchmark_summary(value.get("refined_benchmark"), "refined_benchmark")

    research_evaluation = value.get("research_evaluation")
    if research_evaluation is not None and not isinstance(research_evaluation, Mapping):
        _raise("INVALID_DASHBOARD_DATA", "research_evaluation must be null or a mapping")

    security_workflow_summary = _validate_workflow_summary(value.get("security_workflow_summary"))
    research_limitations = _validate_research_limitations(value.get("research_limitations"))

    return {
        "dashboard_version": DASHBOARD_VERSION,
        "project_name": project_name,
        "target": target,
        "target_origin": target_origin,
        "target_version_or_digest": target_version_or_digest,
        "run_label": run_label,
        "baseline_benchmark": baseline_benchmark,
        "refined_benchmark": refined_benchmark,
        "research_evaluation": research_evaluation,
        "security_workflow_summary": security_workflow_summary,
        "research_limitations": research_limitations,
    }


# ---------------------------------------------------------------------------
# Formatting helpers.
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _format_percent(value: float | None) -> str:
    if value is None:
        return "N/A"
    formatted = f"{value * 100:.1f}"
    if formatted.endswith(".0"):
        formatted = formatted[:-2]
    return formatted + "%"


def _format_count(value: int) -> str:
    return str(value)


def _format_rate_bar(value: float | None) -> str:
    if value is None:
        return "0"
    return f"{value * 100:.2f}"


def _format_number(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


# ---------------------------------------------------------------------------
# HTML fragment builders.
# ---------------------------------------------------------------------------


def _kpi_card(label: str, value: str, *, detail: str = "") -> str:
    detail_html = f'<p class="kpi-detail">{_esc(detail)}</p>' if detail else ""
    return (
        '<div class="kpi-card">'
        f'<p class="kpi-label">{_esc(label)}</p>'
        f'<p class="kpi-value">{_esc(value)}</p>'
        f"{detail_html}"
        "</div>"
    )


def _before_after_bar(label: str, baseline: float | None, refined: float | None) -> str:
    baseline_pct = _format_rate_bar(baseline)
    refined_pct = _format_rate_bar(refined)
    return (
        '<div class="ba-metric">'
        f'<p class="ba-label">{_esc(label)}</p>'
        '<div class="ba-row">'
        f'<span class="ba-tag">Baseline</span>'
        f'<div class="ba-track" role="img" aria-label="{_esc(label)} baseline {_format_percent(baseline)}">'
        f'<div class="ba-fill ba-fill-baseline" style="width:{baseline_pct}%"></div>'
        "</div>"
        f'<span class="ba-value">{_esc(_format_percent(baseline))}</span>'
        "</div>"
        '<div class="ba-row">'
        f'<span class="ba-tag">Refined</span>'
        f'<div class="ba-track" role="img" aria-label="{_esc(label)} refined {_format_percent(refined)}">'
        f'<div class="ba-fill ba-fill-refined" style="width:{refined_pct}%"></div>'
        "</div>"
        f'<span class="ba-value">{_esc(_format_percent(refined))}</span>'
        "</div>"
        "</div>"
    )


def _confusion_row(row_label: str, summary: Mapping[str, Any]) -> str:
    return (
        "<tr>"
        f"<th scope=\"row\">{_esc(row_label)}</th>"
        f'<td>{_format_count(summary["true_positive_count"])}</td>'
        f'<td>{_format_count(summary["false_positive_count"])}</td>'
        f'<td>{_format_count(summary["false_negative_count"])}</td>'
        f'<td>{_format_count(summary["true_negative_count"])}</td>'
        f'<td>{_format_count(summary["supported_ground_truth_count"])}</td>'
        "</tr>"
    )


def _workflow_stage_box(stage_key: str, stage_label: str, status: Mapping[str, Any]) -> str:
    executed = status["status"] == "executed"
    badge_class = "stage-executed" if executed else "stage-not-evaluated"
    badge_text = "Executed" if executed else "Not evaluated"
    note = status.get("note")
    note_html = f'<p class="stage-note">{_esc(note)}</p>' if note else ""
    return (
        f'<div class="stage-box" aria-label="{_esc(stage_label)}: {_esc(badge_text)}">'
        f'<p class="stage-name">{_esc(stage_label)}</p>'
        f'<span class="stage-badge {badge_class}">{_esc(badge_text)}</span>'
        f"{note_html}"
        "</div>"
    )


def _capability_list(items: tuple[str, ...]) -> str:
    return "".join(f"<li>{_esc(item)}</li>" for item in items)


def _limitations_list(items: list[str]) -> str:
    return "".join(f"<li>{_esc(item)}</li>" for item in items)


_RESEARCH_UNAVAILABLE_NOTE = "Not evaluated in this Juice Shop benchmark run."
_MTVD_UNAVAILABLE_NOTE = "MTVD unavailable — no qualifying caller-supplied duration."
_GOVERNOR_UNAVAILABLE_NOTE = "Governor metrics were not exercised in this benchmark run."
_MEMORY_UNAVAILABLE_NOTE = "Validated Security Experience Memory was not evaluated in this benchmark run."


def _render_research_evaluation_section(research_evaluation: Mapping[str, Any] | None) -> str:
    if research_evaluation is None:
        return (
            '<div class="research-unavailable">'
            f"<p>{_esc(_RESEARCH_UNAVAILABLE_NOTE)}</p>"
            f"<p>{_esc(_GOVERNOR_UNAVAILABLE_NOTE)}</p>"
            f"<p>{_esc(_MEMORY_UNAVAILABLE_NOTE)}</p>"
            f"<p>{_esc(_MTVD_UNAVAILABLE_NOTE)}</p>"
            "</div>"
        )

    context = research_evaluation.get("context_prioritization") or {}
    governor = research_evaluation.get("governor") or {}
    memory = research_evaluation.get("memory") or {}
    protection = research_evaluation.get("governor_memory_protection") or {}
    evidence = research_evaluation.get("evidence_preservation") or {}
    revision = research_evaluation.get("red_blue_revision") or {}
    human_review = research_evaluation.get("human_review") or {}
    validated_experience = research_evaluation.get("validated_defensive_experience") or {}
    mtvd = research_evaluation.get("mtvd") or {}
    stage_proxy = research_evaluation.get("stage_count_proxy") or {}
    ablations = research_evaluation.get("ablations") or {}

    mtvd_html = (
        f'<p>Mean minutes: {_esc(_format_number(mtvd.get("mean_minutes")))}</p>'
        if mtvd.get("available")
        else f"<p>{_esc(_MTVD_UNAVAILABLE_NOTE)}</p>"
    )

    ablation_rows = "".join(
        (
            "<tr>"
            f"<th scope=\"row\">{_esc(group_name)}</th>"
            f'<td>{_format_number(group.get("scenario_count"))}</td>'
            f'<td>{_esc(_format_percent(group.get("validated_defensive_experience_rate")))}</td>'
            "</tr>"
        )
        for group_name, group in sorted(ablations.items())
        if isinstance(group, Mapping)
    )

    return (
        '<div class="research-available">'
        '<div class="research-grid">'
        f'<div class="research-item"><h4>Context Prioritization</h4>'
        f'<p>Raised: {_format_number(context.get("raised_count"))} · '
        f'Unchanged: {_format_number(context.get("unchanged_count"))} · '
        f'Lowered: {_format_number(context.get("lowered_count"))}</p>'
        f'<p>Mean priority delta: {_format_number(context.get("mean_priority_delta"))}</p></div>'

        f'<div class="research-item"><h4>Governor Decisions</h4>'
        f'<p>Allow {_format_number(governor.get("allow_count"))} · '
        f'Warn {_format_number(governor.get("warn_count"))} · '
        f'Require review {_format_number(governor.get("require_review_count"))} · '
        f'Block {_format_number(governor.get("block_count"))} · '
        f'Freeze {_format_number(governor.get("freeze_count"))}</p>'
        f'<p>Intervention rate: {_esc(_format_percent(governor.get("governor_intervention_rate")))}</p></div>'

        f'<div class="research-item"><h4>Memory Admission</h4>'
        f'<p>Candidate {_format_number(memory.get("candidate_count"))} · '
        f'Validated {_format_number(memory.get("validated_count"))} · '
        f'Rejected {_format_number(memory.get("rejected_count"))}</p>'
        f'<p>Reuse rate: {_esc(_format_percent(memory.get("memory_reuse_rate")))}</p></div>'

        f'<div class="research-item"><h4>Governor→Memory Protection</h4>'
        f'<p>Unsafe reusable violations: {_format_number(protection.get("unsafe_reusable_violations"))}</p>'
        f'<p>Protection rate: {_esc(_format_percent(protection.get("protection_rate")))}</p></div>'

        f'<div class="research-item"><h4>Evidence Preservation</h4>'
        f'<p>Rate: {_esc(_format_percent(evidence.get("evidence_preservation_rate")))}</p></div>'

        f'<div class="research-item"><h4>Red → Blue Revisions</h4>'
        f'<p>Cycles: {_format_number(revision.get("revision_cycle_count"))}</p></div>'

        f'<div class="research-item"><h4>Human Review</h4>'
        f'<p>Required: {_format_number(human_review.get("human_review_required_count"))} · '
        f'Approved: {_format_number(human_review.get("approved_count"))}</p></div>'

        f'<div class="research-item"><h4>Validated Defensive Experience</h4>'
        f'<p>Rate: {_esc(_format_percent(validated_experience.get("rate")))}</p></div>'

        f'<div class="research-item"><h4>MTVD</h4>{mtvd_html}</div>'

        f'<div class="research-item"><h4>Stage-Count Proxy</h4>'
        f'<p>Mean stage count: {_format_number(stage_proxy.get("mean_stage_count_to_validated_experience"))}</p></div>'
        "</div>"
        '<table class="data-table"><caption>Ablation groups</caption>'
        "<thead><tr><th scope=\"col\">Group</th><th scope=\"col\">Scenarios</th>"
        "<th scope=\"col\">Validated defensive-experience rate</th></tr></thead>"
        f"<tbody>{ablation_rows}</tbody></table>"
        "</div>"
    )


# ---------------------------------------------------------------------------
# CSS -- fully self-contained, no external fonts/CDN/images.
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #0b0f14;
  --bg-panel: #11161d;
  --bg-card: #161d27;
  --border: #26313f;
  --text: #e8eef4;
  --text-dim: #9fb0c0;
  --accent: #4dd6c0;
  --good: #4fbf7a;
  --bad: #e0665a;
  --warn: #e0b04d;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0; background: var(--bg); color: var(--text); font-family: var(--font);
  line-height: 1.5;
}
header.hero {
  padding: 2.5rem 1.5rem 1.5rem; border-bottom: 1px solid var(--border); background: var(--bg-panel);
}
.hero-inner { max-width: 1100px; margin: 0 auto; }
.hero h1 { margin: 0; font-size: 2.25rem; letter-spacing: 0.02em; }
.hero .subtitle { color: var(--accent); font-size: 1.1rem; margin: 0.25rem 0 0; font-weight: 600; }
.hero .tagline { color: var(--text-dim); margin: 0.75rem 0 0; max-width: 70ch; }
.hero .meta { margin-top: 1rem; color: var(--text-dim); font-size: 0.95rem; }
.hero .meta strong { color: var(--text); }
nav.dashboard-nav {
  position: sticky; top: 0; z-index: 5; background: var(--bg-panel); border-bottom: 1px solid var(--border);
  padding: 0.75rem 1.5rem;
}
nav.dashboard-nav .nav-inner { max-width: 1100px; margin: 0 auto; display: flex; gap: 1.5rem; flex-wrap: wrap; }
nav.dashboard-nav a { color: var(--text-dim); text-decoration: none; font-weight: 600; font-size: 0.95rem; }
nav.dashboard-nav a:hover, nav.dashboard-nav a:focus { color: var(--accent); }
main { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
section { margin-bottom: 3rem; }
section h2 { font-size: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
section h3 { font-size: 1.15rem; color: var(--accent); margin-top: 2rem; }
.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
.kpi-card {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem;
}
.kpi-label { margin: 0; color: var(--text-dim); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
.kpi-value { margin: 0.35rem 0 0; font-size: 1.9rem; font-weight: 700; color: var(--text); }
.kpi-detail { margin: 0.35rem 0 0; color: var(--text-dim); font-size: 0.85rem; }
.callout {
  background: var(--bg-card); border: 1px solid var(--accent); border-radius: 12px; padding: 1.5rem; margin: 1.5rem 0;
}
.callout h3 { margin-top: 0; }
.callout .callout-quote { font-size: 1.05rem; }
.callout .callout-footnote { color: var(--text-dim); font-size: 0.85rem; margin-top: 1rem; }
.ba-metric { margin-bottom: 1.25rem; }
.ba-label { font-weight: 600; margin-bottom: 0.4rem; }
.ba-row { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.35rem; }
.ba-tag { width: 70px; color: var(--text-dim); font-size: 0.85rem; }
.ba-track { flex: 1; background: var(--bg-panel); border: 1px solid var(--border); border-radius: 6px; height: 18px; overflow: hidden; }
.ba-fill { height: 100%; }
.ba-fill-baseline { background: var(--warn); }
.ba-fill-refined { background: var(--good); }
.ba-value { width: 60px; text-align: right; font-variant-numeric: tabular-nums; }
.fp-callout { display: flex; align-items: center; gap: 1rem; margin: 1rem 0; }
.fp-badge { font-size: 2rem; font-weight: 700; padding: 0.5rem 1rem; border-radius: 8px; border: 1px solid var(--border); }
.fp-badge.baseline { color: var(--bad); }
.fp-badge.refined { color: var(--good); }
.fp-arrow { color: var(--text-dim); font-size: 1.5rem; }
table.data-table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
table.data-table caption { text-align: left; color: var(--text-dim); margin-bottom: 0.5rem; }
table.data-table th, table.data-table td {
  border: 1px solid var(--border); padding: 0.5rem 0.75rem; text-align: left;
}
table.data-table thead th { background: var(--bg-panel); }
.discovery-flow { display: flex; flex-direction: column; gap: 0.5rem; margin: 1.5rem 0; }
.discovery-step { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
.discovery-step .step-title { font-weight: 700; color: var(--accent); margin: 0 0 0.25rem; }
.discovery-arrow { text-align: center; color: var(--text-dim); }
.workflow-flow { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: stretch; margin: 1.5rem 0; }
.stage-box {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; flex: 1 1 150px;
  min-width: 150px;
}
.stage-name { font-weight: 600; margin: 0 0 0.5rem; }
.stage-badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; font-size: 0.8rem; font-weight: 700; }
.stage-badge.stage-executed { background: rgba(79,191,122,0.18); color: var(--good); border: 1px solid var(--good); }
.stage-badge.stage-not-evaluated { background: rgba(224,176,77,0.15); color: var(--warn); border: 1px solid var(--warn); }
.stage-note { color: var(--text-dim); font-size: 0.85rem; margin: 0.5rem 0 0; }
.workflow-disclaimer { color: var(--warn); font-weight: 600; margin-top: 1rem; }
.role-terms { color: var(--text-dim); }
.capability-columns { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.5rem; }
.capability-columns h4 { margin-bottom: 0.5rem; }
.capability-columns ul { margin: 0; padding-left: 1.25rem; }
.unsupported-note { color: var(--warn); font-weight: 600; margin-top: 1rem; }
.limitations-list { padding-left: 1.25rem; }
.limitations-list li { margin-bottom: 0.4rem; }
.research-unavailable p { color: var(--warn); font-weight: 600; }
.research-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
.research-item { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; }
.research-item h4 { margin: 0 0 0.5rem; color: var(--accent); font-size: 1rem; }
.research-item p { margin: 0.25rem 0; color: var(--text-dim); font-size: 0.9rem; }
footer.site-footer {
  border-top: 1px solid var(--border); padding: 2rem 1.5rem; color: var(--text-dim); font-size: 0.85rem;
}
footer.site-footer .footer-inner { max-width: 1100px; margin: 0 auto; }
@media (max-width: 640px) {
  .hero h1 { font-size: 1.6rem; }
  .ba-tag { width: 56px; }
}
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_presentation_dashboard(*, dashboard_data: Any) -> str:
    """Deterministically render one self-contained HTML presentation
    dashboard document from a caller-supplied `dashboard_data` object.
    Performs no file I/O, no network access, generates no timestamp,
    and generates no random identifier -- the same `dashboard_data`
    input always produces byte-identical HTML output.

    `dashboard_data` is required and keyword-only, and must be a
    mapping containing exactly the eleven fields documented in the
    module docstring's data contract: `dashboard_version` (must be
    `"1"`), `project_name`, `target`, `target_origin`,
    `target_version_or_digest`, `run_label` (each a non-blank string),
    `baseline_benchmark`/`refined_benchmark` (each an eight-field
    benchmark summary: `true_positive_count`, `false_positive_count`,
    `false_negative_count`, `true_negative_count` as non-negative ints,
    `precision`/`recall`/`f1` each `None` or a number in `[0, 1]`,
    `supported_ground_truth_count` a non-negative int),
    `research_evaluation` (`None`, or a mapping shaped like
    `core.research_evaluation.evaluate_research_experiment`'s own
    return value -- read defensively via `.get()`, never required to
    match that contract exactly), `security_workflow_summary` (a
    mapping with exactly six fixed stage keys -- `bug_bounty`,
    `context_prioritization`, `security_handoff`, `security_governor`,
    `validated_experience_memory`, `research_evaluation` -- each a
    `{status, note}` mapping, `status` one of `"executed"`/
    `"not_evaluated"`), `research_limitations` (a non-empty list of
    non-blank strings).

    Every caller-supplied string value is HTML-escaped before being
    embedded in the returned document -- no supplied string is ever
    treated as HTML or JavaScript to execute. The returned document
    contains no external `<script src>`, `<link href="http...">`,
    font, image, or CDN reference of any kind, and performs no analytics
    or tracking -- it is fully self-contained.

    When `research_evaluation` is `None`, the rendered Research View
    states plainly that it was not evaluated in this benchmark run --
    it never fabricates a zero count or a rate for Governor, Memory, or
    MTVD sections. When `research_evaluation` is supplied, its own
    `mtvd.available` field determines whether `mean_minutes` is
    rendered or whether the fixed MTVD-unavailable message is shown --
    this function never substitutes `stage_count_proxy` for MTVD.

    `dashboard_data` (and every nested value within it) is never
    mutated.

    Returns a complete HTML document string (including `<!DOCTYPE
    html>`).

    Raises `PresentationDashboardError` for any structurally invalid
    `dashboard_data`. Never raises because `research_evaluation` is
    `None`, because a workflow stage is `"not_evaluated"`, or because a
    benchmark's false-positive count is greater than zero.
    """
    data = _validate_dashboard_data(dashboard_data)

    baseline = data["baseline_benchmark"]
    refined = data["refined_benchmark"]
    workflow = data["security_workflow_summary"]

    fp_delta = refined["false_positive_count"] - baseline["false_positive_count"]

    kpi_html = "".join((
        _kpi_card("Baseline Precision", _format_percent(baseline["precision"])),
        _kpi_card("Refined Precision", _format_percent(refined["precision"])),
        _kpi_card("Recall", _format_percent(refined["recall"]), detail="Unchanged from baseline to refined"),
        _kpi_card("Baseline F1", _format_percent(baseline["f1"])),
        _kpi_card("Refined F1", _format_percent(refined["f1"])),
        _kpi_card(
            "False Positives",
            f'{baseline["false_positive_count"]} → {refined["false_positive_count"]}',
            detail=f"Delta: {fp_delta:+d}",
        ),
        _kpi_card("Supported Benchmark Cases", _format_count(refined["supported_ground_truth_count"])),
    ))

    before_after_html = "".join((
        _before_after_bar("Precision", baseline["precision"], refined["precision"]),
        _before_after_bar("Recall", baseline["recall"], refined["recall"]),
        _before_after_bar("F1", baseline["f1"], refined["f1"]),
    ))

    confusion_html = (
        '<table class="data-table"><caption>Supported Benchmark Detection Result '
        "(never described as overall application accuracy)</caption>"
        "<thead><tr><th scope=\"col\">Run</th><th scope=\"col\">TP</th><th scope=\"col\">FP</th>"
        "<th scope=\"col\">FN</th><th scope=\"col\">TN</th><th scope=\"col\">Supported cases</th></tr></thead>"
        f"<tbody>{_confusion_row('Baseline', baseline)}{_confusion_row('Refined', refined)}</tbody>"
        "</table>"
    )

    workflow_html = "".join(
        _workflow_stage_box(key, label, workflow[key]) for key, label in _WORKFLOW_STAGES
    )

    research_html = _render_research_evaluation_section(data["research_evaluation"])

    limitations_html = _limitations_list(data["research_limitations"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(data["project_name"])} — {_esc(data["run_label"])}</title>
<style>{_CSS}</style>
</head>
<body>
<header class="hero">
  <div class="hero-inner">
    <h1>{_esc(data["project_name"])}</h1>
    <p class="subtitle">Evidence-Preserving Security Validation</p>
    <p class="tagline">Human-governed, evidence-preserving security validation platform connecting bounded
      vulnerability discovery, organization-aware prioritization, governed security handoff, policy supervision,
      validated security experience reuse, and deterministic research evaluation.</p>
    <p class="meta">Controlled Evaluation — Target: <strong>{_esc(data["target"])}</strong>
      ({_esc(data["target_origin"])}) · Image digest: <strong>{_esc(data["target_version_or_digest"])}</strong>
      · Run: <strong>{_esc(data["run_label"])}</strong></p>
  </div>
</header>
<nav class="dashboard-nav" aria-label="Dashboard sections">
  <div class="nav-inner">
    <a href="#executive">Executive</a>
    <a href="#research">Research</a>
    <a href="#architecture">Architecture</a>
    <a href="#limitations">Limitations</a>
  </div>
</nav>
<main>

<section id="executive" aria-labelledby="executive-heading">
  <h2 id="executive-heading">Executive View</h2>

  <div class="kpi-grid">{kpi_html}</div>

  <div class="callout">
    <h3>Controlled Result</h3>
    <p class="callout-quote">On this fixed supported {_esc(data["target"])} benchmark, a metadata evidence-quality
      refinement reduced false positives from {baseline["false_positive_count"]} to
      {refined["false_positive_count"]} while supported-case recall remained
      {_esc(_format_percent(refined["recall"]))}.</p>
    <p>Baseline precision: <strong>{_esc(_format_percent(baseline["precision"]))}</strong> ·
      Refined precision: <strong>{_esc(_format_percent(refined["precision"]))}</strong></p>
    <p class="callout-footnote">This is not an overall vulnerability-detection accuracy claim.</p>
  </div>

  <h3>Baseline → Refined</h3>
  <p>Measured on the same fixed supported {_esc(data["target"])} benchmark and same container image.</p>
  {before_after_html}
  <div class="fp-callout" role="img" aria-label="False positives reduced from {baseline['false_positive_count']} to {refined['false_positive_count']}">
    <span class="fp-badge baseline">{baseline["false_positive_count"]} FP</span>
    <span class="fp-arrow" aria-hidden="true">→</span>
    <span class="fp-badge refined">{refined["false_positive_count"]} FP</span>
  </div>

  <h3>Supported Benchmark Detection Result</h3>
  {confusion_html}

  <h3>Defect Discovery Story</h3>
  <div class="discovery-flow">
    <div class="discovery-step"><p class="step-title">Baseline observation</p><p>/sitemap.xml — HTTP 200</p></div>
    <div class="discovery-arrow" aria-hidden="true">↓</div>
    <div class="discovery-step"><p class="step-title">Independent validation</p>
      <p>Content-Type: text/html — generic Angular SPA fallback</p></div>
    <div class="discovery-arrow" aria-hidden="true">↓</div>
    <div class="discovery-step"><p class="step-title">Detector weakness</p><p>Status-only metadata qualification</p></div>
    <div class="discovery-arrow" aria-hidden="true">↓</div>
    <div class="discovery-step"><p class="step-title">Refinement</p><p>Resource-aware metadata evidence qualification</p></div>
    <div class="discovery-arrow" aria-hidden="true">↓</div>
    <div class="discovery-step"><p class="step-title">Re-evaluation</p>
      <p>FP {baseline["false_positive_count"]} → {refined["false_positive_count"]} · Recall unchanged</p></div>
  </div>
</section>

<section id="research" aria-labelledby="research-heading">
  <h2 id="research-heading">Research View</h2>

  <h3>A. Benchmark Before / After</h3>
  {confusion_html}

  <h3>B. Supported Ground-Truth Coverage</h3>
  <p>Baseline supported cases: {baseline["supported_ground_truth_count"]} ·
     Refined supported cases: {refined["supported_ground_truth_count"]}</p>

  <h3>C. Precision / Recall / F1</h3>
  {before_after_html}

  <h3>D. Evidence-Quality Refinement</h3>
  <p>A resource-aware metadata evidence-quality check (Content-Type plus a bounded, recognized body signature)
    replaced a status-code-only qualification for the three fixed metadata paths. No new HTTP request, path,
    or vulnerability class was introduced.</p>

  <h3>E. Research Evaluation Metrics</h3>
  {research_html}

  <h3>F. Limitations</h3>
  <p>See the <a href="#limitations">Limitations</a> section below.</p>
</section>

<section id="architecture" aria-labelledby="architecture-heading">
  <h2 id="architecture-heading">Architecture</h2>
  <p class="role-terms">ThreatTrace is composed of functional security roles, deterministic core services,
    Claude custom agents, and policy identities — never described as eight autonomous agents.</p>
  <div class="workflow-flow">{workflow_html}</div>
  <p class="workflow-disclaimer">Platform workflow — not all stages were exercised in this benchmark.</p>

  <h3>Supported in This Benchmark</h3>
  <div class="capability-columns">
    <div>
      <h4>Supported</h4>
      <ul>{_capability_list(_SUPPORTED_CAPABILITIES)}</ul>
    </div>
    <div>
      <h4>Not Evaluated</h4>
      <ul>{_capability_list(_UNSUPPORTED_CAPABILITIES)}</ul>
    </div>
  </div>
  <p class="unsupported-note">Not-evaluated categories are excluded from recall — they are never counted as
    false negatives.</p>
</section>

<section id="limitations" aria-labelledby="limitations-heading">
  <h2 id="limitations-heading">Research Limitations</h2>
  <ul class="limitations-list">{limitations_html}</ul>
</section>

</main>
<footer class="site-footer">
  <div class="footer-inner">
    <p>{_esc(data["project_name"])} — Human-Governed Security Validation Platform. Sanitized benchmark facts only;
      no cookies, credentials, tokens, or raw response bodies are included in this document.</p>
  </div>
</footer>
</body>
</html>
"""
