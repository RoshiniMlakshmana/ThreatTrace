"""ThreatTrace Live Platform backend (Block 15J-K).

A local-only HTTP/SSE interface that orchestrates the already-existing,
unmodified Bug Bounty and Detection Engineering cores and exposes their
real, structured progress as a live event stream. This package
introduces no new security logic of its own -- every enforcement
decision (scope, tool policy, Governor, telemetry feasibility, rule
validation) is still made by the existing `core.*` modules; this
package only sequences those calls and reports what actually happened.

See `docs/block15jk-live-platform-dashboard.md` for the full
architecture, security boundaries, and honesty commitments (local-only
bind, in-memory non-persistent history, no authentication claims, no
LLM calls from within the backend process itself).
"""
