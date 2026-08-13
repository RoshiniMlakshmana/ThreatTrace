"""Non-pure execution adapters for ThreatTrace.

Unlike every module under `core/`, modules in this package perform real
I/O (network requests, and in the future possibly other external
effects). They exist specifically so `core/` can remain fully pure and
unit-testable -- a `core/` orchestrator depends only on a small injected
interface, and a module here provides one real implementation of it.
"""
