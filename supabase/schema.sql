-- ============================================================================
-- ThreatTrace Database Schema
-- ============================================================================
-- Purpose: Stores Purple Team investigation state — from initial anomaly or
--          threat-intel intake, through evidence collection, ATT&CK mapping,
--          Red/Blue Team handoffs, detection validation, and retesting.
--
-- Safety: This script is idempotent where practical (IF NOT EXISTS / OR REPLACE /
--         DROP ... IF EXISTS guards) so it can be re-run safely. It is NOT
--         executed automatically — review and apply manually via the Supabase
--         CLI or dashboard.
-- ============================================================================

-- Required for gen_random_uuid()
create extension if not exists pgcrypto;

-- ============================================================================
-- Table: investigations
-- ----------------------------------------------------------------------------
-- The root record for a single Purple Team investigation. Every other table
-- (evidence, attack_mappings, handoffs, detection_results, retests) hangs off
-- an investigation via investigation_id.
-- ============================================================================
create table if not exists investigations (
    id uuid primary key default gen_random_uuid(),
    title text not null,
    description text,
    entry_point text not null
        check (entry_point in ('known_threat', 'unknown_anomaly', 'completed_simulation')),
    status text not null default 'open'
        check (status in ('open', 'investigating', 'awaiting_evidence', 'escalated', 'closed')),
    confidence text not null default 'unknown'
        check (confidence in ('low', 'medium', 'high', 'unknown')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

comment on table investigations is
    'Root record for a Purple Team investigation: tracks its entry point (Red Team-led known threat, Threat Hunter-led anomaly, or Blue Team-led completed simulation), current status, and confidence level.';
comment on column investigations.entry_point is
    'Which of the three ThreatTrace investigation entry points originated this record.';
comment on column investigations.confidence is
    'Current confidence level in the investigation''s working hypothesis, per Threat Hunter/Purple Team assessment.';

-- ============================================================================
-- Table: evidence
-- ----------------------------------------------------------------------------
-- Individual pieces of telemetry or observations collected during an
-- investigation, and whether each one supports or contradicts the working
-- hypothesis. Includes a normalized evidence envelope (source_type through
-- provenance) so records from different origins (analyst entry, Hayabusa,
-- threat intelligence, query results, Threat Hunter findings) share a common,
-- queryable shape without displacing the original free-form `details`
-- payload. All envelope fields are nullable so existing rows and existing
-- insert paths remain fully compatible.
-- ============================================================================
create table if not exists evidence (
    id uuid primary key default gen_random_uuid(),
    investigation_id uuid not null
        references investigations (id) on delete cascade,
    evidence_type text not null,
    source text,
    observed_at timestamptz,
    details jsonb,
    supports_hypothesis boolean,
    created_at timestamptz not null default now(),

    -- Normalized evidence envelope (nullable; populated incrementally).
    source_type text
        check (source_type is null or source_type in (
            'analyst', 'hayabusa', 'threat_intelligence', 'query_result',
            'threat_hunter', 'system', 'unknown'
        )),
    source_identifier text,
    source_location text,
    ingested_at timestamptz default now(),
    assertion_type text
        check (assertion_type is null or assertion_type in (
            'observation', 'derived_fact', 'hypothesis', 'interpretation',
            'recommendation', 'unknown'
        )),
    trust_level text
        check (trust_level is null or trust_level in ('high', 'medium', 'low', 'unknown')),
    confidence text
        check (confidence is null or confidence in ('high', 'medium', 'low', 'unknown')),
    event_id text,
    host_name text,
    user_name text,
    process_name text,
    command_line text,
    ip_address text,
    file_hash text,
    provenance jsonb default '{}'::jsonb
        check (provenance is null or jsonb_typeof(provenance) = 'object')
);

comment on table evidence is
    'Individual telemetry items or observations gathered for an investigation (e.g. logon events, process activity, change records), each tagged with whether it supports or contradicts the working hypothesis.';
comment on column evidence.supports_hypothesis is
    'true = supports the malicious/primary hypothesis, false = contradicts it, null = undetermined/neutral.';
comment on column evidence.details is
    'Raw or structured evidence payload (e.g. log fields, query results) stored as JSONB.';
comment on column evidence.observed_at is
    'When the underlying activity actually occurred, per the source.';
comment on column evidence.source_type is
    'Category that produced this evidence record.';
comment on column evidence.source_identifier is
    'Identifier of the specific report, file, event, query, or analyst record this evidence came from.';
comment on column evidence.source_location is
    'Original project-relative file or external reference for this evidence.';
comment on column evidence.ingested_at is
    'When ThreatTrace received the evidence, as distinct from when the activity occurred.';
comment on column evidence.assertion_type is
    'Separates observations from interpretations and recommendations.';
comment on column evidence.trust_level is
    'Confidence in the source that produced this evidence.';
comment on column evidence.confidence is
    'Confidence in this individual evidence record.';
comment on column evidence.provenance is
    'Where and how this evidence record was produced.';

-- ============================================================================
-- Table: attack_mappings
-- ----------------------------------------------------------------------------
-- MITRE ATT&CK technique mappings associated with an investigation, marked as
-- provisional (evidence incomplete) or supported (evidence confirms it).
-- ============================================================================
create table if not exists attack_mappings (
    id uuid primary key default gen_random_uuid(),
    investigation_id uuid not null
        references investigations (id) on delete cascade,
    technique_id text not null,
    technique_name text,
    mapping_status text not null default 'provisional'
        check (mapping_status in ('provisional', 'supported')),
    rationale text,
    created_at timestamptz not null default now()
);

comment on table attack_mappings is
    'MITRE ATT&CK technique(s) mapped to an investigation, labeled provisional (evidence incomplete) or supported (evidence confirms the mapping), with a rationale for the mapping.';
comment on column attack_mappings.technique_id is
    'MITRE ATT&CK technique identifier, e.g. T1078.002.';

-- ============================================================================
-- Table: handoffs
-- ----------------------------------------------------------------------------
-- Records each transfer of an investigation between roles (Threat Hunter,
-- Red Team, Blue Team, Purple Team) and its acceptance status.
-- ============================================================================
create table if not exists handoffs (
    id uuid primary key default gen_random_uuid(),
    investigation_id uuid not null
        references investigations (id) on delete cascade,
    from_role text not null,
    to_role text not null,
    handoff_status text not null default 'pending'
        check (handoff_status in ('pending', 'accepted', 'rejected', 'returned')),
    reason text,
    created_at timestamptz not null default now()
);

comment on table handoffs is
    'Tracks each handoff of an investigation between roles (e.g. Threat Hunter to Purple Team, Purple Team to Blue Team), its status, and the reason for acceptance/rejection/return.';

-- ============================================================================
-- Table: detection_results
-- ----------------------------------------------------------------------------
-- Outcome of Blue Team validation for a given investigation/simulation:
-- whether the activity was detected, and by which rule, with any gaps noted.
-- ============================================================================
create table if not exists detection_results (
    id uuid primary key default gen_random_uuid(),
    investigation_id uuid not null
        references investigations (id) on delete cascade,
    detection_status text not null
        check (detection_status in ('detected', 'partially_detected', 'not_detected', 'insufficient_telemetry')),
    rule_name text,
    observed_telemetry jsonb,
    detection_gaps text,
    created_at timestamptz not null default now()
);

comment on table detection_results is
    'Blue Team validation outcome for an investigation: whether the associated activity was detected, which rule (if any) fired, the observed telemetry, and any identified detection gaps.';
comment on column detection_results.observed_telemetry is
    'Telemetry/log evidence collected during Blue Team validation, stored as JSONB.';

-- ============================================================================
-- Table: retests
-- ----------------------------------------------------------------------------
-- Planned and completed retests of a detection improvement, tied back to the
-- originating investigation.
-- ============================================================================
create table if not exists retests (
    id uuid primary key default gen_random_uuid(),
    investigation_id uuid not null
        references investigations (id) on delete cascade,
    planned_test text,
    approval_status text not null default 'pending'
        check (approval_status in ('pending', 'approved', 'rejected', 'completed')),
    result text,
    created_at timestamptz not null default now()
);

comment on table retests is
    'Retest plans for validating detection improvements after a gap is remediated; requires explicit approval before execution and records the eventual result.';

-- ============================================================================
-- Table: approvals
-- ----------------------------------------------------------------------------
-- Persists the request-and-lifecycle contract already validated in pure
-- Python by core/approval_request.py and core/approval_transition.py: an
-- analyst-proposed action envelope (currently only update_investigation_state)
-- moving through pending -> approved -> consumed, or pending -> rejected.
-- This table stores exactly that contract -- it introduces no new fields,
-- vocabulary, or lifecycle rules beyond what those validators already define
-- and test. No trigger, RLS policy, or authenticated-identity enforcement
-- exists yet for this table.
-- ============================================================================
create table if not exists approvals (
    id uuid primary key default gen_random_uuid(),
    investigation_id uuid not null
        references investigations (id) on delete cascade,
    action_type text not null,
    action_payload jsonb not null,
    requested_by text not null,
    requested_at timestamptz not null,
    status text not null default 'pending',
    approved_by text,
    approved_at timestamptz,
    rejected_by text,
    rejected_at timestamptz,
    rejection_reason text,
    expires_at timestamptz,
    consumed_by text,
    consumed_at timestamptz,
    created_at timestamptz not null default now(),

    constraint chk_approvals_status
        check (status in ('pending', 'approved', 'rejected', 'consumed')),

    constraint chk_approvals_action_type
        check (action_type in ('update_investigation_state')),

    constraint chk_approvals_action_payload_object
        check (jsonb_typeof(action_payload) = 'object'),

    constraint chk_approvals_requested_by_nonblank
        check (
            requested_by = btrim(requested_by)
            and btrim(requested_by) <> ''
        ),

    constraint chk_approvals_approved_by_nonblank
        check (
            approved_by is null
            or (
                approved_by = btrim(approved_by)
                and btrim(approved_by) <> ''
            )
        ),

    constraint chk_approvals_rejected_by_nonblank
        check (
            rejected_by is null
            or (
                rejected_by = btrim(rejected_by)
                and btrim(rejected_by) <> ''
            )
        ),

    constraint chk_approvals_consumed_by_nonblank
        check (
            consumed_by is null
            or (
                consumed_by = btrim(consumed_by)
                and btrim(consumed_by) <> ''
            )
        ),

    constraint chk_approvals_lifecycle_pending
        check (
            status <> 'pending'
            or (
                approved_by is null
                and approved_at is null
                and rejected_by is null
                and rejected_at is null
                and rejection_reason is null
                and consumed_by is null
                and consumed_at is null
            )
        ),

    constraint chk_approvals_lifecycle_approved
        check (
            status <> 'approved'
            or (
                approved_by is not null
                and approved_at is not null
                and rejected_by is null
                and rejected_at is null
                and rejection_reason is null
                and consumed_by is null
                and consumed_at is null
            )
        ),

    -- rejection_reason must already be outer-trimmed and nonblank; internal
    -- whitespace and case are preserved (matching the reject-transition
    -- rules already enforced by core.approval_transition).
    constraint chk_approvals_lifecycle_rejected
        check (
            status <> 'rejected'
            or (
                rejected_by is not null
                and rejected_at is not null
                and rejection_reason is not null
                and rejection_reason = btrim(rejection_reason)
                and btrim(rejection_reason) <> ''
                and approved_by is null
                and approved_at is null
                and consumed_by is null
                and consumed_at is null
            )
        ),

    constraint chk_approvals_lifecycle_consumed
        check (
            status <> 'consumed'
            or (
                approved_by is not null
                and approved_at is not null
                and consumed_by is not null
                and consumed_at is not null
                and rejected_by is null
                and rejected_at is null
                and rejection_reason is null
            )
        ),

    constraint chk_approvals_created_after_requested
        check (created_at >= requested_at),

    constraint chk_approvals_expires_after_requested
        check (expires_at is null or expires_at > requested_at),

    constraint chk_approvals_approved_after_requested
        check (approved_at is null or approved_at >= requested_at),

    -- Rejection is deliberately never compared against expires_at --
    -- rejecting an expired-but-still-pending request remains valid.
    constraint chk_approvals_rejected_after_requested
        check (rejected_at is null or rejected_at >= requested_at),

    constraint chk_approvals_consumed_after_approved
        check (
            consumed_at is null
            or (
                approved_at is not null
                and consumed_at >= approved_at
            )
        ),

    -- Approval or consumption exactly at expires_at is rejected (strict <).
    constraint chk_approvals_approved_before_expires
        check (
            approved_at is null
            or expires_at is null
            or approved_at < expires_at
        ),

    constraint chk_approvals_consumed_before_expires
        check (
            consumed_at is null
            or expires_at is null
            or consumed_at < expires_at
        )
);

comment on table approvals is
    'Persists the pure-Python-validated approval request/lifecycle contract (core/approval_request.py, core/approval_transition.py): a proposed action envelope moving through pending -> approved -> consumed, or pending -> rejected.';
comment on column approvals.action_payload is
    'The frozen proposed action envelope, validated by core.approval_request.validate_approval_request. This table checks only that it is a JSON object -- exact shape/vocabulary validation remains Python-only, to avoid duplicating (and drifting from) that logic in SQL.';
comment on column approvals.requested_by is
    'Claimed, not authenticated, requester identity.';
comment on column approvals.approved_by is
    'Claimed, not authenticated, reviewer identity. Two-person separation (reviewed_by != requested_by) is enforced only by core.approval_transition.validate_approval_transition using a trimmed Unicode casefold comparison -- PostgreSQL lower() is not equivalent (e.g. it does not fold characters such as German ß the way Python str.casefold() does), so this schema intentionally does not approximate that rule in SQL.';
comment on column approvals.consumed_by is
    'Claimed, not authenticated, identity of whatever executed the approved action.';

-- ============================================================================
-- Indexes
-- ============================================================================
create index if not exists idx_investigations_status on investigations (status);
create index if not exists idx_investigations_confidence on investigations (confidence);
create index if not exists idx_investigations_created_at on investigations (created_at);

create index if not exists idx_evidence_investigation_id on evidence (investigation_id);
create index if not exists idx_evidence_created_at on evidence (created_at);

create index if not exists idx_attack_mappings_investigation_id on attack_mappings (investigation_id);
create index if not exists idx_attack_mappings_technique_id on attack_mappings (technique_id);
create index if not exists idx_attack_mappings_created_at on attack_mappings (created_at);

create index if not exists idx_handoffs_investigation_id on handoffs (investigation_id);
create index if not exists idx_handoffs_created_at on handoffs (created_at);

create index if not exists idx_detection_results_investigation_id on detection_results (investigation_id);
create index if not exists idx_detection_results_created_at on detection_results (created_at);

create index if not exists idx_retests_investigation_id on retests (investigation_id);
create index if not exists idx_retests_created_at on retests (created_at);

create index if not exists idx_approvals_investigation_id on approvals (investigation_id);
create index if not exists idx_approvals_status on approvals (status);
create index if not exists idx_approvals_created_at on approvals (created_at);

-- ============================================================================
-- Trigger: auto-update investigations.updated_at
-- ============================================================================
create or replace function set_investigations_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

comment on function set_investigations_updated_at() is
    'Sets investigations.updated_at to the current timestamp on every row update.';

drop trigger if exists trg_investigations_updated_at on investigations;

create trigger trg_investigations_updated_at
    before update on investigations
    for each row
    execute function set_investigations_updated_at();

-- ============================================================================
-- Row Level Security
-- ----------------------------------------------------------------------------
-- RLS is enabled on every table with no permissive public-access policies
-- defined here. Access policies must be added separately based on the
-- application's actual auth model (e.g. service-role only, per-user scoping)
-- before this schema is used to serve client requests.
-- ============================================================================
alter table investigations enable row level security;
alter table evidence enable row level security;
alter table attack_mappings enable row level security;
alter table handoffs enable row level security;
alter table detection_results enable row level security;
alter table retests enable row level security;
alter table approvals enable row level security;
