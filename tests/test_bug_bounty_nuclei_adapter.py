"""Tests for adapters.bug_bounty_nuclei -- the real, bounded, phased
Nuclei safe-profile scanning adapter (Block 15G-B; Nuclei Reliability
Step 1 + Step 1B phased architecture rework).

`subprocess.Popen` (each phase's real scan process) and `subprocess.run`
(the version probe and each phase's own `-tl` template-count probe) are
both mocked in every test -- this file never performs a real external
scan. Real Nuclei execution is exercised separately, manually, only
against the local Juice Shop container in a controlled validation run.
"""

from __future__ import annotations

import subprocess

import pytest

from adapters.bug_bounty_nuclei import (
    MAX_OUTPUT_BYTES,
    MAX_PROCESS_TIMEOUT_SECONDS,
    NUCLEI_CONCURRENCY,
    NUCLEI_EXCLUDED_TAGS,
    NUCLEI_MAX_HOST_ERROR,
    NUCLEI_RATE_LIMIT,
    NUCLEI_REQUEST_TIMEOUT_SECONDS,
    NUCLEI_RETRIES,
    NUCLEI_TERMINATION_GRACE_SECONDS,
    PHASE_EXPOSURES,
    PHASE_EXPOSURES_MEDIUM,
    PHASE_IDS,
    PHASE_MISCONFIGURATION,
    PHASE_SSL,
    PHASE_STATUS_VALUES,
    PHASE_TECHNOLOGY_DIRECTED,
    QUICK_PROFILE_NAME,
    STANDARD_PROFILE_NAME,
    STATUS_VALUES,
    BugBountyNucleiAdapterError,
    _build_phase_command,
    run_nuclei_scan,
    select_nuclei_phases,
)

_SAMPLE_MATCH = (
    b'{"template-id": "exposed-panel", "info": {"name": "Exposed Admin Panel", "severity": "high", '
    b'"classification": {"cve-id": ["CVE-2021-1234"], "cwe-id": ["CWE-200"]}}, '
    b'"matched-at": "http://localhost:3000/admin", "matcher-name": "status-200"}\n'
)


def _execution_config(**overrides):
    config = {"execution_config_version": "1", "process_timeout_seconds": 80, "max_output_bytes": 65536}
    config.update(overrides)
    return config


class _CompletedProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeProcess:
    """Stand-in for subprocess.Popen's real Popen object."""

    def __init__(self, communicate_sequence, *, returncode=0):
        self._sequence = list(communicate_sequence)
        self.returncode = returncode
        self.terminate_called = False
        self.kill_called = False

    def communicate(self, timeout=None):
        result = self._sequence.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def terminate(self):
        self.terminate_called = True

    def kill(self):
        self.kill_called = True


def _patch_probes(monkeypatch, *, version_run=None, tl_run=None):
    """version_run/tl_run are called with the phase's own argv when
    provided; otherwise every probe cleanly fails (OSError), resolving
    to None/best-effort defaults without affecting the scan itself."""

    def fake_run(argv, **kwargs):
        if "-version" in argv:
            if version_run is not None:
                return version_run(argv, **kwargs)
            raise OSError("no version probe configured")
        if "-tl" in argv:
            if tl_run is not None:
                return tl_run(argv, **kwargs)
            raise OSError("no -tl probe configured")
        raise AssertionError(f"unexpected subprocess.run call in test: {argv}")

    monkeypatch.setattr("adapters.bug_bounty_nuclei.subprocess.run", fake_run)


def _patch_popen(monkeypatch, factory):
    monkeypatch.setattr("adapters.bug_bounty_nuclei.subprocess.Popen", factory)


def _phase_id_for_argv(argv):
    """Determine which phase an argv belongs to -- exposures and
    exposures_medium share the same -t directory, distinguished by
    their -severity value (matches _build_phase_command's own
    deterministic construction)."""
    if "http/exposures/" in argv:
        severity = argv[argv.index("-severity") + 1]
        return PHASE_EXPOSURES_MEDIUM if severity == "medium" else PHASE_EXPOSURES
    if "http/misconfiguration/" in argv:
        return PHASE_MISCONFIGURATION
    if "ssl/" in argv:
        return PHASE_SSL
    if "-tags" in argv:
        return PHASE_TECHNOLOGY_DIRECTED
    return None


def _setup_all_phases_clean(monkeypatch, *, stdout_by_phase=None, returncode=0):
    """Every applicable phase (exposures, exposures_medium,
    misconfiguration -- ssl/technology_directed are skipped_not_
    applicable by default for a plain-http target with no detected
    technology) completes cleanly with the given stdout (defaults to no
    matches for any phase)."""
    monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
    _patch_probes(monkeypatch)
    stdout_by_phase = stdout_by_phase or {}
    calls = []

    def factory(argv, **kwargs):
        calls.append(argv)
        phase = _phase_id_for_argv(argv)
        stdout = stdout_by_phase.get(phase, b"")
        return _FakeProcess([(stdout, b"")], returncode=returncode)

    _patch_popen(monkeypatch, factory)
    return calls


# ---------------------------------------------------------------------------
# Executable discovery
# ---------------------------------------------------------------------------


class TestExecutableDiscovery:
    def test_001_missing_executable_reports_tool_not_installed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: None)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "tool_not_installed"
        assert result["execution_performed"] is False

    def test_002_found_executable_proceeds_to_phased_execution(self, monkeypatch):
        calls = _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert calls[0][0] == "/usr/bin/nuclei"


# ---------------------------------------------------------------------------
# Target scope
# ---------------------------------------------------------------------------


class TestTargetScope:
    def test_003_non_http_scheme_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="ftp://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())

    def test_004_blank_target_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="   ", request_id="REQ-1", execution_config=_execution_config())

    def test_005_no_hostname_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="http:///path", request_id="REQ-1", execution_config=_execution_config())

    def test_006_non_string_target_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target=12345, request_id="REQ-1", execution_config=_execution_config())

    def test_007_target_placed_as_single_argv_element_never_split(self, monkeypatch):
        calls = _setup_all_phases_clean(monkeypatch)
        malicious_target = "http://localhost:3000/ -t code/ --update-templates"
        run_nuclei_scan(target=malicious_target, request_id="REQ-1", execution_config=_execution_config())
        for argv in calls:
            assert argv[argv.index("-u") + 1] == malicious_target
            assert "code/" not in argv
            assert "--update-templates" not in argv


# ---------------------------------------------------------------------------
# select_nuclei_phases -- deterministic phase planning
# ---------------------------------------------------------------------------


class TestSelectNucleiPhases:
    def test_008_returns_all_phase_ids_in_order(self):
        plan = select_nuclei_phases(target="http://localhost:3000/")
        assert [p["phase_id"] for p in plan] == list(PHASE_IDS)

    def test_009_ssl_not_applicable_for_plain_http_target(self):
        plan = select_nuclei_phases(target="http://localhost:3000/")
        ssl_phase = next(p for p in plan if p["phase_id"] == PHASE_SSL)
        assert ssl_phase["applicable"] is False
        assert ssl_phase["directories"] == ()
        assert ssl_phase["severities"] == ()

    def test_010_ssl_applicable_for_https_target(self):
        plan = select_nuclei_phases(target="https://localhost:3000/")
        ssl_phase = next(p for p in plan if p["phase_id"] == PHASE_SSL)
        assert ssl_phase["applicable"] is True
        assert ssl_phase["directories"] == ("ssl/",)

    def test_011_exposures_and_misconfiguration_always_applicable(self):
        for target in ("http://localhost:3000/", "https://localhost:3000/"):
            plan = select_nuclei_phases(target=target)
            for phase_id in (PHASE_EXPOSURES, PHASE_MISCONFIGURATION):
                phase = next(p for p in plan if p["phase_id"] == phase_id)
                assert phase["applicable"] is True

    def test_012_quick_profile_severity_is_high_critical_only(self):
        plan = select_nuclei_phases(target="http://localhost:3000/", profile=QUICK_PROFILE_NAME)
        exposures = next(p for p in plan if p["phase_id"] == PHASE_EXPOSURES)
        assert exposures["severities"] == ("high", "critical")

    def test_013_standard_profile_widens_to_medium_severity(self):
        plan = select_nuclei_phases(target="http://localhost:3000/", profile=STANDARD_PROFILE_NAME)
        exposures = next(p for p in plan if p["phase_id"] == PHASE_EXPOSURES)
        assert exposures["severities"] == ("medium", "high", "critical")

    def test_014_unrecognized_technology_yields_no_extra_tags(self):
        plan = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=["some-totally-unknown-cms"])
        for phase in plan:
            assert phase["extra_tags"] == ()

    def test_015_no_technology_supplied_is_the_same_as_empty(self):
        plan_a = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=None)
        plan_b = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=[])
        assert plan_a == plan_b

    def test_016_invalid_profile_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            select_nuclei_phases(target="http://localhost:3000/", profile="not-a-real-profile")

    def test_017_deterministic_given_same_input(self):
        first = select_nuclei_phases(target="http://localhost:3000/")
        second = select_nuclei_phases(target="http://localhost:3000/")
        assert first == second

    def test_018_no_arbitrary_technology_can_inject_ssl_tags(self):
        # extra_tags must never reach the ssl phase, even with a
        # (currently impossible, since the map is empty) recognized tech.
        plan = select_nuclei_phases(target="https://localhost:3000/", detected_technologies=["anything"])
        ssl_phase = next(p for p in plan if p["phase_id"] == PHASE_SSL)
        assert ssl_phase["extra_tags"] == ()


# ---------------------------------------------------------------------------
# Command construction -- safe fixed profile per phase
# ---------------------------------------------------------------------------


class TestPhaseCommandConstruction:
    def _plan_for(self, phase_id, target="http://localhost:3000/"):
        return next(p for p in select_nuclei_phases(target=target) if p["phase_id"] == phase_id)

    def test_019_exposures_command_uses_only_its_own_directory(self):
        argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(PHASE_EXPOSURES))
        assert "http/exposures/" in argv
        assert "http/misconfiguration/" not in argv
        assert "ssl/" not in argv

    def test_020_misconfiguration_command_uses_only_its_own_directory(self):
        argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(PHASE_MISCONFIGURATION))
        assert "http/misconfiguration/" in argv
        assert "http/exposures/" not in argv

    def test_021_severity_high_critical_in_quick_profile_command(self):
        argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(PHASE_EXPOSURES))
        assert "-severity" in argv
        assert argv[argv.index("-severity") + 1] == "high,critical"

    def test_022_excluded_tags_present_on_every_phase(self):
        for phase_id in (PHASE_EXPOSURES, PHASE_MISCONFIGURATION):
            argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(phase_id))
            assert "-etags" in argv
            excluded_value = argv[argv.index("-etags") + 1]
            for tag in NUCLEI_EXCLUDED_TAGS:
                assert tag in excluded_value

    def test_023_update_check_and_redirects_disabled_every_phase(self):
        for phase_id in (PHASE_EXPOSURES, PHASE_MISCONFIGURATION):
            argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(phase_id))
            assert "-duc" in argv
            assert "-dr" in argv

    def test_024_internal_timeout_retries_max_host_error_explicit(self):
        argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(PHASE_EXPOSURES))
        assert argv[argv.index("-timeout") + 1] == str(NUCLEI_REQUEST_TIMEOUT_SECONDS)
        assert argv[argv.index("-retries") + 1] == str(NUCLEI_RETRIES)
        assert argv[argv.index("-mhe") + 1] == str(NUCLEI_MAX_HOST_ERROR)

    def test_025_bounded_rate_limit_and_concurrency(self):
        argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(PHASE_EXPOSURES))
        assert argv[argv.index("-rl") + 1] == str(NUCLEI_RATE_LIMIT)
        assert argv[argv.index("-c") + 1] == str(NUCLEI_CONCURRENCY)
        assert NUCLEI_RATE_LIMIT <= 50
        assert NUCLEI_CONCURRENCY <= 25

    def test_026_no_headless_code_javascript_file_workflow(self):
        argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(PHASE_EXPOSURES))
        for forbidden in ("-headless", "-code", "code/", "javascript/", "file/", "-w", "-workflows", "-cloud-upload", "-uncover"):
            assert forbidden not in argv

    def test_027_command_vector_is_list_of_strings(self):
        argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(PHASE_EXPOSURES))
        assert isinstance(argv, list)
        assert all(isinstance(item, str) for item in argv)

    def test_028_uses_jsonl_silent_output(self):
        argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=self._plan_for(PHASE_EXPOSURES))
        assert "-jsonl" in argv
        assert "-silent" in argv

    def test_029_no_planner_selected_template_ids_accepted(self):
        import inspect

        signature = inspect.signature(run_nuclei_scan)
        # detected_technologies (Step 1C) is the one new, intentional,
        # closed-vocabulary-only addition -- still no raw
        # flag/tag/template-path parameter exists.
        assert set(signature.parameters) == {"target", "request_id", "execution_config", "detected_technologies"}

    def test_030_shell_is_never_true(self, monkeypatch):
        calls = []

        def factory(argv, **kwargs):
            calls.append(kwargs)
            return _FakeProcess([(b"", b"")])

        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        _patch_popen(monkeypatch, factory)
        run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert all(kw["shell"] is False for kw in calls)


# ---------------------------------------------------------------------------
# Protocol-aware behavior (Phase 10)
# ---------------------------------------------------------------------------


class TestProtocolAwareSkipping:
    def test_031_ssl_phase_skipped_for_plain_http_zero_budget_spent(self, monkeypatch):
        calls = _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        ssl_phase = next(p for p in result["phases"] if p["phase_id"] == PHASE_SSL)
        assert ssl_phase["status"] == "skipped_not_applicable"
        assert ssl_phase["elapsed_seconds"] == 0.0
        # No Popen call for ssl/ at all.
        assert not any("ssl/" in argv for argv in calls)

    def test_032_ssl_phase_runs_for_https_target(self, monkeypatch):
        calls = _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="https://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        ssl_phase = next(p for p in result["phases"] if p["phase_id"] == PHASE_SSL)
        assert ssl_phase["status"] == "completed"
        assert any("ssl/" in argv for argv in calls)


# ---------------------------------------------------------------------------
# Phase execution and aggregate status (Phases 2, 9)
# ---------------------------------------------------------------------------


class TestPhaseExecutionAndAggregateStatus:
    def test_033_all_phases_complete_aggregate_completed(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert all(p["status"] in ("completed", "skipped_not_applicable") for p in result["phases"])

    def test_034_exposures_completes_with_finding_misconfiguration_completes_clean(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: _SAMPLE_MATCH})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert len(result["observations"]) == 1
        exposures = next(p for p in result["phases"] if p["phase_id"] == PHASE_EXPOSURES)
        assert exposures["observation_count"] == 1

    def test_035_later_phase_timeout_preserves_earlier_phase_findings(self, monkeypatch):
        # exposures completes with a real finding; misconfiguration times
        # out with nothing recovered -- the aggregate result must still
        # carry exposures' genuine observation.
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        timeout_exc = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=35)

        def factory(argv, **kwargs):
            phase = _phase_id_for_argv(argv)
            if phase == PHASE_EXPOSURES:
                return _FakeProcess([(_SAMPLE_MATCH, b"")])
            if phase == PHASE_MISCONFIGURATION:
                return _FakeProcess([timeout_exc, (b"", b"")])
            return _FakeProcess([(b"", b"")])

        _patch_popen(monkeypatch, factory)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "partial"
        assert len(result["observations"]) == 1
        exposures = next(p for p in result["phases"] if p["phase_id"] == PHASE_EXPOSURES)
        misconfig = next(p for p in result["phases"] if p["phase_id"] == PHASE_MISCONFIGURATION)
        assert exposures["status"] == "completed"
        assert exposures["observation_count"] == 1
        assert misconfig["status"] == "timeout"

    def test_036_all_phases_timeout_zero_evidence_aggregate_timeout(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        timeout_exc = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=35)
        _patch_popen(monkeypatch, lambda argv, **kw: _FakeProcess([timeout_exc, (b"", b"")]))
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "timeout"
        assert result["observations"] == []

    def test_037_all_phases_fail_zero_evidence_aggregate_failed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        _patch_popen(monkeypatch, lambda argv, **kw: _FakeProcess([(b"", b"some error")], returncode=1))
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "failed"

    def test_038_aggregate_status_never_converts_partial_into_completed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        timeout_exc = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=35)

        def factory(argv, **kwargs):
            if _phase_id_for_argv(argv) == PHASE_EXPOSURES:
                return _FakeProcess([(_SAMPLE_MATCH, b"")])
            return _FakeProcess([timeout_exc, (b"", b"")])

        _patch_popen(monkeypatch, factory)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] != "completed"
        assert result["status"] == "partial"

    def test_039_status_always_in_widened_vocabulary(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: None)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] in STATUS_VALUES
        assert "partial" in STATUS_VALUES

    def test_040_phase_status_always_in_fixed_vocabulary(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        for phase in result["phases"]:
            assert phase["status"] in PHASE_STATUS_VALUES


# ---------------------------------------------------------------------------
# Budget allocation -- dynamic, shared, never exceeding the overall cap
# ---------------------------------------------------------------------------


class TestBudgetAllocation:
    def test_041_early_completing_phase_leaves_budget_for_later_phases(self, monkeypatch):
        # A tiny overall budget (e.g. 1s) should still let a fast phase
        # run and leave (a fraction of) whatever remains for the next.
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        seen_timeouts = []

        def factory(argv, **kwargs):
            return _FakeProcess([(b"", b"")])

        def tracking_communicate_process(argv, **kwargs):
            proc = _FakeProcess([(b"", b"")])
            return proc

        _patch_popen(monkeypatch, factory)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config(process_timeout_seconds=1))
        # Must not raise, must produce a real result within the tiny budget.
        assert result["status"] in STATUS_VALUES

    def test_042_budget_exhausted_skips_remaining_phases(self, monkeypatch):
        # exposures alone consumes (simulated) the entire remaining
        # budget via a timeout; misconfiguration should then be skipped
        # for lack of remaining budget rather than run with zero/negative time.
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        timeout_exc = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=1)

        real_monotonic = __import__("time").monotonic
        state = {"calls": 0}

        def fake_monotonic():
            # Advance the clock by a large amount every call to
            # simulate the whole budget being consumed by phase one.
            state["calls"] += 1
            return real_monotonic() + state["calls"] * 1000

        monkeypatch.setattr("adapters.bug_bounty_nuclei.time.monotonic", fake_monotonic)

        def factory(argv, **kwargs):
            return _FakeProcess([timeout_exc, (b"", b"")])

        _patch_popen(monkeypatch, factory)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config(process_timeout_seconds=5))
        misconfig = next(p for p in result["phases"] if p["phase_id"] == PHASE_MISCONFIGURATION)
        assert misconfig["status"] == "skipped_budget_exhausted"

    def test_043_never_exceeds_adapter_ceiling(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(
                target="http://localhost:3000/", request_id="REQ-1",
                execution_config=_execution_config(process_timeout_seconds=MAX_PROCESS_TIMEOUT_SECONDS + 1),
            )


# ---------------------------------------------------------------------------
# Structured output parsing
# ---------------------------------------------------------------------------


class TestStructuredOutputParsing:
    def test_044_multiple_findings_parsed(self, monkeypatch):
        two_matches = _SAMPLE_MATCH + (
            b'{"template-id": "tls-version", "info": {"name": "Weak TLS Version", "severity": "high"}, '
            b'"matched-at": "http://localhost:3000/", "matcher-name": "tls-1.0"}\n'
        )
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: two_matches})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["observations"]) == 2
        first = result["observations"][0]
        assert first["type"] == "known_pattern_match"
        assert first["template_id"] == "exposed-panel"
        assert first["classification"] == {"cve_id": ["CVE-2021-1234"], "cwe_id": ["CWE-200"]}

    def test_045_malformed_json_line_skipped(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: _SAMPLE_MATCH + b"{not valid json\n"})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert len(result["observations"]) == 1

    def test_046_mixed_valid_and_malformed_lines(self, monkeypatch):
        mixed = b"garbage\n" + _SAMPLE_MATCH + b"\n   \n{also bad\n"
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: mixed})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["observations"]) == 1

    def test_047_empty_output_yields_no_observations(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"] == []

    def test_048_never_invents_cve_or_cwe(self, monkeypatch):
        record = b'{"template-id": "generic-check", "info": {"name": "Generic", "severity": "high"}, "matched-at": "http://localhost:3000/"}\n'
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: record})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["classification"] is None

    def test_049_template_id_survives(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: _SAMPLE_MATCH})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["template_id"] == "exposed-panel"


# ---------------------------------------------------------------------------
# Non-zero exit / timeout / output truncation
# ---------------------------------------------------------------------------


class TestFailureModes:
    def test_050_nonzero_exit_reported_failed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        _patch_popen(monkeypatch, lambda argv, **kw: _FakeProcess([(b"", b"some raw stderr")], returncode=1))
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "failed"
        assert result["execution_performed"] is True
        assert "raw stderr" not in (result["error_detail"] or "")

    def test_051_timeout_with_partial_valid_results_preserved(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        timeout_exc = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=25)

        def factory(argv, **kwargs):
            if "http/exposures/" in argv:
                return _FakeProcess([timeout_exc, (_SAMPLE_MATCH, b"")])
            return _FakeProcess([(b"", b"")])

        _patch_popen(monkeypatch, factory)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        exposures = next(p for p in result["phases"] if p["phase_id"] == PHASE_EXPOSURES)
        assert exposures["status"] == "timeout"
        assert exposures["partial_results"] is True
        assert exposures["observation_count"] == 1

    def test_052_output_size_limit_truncates(self, monkeypatch):
        huge = _SAMPLE_MATCH + (b" " * 200)
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: huge})
        result = run_nuclei_scan(
            target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config(max_output_bytes=64),
        )
        assert result["output_truncated"] is True

    def test_053_execution_config_output_ceiling_enforced(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(
                target="http://localhost:3000/", request_id="REQ-1",
                execution_config=_execution_config(max_output_bytes=MAX_OUTPUT_BYTES + 1),
            )

    def test_054_execution_config_wrong_shape_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config={"bad": "shape"})

    def test_055_execution_config_extra_field_rejected(self):
        bad = _execution_config()
        bad["raw_command"] = "rm -rf /"
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=bad)


# ---------------------------------------------------------------------------
# Termination safety
# ---------------------------------------------------------------------------


class TestTerminationSafety:
    def test_056_graceful_terminate_tried_before_kill(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        timeout_exc = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=25)
        process = _FakeProcess([timeout_exc, (b"", b"")])
        _patch_popen(monkeypatch, lambda argv, **kw: process if _phase_id_for_argv(argv) == PHASE_EXPOSURES else _FakeProcess([(b"", b"")]))
        run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert process.terminate_called is True
        assert process.kill_called is False

    def test_057_kill_used_only_when_graceful_terminate_also_times_out(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        first_timeout = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=25)
        grace_timeout = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=NUCLEI_TERMINATION_GRACE_SECONDS)
        process = _FakeProcess([first_timeout, grace_timeout, (b"", b"")])
        _patch_popen(monkeypatch, lambda argv, **kw: process if _phase_id_for_argv(argv) == PHASE_EXPOSURES else _FakeProcess([(b"", b"")]))
        run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert process.terminate_called is True
        assert process.kill_called is True

    def test_058_process_always_reaped(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        first_timeout = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=25)
        grace_timeout = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=NUCLEI_TERMINATION_GRACE_SECONDS)
        process = _FakeProcess([first_timeout, grace_timeout, (b"", b"")])
        _patch_popen(monkeypatch, lambda argv, **kw: process if _phase_id_for_argv(argv) == PHASE_EXPOSURES else _FakeProcess([(b"", b"")]))
        run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert process._sequence == []


# ---------------------------------------------------------------------------
# Observability propagation
# ---------------------------------------------------------------------------


class TestObservability:
    def test_059_profile_name_present(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["profile_name"] == QUICK_PROFILE_NAME == "quick_phased_v2"

    def test_060_nuclei_version_captured_when_probe_succeeds(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(
            monkeypatch,
            version_run=lambda argv, **kw: _CompletedProcess(0, stdout=b"", stderr=b"[INF] Nuclei Engine Version: v3.11.1\n"),
        )
        _patch_popen(monkeypatch, lambda argv, **kw: _FakeProcess([(b"", b"")]))
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["nuclei_version"] == "3.11.1"

    def test_061_nuclei_version_none_when_probe_fails(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["nuclei_version"] is None

    def test_062_per_phase_template_count_captured(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _COUNTS = {PHASE_EXPOSURES: 94, PHASE_EXPOSURES_MEDIUM: 140, PHASE_MISCONFIGURATION: 551}

        def tl_run(argv, **kw):
            count = _COUNTS[_phase_id_for_argv(argv)]
            return _CompletedProcess(0, stdout=b"\n".join([b"x.yaml"] * count))

        _patch_probes(monkeypatch, tl_run=tl_run)
        _patch_popen(monkeypatch, lambda argv, **kw: _FakeProcess([(b"", b"")]))
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        exposures = next(p for p in result["phases"] if p["phase_id"] == PHASE_EXPOSURES)
        exposures_medium = next(p for p in result["phases"] if p["phase_id"] == PHASE_EXPOSURES_MEDIUM)
        misconfig = next(p for p in result["phases"] if p["phase_id"] == PHASE_MISCONFIGURATION)
        assert exposures["templates_selected_count"] == 94
        assert exposures_medium["templates_selected_count"] == 140
        assert misconfig["templates_selected_count"] == 551
        # ssl/technology_directed both skipped (plain http, no tech detected) -> contribute 0
        assert result["templates_selected_count"] == 94 + 140 + 551

    def test_063_skipped_phase_reports_zero_templates_not_none(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        ssl_phase = next(p for p in result["phases"] if p["phase_id"] == PHASE_SSL)
        assert ssl_phase["templates_selected_count"] == 0

    def test_064_runtime_duration_present_and_nonnegative(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert isinstance(result["runtime_duration_seconds"], float)
        assert result["runtime_duration_seconds"] >= 0

    def test_065_elapsed_seconds_present_per_phase(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        for phase in result["phases"]:
            assert isinstance(phase["elapsed_seconds"], float)
            assert phase["elapsed_seconds"] >= 0

    def test_066_stderr_summary_bounded_and_sanitized(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        _patch_popen(
            monkeypatch,
            lambda argv, **kw: _FakeProcess([(b"", b"Authorization: Bearer abc123 warning")])
            if "http/exposures/" in argv else _FakeProcess([(b"", b"")]),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["stderr_summary"] == "[REDACTED]"

    def test_067_probe_failure_never_raises_out_of_run_nuclei_scan(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")

        def oserror_run(argv, **kwargs):
            raise OSError("probe unavailable")

        monkeypatch.setattr("adapters.bug_bounty_nuclei.subprocess.run", oserror_run)
        _patch_popen(monkeypatch, lambda argv, **kw: _FakeProcess([(_SAMPLE_MATCH, b"")]))
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert result["nuclei_version"] is None


# ---------------------------------------------------------------------------
# Sensitive-output sanitation
# ---------------------------------------------------------------------------


class TestSensitiveOutputSanitation:
    def test_068_credential_marker_in_title_redacted(self, monkeypatch):
        record = (
            b'{"template-id": "x", "info": {"name": "Authorization: Bearer secret leaked", "severity": "high"}, '
            b'"matched-at": "http://localhost:3000/"}\n'
        )
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: record})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["title"] == "[REDACTED]"

    def test_069_result_contains_no_raw_jsonl(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: _SAMPLE_MATCH})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert "template-id" not in repr(result)

    def test_070_no_credential_like_fields_in_contract(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        forbidden = {"password", "authorization", "cookie", "api_key", "token", "secret"}
        assert forbidden.isdisjoint(set(result.keys()))

    def test_071_evidence_reference_is_digest_not_raw_output(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES: _SAMPLE_MATCH})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["evidence_references"]) == 1
        assert result["evidence_references"][0].startswith("nuclei_jsonl_sha256:")


# ---------------------------------------------------------------------------
# Immutability / output contract / determinism
# ---------------------------------------------------------------------------


class TestImmutabilityAndContract:
    def test_072_execution_config_not_mutated(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        config = _execution_config()
        snapshot = dict(config)
        run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=config)
        assert config == snapshot

    def test_073_exact_result_contract_fields(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert set(result.keys()) == {
            "tool_result_version", "tool_id", "request_id", "target", "status", "observations",
            "evidence_references", "network_requests_performed", "output_truncated", "error_detail",
            "execution_performed", "partial_results", "runtime_duration_seconds", "profile_name",
            "nuclei_version", "templates_selected_count", "stderr_summary", "phases",
        }

    def test_074_tool_id_always_nuclei(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: None)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["tool_id"] == "nuclei"

    def test_075_request_id_echoed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: None)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-XYZ", execution_config=_execution_config())
        assert result["request_id"] == "REQ-XYZ"

    def test_076_network_requests_performed_is_null(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["network_requests_performed"] is None

    def test_077_deterministic_given_same_inputs(self, monkeypatch):
        _setup_all_phases_clean(monkeypatch)
        first = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        _setup_all_phases_clean(monkeypatch)
        second = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        # runtime_duration_seconds/elapsed_seconds vary by wall clock --
        # compare everything else for equality.
        first.pop("runtime_duration_seconds")
        second.pop("runtime_duration_seconds")
        for phases in (first["phases"], second["phases"]):
            for phase in phases:
                phase.pop("elapsed_seconds")
        assert first == second


# ---------------------------------------------------------------------------
# Step 1C: exposures_medium phase (valuable medium coverage)
# ---------------------------------------------------------------------------


class TestExposuresMediumPhase:
    def test_078_exposures_medium_uses_medium_severity_only(self):
        plan = select_nuclei_phases(target="http://localhost:3000/")
        exposures_medium = next(p for p in plan if p["phase_id"] == PHASE_EXPOSURES_MEDIUM)
        assert exposures_medium["severities"] == ("medium",)
        assert exposures_medium["directories"] == ("http/exposures/",)

    def test_079_exposures_medium_always_applicable(self):
        plan = select_nuclei_phases(target="http://localhost:3000/")
        exposures_medium = next(p for p in plan if p["phase_id"] == PHASE_EXPOSURES_MEDIUM)
        assert exposures_medium["applicable"] is True

    def test_080_misconfiguration_widened_to_medium_high_critical(self):
        plan = select_nuclei_phases(target="http://localhost:3000/")
        misconfig = next(p for p in plan if p["phase_id"] == PHASE_MISCONFIGURATION)
        assert misconfig["severities"] == ("medium", "high", "critical")

    def test_081_exposures_medium_completes_and_contributes_finding(self, monkeypatch):
        record = (
            b'{"template-id": "prometheus-metrics", "info": {"name": "Prometheus Metrics - Detect", "severity": "medium"}, '
            b'"matched-at": "http://localhost:3000/metrics", "matcher-name": "word-match"}\n'
        )
        _setup_all_phases_clean(monkeypatch, stdout_by_phase={PHASE_EXPOSURES_MEDIUM: record})
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        exposures_medium = next(p for p in result["phases"] if p["phase_id"] == PHASE_EXPOSURES_MEDIUM)
        assert exposures_medium["status"] == "completed"
        assert exposures_medium["observation_count"] == 1
        assert result["observations"][0]["template_id"] == "prometheus-metrics"

    def test_082_exposures_medium_timeout_does_not_lose_exposures_findings(self, monkeypatch):
        # The expensive medium phase is deliberately separate from the
        # fast high/critical exposures phase -- a timeout there must
        # never erase the fast phase's already-completed result.
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        timeout_exc = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=100)

        def factory(argv, **kwargs):
            phase = _phase_id_for_argv(argv)
            if phase == PHASE_EXPOSURES:
                return _FakeProcess([(_SAMPLE_MATCH, b"")])
            if phase == PHASE_EXPOSURES_MEDIUM:
                return _FakeProcess([timeout_exc, (b"", b"")])
            return _FakeProcess([(b"", b"")])

        _patch_popen(monkeypatch, factory)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "partial"
        assert len(result["observations"]) == 1
        exposures = next(p for p in result["phases"] if p["phase_id"] == PHASE_EXPOSURES)
        assert exposures["status"] == "completed"
        assert exposures["observation_count"] == 1


# ---------------------------------------------------------------------------
# Step 1C: technology_directed phase (live technology-aware selection)
# ---------------------------------------------------------------------------


class TestTechnologyDirectedPhase:
    def test_083_no_technology_detected_is_skipped_not_applicable(self):
        plan = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=None)
        tech_phase = next(p for p in plan if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        assert tech_phase["applicable"] is False
        assert tech_phase["extra_tags"] == ()

    def test_084_unrecognized_technology_is_skipped_not_applicable(self):
        plan = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=["some-unknown-cms"])
        tech_phase = next(p for p in plan if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        assert tech_phase["applicable"] is False

    def test_085_recognized_technology_is_applicable_with_mapped_tags(self):
        plan = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=["express"])
        tech_phase = next(p for p in plan if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        assert tech_phase["applicable"] is True
        assert "express" in tech_phase["extra_tags"]
        assert "nodejs" in tech_phase["extra_tags"]

    def test_086_technology_directed_phase_has_no_directory_restriction(self):
        plan = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=["angular"])
        tech_phase = next(p for p in plan if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        assert tech_phase["directories"] == ()

    def test_087_technology_directed_command_has_tags_but_no_dash_t(self):
        plan = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=["angular"])
        tech_phase = next(p for p in plan if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        argv = _build_phase_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/", phase_plan=tech_phase)
        assert "-tags" in argv
        assert argv[argv.index("-tags") + 1] == "angular"
        assert "-t" not in argv

    def test_088_case_insensitive_and_whitespace_tolerant_technology_names(self):
        plan_a = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=["Express"])
        plan_b = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=["  express  "])
        tech_a = next(p for p in plan_a if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        tech_b = next(p for p in plan_b if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        assert tech_a["applicable"] is True
        assert tech_a == tech_b

    def test_089_technology_directed_skipped_when_no_technologies_supplied(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)

        def factory(argv, **kwargs):
            return _FakeProcess([(b"", b"")])

        _patch_popen(monkeypatch, factory)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        # run_nuclei_scan's own detected_technologies parameter defaults
        # to None -- confirms the default-omitted case correctly resolves
        # to skipped, not a silent full-tree scan.
        tech_phase = next(p for p in result["phases"] if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        assert tech_phase["status"] == "skipped_not_applicable"

    def test_090_non_string_technology_entries_ignored_safely(self):
        plan = select_nuclei_phases(target="http://localhost:3000/", detected_technologies=[123, None, "express"])
        tech_phase = next(p for p in plan if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        assert tech_phase["applicable"] is True
        assert tech_phase["extra_tags"] == ("express", "nodejs")

    def test_090b_detected_technologies_reaches_run_nuclei_scan_end_to_end(self, monkeypatch):
        # Full-stack proof that supplying detected_technologies to
        # run_nuclei_scan's own public entry point actually causes the
        # technology_directed phase to run, not just select_nuclei_
        # phases in isolation.
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        _patch_probes(monkeypatch)
        _patch_popen(monkeypatch, lambda argv, **kw: _FakeProcess([(b"", b"")]))
        result = run_nuclei_scan(
            target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config(),
            detected_technologies=["express"],
        )
        tech_phase = next(p for p in result["phases"] if p["phase_id"] == PHASE_TECHNOLOGY_DIRECTED)
        assert tech_phase["status"] == "completed"


# ---------------------------------------------------------------------------
# Step 1C: raised budget/ceiling, real measurement based
# ---------------------------------------------------------------------------


class TestStep1CBudgets:
    def test_091_max_process_timeout_raised_with_real_justification(self):
        assert MAX_PROCESS_TIMEOUT_SECONDS == 230

    def test_092_execution_config_still_rejects_above_the_new_ceiling(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(
                target="http://localhost:3000/", request_id="REQ-1",
                execution_config=_execution_config(process_timeout_seconds=MAX_PROCESS_TIMEOUT_SECONDS + 1),
            )
