"""Tests for adapters.bug_bounty_nuclei -- the real, bounded Nuclei
safe-profile scanning adapter (Block 15G-B).

`subprocess.run` and `shutil.which` are mocked in every test -- this
file never performs a real external scan. Real Nuclei execution is
exercised separately, manually, only against the local Juice Shop
container (see docs/block15g-nmap-nuclei-adapters.md).
"""

from __future__ import annotations

import subprocess

import pytest

from adapters.bug_bounty_nuclei import (
    MAX_OUTPUT_BYTES,
    MAX_PROCESS_TIMEOUT_SECONDS,
    NUCLEI_CONCURRENCY,
    NUCLEI_RATE_LIMIT,
    NUCLEI_TEMPLATE_DIRECTORIES,
    STATUS_VALUES,
    BugBountyNucleiAdapterError,
    _build_nuclei_command,
    run_nuclei_scan,
)

_SAMPLE_MATCH = (
    b'{"template-id": "exposed-panel", "info": {"name": "Exposed Admin Panel", "severity": "medium", '
    b'"classification": {"cve-id": ["CVE-2021-1234"], "cwe-id": ["CWE-200"]}}, '
    b'"matched-at": "http://localhost:3000/admin", "matcher-name": "status-200"}\n'
    b'{"template-id": "tls-version", "info": {"name": "Weak TLS Version", "severity": "low"}, '
    b'"matched-at": "http://localhost:3000/", "matcher-name": "tls-1.0"}\n'
)


def _execution_config(**overrides):
    config = {"execution_config_version": "1", "process_timeout_seconds": 45, "max_output_bytes": 65536}
    config.update(overrides)
    return config


class _CompletedProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# Executable discovery
# ---------------------------------------------------------------------------


class TestExecutableDiscovery:
    def test_001_missing_executable_reports_tool_not_installed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: None)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "tool_not_installed"
        assert result["execution_performed"] is False

    def test_002_found_executable_proceeds_to_subprocess(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        called = {}

        def fake_run(argv, **kwargs):
            called["argv"] = argv
            return _CompletedProcess(0, stdout=_SAMPLE_MATCH)

        monkeypatch.setattr("adapters.bug_bounty_nuclei.subprocess.run", fake_run)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert called["argv"][0] == "/usr/bin/nuclei"

    def test_003_oserror_on_launch_reports_tool_not_installed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")

        def fake_run(argv, **kwargs):
            raise OSError("no such file")

        monkeypatch.setattr("adapters.bug_bounty_nuclei.subprocess.run", fake_run)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "tool_not_installed"
        assert result["execution_performed"] is False


# ---------------------------------------------------------------------------
# Target scope
# ---------------------------------------------------------------------------


class TestTargetScope:
    def test_004_exact_target_only(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        captured = {}

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            return _CompletedProcess(0, stdout=_SAMPLE_MATCH)

        monkeypatch.setattr("adapters.bug_bounty_nuclei.subprocess.run", fake_run)
        run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert "http://localhost:3000/" in captured["argv"]

    def test_005_non_http_scheme_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="ftp://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())

    def test_006_blank_target_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="   ", request_id="REQ-1", execution_config=_execution_config())

    def test_007_no_hostname_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="http:///path", request_id="REQ-1", execution_config=_execution_config())

    def test_008_non_string_target_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target=12345, request_id="REQ-1", execution_config=_execution_config())

    def test_009_https_target_accepted(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        result = run_nuclei_scan(target="https://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["target"] == "https://localhost:3000/"


# ---------------------------------------------------------------------------
# Safe fixed profile
# ---------------------------------------------------------------------------


class TestSafeFixedProfile:
    def test_010_uses_http_and_ssl_template_directories_only(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert NUCLEI_TEMPLATE_DIRECTORIES == ("http/", "ssl/")
        for directory in NUCLEI_TEMPLATE_DIRECTORIES:
            assert directory in argv

    def test_011_no_fuzzing(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-etags" in argv
        assert "fuzz" in argv[argv.index("-etags") + 1]

    def test_012_no_oast_interactsh(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-ni" in argv
        assert "-interactsh-server" not in argv

    def test_013_no_headless_flag(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-headless" not in argv

    def test_014_no_code_or_javascript_templates(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-code" not in argv
        assert "-enable-code-templates" not in argv
        assert "code/" not in argv
        assert "javascript/" not in argv

    def test_015_no_authentication_flags(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-secret-file" not in argv
        assert not any(item.startswith("-a") and item not in ("-a",) for item in argv)

    def test_016_no_cloud_upload(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-cloud-upload" not in argv

    def test_017_no_uncover_discovery(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-uncover" not in argv

    def test_018_no_file_or_workflow_templates(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "file/" not in argv
        assert "-w" not in argv
        assert "-workflows" not in argv

    def test_019_no_planner_selected_template_ids_accepted(self):
        # run_nuclei_scan has no template_id/tags parameter at all.
        import inspect

        signature = inspect.signature(run_nuclei_scan)
        assert set(signature.parameters) == {"target", "request_id", "execution_config"}


# ---------------------------------------------------------------------------
# Rate limit / concurrency
# ---------------------------------------------------------------------------


class TestRateLimitAndConcurrency:
    def test_020_bounded_rate_limit(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-rl" in argv
        assert argv[argv.index("-rl") + 1] == str(NUCLEI_RATE_LIMIT)
        assert NUCLEI_RATE_LIMIT <= 50  # well under nuclei's own higher default

    def test_021_bounded_concurrency(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-c" in argv
        assert argv[argv.index("-c") + 1] == str(NUCLEI_CONCURRENCY)
        assert NUCLEI_CONCURRENCY <= 25


# ---------------------------------------------------------------------------
# Deterministic command vector
# ---------------------------------------------------------------------------


class TestCommandVector:
    def test_022_deterministic_command_vector(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert argv == [
            "/usr/bin/nuclei", "-u", "http://localhost:3000/",
            "-t", "http/", "-t", "ssl/",
            "-etags", "fuzz", "-ni", "-rl", "10", "-c", "5", "-jsonl", "-silent",
        ]

    def test_023_command_vector_is_a_list_not_a_string(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert isinstance(argv, list)
        assert all(isinstance(item, str) for item in argv)

    def test_024_shell_is_never_true(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        captured = {}

        def fake_run(argv, **kwargs):
            captured["kwargs"] = kwargs
            return _CompletedProcess(0, stdout=_SAMPLE_MATCH)

        monkeypatch.setattr("adapters.bug_bounty_nuclei.subprocess.run", fake_run)
        run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert captured["kwargs"]["shell"] is False

    def test_025_uses_jsonl_output(self):
        argv = _build_nuclei_command(nuclei_path="/usr/bin/nuclei", target="http://localhost:3000/")
        assert "-jsonl" in argv


# ---------------------------------------------------------------------------
# Structured output parsing
# ---------------------------------------------------------------------------


class TestStructuredOutputParsing:
    def test_026_multiple_findings_parsed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["observations"]) == 2
        first = result["observations"][0]
        assert first["type"] == "known_pattern_match"
        assert first["template_id"] == "exposed-panel"
        assert first["title"] == "Exposed Admin Panel"
        assert first["severity"] == "medium"
        assert first["target"] == "http://localhost:3000/admin"
        assert first["matcher"] == "status-200"
        assert first["classification"] == {"cve_id": ["CVE-2021-1234"], "cwe_id": ["CWE-200"]}

    def test_027_finding_without_classification_yields_null(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        second = result["observations"][1]
        assert second["classification"] is None

    def test_028_malformed_json_line_skipped(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        broken = _SAMPLE_MATCH + b"{not valid json\n"
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=broken),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert len(result["observations"]) == 2

    def test_029_empty_output_yields_no_observations(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=b""),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert result["observations"] == []

    def test_030_never_invents_cve_or_cwe(self, monkeypatch):
        record = b'{"template-id": "generic-check", "info": {"name": "Generic", "severity": "info"}, "matched-at": "http://localhost:3000/"}\n'
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=record),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["classification"] is None


# ---------------------------------------------------------------------------
# Non-zero exit / timeout / output truncation
# ---------------------------------------------------------------------------


class TestFailureModes:
    def test_031_nonzero_exit_reported_failed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run",
            lambda argv, **kw: _CompletedProcess(1, stdout=b"", stderr=b"some raw stderr"),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "failed"
        assert result["execution_performed"] is True
        assert "raw stderr" not in (result["error_detail"] or "")

    def test_032_timeout_reported(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")

        def fake_run(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 45))

        monkeypatch.setattr("adapters.bug_bounty_nuclei.subprocess.run", fake_run)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "timeout"
        assert result["execution_performed"] is True

    def test_033_output_size_limit_truncates(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        huge = _SAMPLE_MATCH + (b" " * 200)
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=huge),
        )
        result = run_nuclei_scan(
            target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config(max_output_bytes=64),
        )
        assert result["output_truncated"] is True

    def test_034_output_within_limit_not_truncated(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["output_truncated"] is False

    def test_035_execution_config_timeout_ceiling_enforced(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(
                target="http://localhost:3000/", request_id="REQ-1",
                execution_config=_execution_config(process_timeout_seconds=MAX_PROCESS_TIMEOUT_SECONDS + 1),
            )

    def test_036_execution_config_output_ceiling_enforced(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(
                target="http://localhost:3000/", request_id="REQ-1",
                execution_config=_execution_config(max_output_bytes=MAX_OUTPUT_BYTES + 1),
            )

    def test_037_execution_config_wrong_shape_rejected(self):
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config={"bad": "shape"})

    def test_038_execution_config_extra_field_rejected(self):
        bad = _execution_config()
        bad["raw_command"] = "rm -rf /"
        with pytest.raises(BugBountyNucleiAdapterError):
            run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=bad)


# ---------------------------------------------------------------------------
# Sensitive-output sanitation
# ---------------------------------------------------------------------------


class TestSensitiveOutputSanitation:
    def test_039_credential_marker_in_title_redacted(self, monkeypatch):
        record = (
            b'{"template-id": "x", "info": {"name": "Authorization: Bearer secret leaked", "severity": "high"}, '
            b'"matched-at": "http://localhost:3000/"}\n'
        )
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=record),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["title"] == "[REDACTED]"

    def test_040_result_contains_no_raw_jsonl(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert "template-id" not in repr(result)

    def test_041_no_credential_like_fields_in_contract(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        forbidden = {"password", "authorization", "cookie", "api_key", "token", "secret"}
        assert forbidden.isdisjoint(set(result.keys()))

    def test_042_evidence_reference_is_digest_not_raw_output(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["evidence_references"]) == 1
        assert result["evidence_references"][0].startswith("nuclei_jsonl_sha256:")


# ---------------------------------------------------------------------------
# Immutability / output contract / determinism
# ---------------------------------------------------------------------------


class TestImmutabilityAndContract:
    def test_043_execution_config_not_mutated(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        config = _execution_config()
        snapshot = dict(config)
        run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=config)
        assert config == snapshot

    def test_044_exact_result_contract_fields(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert set(result.keys()) == {
            "tool_result_version", "tool_id", "request_id", "target", "status", "observations",
            "evidence_references", "network_requests_performed", "output_truncated", "error_detail",
            "execution_performed",
        }

    def test_045_tool_id_always_nuclei(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: None)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["tool_id"] == "nuclei"

    def test_046_status_always_in_fixed_vocabulary(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: None)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] in STATUS_VALUES

    def test_047_request_id_echoed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: None)
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-XYZ", execution_config=_execution_config())
        assert result["request_id"] == "REQ-XYZ"

    def test_048_deterministic_given_same_inputs(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        first = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        second = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert first == second

    def test_049_network_requests_performed_is_null(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nuclei.shutil.which", lambda name: "/usr/bin/nuclei")
        monkeypatch.setattr(
            "adapters.bug_bounty_nuclei.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_MATCH),
        )
        result = run_nuclei_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["network_requests_performed"] is None
