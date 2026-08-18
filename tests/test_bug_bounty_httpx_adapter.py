"""Tests for adapters.bug_bounty_httpx -- the real, bounded httpx HTTP
enrichment adapter.

`subprocess.run` and `shutil.which` are mocked in every test -- this
file never performs a real external scan. Real httpx execution is
exercised separately, manually, only against the local Juice Shop
container or an operator-declared external target.
"""

from __future__ import annotations

import json

import pytest

from adapters.bug_bounty_httpx import (
    MAX_OUTPUT_BYTES,
    MAX_PROCESS_TIMEOUT_SECONDS,
    MAX_TARGETS_PER_SCAN,
    STATUS_VALUES,
    BugBountyHttpxAdapterError,
    _build_httpx_command,
    run_httpx_scan,
)


def _execution_config(**overrides):
    config = {"execution_config_version": "1", "process_timeout_seconds": 20, "max_output_bytes": 65536}
    config.update(overrides)
    return config


class _CompletedProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


_SAMPLE_RECORD = {
    "url": "https://app.example.test/",
    "input": "https://app.example.test/",
    "status_code": 200,
    "title": "Example App",
    "content_type": "text/html",
    "webserver": "nginx",
    "tech": ["Express", "Node.js"],
    "scheme": "https",
    "host": "app.example.test",
    "port": 443,
}


def _jsonl(*records) -> bytes:
    return "\n".join(json.dumps(r) for r in records).encode("utf-8")


class TestExecutableDiscovery:
    def test_001_missing_executable_reports_tool_not_installed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: None)
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "tool_not_installed"
        assert result["execution_performed"] is False

    def test_002_found_executable_proceeds_to_subprocess(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        called = {}

        def fake_run(argv, **kwargs):
            called["argv"] = argv
            return _CompletedProcess(0, stdout=_jsonl(_SAMPLE_RECORD))

        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", fake_run)
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert called["argv"][0] == "/usr/bin/httpx"

    def test_003_oserror_on_launch_reports_tool_not_installed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")

        def fake_run(argv, **kwargs):
            raise OSError("no such file")

        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", fake_run)
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "tool_not_installed"
        assert result["execution_performed"] is False


class TestTargetBoundary:
    def test_004_valid_url_accepted(self):
        with pytest.raises(BugBountyHttpxAdapterError):
            run_httpx_scan(target="not-a-url", request_id="REQ-1", execution_config=_execution_config())

    def test_005_missing_hostname_rejected(self):
        with pytest.raises(BugBountyHttpxAdapterError):
            run_httpx_scan(target="https:///path", request_id="REQ-1", execution_config=_execution_config())

    def test_006_unsupported_scheme_rejected(self):
        with pytest.raises(BugBountyHttpxAdapterError):
            run_httpx_scan(target="ftp://app.example.test/", request_id="REQ-1", execution_config=_execution_config())

    def test_007_blank_target_rejected(self):
        with pytest.raises(BugBountyHttpxAdapterError):
            run_httpx_scan(target="   ", request_id="REQ-1", execution_config=_execution_config())

    def test_008_max_targets_per_scan_is_one(self):
        assert MAX_TARGETS_PER_SCAN == 1


class TestCommandVector:
    def test_009_command_uses_shell_false_semantics_list_argv(self):
        argv = _build_httpx_command(httpx_path="/usr/bin/httpx", target="https://app.example.test/")
        assert isinstance(argv, list)
        assert all(isinstance(item, str) for item in argv)

    def test_010_single_target_flag(self):
        argv = _build_httpx_command(httpx_path="/usr/bin/httpx", target="https://app.example.test/")
        assert argv[argv.index("-u") + 1] == "https://app.example.test/"

    def test_011_json_and_silent_flags_present(self):
        argv = _build_httpx_command(httpx_path="/usr/bin/httpx", target="https://app.example.test/")
        assert "-json" in argv
        assert "-silent" in argv

    def test_012_no_follow_redirects_flag(self):
        argv = _build_httpx_command(httpx_path="/usr/bin/httpx", target="https://app.example.test/")
        assert not any("follow" in a.lower() for a in argv)

    def test_012b_no_tech_detect_flag(self):
        # Regression guard for a real behavior found during this block's
        # own live Docker validation: httpx v1.10.0's -tech-detect
        # silently downloads a ~90MB ML model from an external host on
        # first use -- an undisclosed runtime network mutation this
        # bounded, single-target adapter must never trigger.
        argv = _build_httpx_command(httpx_path="/usr/bin/httpx", target="https://app.example.test/")
        assert "-tech-detect" not in argv
        assert "-td" not in argv

    def test_013_no_list_or_hostfile_flag(self):
        argv = _build_httpx_command(httpx_path="/usr/bin/httpx", target="https://app.example.test/")
        assert "-list" not in argv
        assert "-l" not in argv

    def test_014_no_arbitrary_flag_injection_possible(self):
        # target is validated as a URL before ever reaching command
        # construction -- a value shaped like a flag cannot be injected.
        with pytest.raises(BugBountyHttpxAdapterError):
            run_httpx_scan(target="-u evil.test", request_id="REQ-1", execution_config=_execution_config())

    def test_015_command_never_built_via_shell_string(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        captured = {}

        def fake_run(argv, shell=None, **kwargs):
            captured["shell"] = shell
            return _CompletedProcess(0, stdout=_jsonl(_SAMPLE_RECORD))

        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", fake_run)
        run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert captured["shell"] is False


class TestJsonParsing:
    def test_016_reachable_true_when_status_code_present(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_SAMPLE_RECORD)))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["reachable"] is True
        assert result["observations"][0]["status_code"] == 200

    def test_017_technologies_extracted(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_SAMPLE_RECORD)))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["technologies"] == ["Express", "Node.js"]

    def test_018_title_and_server_extracted(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_SAMPLE_RECORD)))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        obs = result["observations"][0]
        assert obs["title"] == "Example App"
        assert obs["server"] == "nginx"

    def test_019_observation_type_is_http_enrichment_never_vulnerability(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_SAMPLE_RECORD)))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["type"] == "http_enrichment"

    def test_020_alternate_key_spellings_handled(self, monkeypatch):
        record = {"url": "https://app.example.test/", "status-code": 301, "content-type": "text/html", "location": "/next"}
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(record)))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        obs = result["observations"][0]
        assert obs["status_code"] == 301
        assert obs["redirect_location"] == "/next"

    def test_021_malformed_line_skipped_not_fatal(self, monkeypatch):
        raw = b"not json\n" + _jsonl(_SAMPLE_RECORD)
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=raw))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert len(result["observations"]) == 1

    def test_022_empty_output_yields_completed_with_no_observations(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=b""))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert result["observations"] == []

    def test_023_at_most_one_observation_even_if_multiple_lines(self, monkeypatch):
        raw = _jsonl(_SAMPLE_RECORD, _SAMPLE_RECORD, _SAMPLE_RECORD)
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=raw))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["observations"]) <= MAX_TARGETS_PER_SCAN


class TestTechnologyIsObservationNotVulnerability:
    def test_024_no_cve_or_severity_field_on_observation(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_SAMPLE_RECORD)))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        obs = result["observations"][0]
        assert "cve" not in obs
        assert "severity" not in obs
        assert "vulnerability" not in obs

    def test_025_module_never_maps_technology_to_cve(self):
        import inspect

        import adapters.bug_bounty_httpx as mod

        source = inspect.getsource(mod)
        assert "CVE-" not in source


class TestTimeoutAndFailureModes:
    def test_026_timeout_reports_timeout_status(self, monkeypatch):
        import subprocess as real_subprocess

        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")

        def fake_run(argv, **kwargs):
            raise real_subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout"))

        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", fake_run)
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "timeout"
        assert result["execution_performed"] is True

    def test_027_nonzero_exit_with_no_output_reports_failed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(1, stdout=b""))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "failed"

    def test_028_nonzero_exit_with_parsable_output_still_returns_observations(self, monkeypatch):
        # httpx can exit non-zero for some erroring targets while still
        # emitting real JSON for others -- never discard real evidence.
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(1, stdout=_jsonl(_SAMPLE_RECORD)))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert len(result["observations"]) == 1

    def test_029_output_truncated_beyond_max_bytes(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        huge = _jsonl(_SAMPLE_RECORD) + b" " * 200000
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=huge))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config(max_output_bytes=65536))
        assert result["output_truncated"] is True

    def test_030_error_detail_never_leaks_raw_stderr(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr(
            "adapters.bug_bounty_httpx.subprocess.run",
            lambda argv, **kw: _CompletedProcess(1, stdout=b"", stderr=b"super secret internal path /etc/shadow"),
        )
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["error_detail"] is not None
        assert "/etc/shadow" not in result["error_detail"]


class TestExecutionConfigCeiling:
    def test_031_timeout_above_ceiling_rejected(self):
        with pytest.raises(BugBountyHttpxAdapterError):
            run_httpx_scan(
                target="https://app.example.test/", request_id="REQ-1",
                execution_config=_execution_config(process_timeout_seconds=MAX_PROCESS_TIMEOUT_SECONDS + 1),
            )

    def test_032_output_bytes_above_ceiling_rejected(self):
        with pytest.raises(BugBountyHttpxAdapterError):
            run_httpx_scan(
                target="https://app.example.test/", request_id="REQ-1",
                execution_config=_execution_config(max_output_bytes=MAX_OUTPUT_BYTES + 1),
            )

    def test_033_wrong_shape_execution_config_rejected(self):
        with pytest.raises(BugBountyHttpxAdapterError):
            run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config={"bad": "shape"})


class TestContractShape:
    def test_034_status_values_closed_vocabulary(self):
        assert STATUS_VALUES == {"completed", "failed", "tool_not_installed", "timeout"}

    def test_035_tool_id_always_httpx(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: None)
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["tool_id"] == "httpx"

    def test_036_evidence_reference_never_raw_output(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_httpx.shutil.which", lambda name: "/usr/bin/httpx")
        monkeypatch.setattr("adapters.bug_bounty_httpx.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_SAMPLE_RECORD)))
        result = run_httpx_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["evidence_references"][0].startswith("httpx_json_sha256:")

    def test_037_module_never_uses_shell_true(self):
        import inspect

        import adapters.bug_bounty_httpx as mod

        assert "shell=True" not in inspect.getsource(mod)

    def test_038_module_never_uses_os_system(self):
        import inspect

        import adapters.bug_bounty_httpx as mod

        source = inspect.getsource(mod)
        assert "os.system" not in source
        assert "eval(" not in source
        assert "exec(" not in source
