"""Tests for adapters.bug_bounty_katana -- the real, bounded Katana
discovery adapter.

`subprocess.run` and `shutil.which` are mocked in every test -- this
file never performs a real external scan. Real Katana execution is
exercised separately, manually, only against the local Juice Shop
container or an operator-declared external target.
"""

from __future__ import annotations

import json

import pytest

from adapters.bug_bounty_katana import (
    KATANA_MAX_DEPTH,
    MAX_ENDPOINTS_RETURNED,
    MAX_OUTPUT_BYTES,
    MAX_PROCESS_TIMEOUT_SECONDS,
    STATUS_VALUES,
    BugBountyKatanaAdapterError,
    _build_katana_command,
    run_katana_scan,
)


def _execution_config(**overrides):
    config = {"execution_config_version": "1", "process_timeout_seconds": 30, "max_output_bytes": 65536}
    config.update(overrides)
    return config


class _CompletedProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _record(url, **overrides):
    base = {"request": {"endpoint": url, "method": "GET", "source": "body"}, "response": {"status_code": 200}}
    base.update(overrides)
    return base


def _jsonl(*records) -> bytes:
    return "\n".join(json.dumps(r) for r in records).encode("utf-8")


class TestExecutableDiscovery:
    def test_001_missing_executable_reports_tool_not_installed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: None)
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "tool_not_installed"
        assert result["execution_performed"] is False

    def test_002_found_executable_proceeds_to_subprocess(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        called = {}

        def fake_run(argv, **kwargs):
            called["argv"] = argv
            return _CompletedProcess(0, stdout=_jsonl(_record("https://app.example.test/")))

        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", fake_run)
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert called["argv"][0] == "/usr/bin/katana"

    def test_003_oserror_on_launch_reports_tool_not_installed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")

        def fake_run(argv, **kwargs):
            raise OSError("no such file")

        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", fake_run)
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "tool_not_installed"
        assert result["execution_performed"] is False


class TestTargetBoundary:
    def test_004_malformed_url_rejected(self):
        with pytest.raises(BugBountyKatanaAdapterError):
            run_katana_scan(target="not-a-url", request_id="REQ-1", execution_config=_execution_config())

    def test_005_missing_hostname_rejected(self):
        with pytest.raises(BugBountyKatanaAdapterError):
            run_katana_scan(target="https:///path", request_id="REQ-1", execution_config=_execution_config())

    def test_006_unsupported_scheme_rejected(self):
        with pytest.raises(BugBountyKatanaAdapterError):
            run_katana_scan(target="ftp://app.example.test/", request_id="REQ-1", execution_config=_execution_config())


class TestCommandVector:
    def test_007_depth_bound_present(self):
        argv = _build_katana_command(katana_path="/usr/bin/katana", target="https://app.example.test/")
        assert argv[argv.index("-depth") + 1] == str(KATANA_MAX_DEPTH)

    def test_008_max_depth_is_two(self):
        assert KATANA_MAX_DEPTH == 2

    def test_009_no_headless_flag(self):
        argv = _build_katana_command(katana_path="/usr/bin/katana", target="https://app.example.test/")
        assert not any("headless" in a.lower() for a in argv)

    def test_010_single_seed_url(self):
        argv = _build_katana_command(katana_path="/usr/bin/katana", target="https://app.example.test/")
        assert argv[argv.index("-u") + 1] == "https://app.example.test/"

    def test_011_same_host_scope_flag_present(self):
        argv = _build_katana_command(katana_path="/usr/bin/katana", target="https://app.example.test/")
        assert "-field-scope" in argv

    def test_012_json_and_silent_flags_present(self):
        argv = _build_katana_command(katana_path="/usr/bin/katana", target="https://app.example.test/")
        assert "-json" in argv
        assert "-silent" in argv

    def test_013_no_form_submission_or_upload_flag(self):
        argv = _build_katana_command(katana_path="/usr/bin/katana", target="https://app.example.test/")
        for forbidden in ("form", "upload", "fuzz", "auth"):
            assert not any(forbidden in a.lower() for a in argv)

    def test_014_command_never_built_via_shell_string(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        captured = {}

        def fake_run(argv, shell=None, **kwargs):
            captured["shell"] = shell
            return _CompletedProcess(0, stdout=_jsonl(_record("https://app.example.test/")))

        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", fake_run)
        run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert captured["shell"] is False


class TestJsonlParsing:
    def test_015_url_and_method_extracted(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr(
            "adapters.bug_bounty_katana.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_record("https://app.example.test/page"))),
        )
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        obs = result["observations"][0]
        assert obs["url"] == "https://app.example.test/page"
        assert obs["method"] == "GET"

    def test_016_observation_type_is_discovered_url(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr(
            "adapters.bug_bounty_katana.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_record("https://app.example.test/page"))),
        )
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["type"] == "discovered_url"

    def test_017_query_parameter_names_extracted_never_values(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr(
            "adapters.bug_bounty_katana.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_record("https://app.example.test/search?q=secretvalue&page=1"))),
        )
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        obs = result["observations"][0]
        assert set(obs["parameter_names"]) == {"q", "page"}
        # There is no separate parameter-VALUES field at all -- only the
        # already-discovered URL itself (which legitimately keeps its
        # full query string, exactly like core.bug_bounty_crawler's own
        # canonical_url) and the value-free parameter_names list.
        assert "parameter_values" not in obs
        assert "values" not in obs

    def test_018_no_query_string_yields_none_parameter_names(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr(
            "adapters.bug_bounty_katana.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_record("https://app.example.test/page"))),
        )
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["parameter_names"] is None

    def test_019_duplicate_urls_deduplicated(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        raw = _jsonl(_record("https://app.example.test/page"), _record("https://app.example.test/page"))
        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=raw))
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["observations"]) == 1

    def test_020_malformed_line_skipped_not_fatal(self, monkeypatch):
        raw = b"not json\n" + _jsonl(_record("https://app.example.test/page"))
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=raw))
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert len(result["observations"]) == 1

    def test_021_record_missing_url_skipped(self, monkeypatch):
        raw = _jsonl({"request": {"method": "GET"}}, _record("https://app.example.test/page"))
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=raw))
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["observations"]) == 1


class TestEndpointCap:
    def test_022_max_endpoints_returned_is_100(self):
        assert MAX_ENDPOINTS_RETURNED == 100

    def test_023_output_bounded_to_max_endpoints(self, monkeypatch):
        records = [_record(f"https://app.example.test/page{i}") for i in range(150)]
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(*records)))
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config(max_output_bytes=1_048_576))
        assert len(result["observations"]) == MAX_ENDPOINTS_RETURNED
        assert result["endpoint_limit_reached"] is True

    def test_024_under_cap_reports_limit_not_reached(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr(
            "adapters.bug_bounty_katana.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_record("https://app.example.test/page"))),
        )
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["endpoint_limit_reached"] is False


class TestUntrustedCandidateData:
    def test_025_no_scope_validation_performed_by_adapter_itself(self):
        # Checks real code behavior (no import of the scope module, no
        # scope-evaluation call bound into this module's namespace) --
        # not the module's own honest prose explaining why it
        # deliberately doesn't, which legitimately names the real
        # function for clarity.
        import adapters.bug_bounty_katana as mod

        assert not hasattr(mod, "evaluate_bug_bounty_request_scope")
        assert not hasattr(mod, "create_bug_bounty_scope")

    def test_026_docstring_labels_output_untrusted(self):
        import adapters.bug_bounty_katana as mod

        assert "UNTRUSTED CANDIDATE" in mod.__doc__


class TestTimeoutAndFailureModes:
    def test_027_timeout_reports_timeout_status(self, monkeypatch):
        import subprocess as real_subprocess

        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")

        def fake_run(argv, **kwargs):
            raise real_subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout"))

        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", fake_run)
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "timeout"
        assert result["execution_performed"] is True

    def test_028_nonzero_exit_with_no_output_reports_failed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", lambda argv, **kw: _CompletedProcess(1, stdout=b""))
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "failed"

    def test_029_output_truncated_beyond_max_bytes(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        huge = _jsonl(_record("https://app.example.test/page")) + b" " * 200000
        monkeypatch.setattr("adapters.bug_bounty_katana.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=huge))
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config(max_output_bytes=65536))
        assert result["output_truncated"] is True

    def test_030_error_detail_never_leaks_raw_stderr(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr(
            "adapters.bug_bounty_katana.subprocess.run",
            lambda argv, **kw: _CompletedProcess(1, stdout=b"", stderr=b"super secret internal path /etc/shadow"),
        )
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["error_detail"] is not None
        assert "/etc/shadow" not in result["error_detail"]


class TestExecutionConfigCeiling:
    def test_031_timeout_above_ceiling_rejected(self):
        with pytest.raises(BugBountyKatanaAdapterError):
            run_katana_scan(
                target="https://app.example.test/", request_id="REQ-1",
                execution_config=_execution_config(process_timeout_seconds=MAX_PROCESS_TIMEOUT_SECONDS + 1),
            )

    def test_032_output_bytes_above_ceiling_rejected(self):
        with pytest.raises(BugBountyKatanaAdapterError):
            run_katana_scan(
                target="https://app.example.test/", request_id="REQ-1",
                execution_config=_execution_config(max_output_bytes=MAX_OUTPUT_BYTES + 1),
            )


class TestContractShape:
    def test_033_status_values_closed_vocabulary(self):
        assert STATUS_VALUES == {"completed", "failed", "tool_not_installed", "timeout"}

    def test_034_tool_id_always_katana(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: None)
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["tool_id"] == "katana"

    def test_035_evidence_reference_never_raw_output(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_katana.shutil.which", lambda name: "/usr/bin/katana")
        monkeypatch.setattr(
            "adapters.bug_bounty_katana.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_jsonl(_record("https://app.example.test/page"))),
        )
        result = run_katana_scan(target="https://app.example.test/", request_id="REQ-1", execution_config=_execution_config())
        assert result["evidence_references"][0].startswith("katana_json_sha256:")

    def test_036_module_never_uses_shell_true(self):
        import inspect

        import adapters.bug_bounty_katana as mod

        assert "shell=True" not in inspect.getsource(mod)

    def test_037_module_never_uses_os_system_eval_exec(self):
        import inspect

        import adapters.bug_bounty_katana as mod

        source = inspect.getsource(mod)
        assert "os.system" not in source
        assert "eval(" not in source
        assert "exec(" not in source
