"""Focused tests for runtime.tool_runtime -- deterministic tool/runtime
readiness detection (Block 15L-16). Every environment discovery call
(which/subprocess/HTTP) is mocked; no real nmap/docker/nuclei/ZAP
process is ever invoked by these tests.
"""

from __future__ import annotations

import pytest

from runtime.tool_runtime import (
    READINESS_STATES,
    TOOL_IDS,
    check_authenticated_testing,
    check_burp_dast,
    check_controlled_validation,
    check_docker,
    check_http_assessor,
    check_httpx,
    check_katana,
    check_nmap,
    check_nuclei,
    check_nuclei_templates,
    check_zap,
    evaluate_tool_readiness,
)


def _which(mapping):
    return lambda name: mapping.get(name)


def _runner(response):
    calls = []

    def run(argv, *, timeout):
        calls.append((tuple(argv), timeout))
        return response(argv) if callable(response) else response

    run.calls = calls
    return run


class TestVocabulary:
    def test_001_readiness_states_fixed(self):
        assert READINESS_STATES == {
            "ready", "missing", "not_configured", "requires_admin_install", "container_available",
            "runtime_unavailable", "version_incompatible", "unsupported", "not_implemented",
        }

    def test_002_tool_ids_include_all_supported_tools(self):
        for tool_id in ("http_assessor", "nmap", "nuclei", "zap", "burp_dast", "authenticated_testing", "controlled_validation"):
            assert tool_id in TOOL_IDS


class TestHttpAssessor:
    def test_003_always_ready_no_io(self):
        result = check_http_assessor()
        assert result["state"] == "ready"


class TestDeclaredNotImplemented:
    def test_004_authenticated_testing_not_implemented(self):
        assert check_authenticated_testing()["state"] == "not_implemented"

    def test_005_controlled_validation_not_implemented(self):
        assert check_controlled_validation()["state"] == "not_implemented"


class TestNmap:
    def test_006_missing_on_windows_requires_admin_install(self):
        result = check_nmap(which_func=_which({}), runner=_runner({}), platform_name="Windows")
        assert result["state"] == "requires_admin_install"

    def test_007_missing_on_linux_is_missing(self):
        result = check_nmap(which_func=_which({}), runner=_runner({}), platform_name="Linux")
        assert result["state"] == "missing"

    def test_008_present_parses_version(self):
        which = _which({"nmap": "/usr/bin/nmap"})
        runner = _runner({"returncode": 0, "stdout": "Nmap version 7.94SVN ( https://nmap.org )", "stderr": "", "timed_out": False})
        result = check_nmap(which_func=which, runner=runner, platform_name="Linux")
        assert result["state"] == "ready"
        assert result["version"] == "7.94SVN"

    def test_009_present_but_command_fails(self):
        which = _which({"nmap": "/usr/bin/nmap"})
        runner = _runner({"returncode": 1, "stdout": "", "stderr": "boom", "timed_out": False})
        result = check_nmap(which_func=which, runner=runner, platform_name="Linux")
        assert result["state"] == "runtime_unavailable"

    def test_010_present_but_times_out(self):
        which = _which({"nmap": "/usr/bin/nmap"})
        runner = _runner({"returncode": None, "stdout": "", "stderr": "", "timed_out": True})
        result = check_nmap(which_func=which, runner=runner, platform_name="Linux")
        assert result["state"] == "runtime_unavailable"

    def test_011_never_calls_runner_when_missing(self):
        runner = _runner({})
        check_nmap(which_func=_which({}), runner=runner, platform_name="Windows")
        assert runner.calls == []


class TestNuclei:
    def test_012_missing(self):
        result = check_nuclei(which_func=_which({}), runner=_runner({}))
        assert result["state"] == "missing"

    def test_013_present_parses_version(self):
        which = _which({"nuclei": "/usr/local/bin/nuclei"})
        runner = _runner({"returncode": 0, "stdout": "Nuclei Engine Version: v3.3.7\n", "stderr": "", "timed_out": False})
        result = check_nuclei(which_func=which, runner=runner)
        assert result["state"] == "ready"
        assert result["version"] == "3.3.7"

    def test_014_present_version_unparseable(self):
        which = _which({"nuclei": "/usr/local/bin/nuclei"})
        runner = _runner({"returncode": 0, "stdout": "unexpected output", "stderr": "", "timed_out": False})
        result = check_nuclei(which_func=which, runner=runner)
        assert result["state"] == "runtime_unavailable"

    def test_015_times_out(self):
        which = _which({"nuclei": "/usr/local/bin/nuclei"})
        runner = _runner({"returncode": None, "stdout": "", "stderr": "", "timed_out": True})
        result = check_nuclei(which_func=which, runner=runner)
        assert result["state"] == "runtime_unavailable"


class TestNucleiTemplates:
    def test_016_missing_directory(self, tmp_path):
        result = check_nuclei_templates(templates_dir=str(tmp_path / "does-not-exist"))
        assert result["state"] == "missing"

    def test_017_empty_directory(self, tmp_path):
        empty = tmp_path / "empty-templates"
        empty.mkdir()
        result = check_nuclei_templates(templates_dir=str(empty))
        assert result["state"] == "missing"

    def test_018_populated_directory_is_ready(self, tmp_path):
        populated = tmp_path / "templates"
        populated.mkdir()
        (populated / "cves").mkdir()
        result = check_nuclei_templates(templates_dir=str(populated))
        assert result["state"] == "ready"

    def test_019_env_var_override(self, tmp_path):
        populated = tmp_path / "custom-templates"
        populated.mkdir()
        (populated / "file.yaml").write_text("x")
        result = check_nuclei_templates(env={"THREATTRACE_NUCLEI_TEMPLATES_DIR": str(populated)})
        assert result["state"] == "ready"


class TestHttpx:
    def test_020_missing(self):
        result = check_httpx(which_func=_which({}), runner=_runner({}))
        assert result["state"] == "missing"

    def test_021_present_parses_version(self):
        which = _which({"httpx": "/usr/local/bin/httpx"})
        runner = _runner({"returncode": 0, "stdout": "Current Version: v1.10.0\n", "stderr": "", "timed_out": False})
        result = check_httpx(which_func=which, runner=runner)
        assert result["state"] == "ready"
        assert result["version"] == "1.10.0"

    def test_022_present_version_unparseable(self):
        which = _which({"httpx": "/usr/local/bin/httpx"})
        runner = _runner({"returncode": 0, "stdout": "unexpected output", "stderr": "", "timed_out": False})
        result = check_httpx(which_func=which, runner=runner)
        assert result["state"] == "runtime_unavailable"

    def test_023_times_out(self):
        which = _which({"httpx": "/usr/local/bin/httpx"})
        runner = _runner({"returncode": None, "stdout": "", "stderr": "", "timed_out": True})
        result = check_httpx(which_func=which, runner=runner)
        assert result["state"] == "runtime_unavailable"

    def test_024_never_calls_runner_when_missing(self):
        runner = _runner({})
        check_httpx(which_func=_which({}), runner=runner)
        assert runner.calls == []


class TestKatana:
    def test_025_missing(self):
        result = check_katana(which_func=_which({}), runner=_runner({}))
        assert result["state"] == "missing"

    def test_026_present_parses_version(self):
        which = _which({"katana": "/usr/local/bin/katana"})
        runner = _runner({"returncode": 0, "stdout": "Current Version: v1.7.0\n", "stderr": "", "timed_out": False})
        result = check_katana(which_func=which, runner=runner)
        assert result["state"] == "ready"
        assert result["version"] == "1.7.0"

    def test_027_present_version_unparseable(self):
        which = _which({"katana": "/usr/local/bin/katana"})
        runner = _runner({"returncode": 0, "stdout": "unexpected output", "stderr": "", "timed_out": False})
        result = check_katana(which_func=which, runner=runner)
        assert result["state"] == "runtime_unavailable"

    def test_028_times_out(self):
        which = _which({"katana": "/usr/local/bin/katana"})
        runner = _runner({"returncode": None, "stdout": "", "stderr": "", "timed_out": True})
        result = check_katana(which_func=which, runner=runner)
        assert result["state"] == "runtime_unavailable"

    def test_029_never_calls_runner_when_missing(self):
        runner = _runner({})
        check_katana(which_func=_which({}), runner=runner)
        assert runner.calls == []


class TestDocker:
    def test_020_missing(self):
        result = check_docker(which_func=_which({}), runner=_runner({}))
        assert result["state"] == "missing"

    def test_021_present_and_ready(self):
        which = _which({"docker": "/usr/bin/docker"})
        runner = _runner({"returncode": 0, "stdout": "27.3.1\n", "stderr": "", "timed_out": False})
        result = check_docker(which_func=which, runner=runner)
        assert result["state"] == "ready"
        assert result["version"] == "27.3.1"

    def test_022_present_but_daemon_unreachable(self):
        which = _which({"docker": "/usr/bin/docker"})
        runner = _runner({"returncode": 1, "stdout": "", "stderr": "Cannot connect to the Docker daemon", "timed_out": False})
        result = check_docker(which_func=which, runner=runner)
        assert result["state"] == "runtime_unavailable"

    def test_023_times_out(self):
        which = _which({"docker": "/usr/bin/docker"})
        runner = _runner({"returncode": None, "stdout": "", "stderr": "", "timed_out": True})
        result = check_docker(which_func=which, runner=runner)
        assert result["state"] == "runtime_unavailable"


class TestZap:
    def test_024_docker_not_ready_falls_back_to_direct_api_probe(self):
        # No Docker CLI visibility (e.g. inside a self-hosted container
        # deployment with no Docker socket mounted) -- this is expected
        # and normal, not itself a failure; readiness now depends purely
        # on whether the API actually answers.
        def _broken_http_get(url, *, timeout):
            raise OSError("connection refused")

        result = check_zap(
            docker_state={"tool_id": "docker", "state": "missing", "version": None, "detail": ""},
            which_func=_which({}), http_get=_broken_http_get,
        )
        assert result["state"] == "runtime_unavailable"

    def test_024b_docker_not_ready_but_api_reachable_is_ready(self):
        # The container-mode case this fallback exists for: no Docker
        # visibility from this process, but the configured ZAP API URL
        # (e.g. via ZAP_API_URL=http://zap:8080) genuinely answers.
        http_get = lambda url, *, timeout: '{"version": "2.15.0"}'
        result = check_zap(
            docker_state={"tool_id": "docker", "state": "missing", "version": None, "detail": ""},
            which_func=_which({}), http_get=http_get,
        )
        assert result["state"] == "ready"
        assert result["version"] == "2.15.0"

    def test_025_docker_ready_container_not_running_is_container_available(self):
        which = _which({"docker": "/usr/bin/docker"})
        runner = _runner({"returncode": 0, "stdout": "", "stderr": "", "timed_out": False})  # empty ps output
        result = check_zap(
            docker_state={"tool_id": "docker", "state": "ready", "version": "27.0.0", "detail": ""},
            which_func=which, runner=runner,
        )
        assert result["state"] == "container_available"

    def test_026_container_running_and_api_responds_is_ready(self):
        which = _which({"docker": "/usr/bin/docker"})
        runner = _runner({"returncode": 0, "stdout": "threattrace-zap\n", "stderr": "", "timed_out": False})
        http_get = lambda url, *, timeout: '{"version": "2.15.0"}'
        result = check_zap(
            docker_state={"tool_id": "docker", "state": "ready", "version": "27.0.0", "detail": ""},
            which_func=which, runner=runner, http_get=http_get,
        )
        assert result["state"] == "ready"
        assert result["version"] == "2.15.0"

    def test_027_container_running_but_api_unreachable(self):
        which = _which({"docker": "/usr/bin/docker"})
        runner = _runner({"returncode": 0, "stdout": "threattrace-zap\n", "stderr": "", "timed_out": False})

        def _broken_http_get(url, *, timeout):
            raise OSError("connection refused")

        result = check_zap(
            docker_state={"tool_id": "docker", "state": "ready", "version": "27.0.0", "detail": ""},
            which_func=which, runner=runner, http_get=_broken_http_get,
        )
        assert result["state"] == "runtime_unavailable"

    def test_028_computes_own_docker_state_when_not_supplied(self):
        def _broken_http_get(url, *, timeout):
            raise OSError("connection refused")

        result = check_zap(which_func=_which({}), runner=_runner({}), http_get=_broken_http_get)
        assert result["state"] == "runtime_unavailable"

    def test_028b_env_var_selects_docker_dns_target(self):
        http_get_calls = []

        def _http_get(url, *, timeout):
            http_get_calls.append(url)
            return '{"version": "2.17.0"}'

        result = check_zap(
            docker_state={"tool_id": "docker", "state": "missing", "version": None, "detail": ""},
            which_func=_which({}), http_get=_http_get, env={"ZAP_API_URL": "http://zap:8080"},
        )
        assert result["state"] == "ready"
        assert http_get_calls == ["http://zap:8080/JSON/core/view/version/"]

    def test_028c_explicit_api_host_port_still_takes_priority(self):
        http_get_calls = []

        def _http_get(url, *, timeout):
            http_get_calls.append(url)
            return '{"version": "2.17.0"}'

        result = check_zap(
            docker_state={"tool_id": "docker", "state": "missing", "version": None, "detail": ""},
            which_func=_which({}), http_get=_http_get, api_host="explicit-host", api_port=9999,
            env={"ZAP_API_URL": "http://zap:8080"},
        )
        assert http_get_calls == ["http://explicit-host:9999/JSON/core/view/version/"]


class TestBurpDast:
    def test_029_not_configured_without_api_key(self):
        result = check_burp_dast(env={})
        assert result["state"] == "not_configured"

    def test_030_configured_but_unreachable(self):
        def _broken_http_get(url, *, timeout):
            raise OSError("refused")

        result = check_burp_dast(
            env={"THREATTRACE_BURP_API_KEY": "test-key", "THREATTRACE_BURP_API_HOST": "127.0.0.1", "THREATTRACE_BURP_API_PORT": "1337"},
            http_get=_broken_http_get,
        )
        assert result["state"] == "runtime_unavailable"

    def test_031_configured_and_reachable_is_ready(self):
        http_get = lambda url, *, timeout: "<html></html>"
        result = check_burp_dast(
            env={"THREATTRACE_BURP_API_KEY": "test-key"}, http_get=http_get,
        )
        assert result["state"] == "ready"

    def test_032_blank_api_key_is_not_configured(self):
        result = check_burp_dast(env={"THREATTRACE_BURP_API_KEY": "   "})
        assert result["state"] == "not_configured"


class TestEvaluateToolReadiness:
    def test_033_aggregates_every_tool(self):
        def _broken_http_get(url, *, timeout):
            raise OSError("connection refused")

        report = evaluate_tool_readiness(
            which_func=_which({}), runner=_runner({}), http_get=_broken_http_get, env={}, platform_name="Linux",
        )
        assert set(report["tools"]) == {
            "http_assessor", "nmap", "nuclei", "nuclei_templates", "httpx", "katana", "docker", "zap", "burp_dast",
            "authenticated_testing", "controlled_validation",
        }
        assert report["tools"]["http_assessor"]["state"] == "ready"
        assert report["tools"]["docker"]["state"] == "missing"
        assert report["tools"]["zap"]["state"] == "runtime_unavailable"

    def test_034_every_reported_state_is_recognized(self):
        report = evaluate_tool_readiness(which_func=_which({}), runner=_runner({}), env={}, platform_name="Windows")
        for result in report["tools"].values():
            assert result["state"] in READINESS_STATES

    def test_035_no_silent_install_no_mutating_commands_issued(self):
        runner = _runner({"returncode": 0, "stdout": "Docker version 27.0.0", "stderr": "", "timed_out": False})
        evaluate_tool_readiness(which_func=_which({"docker": "/usr/bin/docker"}), runner=runner, env={}, platform_name="Linux")
        for argv, _timeout in runner.calls:
            joined = " ".join(argv)
            assert "install" not in joined
            assert "pull" not in joined
            assert "update-templates" not in joined
