"""Focused tests for runtime.bootstrap -- the local demo bootstrap CLI
(Block 15L-16). No real container is ever started by these tests --
every Docker call is mocked, and `execute_start_demo`/`execute_stop_demo`
are exercised with `dry_run=True` wherever a real command would
otherwise be attempted.
"""

from __future__ import annotations

import pytest

import runtime.bootstrap as bootstrap
from runtime.bootstrap import (
    build_start_demo_plan,
    build_stop_demo_plan,
    check_juice_shop_status,
    execute_start_demo,
    execute_stop_demo,
    format_readiness_table,
    main,
)


def _which(mapping):
    return lambda name: mapping.get(name)


def _runner(response):
    calls = []

    def run(argv, *, timeout):
        calls.append(tuple(argv))
        return response(argv) if callable(response) else response

    run.calls = calls
    return run


_READY = {"tool_id": "docker", "state": "ready", "version": "27.0.0", "detail": "/usr/bin/docker"}
_NOT_READY = {"tool_id": "docker", "state": "missing", "version": None, "detail": ""}


def _sample_report():
    return {
        "runtime_report_version": "1", "platform": "Linux",
        "tools": {
            "http_assessor": {"tool_id": "http_assessor", "state": "ready", "version": None, "detail": "x"},
            "nmap": {"tool_id": "nmap", "state": "requires_admin_install", "version": None, "detail": "x"},
            "nuclei": {"tool_id": "nuclei", "state": "ready", "version": "3.3.7", "detail": "x"},
            "nuclei_templates": {"tool_id": "nuclei_templates", "state": "ready", "version": None, "detail": "x"},
            "docker": _READY,
            "zap": {"tool_id": "zap", "state": "container_available", "version": None, "detail": "x"},
            "burp_dast": {"tool_id": "burp_dast", "state": "not_configured", "version": None, "detail": "x"},
            "authenticated_testing": {"tool_id": "authenticated_testing", "state": "not_implemented", "version": None, "detail": "x"},
            "controlled_validation": {"tool_id": "controlled_validation", "state": "not_implemented", "version": None, "detail": "x"},
        },
    }


class TestFormatReadinessTable:
    def test_001_renders_all_nine_rows(self):
        text = format_readiness_table(_sample_report())
        for label in ["HTTP Assessor", "Nmap", "Nuclei", "Nuclei Templates", "Docker", "ZAP", "Burp DAST", "Authenticated Testing", "Controlled Validation"]:
            assert label in text

    def test_002_includes_version_when_present(self):
        text = format_readiness_table(_sample_report())
        assert "READY 3.3.7" in text

    def test_003_never_fabricates_version(self):
        text = format_readiness_table(_sample_report())
        assert "CONTAINER_AVAILABLE None" not in text
        assert "CONTAINER_AVAILABLE" in text


class TestJuiceShopStatus:
    def test_004_docker_unavailable(self):
        result = check_juice_shop_status(which_func=_which({}), runner=_runner({}))
        assert result["status"] == "docker_unavailable"

    def test_005_running(self):
        which = _which({"docker": "/usr/bin/docker"})
        runner = _runner({"returncode": 0, "stdout": "threattrace-juice-shop\n", "stderr": "", "timed_out": False})
        result = check_juice_shop_status(which_func=which, runner=runner)
        assert result["status"] == "running"

    def test_006_exists_but_stopped(self):
        which = _which({"docker": "/usr/bin/docker"})
        calls = {"n": 0}

        def response(argv):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}  # running filter: empty
            return {"returncode": 0, "stdout": "threattrace-juice-shop\n", "stderr": "", "timed_out": False}  # -a filter: found

        result = check_juice_shop_status(which_func=which, runner=_runner(response))
        assert result["status"] == "exists_stopped"

    def test_007_not_present(self):
        which = _which({"docker": "/usr/bin/docker"})
        runner = _runner({"returncode": 0, "stdout": "", "stderr": "", "timed_out": False})
        result = check_juice_shop_status(which_func=which, runner=runner)
        assert result["status"] == "not_present"


class TestBuildStartDemoPlan:
    def test_008_missing_docker_blocks_everything(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "not_present"}, zap_readiness={"state": "missing"},
            docker_readiness=_NOT_READY, with_zap=True,
        )
        assert plan["docker_ready"] is False
        assert plan["steps"] == []
        assert plan["blocked_reason"] is not None

    def test_009_juice_shop_already_running_is_noop(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "running"}, zap_readiness={"state": "missing"},
            docker_readiness=_READY, with_zap=False,
        )
        assert plan["steps"] == [{"target": "juice_shop", "action": "already_running", "command": None}]

    def test_010_juice_shop_stopped_starts_existing(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "exists_stopped"}, zap_readiness={"state": "missing"},
            docker_readiness=_READY, with_zap=False,
        )
        assert plan["steps"][0]["action"] == "start_existing_container"
        assert plan["steps"][0]["command"] == ["docker", "start", "threattrace-juice-shop"]

    def test_011_juice_shop_not_present_runs_new_container(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "not_present"}, zap_readiness={"state": "missing"},
            docker_readiness=_READY, with_zap=False,
        )
        step = plan["steps"][0]
        assert step["action"] == "run_new_container"
        assert "127.0.0.1:3000:3000" in step["command"]
        assert not any(":3000" == entry for entry in step["command"] if entry.count(":") == 1)  # never a bare host-port mapping

    def test_012_zap_not_requested_adds_no_step(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "running"}, zap_readiness={"state": "container_available"},
            docker_readiness=_READY, with_zap=False,
        )
        assert len(plan["steps"]) == 1

    def test_013_zap_container_available_runs_new_container(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "running"}, zap_readiness={"state": "container_available"},
            docker_readiness=_READY, with_zap=True,
        )
        zap_step = next(s for s in plan["steps"] if s["target"] == "zap")
        assert zap_step["action"] == "run_new_container"
        assert "127.0.0.1:8080:8080" in zap_step["command"]

    def test_014_zap_already_ready_is_noop(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "running"}, zap_readiness={"state": "ready"},
            docker_readiness=_READY, with_zap=True,
        )
        zap_step = next(s for s in plan["steps"] if s["target"] == "zap")
        assert zap_step["action"] == "already_running"
        assert zap_step["command"] is None

    def test_015_never_proposes_a_command_touching_an_unrelated_container(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "not_present"}, zap_readiness={"state": "container_available"},
            docker_readiness=_READY, with_zap=True,
        )
        for step in plan["steps"]:
            if step["command"]:
                assert "threattrace-juice-shop" in step["command"] or "threattrace-zap" in step["command"]


class TestExecuteStartDemo:
    def test_016_blocked_plan_never_calls_runner(self):
        plan = {"plan_version": "1", "docker_ready": False, "steps": [], "blocked_reason": "no docker"}
        runner = _runner({})
        outcome = execute_start_demo(plan=plan, runner=runner, dry_run=False)
        assert outcome["executed"] is False
        assert runner.calls == []

    def test_017_dry_run_never_calls_runner(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "not_present"}, zap_readiness={"state": "missing"},
            docker_readiness=_READY, with_zap=False,
        )
        runner = _runner({})
        outcome = execute_start_demo(plan=plan, runner=runner, dry_run=True)
        assert runner.calls == []
        assert "DRY RUN" in outcome["results"][0]["detail"]

    def test_018_real_execution_reports_success(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "not_present"}, zap_readiness={"state": "missing"},
            docker_readiness=_READY, with_zap=False,
        )
        runner = _runner({"returncode": 0, "stdout": "abc123containerid\n", "stderr": "", "timed_out": False})
        outcome = execute_start_demo(plan=plan, runner=runner, dry_run=False)
        assert outcome["results"][0]["success"] is True
        assert len(runner.calls) == 1

    def test_019_port_conflict_reports_failure(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "not_present"}, zap_readiness={"state": "missing"},
            docker_readiness=_READY, with_zap=False,
        )
        runner = _runner({"returncode": 1, "stdout": "", "stderr": "port is already allocated", "timed_out": False})
        outcome = execute_start_demo(plan=plan, runner=runner, dry_run=False)
        assert outcome["results"][0]["success"] is False
        assert "already allocated" in outcome["results"][0]["detail"]

    def test_020_already_running_never_calls_runner(self):
        plan = build_start_demo_plan(
            juice_shop_status={"status": "running"}, zap_readiness={"state": "ready"},
            docker_readiness=_READY, with_zap=True,
        )
        runner = _runner({})
        outcome = execute_start_demo(plan=plan, runner=runner, dry_run=False)
        assert runner.calls == []
        assert all(r["success"] for r in outcome["results"])


class TestBuildAndExecuteStopDemo:
    def test_021_stops_only_running_containers(self):
        plan = build_stop_demo_plan(juice_shop_status={"status": "running"}, zap_running=False)
        assert plan["steps"][0]["command"] == ["docker", "stop", "threattrace-juice-shop"]
        assert plan["steps"][1]["command"] is None

    def test_022_no_op_when_nothing_running(self):
        plan = build_stop_demo_plan(juice_shop_status={"status": "not_present"}, zap_running=False)
        runner = _runner({})
        outcome = execute_stop_demo(plan=plan, runner=runner, dry_run=False)
        assert runner.calls == []
        assert all(r["success"] for r in outcome["results"])

    def test_023_dry_run_never_calls_runner(self):
        plan = build_stop_demo_plan(juice_shop_status={"status": "running"}, zap_running=True)
        runner = _runner({})
        execute_stop_demo(plan=plan, runner=runner, dry_run=True)
        assert runner.calls == []


class TestCliEntrypoints:
    def test_024_check_command(self, monkeypatch, capsys):
        monkeypatch.setattr(bootstrap, "evaluate_tool_readiness", lambda **kwargs: _sample_report())
        code = main(["check"])
        assert code == 0
        assert "HTTP Assessor" in capsys.readouterr().out

    def test_025_start_demo_dry_run_safe_no_op(self, monkeypatch, capsys):
        monkeypatch.setattr(bootstrap, "evaluate_tool_readiness", lambda **kwargs: _sample_report())
        monkeypatch.setattr(bootstrap, "check_juice_shop_status", lambda **kwargs: {"status": "running", "detail": "x"})
        code = main(["start-demo", "--dry-run"])
        assert code == 0
        assert "already_running" in capsys.readouterr().out

    def test_026_start_demo_missing_docker_reports_blocked(self, monkeypatch, capsys):
        report = _sample_report()
        report["tools"]["docker"] = _NOT_READY
        monkeypatch.setattr(bootstrap, "evaluate_tool_readiness", lambda **kwargs: report)
        monkeypatch.setattr(bootstrap, "check_juice_shop_status", lambda **kwargs: {"status": "docker_unavailable", "detail": "x"})
        code = main(["start-demo", "--dry-run"])
        assert code == 1
        assert "BLOCKED" in capsys.readouterr().out

    def test_027_stop_demo_dry_run(self, monkeypatch, capsys):
        monkeypatch.setattr(bootstrap, "evaluate_tool_readiness", lambda **kwargs: _sample_report())
        monkeypatch.setattr(bootstrap, "check_juice_shop_status", lambda **kwargs: {"status": "running", "detail": "x"})
        code = main(["stop-demo", "--dry-run"])
        assert code == 0
        assert "DRY RUN" in capsys.readouterr().out

    def test_028_failure_reporting_exit_code(self, monkeypatch, capsys):
        monkeypatch.setattr(bootstrap, "evaluate_tool_readiness", lambda **kwargs: _sample_report())
        monkeypatch.setattr(bootstrap, "check_juice_shop_status", lambda **kwargs: {"status": "not_present", "detail": "x"})
        monkeypatch.setattr(
            bootstrap, "execute_start_demo",
            lambda **kwargs: {"executed": True, "dry_run": False, "results": [{"target": "juice_shop", "action": "run_new_container", "executed": True, "success": False, "detail": "port is already allocated"}], "blocked_reason": None},
        )
        code = main(["start-demo"])
        assert code == 1
