"""Tests for adapters.bug_bounty_nmap -- the real, bounded Nmap TCP
reconnaissance adapter (Block 15G-B).

`subprocess.run` and `shutil.which` are mocked in every test except none
-- this file never performs a real external scan. Real Nmap execution is
exercised separately, manually, only against the local Juice Shop
container (see docs/block15g-nmap-nuclei-adapters.md).
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET

import pytest

from adapters.bug_bounty_nmap import (
    MAX_OUTPUT_BYTES,
    MAX_PORTS_PER_SCAN,
    MAX_PROCESS_TIMEOUT_SECONDS,
    STATUS_VALUES,
    BugBountyNmapAdapterError,
    _build_nmap_command,
    run_nmap_scan,
)

_SAMPLE_XML_OPEN_CLOSED = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open"/>
        <service name="http" product="Juice Shop" version="17.0"/>
      </port>
      <port protocol="tcp" portid="3001">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_SAMPLE_XML_NO_SERVICE = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _execution_config(**overrides):
    config = {"execution_config_version": "1", "process_timeout_seconds": 30, "max_output_bytes": 65536}
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
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: None)
        result = run_nmap_scan(
            target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config(),
        )
        assert result["status"] == "tool_not_installed"
        assert result["execution_performed"] is False

    def test_002_found_executable_proceeds_to_subprocess(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        called = {}

        def fake_run(argv, **kwargs):
            called["argv"] = argv
            return _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED)

        monkeypatch.setattr("adapters.bug_bounty_nmap.subprocess.run", fake_run)
        result = run_nmap_scan(
            target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config(),
        )
        assert result["status"] == "completed"
        assert called["argv"][0] == "/usr/bin/nmap"

    def test_003_oserror_on_launch_reports_tool_not_installed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")

        def fake_run(argv, **kwargs):
            raise OSError("no such file")

        monkeypatch.setattr("adapters.bug_bounty_nmap.subprocess.run", fake_run)
        result = run_nmap_scan(
            target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config(),
        )
        assert result["status"] == "tool_not_installed"
        assert result["execution_performed"] is False


# ---------------------------------------------------------------------------
# Target boundary
# ---------------------------------------------------------------------------


class TestTargetBoundary:
    def test_004_single_valid_host_accepted(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert result["target"] == "localhost"

    def test_005_url_target_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(
                target="http://localhost:3000/", ports=[3000], request_id="REQ-1",
                execution_config=_execution_config(),
            )

    def test_006_cidr_target_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="192.168.1.0/24", ports=[3000], request_id="REQ-1", execution_config=_execution_config())

    def test_007_multiple_hosts_comma_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(
                target="localhost,127.0.0.1", ports=[3000], request_id="REQ-1", execution_config=_execution_config(),
            )

    def test_008_multiple_hosts_space_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(
                target="localhost 127.0.0.1", ports=[3000], request_id="REQ-1", execution_config=_execution_config(),
            )

    def test_009_wildcard_target_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="10.0.0.*", ports=[3000], request_id="REQ-1", execution_config=_execution_config())

    def test_010_blank_target_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="   ", ports=[3000], request_id="REQ-1", execution_config=_execution_config())

    def test_011_non_string_target_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target=12345, ports=[3000], request_id="REQ-1", execution_config=_execution_config())


# ---------------------------------------------------------------------------
# Port boundary
# ---------------------------------------------------------------------------


class TestPortBoundary:
    def test_012_explicit_ports_only(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        captured = {}

        def fake_run(argv, **kw):
            captured["argv"] = argv
            return _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED)

        monkeypatch.setattr("adapters.bug_bounty_nmap.subprocess.run", fake_run)
        run_nmap_scan(target="localhost", ports=[3000, 3001], request_id="REQ-1", execution_config=_execution_config())
        assert "3000,3001" in captured["argv"]

    def test_013_empty_ports_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="localhost", ports=[], request_id="REQ-1", execution_config=_execution_config())

    def test_014_port_out_of_range_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="localhost", ports=[70000], request_id="REQ-1", execution_config=_execution_config())

    def test_015_port_zero_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="localhost", ports=[0], request_id="REQ-1", execution_config=_execution_config())

    def test_016_duplicate_port_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="localhost", ports=[3000, 3000], request_id="REQ-1", execution_config=_execution_config())

    def test_017_hard_port_limit_enforced(self):
        assert MAX_PORTS_PER_SCAN == 20
        too_many = list(range(1000, 1000 + MAX_PORTS_PER_SCAN + 1))
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="localhost", ports=too_many, request_id="REQ-1", execution_config=_execution_config())

    def test_018_exactly_hard_port_limit_accepted(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        exactly_max = list(range(1000, 1000 + MAX_PORTS_PER_SCAN))
        result = run_nmap_scan(
            target="localhost", ports=exactly_max, request_id="REQ-1", execution_config=_execution_config(),
        )
        assert result["status"] == "completed"

    def test_019_bool_port_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="localhost", ports=[True], request_id="REQ-1", execution_config=_execution_config())


# ---------------------------------------------------------------------------
# Deterministic command vector
# ---------------------------------------------------------------------------


class TestCommandVector:
    def test_020_deterministic_command_vector(self):
        argv = _build_nmap_command(nmap_path="/usr/bin/nmap", target="localhost", ports=[3000])
        assert argv == ["/usr/bin/nmap", "-Pn", "-sT", "-T3", "-p", "3000", "-oX", "-", "localhost"]

    def test_021_command_vector_is_a_list_not_a_string(self):
        argv = _build_nmap_command(nmap_path="/usr/bin/nmap", target="localhost", ports=[3000])
        assert isinstance(argv, list)
        assert all(isinstance(item, str) for item in argv)

    def test_022_no_nse_scripts(self):
        argv = _build_nmap_command(nmap_path="/usr/bin/nmap", target="localhost", ports=[3000])
        assert "-sC" not in argv
        assert "--script" not in argv

    def test_023_no_os_detection(self):
        argv = _build_nmap_command(nmap_path="/usr/bin/nmap", target="localhost", ports=[3000])
        assert "-O" not in argv

    def test_024_no_udp_scanning(self):
        argv = _build_nmap_command(nmap_path="/usr/bin/nmap", target="localhost", ports=[3000])
        assert "-sU" not in argv

    def test_025_uses_xml_output_to_stdout(self):
        argv = _build_nmap_command(nmap_path="/usr/bin/nmap", target="localhost", ports=[3000])
        assert "-oX" in argv
        assert argv[argv.index("-oX") + 1] == "-"

    def test_026_shell_is_never_true(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        captured = {}

        def fake_run(argv, **kwargs):
            captured["kwargs"] = kwargs
            return _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED)

        monkeypatch.setattr("adapters.bug_bounty_nmap.subprocess.run", fake_run)
        run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert captured["kwargs"]["shell"] is False

    def test_027_multiple_ports_joined_by_comma(self):
        argv = _build_nmap_command(nmap_path="/usr/bin/nmap", target="localhost", ports=[80, 443, 3000])
        assert "80,443,3000" in argv


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------


class TestXmlParsing:
    def test_028_open_service_parsed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(target="localhost", ports=[3000, 3001], request_id="REQ-1", execution_config=_execution_config())
        open_obs = [o for o in result["observations"] if o["port"] == 3000][0]
        assert open_obs["state"] == "open"
        assert open_obs["service"] == "http"
        assert open_obs["product"] == "Juice Shop"
        assert open_obs["version"] == "17.0"
        assert open_obs["protocol"] == "tcp"
        assert open_obs["type"] == "service"

    def test_029_closed_port_handled(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(target="localhost", ports=[3000, 3001], request_id="REQ-1", execution_config=_execution_config())
        closed_obs = [o for o in result["observations"] if o["port"] == 3001][0]
        assert closed_obs["state"] == "closed"
        assert closed_obs["service"] is None

    def test_030_missing_service_element_yields_null_fields(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_NO_SERVICE),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        obs = result["observations"][0]
        assert obs["service"] is None
        assert obs["product"] is None
        assert obs["version"] is None

    def test_031_malformed_xml_reports_failed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=b"<not><valid"),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "failed"
        assert result["execution_performed"] is True
        assert result["error_detail"] is not None

    def test_032_empty_hosts_yields_no_observations(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=b"<?xml version='1.0'?><nmaprun></nmaprun>"),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert result["observations"] == []


# ---------------------------------------------------------------------------
# Timeout / non-zero exit / output bounds
# ---------------------------------------------------------------------------


class TestTimeoutAndFailureModes:
    def test_033_timeout_reported(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")

        def fake_run(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 30))

        monkeypatch.setattr("adapters.bug_bounty_nmap.subprocess.run", fake_run)
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "timeout"
        assert result["execution_performed"] is True

    def test_034_nonzero_exit_reported_failed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(1, stdout=b"", stderr=b"some raw stderr"),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "failed"
        assert result["execution_performed"] is True
        assert "raw stderr" not in (result["error_detail"] or "")

    def test_035_output_size_limit_truncates(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        huge = _SAMPLE_XML_OPEN_CLOSED + (b" " * 200)
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=huge),
        )
        result = run_nmap_scan(
            target="localhost", ports=[3000], request_id="REQ-1",
            execution_config=_execution_config(max_output_bytes=64),
        )
        assert result["output_truncated"] is True

    def test_036_output_within_limit_not_truncated(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert result["output_truncated"] is False

    def test_037_execution_config_timeout_ceiling_enforced(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(
                target="localhost", ports=[3000], request_id="REQ-1",
                execution_config=_execution_config(process_timeout_seconds=MAX_PROCESS_TIMEOUT_SECONDS + 1),
            )

    def test_038_execution_config_output_ceiling_enforced(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(
                target="localhost", ports=[3000], request_id="REQ-1",
                execution_config=_execution_config(max_output_bytes=MAX_OUTPUT_BYTES + 1),
            )

    def test_039_execution_config_caller_may_lower_timeout(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(
            target="localhost", ports=[3000], request_id="REQ-1",
            execution_config=_execution_config(process_timeout_seconds=1),
        )
        assert result["status"] == "completed"

    def test_040_execution_config_wrong_shape_rejected(self):
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config={"bad": "shape"})

    def test_041_execution_config_extra_field_rejected(self):
        bad = _execution_config()
        bad["raw_command"] = "rm -rf /"
        with pytest.raises(BugBountyNmapAdapterError):
            run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=bad)


# ---------------------------------------------------------------------------
# Sanitized result / no credential fields
# ---------------------------------------------------------------------------


class TestSanitizedResult:
    def test_042_result_contains_no_raw_stdout(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        serialized = repr(result)
        assert "<nmaprun>" not in serialized

    def test_043_no_credential_like_fields_in_contract(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        forbidden = {"password", "authorization", "cookie", "api_key", "token", "secret"}
        assert forbidden.isdisjoint(set(result.keys()))

    def test_044_service_text_with_credential_marker_is_redacted(self, monkeypatch):
        xml_with_secret = _SAMPLE_XML_OPEN_CLOSED.replace(b'product="Juice Shop"', b'product="Authorization: secret"')
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run", lambda argv, **kw: _CompletedProcess(0, stdout=xml_with_secret),
        )
        result = run_nmap_scan(target="localhost", ports=[3000, 3001], request_id="REQ-1", execution_config=_execution_config())
        open_obs = [o for o in result["observations"] if o["port"] == 3000][0]
        assert open_obs["product"] == "[REDACTED]"

    def test_045_evidence_reference_is_digest_not_raw_output(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert len(result["evidence_references"]) == 1
        assert result["evidence_references"][0].startswith("nmap_xml_sha256:")
        assert b"<nmaprun>" not in result["evidence_references"][0].encode()

    def test_046_network_requests_performed_is_null(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert result["network_requests_performed"] is None


# ---------------------------------------------------------------------------
# Input immutability / output contract / determinism
# ---------------------------------------------------------------------------


class TestImmutabilityAndContract:
    def test_047_ports_list_not_mutated(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        ports = [3000, 3001]
        snapshot = list(ports)
        run_nmap_scan(target="localhost", ports=ports, request_id="REQ-1", execution_config=_execution_config())
        assert ports == snapshot

    def test_048_execution_config_not_mutated(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        config = _execution_config()
        snapshot = dict(config)
        run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=config)
        assert config == snapshot

    def test_049_exact_result_contract_fields(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert set(result.keys()) == {
            "tool_result_version", "tool_id", "request_id", "target", "status", "observations",
            "evidence_references", "network_requests_performed", "output_truncated", "error_detail",
            "execution_performed",
        }

    def test_050_tool_id_always_nmap(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: None)
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert result["tool_id"] == "nmap"

    def test_051_status_always_in_fixed_vocabulary(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: None)
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] in STATUS_VALUES

    def test_052_request_id_echoed(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: None)
        result = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-XYZ", execution_config=_execution_config())
        assert result["request_id"] == "REQ-XYZ"

    def test_053_deterministic_given_same_inputs(self, monkeypatch):
        monkeypatch.setattr("adapters.bug_bounty_nmap.shutil.which", lambda name: "/usr/bin/nmap")
        monkeypatch.setattr(
            "adapters.bug_bounty_nmap.subprocess.run",
            lambda argv, **kw: _CompletedProcess(0, stdout=_SAMPLE_XML_OPEN_CLOSED),
        )
        first = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        second = run_nmap_scan(target="localhost", ports=[3000], request_id="REQ-1", execution_config=_execution_config())
        assert first == second
