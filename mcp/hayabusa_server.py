import os
import subprocess
from datetime import datetime
from pathlib import Path, PureWindowsPath

from mcp.server.fastmcp import FastMCP


def _resolve_project_root() -> Path:
    env_root = os.environ.get("CLAUDE_PROJECT_DIR")
    if env_root:
        return Path(env_root).resolve()
    return Path(__file__).resolve().parent.parent


PROJECT_ROOT = _resolve_project_root()
HAYABUSA_DIR = PROJECT_ROOT / "tools" / "hayabusa"
HAYABUSA_EXE = HAYABUSA_DIR / "hayabusa-3.10.0-win-x64.exe"
ENCODED_RULES = HAYABUSA_DIR / "encoded_rules.yml"
RULES_CONFIG = HAYABUSA_DIR / "rules_config_files.txt"
EVTX_DIR = PROJECT_ROOT / "evidence" / "evtx"
OUTPUT_DIR = PROJECT_ROOT / "output" / "hayabusa"

AUTHORIZATION_PHRASE = "RUN AUTHORIZED HAYABUSA ANALYSIS"
MAX_OUTPUT_CHARS = 4000
SUBPROCESS_TIMEOUT_SECONDS = 600

# subcommand, fixed extra flags -- never populated from user input
ANALYSIS_COMMANDS = {
    "csv_timeline": ("csv-timeline", ["-w", "-q", "-Q", "-O"]),
    "log_metrics": ("log-metrics", ["-q", "-Q", "-O"]),
    "eid_metrics": ("eid-metrics", ["-q", "-Q"]),
}

mcp = FastMCP("ThreatTrace Hayabusa")


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [truncated, {len(text) - limit} more characters]"


def _validate_evtx_input(evtx_file: str) -> Path:
    if not evtx_file or not evtx_file.strip():
        raise ValueError("must not be empty")

    if PureWindowsPath(evtx_file).is_absolute():
        raise ValueError("must be a relative path, not absolute")
    if os.path.splitdrive(evtx_file)[0]:
        raise ValueError("must not reference a drive letter")
    if evtx_file.replace("/", "\\").startswith("\\"):
        raise ValueError("must not be a rooted path")
    if ".." in PureWindowsPath(evtx_file).parts:
        raise ValueError("must not contain '..'")
    if not evtx_file.lower().endswith(".evtx"):
        raise ValueError("must have a .evtx extension")

    evtx_root = EVTX_DIR.resolve()
    candidate_unresolved = EVTX_DIR / evtx_file
    if candidate_unresolved.is_symlink():
        raise ValueError("must not be a symbolic link")

    candidate = candidate_unresolved.resolve()
    if not candidate.is_relative_to(evtx_root):
        raise ValueError("resolves outside evidence/evtx")
    if not candidate.exists() or not candidate.is_file():
        raise ValueError("does not exist inside evidence/evtx")

    return candidate


def _validate_output_name(output_name: str) -> Path:
    if not output_name or not output_name.strip():
        raise ValueError("must not be empty")
    if "/" in output_name or "\\" in output_name:
        raise ValueError("must be a simple filename, not a path")
    if not output_name.lower().endswith(".csv"):
        raise ValueError("must end with .csv")

    output_root = OUTPUT_DIR.resolve()
    candidate = (OUTPUT_DIR / output_name).resolve()
    if not candidate.is_relative_to(output_root):
        raise ValueError("resolves outside output/hayabusa")

    return candidate


@mcp.tool()
def hayabusa_status() -> dict:
    """Report Hayabusa binary and rule-file availability plus EVTX/output counts. Read-only; never executes Hayabusa."""
    evtx_count = len(list(EVTX_DIR.glob("*.evtx"))) if EVTX_DIR.exists() else 0
    output_count = len([p for p in OUTPUT_DIR.iterdir() if p.is_file()]) if OUTPUT_DIR.exists() else 0

    return {
        "server_name": "ThreatTrace Hayabusa",
        "hayabusa_executable_exists": HAYABUSA_EXE.is_file(),
        "encoded_rules_exists": ENCODED_RULES.is_file(),
        "rules_config_exists": RULES_CONFIG.is_file(),
        "evtx_file_count": evtx_count,
        "output_file_count": output_count,
        "hayabusa_executed": False,
    }


@mcp.tool()
def list_evtx_files() -> list[dict]:
    """List .evtx files inside evidence/evtx only. Read-only; does not parse or analyze file contents."""
    if not EVTX_DIR.exists():
        return []

    evtx_root = EVTX_DIR.resolve()
    results = []
    for entry in sorted(EVTX_DIR.glob("*.evtx")):
        if entry.is_symlink() or not entry.is_file():
            continue
        resolved = entry.resolve()
        if not resolved.is_relative_to(evtx_root):
            continue
        stat = resolved.stat()
        results.append({
            "relative_path": str(resolved.relative_to(PROJECT_ROOT)),
            "filename": resolved.name,
            "size_bytes": stat.st_size,
            "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        })
    return results


@mcp.tool()
def plan_evtx_analysis(evtx_file: str, analysis_type: str, output_name: str) -> dict:
    """Validate an EVTX analysis request (input file, analysis type, output path) without executing Hayabusa. Execution authorization is always required afterward."""
    result = {
        "evtx_file": evtx_file,
        "analysis_type": analysis_type,
        "output_name": output_name,
        "valid": False,
        "errors": [],
        "output_exists": None,
        "authorization_required": True,
        "authorization_note": f"Execution requires the exact phrase: {AUTHORIZATION_PHRASE}",
    }

    if analysis_type not in ANALYSIS_COMMANDS:
        result["errors"].append(f"analysis_type must be one of {sorted(ANALYSIS_COMMANDS)}")

    input_path = None
    try:
        input_path = _validate_evtx_input(evtx_file)
    except ValueError as exc:
        result["errors"].append(f"evtx_file {exc}")

    output_path = None
    try:
        output_path = _validate_output_name(output_name)
    except ValueError as exc:
        result["errors"].append(f"output_name {exc}")

    if output_path is not None:
        result["output_exists"] = output_path.exists()
        if result["output_exists"]:
            result["errors"].append("output_name already exists in output/hayabusa")

    result["valid"] = input_path is not None and output_path is not None and not result["errors"]
    return result


@mcp.tool()
def run_evtx_analysis(evtx_file: str, analysis_type: str, output_name: str, authorization_phrase: str) -> dict:
    """Execute one authorized Hayabusa analysis (csv_timeline, log_metrics, or eid_metrics) against a single EVTX file in evidence/evtx, writing CSV output into output/hayabusa. Refuses without executing anything unless the exact authorization phrase is supplied."""
    if authorization_phrase != AUTHORIZATION_PHRASE:
        return {
            "success": False,
            "error": "Refused: exact authorization phrase required.",
            "hayabusa_executed": False,
        }

    if analysis_type not in ANALYSIS_COMMANDS:
        return {
            "success": False,
            "error": f"Unsupported analysis_type. Allowed: {sorted(ANALYSIS_COMMANDS)}",
            "hayabusa_executed": False,
        }

    if not HAYABUSA_EXE.is_file():
        return {"success": False, "error": "Hayabusa executable not found.", "hayabusa_executed": False}

    try:
        input_path = _validate_evtx_input(evtx_file)
    except ValueError as exc:
        return {"success": False, "error": f"Invalid evtx_file: {exc}", "hayabusa_executed": False}

    try:
        output_path = _validate_output_name(output_name)
    except ValueError as exc:
        return {"success": False, "error": f"Invalid output_name: {exc}", "hayabusa_executed": False}

    if output_path.exists():
        return {
            "success": False,
            "error": "Refused: output file already exists.",
            "relative_output_path": str(output_path.relative_to(PROJECT_ROOT)),
            "hayabusa_executed": False,
        }

    subcommand, extra_flags = ANALYSIS_COMMANDS[analysis_type]
    args = [str(HAYABUSA_EXE), subcommand, "-f", str(input_path), "-o", str(output_path)] + extra_flags

    try:
        completed = subprocess.run(
            args,
            cwd=str(HAYABUSA_DIR),
            shell=False,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Hayabusa did not complete within {SUBPROCESS_TIMEOUT_SECONDS} seconds.",
            "analysis_type": analysis_type,
            "relative_input_path": str(input_path.relative_to(PROJECT_ROOT)),
            "relative_output_path": str(output_path.relative_to(PROJECT_ROOT)),
            "hayabusa_executed": True,
        }

    output_created = output_path.is_file()

    return {
        "success": completed.returncode == 0 and output_created,
        "exit_code": completed.returncode,
        "analysis_type": analysis_type,
        "relative_input_path": str(input_path.relative_to(PROJECT_ROOT)),
        "relative_output_path": str(output_path.relative_to(PROJECT_ROOT)),
        "output_size_bytes": output_path.stat().st_size if output_created else None,
        "stdout": _truncate(completed.stdout),
        "stderr": _truncate(completed.stderr),
    }


if __name__ == "__main__":
    mcp.run()
