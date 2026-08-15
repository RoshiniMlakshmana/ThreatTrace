<#
.SYNOPSIS
    ThreatTrace Block 17B demo readiness check (Windows PowerShell).

.DESCRIPTION
    Read-only, non-destructive readiness verification for the ThreatTrace
    live demo. This script never installs anything, never modifies the
    firewall, never requires administrator privileges, and never starts,
    stops, or configures any service or container -- it only observes
    already-running state via safe, bounded, read-only calls:
    `docker version` (a read-only info command), a short-timeout HTTP GET
    to each local endpoint, and `Get-Command`/`<tool> --version`-style
    checks for CLI tools. Every command below uses a closed, literal
    argument list -- no user input is ever interpolated into a command.

    Distinguishes REQUIRED (primary demo cannot proceed without these)
    from OPTIONAL (demo explicitly degrades gracefully without these --
    see docs/block17b-demo-backup.md) dependencies.

.NOTES
    Mirrors, but does not replace, `python -m runtime.bootstrap check`
    (the project's own deterministic readiness tool). This script is a
    lightweight, presentation-oriented wrapper intended to be run
    immediately before demoing -- it duplicates no ThreatTrace business
    logic and performs no mutating action of any kind.
#>

$ErrorActionPreference = 'Stop'

$results = New-Object System.Collections.Generic.List[Object]

function Add-Result {
    param(
        [string]$Name,
        [string]$Category,   # REQUIRED or OPTIONAL
        [bool]$Ready,
        [string]$Detail
    )
    $results.Add([PSCustomObject]@{
        Name     = $Name
        Category = $Category
        Ready    = $Ready
        Detail   = $Detail
    })
}

function Test-HttpEndpoint {
    param([string]$Url, [int]$TimeoutSeconds = 3)
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop
        return @{ Ok = $true; Status = $response.StatusCode; Detail = "HTTP $($response.StatusCode)" }
    } catch {
        return @{ Ok = $false; Status = $null; Detail = $_.Exception.Message }
    }
}

# --- Docker (REQUIRED) -------------------------------------------------
try {
    $dockerVersion = & docker version --format '{{.Server.Version}}' 2>$null
    if ($LASTEXITCODE -eq 0 -and $dockerVersion) {
        Add-Result -Name 'Docker' -Category 'REQUIRED' -Ready $true -Detail "Server version $dockerVersion"
    } else {
        Add-Result -Name 'Docker' -Category 'REQUIRED' -Ready $false -Detail 'Docker CLI found but daemon not reachable'
    }
} catch {
    Add-Result -Name 'Docker' -Category 'REQUIRED' -Ready $false -Detail 'Docker CLI not found on PATH'
}

# --- Juice Shop (REQUIRED) ----------------------------------------------
$juiceShop = Test-HttpEndpoint -Url 'http://localhost:3000/'
Add-Result -Name 'Juice Shop (http://localhost:3000/)' -Category 'REQUIRED' -Ready $juiceShop.Ok -Detail $juiceShop.Detail

# --- Backend (REQUIRED) --------------------------------------------------
$backend = Test-HttpEndpoint -Url 'http://127.0.0.1:8420/api/health'
if ($backend.Ok) {
    Add-Result -Name 'Backend (127.0.0.1:8420)' -Category 'REQUIRED' -Ready $true -Detail 'Already running and healthy'
} else {
    # A connection failure here is informational, not necessarily bad --
    # it usually just means the backend has not been started yet. This
    # script never starts it; it only reports observed state.
    Add-Result -Name 'Backend (127.0.0.1:8420)' -Category 'REQUIRED' -Ready $false -Detail 'Not currently running -- start with: python -m backend.app'
}

# --- Dashboard (REQUIRED, same process as backend) ------------------------
$dashboard = Test-HttpEndpoint -Url 'http://127.0.0.1:8420/'
Add-Result -Name 'Live Dashboard (http://127.0.0.1:8420/)' -Category 'REQUIRED' -Ready $dashboard.Ok -Detail $dashboard.Detail

# --- HTTP Assessor (REQUIRED -- always available, pure Python) -----------
Add-Result -Name 'HTTP Assessor' -Category 'REQUIRED' -Ready $true -Detail 'Pure Python -- no external dependency'

# --- Nmap (REQUIRED) -------------------------------------------------------
$nmapCmd = Get-Command nmap -ErrorAction SilentlyContinue
if ($nmapCmd) {
    try {
        $nmapVersionOutput = & nmap --version 2>$null | Select-Object -First 1
        Add-Result -Name 'Nmap' -Category 'REQUIRED' -Ready $true -Detail "$nmapVersionOutput"
    } catch {
        Add-Result -Name 'Nmap' -Category 'REQUIRED' -Ready $false -Detail 'Found on PATH but failed to execute'
    }
} else {
    Add-Result -Name 'Nmap' -Category 'REQUIRED' -Ready $false -Detail 'Not found on PATH (see docs/demo-runbook.md for install guidance -- never auto-installed by this script)'
}

# --- ZAP (REQUIRED) ---------------------------------------------------------
$zap = Test-HttpEndpoint -Url 'http://127.0.0.1:8080/JSON/core/view/version/'
Add-Result -Name 'ZAP (127.0.0.1:8080)' -Category 'REQUIRED' -Ready $zap.Ok -Detail $zap.Detail

# --- Nuclei (OPTIONAL) -------------------------------------------------------
$nucleiCmd = Get-Command nuclei -ErrorAction SilentlyContinue
if ($nucleiCmd) {
    Add-Result -Name 'Nuclei' -Category 'OPTIONAL' -Ready $true -Detail 'Found on PATH'
} else {
    Add-Result -Name 'Nuclei' -Category 'OPTIONAL' -Ready $false -Detail 'Not found on PATH -- primary demo does not require it (see docs/block17b-presentation-demo.md #7)'
}

# --- Burp (OPTIONAL) ----------------------------------------------------------
if ($env:THREATTRACE_BURP_API_KEY) {
    Add-Result -Name 'Burp DAST' -Category 'OPTIONAL' -Ready $true -Detail 'THREATTRACE_BURP_API_KEY is set (reachability not probed by this script)'
} else {
    Add-Result -Name 'Burp DAST' -Category 'OPTIONAL' -Ready $false -Detail 'Not configured -- expected; primary demo does not require it'
}

# --- Report ---------------------------------------------------------------
Write-Host ''
Write-Host 'ThreatTrace Demo Readiness Check' -ForegroundColor Cyan
Write-Host '=================================' -ForegroundColor Cyan
Write-Host ''

$requiredResults = $results | Where-Object { $_.Category -eq 'REQUIRED' }
$optionalResults = $results | Where-Object { $_.Category -eq 'OPTIONAL' }

Write-Host 'REQUIRED for primary demo:' -ForegroundColor Yellow
foreach ($r in $requiredResults) {
    $mark = if ($r.Ready) { '[READY]' } else { '[NOT READY]' }
    $color = if ($r.Ready) { 'Green' } else { 'Red' }
    Write-Host ("  {0,-13} {1,-40} {2}" -f $mark, $r.Name, $r.Detail) -ForegroundColor $color
}

Write-Host ''
Write-Host 'OPTIONAL (demo degrades gracefully without these):' -ForegroundColor Yellow
foreach ($r in $optionalResults) {
    $mark = if ($r.Ready) { '[READY]' } else { '[UNAVAILABLE]' }
    $color = if ($r.Ready) { 'Green' } else { 'DarkYellow' }
    Write-Host ("  {0,-13} {1,-40} {2}" -f $mark, $r.Name, $r.Detail) -ForegroundColor $color
}

Write-Host ''
$requiredNotReady = $requiredResults | Where-Object { -not $_.Ready }
if ($requiredNotReady.Count -eq 0) {
    Write-Host 'All REQUIRED dependencies are ready. Primary demo can proceed.' -ForegroundColor Green
    exit 0
} else {
    Write-Host "$($requiredNotReady.Count) REQUIRED dependency(ies) not ready -- see docs/block17b-demo-backup.md for the fallback plan." -ForegroundColor Red
    exit 1
}
