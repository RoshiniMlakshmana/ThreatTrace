#requires -Version 5.1
# ThreatTrace PostToolUse validation hook.
# Read-only: never modifies/deletes files, never executes SQL, never contacts the network,
# never runs Atomic Red Team content, never touches Supabase, never prints secret values.

$ErrorActionPreference = 'Stop'

function Exit-Clean {
    exit 0
}

function Write-BlockAndExit {
    param([string]$RelativePath, [string[]]$Failures)

    $bulletList = ($Failures | ForEach-Object { "- $_" }) -join "`n"
    $reason = "ThreatTrace validation failed for '$RelativePath'. " +
              "The file has already been written to disk and must be corrected before proceeding.`n$bulletList"

    $payload = [ordered]@{
        decision = 'block'
        reason   = $reason
    }

    ($payload | ConvertTo-Json -Compress)
    exit 0
}

# ---- 1-2: read hook input from stdin, extract tool_name / tool_input.file_path ----
try {
    $stdin = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($stdin)) { Exit-Clean }
    $hookInput = $stdin | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Exit-Clean
}

$toolName = $hookInput.tool_name
$filePath = $hookInput.tool_input.file_path

if ([string]::IsNullOrWhiteSpace($filePath)) { Exit-Clean }
if ($toolName -notmatch '^(Write|Edit)$') { Exit-Clean }

# ---- 3: file must still exist ----
$resolved = $null
try { $resolved = (Resolve-Path -LiteralPath $filePath -ErrorAction Stop).Path } catch { Exit-Clean }
if (-not $resolved) { Exit-Clean }

# ---- 3: file must be inside the ThreatTrace project ----
$projectRoot = $env:CLAUDE_PROJECT_DIR
if ([string]::IsNullOrWhiteSpace($projectRoot)) {
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
try { $projectRoot = (Resolve-Path -LiteralPath $projectRoot -ErrorAction Stop).Path } catch { Exit-Clean }

if (-not $resolved.StartsWith($projectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    Exit-Clean
}

$relative = $resolved.Substring($projectRoot.Length).TrimStart('\', '/')
$relativeNormalized = $relative -replace '\\', '/'

# ---- 3: never validate references/atomic-red-team ----
if ($relativeNormalized -eq 'references/atomic-red-team' -or $relativeNormalized -like 'references/atomic-red-team/*') {
    Exit-Clean
}

# ---- load content ----
$content = $null
try { $content = Get-Content -LiteralPath $resolved -Raw -ErrorAction Stop } catch { $content = '' }
if ($null -eq $content) { $content = '' }
$content = $content -replace "^\xFEFF", ''   # strip BOM if present

$extension = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
$fileName  = [System.IO.Path]::GetFileName($resolved)

$failures = New-Object System.Collections.Generic.List[string]

# ---- 4: JSON validation ----
if ($extension -eq '.json') {
    try {
        $null = $content | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $failures.Add("JSON file does not parse: $($_.Exception.Message)")
    }
}

# ---- 5/6/7: Markdown validation ----
if ($extension -eq '.md') {
    $isCommandOrAgent = $relativeNormalized -match '^\.claude/(commands|agents)/'
    $isSkillFile      = $fileName -eq 'SKILL.md'
    $isUnderSkills    = $relativeNormalized -match '^\.claude/skills/'

    if ($isCommandOrAgent) {
        if ([string]::IsNullOrWhiteSpace($content)) {
            $failures.Add("command/agent markdown file is empty")
        }
        else {
            $lines = $content -split "`r?`n"
            if ($lines[0].Trim() -ne '---') {
                $failures.Add("command/agent markdown must start with YAML frontmatter delimited by '---'")
            }
            else {
                $closingIndex = -1
                for ($i = 1; $i -lt $lines.Count; $i++) {
                    if ($lines[$i].Trim() -eq '---') { $closingIndex = $i; break }
                }
                if ($closingIndex -eq -1) {
                    $failures.Add("command/agent markdown frontmatter has no closing '---'")
                }
                else {
                    $frontmatter = ($lines[1..($closingIndex - 1)] -join "`n")
                    if ($frontmatter -notmatch '(?im)^\s*description\s*:') {
                        $failures.Add("command/agent markdown frontmatter is missing a 'description' field")
                    }
                }
            }
        }
    }
    elseif ($isSkillFile) {
        if ([string]::IsNullOrWhiteSpace($content)) {
            $failures.Add("SKILL.md is empty")
        }
        else {
            $lines = $content -split "`r?`n"
            if ($lines[0].Trim() -ne '---') {
                $failures.Add("SKILL.md must start with YAML frontmatter delimited by '---'")
            }
            else {
                $closingIndex = -1
                for ($i = 1; $i -lt $lines.Count; $i++) {
                    if ($lines[$i].Trim() -eq '---') { $closingIndex = $i; break }
                }
                if ($closingIndex -eq -1) {
                    $failures.Add("SKILL.md frontmatter has no closing '---'")
                }
                else {
                    $frontmatter = ($lines[1..($closingIndex - 1)] -join "`n")
                    if ($frontmatter -notmatch '(?im)^\s*description\s*:') {
                        $failures.Add("SKILL.md frontmatter is missing a 'description' field")
                    }
                }
            }
        }
    }
    elseif ($isUnderSkills) {
        if ([string]::IsNullOrWhiteSpace($content)) {
            $failures.Add("markdown file under .claude/skills is empty")
        }
    }
}

# ---- 8: SQL validation (never executed) ----
if ($extension -eq '.sql') {
    if ([string]::IsNullOrWhiteSpace($content)) {
        $failures.Add("SQL file is empty")
    }
    else {
        $openParens  = ([regex]::Matches($content, '\(')).Count
        $closeParens = ([regex]::Matches($content, '\)')).Count
        if ($openParens -ne $closeParens) {
            $failures.Add("SQL parentheses appear unbalanced ($openParens open vs $closeParens close)")
        }

        if ($content.TrimEnd() -notmatch ';\s*$') {
            $failures.Add("SQL statements do not appear terminated (no trailing ';')")
        }

        $dangerousPatterns = @('DROP\s+DATABASE', 'DROP\s+SCHEMA', 'TRUNCATE\s+TABLE', 'ALTER\s+ROLE')
        foreach ($pattern in $dangerousPatterns) {
            if ($content -match "(?i)$pattern") {
                $failures.Add("dangerous SQL operation detected (pattern: $pattern) - review required, not executed")
            }
        }
    }
}

# ---- 9: hard-coded secret scan (assignment-style only) ----
$secretScanExtensions = @('.json', '.md', '.sql', '.ps1', '.py', '.yaml', '.yml')
if ($secretScanExtensions -contains $extension) {
    $secretFields = @('password', 'api[_-]?key', 'access[_-]?token', 'private[_-]?key', 'secret')
    $placeholderPattern = '(?i)^(your|change[-_ ]?me|example|placeholder|xxx+|redacted|todo|insert[-_ ]?|<.*>|\$\{.*\})'

    foreach ($field in $secretFields) {
        $pattern = "(?im)^\s*[""']?\b(?:$field)\b[""']?\s*[:=]\s*[""']([^""'\r\n]{4,})[""']"
        $matches = [regex]::Matches($content, $pattern)
        foreach ($m in $matches) {
            $value = $m.Groups[1].Value
            if ($value -match $placeholderPattern) { continue }
            $lineNumber = ($content.Substring(0, $m.Index) -split "`n").Count
            $failures.Add("possible hard-coded secret near line $lineNumber (assignment matching '$field'); value withheld")
        }
    }
}

# ---- 10/11: report ----
if ($failures.Count -gt 0) {
    Write-BlockAndExit -RelativePath $relativeNormalized -Failures $failures
}

Exit-Clean
