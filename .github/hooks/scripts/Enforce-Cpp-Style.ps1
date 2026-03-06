$ErrorActionPreference = 'Stop'

function Write-JsonResponse {
    param(
        [hashtable]$Response
    )

    $Response | ConvertTo-Json -Compress
}

function Continue-Response {
    Write-JsonResponse @{ continue = $true }
}

function Block-Response {
    param(
        [string]$Reason,
        [string]$SystemMessage
    )

    Write-JsonResponse @{
        decision = 'block'
        reason = $Reason
        systemMessage = $SystemMessage
    }
}

function Get-PathValues {
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]$Node
    )

    $Paths = New-Object System.Collections.Generic.List[string]

    function Visit-Node {
        param([object]$Object)

        if ($null -eq $Object) {
            return
        }

        if ($Object -is [string]) {
            return
        }

        if ($Object -is [System.Collections.IDictionary]) {
            foreach ($Key in $Object.Keys) {
                $Value = $Object[$Key]
                if ($Value -is [string] -and ($Key -in @('filePath', 'path', 'new_path', 'old_path'))) {
                    $Paths.Add($Value)
                }
                Visit-Node -Object $Value
            }
            return
        }

        if ($Object -is [System.Collections.IEnumerable]) {
            foreach ($Item in $Object) {
                Visit-Node -Object $Item
            }
            return
        }

        foreach ($Property in $Object.PSObject.Properties) {
            $Value = $Property.Value
            if ($Value -is [string] -and ($Property.Name -in @('filePath', 'path', 'new_path', 'old_path'))) {
                $Paths.Add($Value)
            }
            Visit-Node -Object $Value
        }
    }

    Visit-Node -Object $Node
    return $Paths
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "../../..")
Set-Location $RepoRoot

$Payload = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($Payload)) {
    Continue-Response
    exit 0
}

# Option 3: try Bash hook first on Windows, fallback to native PowerShell implementation.
$Bash = Get-Command bash -ErrorAction SilentlyContinue
if ($null -ne $Bash) {
    try {
        $BashOutput = $Payload | & $Bash.Source ".github/hooks/scripts/enforce-cpp-style.sh" 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($BashOutput)) {
            $Trimmed = $BashOutput.Trim()
            if ($Trimmed.StartsWith('{') -and $Trimmed.EndsWith('}')) {
                Write-Output $Trimmed
                exit 0
            }
        }
    }
    catch {
        # Fall through to native PowerShell checks.
    }
}

try {
    $Data = $Payload | ConvertFrom-Json -Depth 64
}
catch {
    Continue-Response
    exit 0
}

$EventName = $Data.hookEventName
if ([string]::IsNullOrWhiteSpace($EventName)) {
    $EventName = $Data.hook_event_name
}

if ($EventName -eq 'SessionStart') {
    Write-JsonResponse @{
        continue = $true
        systemMessage = 'C++ style enforcement is active: use C++20/C++23, Allman braces (namespace braces on same line), Vlinder naming rules, and keep OpenSSL/CNG-specific code confined to backend-specific files.'
    }
    exit 0
}

if ($EventName -ne 'PostToolUse') {
    Continue-Response
    exit 0
}

$ToolName = $Data.toolName
if ([string]::IsNullOrWhiteSpace($ToolName)) {
    $ToolName = $Data.tool_name
}

if ($ToolName -notin @('apply_patch', 'create_file', 'edit_file', 'write_file')) {
    Continue-Response
    exit 0
}

$CandidatePaths = Get-PathValues $Data
$CppFiles = $CandidatePaths |
    Where-Object { $_ -is [string] } |
    Where-Object { $_ -match '\.c[^./]*$|\.h[^./]*$' } |
    Sort-Object -Unique

if ($CppFiles.Count -eq 0) {
    Continue-Response
    exit 0
}

$MissingTools = New-Object System.Collections.Generic.List[string]
if ($IsLinux -and -not (Get-Command jq -ErrorAction SilentlyContinue)) {
    $MissingTools.Add('jq')
}
if (-not (Get-Command clang-format -ErrorAction SilentlyContinue)) {
    $MissingTools.Add('clang-format')
}
if (-not (Get-Command clang-tidy -ErrorAction SilentlyContinue)) {
    $MissingTools.Add('clang-tidy')
}

if ($MissingTools.Count -gt 0) {
    Block-Response -Reason 'Hook bootstrap failed' -SystemMessage ("Required tools are missing: {0}" -f (($MissingTools | Sort-Object -Unique) -join ', '))
    exit 0
}

$FormatViolations = New-Object System.Collections.Generic.List[string]
foreach ($File in $CppFiles) {
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
        continue
    }

    & clang-format --dry-run --Werror -- "$File" *> $null
    if ($LASTEXITCODE -ne 0) {
        $FormatViolations.Add($File)
    }
}

$CompileDbDir = $null
foreach ($Candidate in @((Join-Path $RepoRoot 'build'), $RepoRoot.Path)) {
    if (Test-Path -LiteralPath (Join-Path $Candidate 'compile_commands.json') -PathType Leaf) {
        $CompileDbDir = $Candidate
        break
    }
}

$TidyViolations = New-Object System.Collections.Generic.List[string]
foreach ($File in $CppFiles) {
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
        continue
    }

    if ($null -ne $CompileDbDir) {
        & clang-tidy -p "$CompileDbDir" --quiet --warnings-as-errors='*' -- "$File" *> $null
    }
    else {
        & clang-tidy --quiet --warnings-as-errors='*' -- "$File" -- -std=c++20 -I"$RepoRoot/include" -I"$RepoRoot/src" *> $null
    }

    if ($LASTEXITCODE -ne 0) {
        $TidyViolations.Add($File)
    }
}

if ($FormatViolations.Count -eq 0 -and $TidyViolations.Count -eq 0) {
    Continue-Response
    exit 0
}

$Message = 'C++ style check failed.'
if ($FormatViolations.Count -gt 0) {
    $Message += ' clang-format violations in:'
    foreach ($File in ($FormatViolations | Sort-Object -Unique)) {
        $Message += " $File;"
    }
}
if ($TidyViolations.Count -gt 0) {
    $Message += ' clang-tidy violations in:'
    foreach ($File in ($TidyViolations | Sort-Object -Unique)) {
        $Message += " $File;"
    }
}
$Message += ' Fix the listed files before continuing.'

Block-Response -Reason 'C++ style check failed' -SystemMessage $Message
exit 0
