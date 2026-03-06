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

function Add-VisualStudioLlvmToPath {
    if ($env:OS -ne 'Windows_NT') {
        return
    }

    if ((Get-Command clang-format -ErrorAction SilentlyContinue) -and (Get-Command clang-tidy -ErrorAction SilentlyContinue)) {
        return
    }

    $VsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $VsWhere -PathType Leaf)) {
        return
    }

    $Json = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json
    if (-not $Json) {
        return
    }

    $Instances = $Json | ConvertFrom-Json
    if (-not $Instances) {
        return
    }

    $InstallationPath = $Instances[0].installationPath
    if ([string]::IsNullOrWhiteSpace($InstallationPath)) {
        return
    }

    $Candidates = @(
        (Join-Path $InstallationPath 'VC\Tools\Llvm\bin'),
        (Join-Path $InstallationPath 'VC\Tools\Llvm\x64\bin')
    )

    foreach ($Candidate in $Candidates) {
        if (-not (Test-Path -LiteralPath $Candidate -PathType Container)) {
            continue
        }

        $HasClangFormat = Test-Path -LiteralPath (Join-Path $Candidate 'clang-format.exe') -PathType Leaf
        $HasClangTidy = Test-Path -LiteralPath (Join-Path $Candidate 'clang-tidy.exe') -PathType Leaf
        if (-not ($HasClangFormat -and $HasClangTidy)) {
            continue
        }

        $PathParts = @($env:Path -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($PathParts -contains $Candidate) {
            return
        }

        $env:Path = "$Candidate;$env:Path"
        return
    }
}

function Test-BootstrapTools {
    param(
        [string]$RepositoryRoot
    )

    $BootstrapPath = Join-Path $RepositoryRoot 'bootstrap'
    if (-not (Test-Path -LiteralPath $BootstrapPath -PathType Leaf)) {
        return @{
            ok = $false
            message = "Unable to load bootstrap script: $BootstrapPath"
        }
    }

    $IsWindowsPlatform = ($env:OS -eq 'Windows_NT')
    if (-not $IsWindowsPlatform) {
        $Bash = Get-Command bash -ErrorAction SilentlyContinue
        if ($null -ne $Bash) {
            $EscapedRepoRoot = $RepositoryRoot.Replace("'", "''")
            $CheckScript = "set -euo pipefail; cd '$EscapedRepoRoot'; CPP_JOSE_BOOTSTRAP_AUTO_CHECK=0; source ./bootstrap; hookBootstrapCheckTools"
            & $Bash.Source -lc $CheckScript *> $null
            if ($LASTEXITCODE -eq 0) {
                return @{
                    ok = $true
                    message = ''
                }
            }
            return @{
                ok = $false
                message = 'Required tools are missing. On Linux, jq is mandatory; clang-format and clang-tidy are required.'
            }
        }
    }

    $MissingTools = New-Object System.Collections.Generic.List[string]
    if ((-not $IsWindowsPlatform) -and -not (Get-Command jq -ErrorAction SilentlyContinue)) {
        $MissingTools.Add('jq')
    }
    if (-not (Get-Command clang-format -ErrorAction SilentlyContinue)) {
        $MissingTools.Add('clang-format')
    }
    if (-not (Get-Command clang-tidy -ErrorAction SilentlyContinue)) {
        $MissingTools.Add('clang-tidy')
    }

    if ($MissingTools.Count -gt 0) {
        return @{
            ok = $false
            message = ("Required tools are missing: {0}" -f (($MissingTools | Sort-Object -Unique) -join ', '))
        }
    }

    return @{
        ok = $true
        message = ''
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

Add-VisualStudioLlvmToPath

$Payload = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($Payload)) {
    Continue-Response
    exit 0
}

try {
    $ConvertFromJson = Get-Command ConvertFrom-Json -ErrorAction Stop
    if ($ConvertFromJson.Parameters.ContainsKey('Depth')) {
        $Data = $Payload | ConvertFrom-Json -Depth 64
    }
    else {
        $Data = $Payload | ConvertFrom-Json
    }
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

$BootstrapResult = Test-BootstrapTools -RepositoryRoot $RepoRoot.Path
if (-not $BootstrapResult.ok) {
    Block-Response -Reason 'Hook bootstrap failed' -SystemMessage $BootstrapResult.message
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
