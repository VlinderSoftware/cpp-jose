param(
    [switch]$Configure,
    [switch]$Build,
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$Architecture = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info
{
    param([string]$Message)
    Write-Host "[bootstrap] $Message" -ForegroundColor Cyan
}

function Write-WarnMessage
{
    param([string]$Message)
    Write-Host "[bootstrap] $Message" -ForegroundColor Yellow
}

function Get-LatestVisualStudio
{
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere))
    {
        throw "Could not find vswhere.exe. Install Visual Studio (or Build Tools) first."
    }

    $json = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json
    if (-not $json)
    {
        throw "No Visual Studio instance with C++ tools was found. Install the 'Desktop development with C++' workload."
    }

    $instances = $json | ConvertFrom-Json
    if (-not $instances)
    {
        throw "No usable Visual Studio instance was returned by vswhere."
    }

    return $instances[0]
}

function Get-CMakePath
{
    param([pscustomobject]$VsInstance)

    $candidates = @(
        (Join-Path $VsInstance.installationPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"),
        (Join-Path $VsInstance.installationPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.cmd")
    )

    foreach ($candidate in $candidates)
    {
        if (Test-Path $candidate)
        {
            return $candidate
        }
    }

    $cmd = Get-Command cmake -ErrorAction SilentlyContinue
    if ($cmd)
    {
        return $cmd.Source
    }

    throw "Could not find cmake.exe in Visual Studio or PATH. Install the Visual Studio CMake component."
}

function Get-VisualStudioGenerator
{
    param(
        [string]$CMakePath,
        [pscustomobject]$VsInstance
    )

    $helpText = & $CMakePath --help | Out-String
    $helpLines = $helpText -split "`r?`n"

    $majorVersion = [int](($VsInstance.installationVersion -split '\.')[0])
    $majorMatch = "Visual Studio\s+$majorVersion\s+\d{4}"

    $line = ($helpLines | Where-Object { $_ -match $majorMatch } | Select-Object -First 1)
    if (-not $line)
    {
        $line = ($helpLines | Where-Object { $_ -match '^\*?\s*Visual Studio\s+\d+\s+\d{4}\s+=' } | Select-Object -First 1)
    }

    if (-not $line)
    {
        throw "Could not determine a Visual Studio generator from 'cmake --help'."
    }

    if ($line -match '(Visual Studio\s+\d+\s+\d{4})')
    {
        return $matches[1]
    }

    throw "Failed to parse Visual Studio generator from line: $line"
}

function Read-JsonMap
{
    param([string]$Path)

    if (-not (Test-Path $Path))
    {
        return @{}
    }

    $raw = Get-Content -Path $Path -Raw
    if (-not $raw.Trim())
    {
        return @{}
    }

    $obj = $raw | ConvertFrom-Json
    $map = @{}
    foreach ($prop in $obj.PSObject.Properties)
    {
        $map[$prop.Name] = $prop.Value
    }

    return $map
}

function Write-Json
{
    param(
        [string]$Path,
        [object]$Object
    )

    $json = $Object | ConvertTo-Json -Depth 20
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + "`n", $utf8NoBom)
}

$repoRoot = Split-Path -Parent $PSCommandPath
Set-Location $repoRoot

if (-not (Test-Path (Join-Path $repoRoot "CMakeLists.txt")))
{
    throw "Run this script from the repository root. Could not find CMakeLists.txt in '$repoRoot'."
}

$vs = Get-LatestVisualStudio
$cmakePath = Get-CMakePath -VsInstance $vs
$generator = Get-VisualStudioGenerator -CMakePath $cmakePath -VsInstance $vs

Write-Info "Visual Studio: $($vs.displayName)"
Write-Info "Installation: $($vs.installationPath)"
Write-Info "CMake: $cmakePath"
Write-Info "Generator: $generator"

$presetBaseName = "vs-latest-$Architecture"
$configurePresetName = "$presetBaseName-$($Configuration.ToLowerInvariant())"

$userPresetsPath = Join-Path $repoRoot "CMakeUserPresets.json"
$userPresets = [ordered]@{
    version = 6
    configurePresets = @(
        [ordered]@{
            name = "$presetBaseName-debug"
            displayName = "Visual Studio Latest $Architecture Debug"
            generator = $generator
            architecture = $Architecture
            binaryDir = "`${sourceDir}/build/$presetBaseName-debug"
            cacheVariables = [ordered]@{
                CMAKE_INSTALL_PREFIX = "`${sourceDir}/build/install/$presetBaseName-debug"
                BUILD_TESTS = "ON"
                BUILD_EXAMPLES = "ON"
            }
        },
        [ordered]@{
            name = "$presetBaseName-release"
            displayName = "Visual Studio Latest $Architecture Release"
            generator = $generator
            architecture = $Architecture
            binaryDir = "`${sourceDir}/build/$presetBaseName-release"
            cacheVariables = [ordered]@{
                CMAKE_INSTALL_PREFIX = "`${sourceDir}/build/install/$presetBaseName-release"
                BUILD_TESTS = "ON"
                BUILD_EXAMPLES = "ON"
            }
        }
    )
    buildPresets = @(
        [ordered]@{
            name = "$presetBaseName-debug"
            configurePreset = "$presetBaseName-debug"
            configuration = "Debug"
        },
        [ordered]@{
            name = "$presetBaseName-release"
            configurePreset = "$presetBaseName-release"
            configuration = "Release"
        }
    )
    testPresets = @(
        [ordered]@{
            name = "$presetBaseName-debug"
            configurePreset = "$presetBaseName-debug"
            configuration = "Debug"
            output = [ordered]@{
                outputOnFailure = $true
            }
        }
    )
}

Write-Json -Path $userPresetsPath -Object $userPresets
Write-Info "Wrote $(Split-Path -Leaf $userPresetsPath)"

$vscodeDir = Join-Path $repoRoot ".vscode"
if (-not (Test-Path $vscodeDir))
{
    New-Item -Path $vscodeDir -ItemType Directory | Out-Null
}

$settingsPath = Join-Path $vscodeDir "settings.json"
$settings = Read-JsonMap -Path $settingsPath
$settings["cmake.useCMakePresets"] = "always"
$settings["cmake.configureOnOpen"] = $true
$settings["cmake.cmakePath"] = $cmakePath
$settings["cmake.generator"] = $generator
$settings["cmake.configurePreset"] = $configurePresetName
$settings["cmake.buildPreset"] = $configurePresetName

Write-Json -Path $settingsPath -Object $settings
Write-Info "Updated .vscode/settings.json"

Write-Info "Bootstrap complete."
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  1) Reopen this folder in VS Code (or run 'CMake: Delete Cache and Reconfigure')."
Write-Host "  2) Use preset '$configurePresetName' in CMake Tools if prompted."
Write-Host ""

if ($Configure)
{
    Write-Info "Running configure with preset '$configurePresetName'"
    & $cmakePath --preset $configurePresetName
}

if ($Build)
{
    Write-Info "Running build with preset '$configurePresetName'"
    & $cmakePath --build --preset $configurePresetName --parallel
}
