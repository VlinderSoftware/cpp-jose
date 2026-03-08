param(
    [Alias("N")]
    [ValidateRange(1, 1000000)]
    [int]$Count = 128,

    [string]$TestDir = "build/baseline-openssl",

    [string]$Config = "Debug",

    [string]$Regex = ""
)

$ErrorActionPreference = "Stop"

function Get-CtestPath {
    $ctestCommand = Get-Command ctest -ErrorAction SilentlyContinue
    if ($null -ne $ctestCommand) {
        return $ctestCommand.Source
    }

    $vsCtestPath = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe"
    if (Test-Path $vsCtestPath) {
        return $vsCtestPath
    }

    throw "Unable to locate ctest. Ensure CMake/ctest is installed and available."
}

if (-not (Test-Path $TestDir)) {
    throw "Test directory not found: $TestDir"
}

$ctestPath = Get-CtestPath
Write-Host "Using ctest: $ctestPath"
Write-Host "Running tests $Count times"
Write-Host "Test directory: $TestDir"
Write-Host "Configuration: $Config"
if (-not [string]::IsNullOrWhiteSpace($Regex)) {
    Write-Host "Regex filter: $Regex"
}

$overallStart = Get-Date

for ($iteration = 1; $iteration -le $Count; $iteration++) {
    Write-Host ""
    Write-Host "=== Iteration $iteration/$Count ==="

    $args = @(
        "--test-dir", $TestDir,
        "-C", $Config,
        "--output-on-failure"
    )

    if (-not [string]::IsNullOrWhiteSpace($Regex)) {
        $args += @("-R", $Regex)
    }

    $iterationStart = Get-Date
    & $ctestPath @args
    $exitCode = $LASTEXITCODE
    $iterationElapsed = (Get-Date) - $iterationStart

    if ($exitCode -ne 0) {
        Write-Error "Iteration $iteration failed after $($iterationElapsed.ToString())."
        exit $exitCode
    }

    Write-Host "Iteration $iteration passed in $($iterationElapsed.ToString())."
}

$overallElapsed = (Get-Date) - $overallStart
Write-Host ""
Write-Host "All $Count iterations passed in $($overallElapsed.ToString())."
exit 0
