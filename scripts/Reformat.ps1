param(
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

function Get-ClangFormatPath {
    $clangFormatCommand = Get-Command clang-format -ErrorAction SilentlyContinue
    if ($null -eq $clangFormatCommand) {
        throw "Unable to locate clang-format. Ensure it is installed and available in PATH."
    }

    return $clangFormatCommand.Source
}

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$clangFormatPath = Get-ClangFormatPath

$roots = @("src", "include", "tests", "examples") |
    ForEach-Object { Join-Path $repoRoot $_ } |
    Where-Object { Test-Path $_ }

$extensions = @("*.c", "*.cc", "*.cpp", "*.cxx", "*.h", "*.hh", "*.hpp", "*.hxx", "*.ipp", "*.inl")

$files = foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -File -Include $extensions
}

$files = $files | Sort-Object FullName -Unique

if ($files.Count -eq 0) {
    Write-Host "No C/C++ files found to format."
    exit 0
}

Write-Host "Using clang-format: $clangFormatPath"
Write-Host "Files discovered: $($files.Count)"

if ($CheckOnly) {
    $needsFormatting = New-Object System.Collections.Generic.List[string]

    foreach ($file in $files) {
        $formatted = & $clangFormatPath --style=file $file.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "clang-format failed while checking: $($file.FullName)"
        }

        $original = Get-Content -Path $file.FullName -Raw
        if ($original -cne $formatted) {
            $relativePath = [System.IO.Path]::GetRelativePath($repoRoot, $file.FullName)
            $needsFormatting.Add($relativePath)
        }
    }

    if ($needsFormatting.Count -gt 0) {
        Write-Host "Files requiring formatting:"
        foreach ($path in $needsFormatting) {
            Write-Host " - $path"
        }
        exit 1
    }

    Write-Host "All checked files already match clang-format output."
    exit 0
}

foreach ($file in $files) {
    & $clangFormatPath -i --style=file $file.FullName
    if ($LASTEXITCODE -ne 0) {
        throw "clang-format failed while formatting: $($file.FullName)"
    }
}

Write-Host "Formatted $($files.Count) files."
exit 0
