param(
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

function Get-ClangFormatPath {
    $clangFormatCommand = Get-Command clang-format -ErrorAction SilentlyContinue
    if ($null -ne $clangFormatCommand) {
        return $clangFormatCommand.Source
    }

    $fallbackPaths = @(
        "C:\Program Files\LLVM\bin\clang-format.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang-format.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\Llvm\x64\bin\clang-format.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\Llvm\x64\bin\clang-format.exe",
        "C:\Program Files\Microsoft Visual Studio\17.0\Community\VC\Tools\Llvm\x64\bin\clang-format.exe",
        "C:\Program Files\Microsoft Visual Studio\17.0\Professional\VC\Tools\Llvm\x64\bin\clang-format.exe",
        "C:\Program Files\Microsoft Visual Studio\17.0\Enterprise\VC\Tools\Llvm\x64\bin\clang-format.exe"
    )

    foreach ($candidate in $fallbackPaths) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "Unable to locate clang-format. Ensure it is installed and available in PATH."
}

function Get-RepoRoot {
    $current = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($current)) {
        $current = Split-Path -Parent $PSCommandPath
    }

    while ($true) {
        $cmakePath = Join-Path $current "CMakeLists.txt"
        if (Test-Path $cmakePath) {
            return $current
        }

        $parent = Split-Path -Parent $current
        if ($parent -eq $current) {
            throw "Unable to locate repository root (CMakeLists.txt not found in parent chain)."
        }

        $current = $parent
    }
}

$repoRoot = Get-RepoRoot
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
        # Use --output-replacements-xml to avoid PowerShell stdout encoding
        # mangling multi-byte UTF-8 characters in files that contain non-ASCII
        # (e.g. Unicode in string literals or comments).  The XML output is
        # pure ASCII: clang-format emits <replacements/> (self-closing) when
        # the file is already formatted, or a non-empty <replacements> element
        # when changes are needed.
        $xml = & $clangFormatPath --style=file --output-replacements-xml $file.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "clang-format failed while checking: $($file.FullName)"
        }

        # Join the captured lines and look for actual replacement entries.
        $xmlText = $xml -join "`n"
        if ($xmlText -match '<replacement ') {
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
