param(
    [string]$RemotePi = "pi@10.0.0.18",

    [string]$RemoteRoot = "~/src",

    [string]$RepoName = "cpp-jose",

    [string]$Branch = "",

    [ValidateSet("OpenSSL", "CNG")]
    [string]$Backend = "OpenSSL",

    [string]$BuildType = "Debug",

    [ValidateRange(1, 1000000)]
    [int]$RsaGenerationMaxAttempts = 8,

    [switch]$CleanBuildDir,

    [switch]$ForceReset,

    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

function Get-RequiredCommandPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName
    )

    $command = Get-Command $CommandName -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw "Required command '$CommandName' was not found in PATH."
    }

    return $command.Source
}

function Get-CurrentBranch {
    $branch = (& git rev-parse --abbrev-ref HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($branch)) {
        throw "Unable to determine current git branch."
    }

    return $branch
}

function Get-OriginUrl {
    $originUrl = (& git config --get remote.origin.url).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($originUrl)) {
        throw "Unable to determine remote.origin.url."
    }

    return $originUrl
}

Get-RequiredCommandPath -CommandName "ssh" | Out-Null
Get-RequiredCommandPath -CommandName "git" | Out-Null

if ([string]::IsNullOrWhiteSpace($Branch)) {
    $Branch = Get-CurrentBranch
}

$originUrl = Get-OriginUrl

$cleanBuildFlag = if ($CleanBuildDir) { "1" } else { "0" }
$forceResetFlag = if ($ForceReset) { "1" } else { "0" }
$skipTestsFlag = if ($SkipTests) { "1" } else { "0" }

Write-Host "Remote host: $RemotePi"
Write-Host "Remote repo root: $RemoteRoot"
Write-Host "Repository name: $RepoName"
Write-Host "Repository URL: $originUrl"
Write-Host "Branch: $Branch"
Write-Host "Backend: $Backend"
Write-Host "Build type: $BuildType"
Write-Host "JOSE_RSA_GENERATION_MAX_ATTEMPTS: $RsaGenerationMaxAttempts"
Write-Host "Clean build dir: $CleanBuildFlag"
Write-Host "Force reset existing clone: $forceResetFlag"
Write-Host "Skip tests: $skipTestsFlag"

$remoteScript = @'
set -eu
if (set -o pipefail) 2>/dev/null; then
    set -o pipefail
fi

REMOTE_ROOT="$1"
REPO_NAME="$2"
REPO_URL="$3"
BRANCH="$4"
BUILD_TYPE="$5"
BACKEND="$6"
RSA_ATTEMPTS="$7"
CLEAN_BUILD="$8"
FORCE_RESET="$9"
SKIP_TESTS="${10}"

REPO_DIR="${REMOTE_ROOT}/${REPO_NAME}"
BUILD_DIR="${REPO_DIR}/build/pi-${BACKEND}-${BUILD_TYPE}"

mkdir -p "${REMOTE_ROOT}"

if [ -d "${REPO_DIR}/.git" ]; then
    echo "Updating existing repository at ${REPO_DIR}"
    cd "${REPO_DIR}"

    git remote set-url origin "${REPO_URL}"
    git fetch --all --prune

    if [ "${FORCE_RESET}" = "1" ]; then
        git checkout "${BRANCH}"
        git reset --hard "origin/${BRANCH}"
    else
        if [ -n "$(git status --porcelain)" ]; then
            echo "Remote repo has uncommitted changes. Re-run with -ForceReset to discard them." >&2
            exit 20
        fi
        git checkout "${BRANCH}"
        git pull --ff-only origin "${BRANCH}"
    fi
else
    echo "Cloning repository into ${REPO_DIR}"
    git clone "${REPO_URL}" "${REPO_DIR}"
    cd "${REPO_DIR}"
    git checkout "${BRANCH}"
fi

if [ "${CLEAN_BUILD}" = "1" ] && [ -d "${BUILD_DIR}" ]; then
    rm -rf "${BUILD_DIR}"
fi

cmake -S "${REPO_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DJOSE_BACKEND="${BACKEND}" \
    -DJOSE_RSA_GENERATION_MAX_ATTEMPTS="${RSA_ATTEMPTS}"

cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}" --parallel

if [ "${SKIP_TESTS}" = "1" ]; then
    echo "Skipping tests because -SkipTests was specified."
else
    ctest --test-dir "${BUILD_DIR}" --output-on-failure -C "${BUILD_TYPE}"
fi
'@

$sshArgs = @(
    $RemotePi,
    "bash",
    "-s",
    "--",
    $RemoteRoot,
    $RepoName,
    $originUrl,
    $Branch,
    $BuildType,
    $Backend,
    "$RsaGenerationMaxAttempts",
    $cleanBuildFlag,
    $forceResetFlag,
    $skipTestsFlag
)

$remoteScriptUnix = ($remoteScript -replace "`r`n", "`n")
if (-not $remoteScriptUnix.EndsWith("`n")) {
    $remoteScriptUnix += "`n"
}

$remoteScriptUnix | & ssh @sshArgs
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    throw "Remote build/test failed with exit code $exitCode"
}

Write-Host "Remote build/test completed successfully."
exit 0
