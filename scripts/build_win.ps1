<#
.DESCRIPTION
Build script for ipr-daemon binary on Windows.
NOTE: Npcap runtime is required (https://npcap.com/#download)

.PARAMETER VersionTag
The version tag to use for the output binary. Defaults to "0.0.0".
#>

[CmdletBinding()]
param (
  [string]$VersionTag = "0.0.0",
  [switch]$help
)

Function Show-Man {
    Get-Help "$PSScriptRoot\build_win.ps1"
}

if ($help) {
    Show-Man
    exit 0
}

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

if (-not $env:GOOS) {
    $env:GOOS = "windows"
}
if (-not $env:GOARCH) {
    $env:GOARCH = ($env:PROCESSOR_ARCHITECTURE -replace "x86", "386").ToLower()
}
# Only amd64/x86_64 and arm64 supported
If ($env:GOARCH -notin "386", "amd64", "arm64") {
    Write-Host "Unsupported architecture: $env:GOARCH"
    exit 1
}

$Tag = (git -C $repoRoot describe --tags (git -C $repoRoot rev-list --tags --max-count=1))
if (-not $Tag) {
    $Tag = "NO-TAG"
}
$Commit = (git -C $repoRoot rev-parse HEAD)
if (-not $Commit) {
    $Commit = "NO-CommitID"
}
$Delta = (git -C $repoRoot diff | Measure-Object -Line).Lines
if ($Delta -eq 0) {
    $Delta = ""
}

$BUILD_INFOS = (Get-Date).ToString("yyyy-MM-dd'T'HH:mm:sszzz").Replace(":", "", 1)
$LDFLAGS = $env:LDFLAGS + " -X main.VERSION=$VersionTag -X main.COMMIT=$Commit"
$LDFLAGS += " -X main.DELTA=$Delta -X main.TAG=$Tag -X main.BUILDINFO=$BUILD_INFOS -s -w"

Write-Host "Setting up build environment..."
$outputDir = Join-Path $repoRoot "dist"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "Building ipr-daemon for $env:GOOS/$env:GOARCH..."
$env:CGO_ENABLED = "0"

$exec = "go"
$outputPath = Join-Path $outputDir "iprd-$VersionTag-$env:GOOS-$env:GOARCH.exe"
$build = @("-C", $repoRoot, "build", "-ldflags", "$LDFLAGS", "-o", $outputPath, "./cmd")
Write-Host ($exec + " " + ($build -join " "))
& $exec $build
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
Write-Host "Output: $outputPath"
