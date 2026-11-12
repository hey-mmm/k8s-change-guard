<#
.SYNOPSIS
  Cross-compile the single static Linux change-guard binary and build the
  deterministic release tarball from Windows.

.DESCRIPTION
  Build-time helper only.  The target host receives the tarball; it needs no
  Python, virtualenv, pip, source tree, or CGO runtime.
#>
param(
    [string]$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$Version = '',
    [ValidateSet('amd64', 'arm64')]
    [string]$Arch = 'amd64',
    [string]$Output = '',
    [string]$Go = 'go'
)

$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path $Repo).Path
# Run every build/package command from the repository root.  Callers may invoke
# this script from any working directory.
Push-Location $Repo

if (-not $Version) {
    $common = Get-Content -LiteralPath (Join-Path $Repo 'internal\guard\common.go') -Raw
    $match = [regex]::Match($common, 'const Version = "([^"]+)"')
    if (-not $match.Success) { throw 'cannot determine release version' }
    $Version = $match.Groups[1].Value
}
if (-not $Output) {
    $Output = Join-Path $Repo "dist\k8s-change-guard-$Version.tar.gz"
}
$Output = [IO.Path]::GetFullPath($Output)

$stage = Join-Path ([IO.Path]::GetTempPath()) ("change-guard-release-" + [guid]::NewGuid().ToString('N'))
$stage = [IO.Path]::GetFullPath($stage)
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
if (-not $stage.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "refusing to use a staging path outside the temporary root: $stage"
}
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$oldCgo = $env:CGO_ENABLED
$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldGoflags = $env:GOFLAGS
try {
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'linux'
    $env:GOARCH = $Arch
    $env:GOFLAGS = ''
    $binary = Join-Path $stage 'k8s-change-guard'
    & $Go build '-trimpath' '-buildvcs=false' '-tags' 'netgo,osusergo' '-ldflags' '-s -w -buildid=' '-o' $binary './cmd/change-guard'
    if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE" }

    $knowledge = Join-Path $Repo 'knowledge'
    $links = Get-ChildItem -LiteralPath $knowledge -Recurse -Force |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }
    if ($links) { throw 'refusing to package symlinks or reparse points in knowledge/' }
    Copy-Item -LiteralPath $knowledge -Destination (Join-Path $stage 'knowledge') -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $Repo 'config.example.yaml') -Destination (Join-Path $stage 'config.example.yaml')
    $readme = Join-Path $Repo 'README.md'
    if (Test-Path -LiteralPath $readme) {
        Copy-Item -LiteralPath $readme -Destination (Join-Path $stage 'README.md')
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $Output) -Force | Out-Null
    # Restore the host toolchain environment before `go run ./scripts/packaging`.
    # The Linux cross-build variables above would try to execute a Linux binary
    # on this Windows host.
    $env:CGO_ENABLED = $oldCgo
    $env:GOOS = $oldGoos
    $env:GOARCH = $oldGoarch
    $env:GOFLAGS = $oldGoflags
    & $Go run './scripts/packaging' '--stage' $stage '--output' $Output '--version' $Version '--arch' $Arch
    if ($LASTEXITCODE -ne 0) { throw "packaging failed with exit code $LASTEXITCODE" }
} finally {
    $env:CGO_ENABLED = $oldCgo
    $env:GOOS = $oldGoos
    $env:GOARCH = $oldGoarch
    $env:GOFLAGS = $oldGoflags
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
    Pop-Location
}
