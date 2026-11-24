# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
# CI-only portable package rehearsal. No installer, settings or service changes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $env:RUNNER_TEMP -or -not $env:GITHUB_ACTIONS) {
    throw 'Run only in the authorized GitHub Actions test environment.'
}
$root = Join-Path $env:RUNNER_TEMP ('aegis-package-' + [Guid]::NewGuid().ToString('N'))
try {
    $stage = Join-Path $root 'stage'
    $unpacked = Join-Path $root 'unpacked'
    $zip = Join-Path $root 'aegis-windows-unsigned-test.zip'
    New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath 'target/release/aegis-policy.exe' -Destination $stage
    Copy-Item -LiteralPath 'LICENSE' -Destination $stage
    @(
        'AEGIS AI development alpha — unsigned CI rehearsal only.'
        'Read-only synthetic demonstrations; no active protection or enforcement.'
        'Not approved for distribution or installation. Keep native protection enabled.'
    ) | Set-Content -LiteralPath (Join-Path $stage 'LIMITATIONS.txt') -Encoding utf8
    $expected = @('aegis-policy.exe', 'LICENSE', 'LIMITATIONS.txt')
    $manifest = foreach ($name in $expected) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $stage $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    $manifest | Set-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Encoding ascii
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
    Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
    $actual = @(Get-ChildItem -LiteralPath $unpacked -Force | Select-Object -ExpandProperty Name)
    if (Compare-Object ($expected + 'SHA256SUMS.txt') $actual) { throw 'Unexpected package contents.' }
    foreach ($name in ($expected + 'SHA256SUMS.txt')) {
        $a = (Get-FileHash -LiteralPath (Join-Path $stage $name) -Algorithm SHA256).Hash
        $b = (Get-FileHash -LiteralPath (Join-Path $unpacked $name) -Algorithm SHA256).Hash
        if ($a -ne $b) { throw 'Package round-trip integrity check failed.' }
    }
    $exe = Join-Path $unpacked 'aegis-policy.exe'
    $status = & $exe status
    if ($LASTEXITCODE -ne 0 -or (($status -join "`n") -notmatch 'Active protection: unavailable')) {
        throw 'Extracted executable status check failed.'
    }
    $zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    Write-Output "Unsigned CI-only package round-trip SHA256: $zipHash"
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
if (Test-Path -LiteralPath $root) { throw 'Temporary package cleanup failed.' }
