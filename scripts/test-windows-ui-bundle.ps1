# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
# Disposable CI-only UI bundle rehearsal. Not an installer or distribution artifact.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $env:RUNNER_TEMP -or $env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows') {
    throw 'Run only in the authorized GitHub Actions test environment.'
}
$root = Join-Path $env:RUNNER_TEMP ('aegis-ui-' + [Guid]::NewGuid().ToString('N'))
$stage = Join-Path $root 'stage'
$unpacked = Join-Path $root 'unpacked'
$zip = Join-Path $root 'ui-rehearsal.zip'
$payload = @('desktop/windows/Show-AegisAlpha.ps1','target/release/aegis-policy.exe','LICENSE','LIMITATIONS.txt')
$original = (Get-FileHash -LiteralPath $payload[1] -Algorithm SHA256).Hash
try {
    New-Item -ItemType Directory -Path (Join-Path $stage 'desktop/windows'),(Join-Path $stage 'target/release') -Force | Out-Null
    foreach ($name in $payload[0..2]) {
        Copy-Item -LiteralPath $name -Destination (Join-Path $stage $name)
    }
    @('AEGIS AI - unsigned development UI rehearsal only.',
        'No active protection. Keep native protections enabled.',
        'Not approved for distribution or installation; dependency inventory incomplete.') |
        Set-Content -LiteralPath (Join-Path $stage 'LIMITATIONS.txt') -Encoding UTF8
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
    Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
    $prefix = (Get-Item -LiteralPath $unpacked).FullName.TrimEnd([char]92) + [char]92
    $actual = @(Get-ChildItem -LiteralPath $unpacked -Force -Recurse -File | ForEach-Object {
        $_.FullName.Substring($prefix.Length).Replace([char]92,[char]47)
    })
    if ($actual.Count -ne $payload.Count -or (Compare-Object $payload $actual -CaseSensitive)) {
        throw 'Unexpected UI bundle contents.'
    }
    foreach ($name in $payload) {
        $first = (Get-FileHash -LiteralPath (Join-Path $stage $name) -Algorithm SHA256).Hash
        $second = (Get-FileHash -LiteralPath (Join-Path $unpacked $name) -Algorithm SHA256).Hash
        if ($first -cne $second) { throw 'UI bundle round-trip integrity failure.' }
    }
    $script = Join-Path $unpacked $payload[0]
    $binary = Join-Path $unpacked $payload[1]
    & powershell.exe -NoProfile -NonInteractive -STA -File $script -UiSmokeTest
    if ($LASTEXITCODE -ne 0) { throw 'Extracted UI bundle smoke failed.' }
    # Negative fixture: rename only the disposable extracted executable.
    Move-Item -LiteralPath $binary -Destination ($binary + '.fixture')
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $negative = & powershell.exe -NoProfile -NonInteractive -STA -File $script -UiSmokeTest 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($code -eq 0 -or ($negative -join ' ') -notmatch 'Build the reviewed development checkout first') {
        throw 'Missing binary UI bundle regression failed.'
    }
    if ((Get-FileHash -LiteralPath $payload[1] -Algorithm SHA256).Hash -cne $original) {
        throw 'Canonical binary changed during UI bundle rehearsal.'
    }
    Write-Output 'PASS: disposable GUI and CLI bundle round-trip, exact payload and missing-binary rejection.'
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
}
if (Test-Path -LiteralPath $root) { throw 'UI rehearsal cleanup failed.' }
exit 0
