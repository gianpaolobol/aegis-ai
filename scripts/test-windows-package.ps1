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
    # Deliberately limited to the current zero-third-party-Cargo-dependency alpha.
    # Fail closed when the dependency graph changes; extend the SBOM before packaging.
    $rawMetadata = & cargo +1.100.0 metadata --locked --offline --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
    $metadata = ($rawMetadata -join "`n") | ConvertFrom-Json
    if (@($metadata.packages).Count -ne 1 -or @($metadata.resolve.nodes).Count -ne 1) {
        throw 'Cargo dependency graph changed; update SBOM generator before packaging.'
    }
    $pkg = $metadata.packages[0]
    $node = $metadata.resolve.nodes[0]
    if ($pkg.name -cne 'aegis-policy' -or $pkg.id -cne $node.id -or
        $metadata.resolve.root -cne $pkg.id -or @($pkg.dependencies).Count -ne 0 -or
        @($node.dependencies).Count -ne 0) {
        throw 'Unexpected Cargo package or dependency graph.'
    }
    $componentRef = 'pkg:cargo/aegis-policy@' + $pkg.version
    $exeHash = (Get-FileHash -LiteralPath (Join-Path $stage 'aegis-policy.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $sbom = [ordered]@{
        bomFormat = 'CycloneDX'
        specVersion = '1.7'
        version = 1
        metadata = @{
            component = @{
                'bom-ref' = $componentRef
                type = 'application'
                name = $pkg.name
                version = $pkg.version
                purl = $componentRef
                hashes = @(@{ alg = 'SHA-256'; content = $exeHash })
                licenses = @(@{ license = @{ name = 'Proprietary; see packaged LICENSE' } })
            }
        }
        dependencies = @(@{ ref = $componentRef; dependsOn = @() })
        properties = @(@{
            name = 'aegis:inventory:scope'
            value = 'Cargo graph only; compiler, standard library and OS/runtime components not inventoried'
        })
    }
    $sbom | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $stage 'SBOM.cdx.json') -Encoding utf8
    $expected = @('aegis-policy.exe', 'LICENSE', 'LIMITATIONS.txt', 'SBOM.cdx.json')
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
    # Validate the extracted manifest against a fixed allowlist, not paths from the manifest.
    function Assert-PackageManifest {
        $lines = @(Get-Content -LiteralPath (Join-Path $unpacked 'SHA256SUMS.txt'))
        if ($lines.Count -ne $expected.Count) { throw 'Invalid manifest length.' }
        foreach ($name in $expected) {
            $hash = (Get-FileHash -LiteralPath (Join-Path $unpacked $name) -Algorithm SHA256).Hash.ToLowerInvariant()
            if (@($lines | Where-Object { $_ -ceq "$hash  $name" }).Count -ne 1) {
                throw 'Manifest verification failed.'
            }
        }
    }
    Assert-PackageManifest
    $readBom = Get-Content -Raw -LiteralPath (Join-Path $unpacked 'SBOM.cdx.json') | ConvertFrom-Json
    if ($readBom.bomFormat -cne 'CycloneDX' -or $readBom.specVersion -cne '1.7' -or
        $readBom.metadata.component.version -cne $pkg.version -or
        $readBom.metadata.component.hashes[0].content -cne $exeHash -or
        $readBom.dependencies[0].ref -cne $componentRef -or
        @($readBom.dependencies[0].dependsOn).Count -ne 0) {
        throw 'Extracted SBOM semantic check failed.'
    }
    $exe = Join-Path $unpacked 'aegis-policy.exe'
    $status = & $exe status
    if ($LASTEXITCODE -ne 0 -or (($status -join "`n") -notmatch 'Active protection: unavailable')) {
        throw 'Extracted executable status check failed.'
    }
    # Negative test: modify only a disposable documentation file; verify rejection.
    Add-Content -LiteralPath (Join-Path $unpacked 'LIMITATIONS.txt') -Value 'Synthetic integrity test.'
    $rejected = $false
    try { Assert-PackageManifest } catch {
        if ($_.Exception.Message -ne 'Manifest verification failed.') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Modified test file was not rejected.' }
    Write-Output 'Cargo-scoped SBOM and negative manifest test passed.'
    $zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    Write-Output "Unsigned CI-only package round-trip SHA256: $zipHash"
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
if (Test-Path -LiteralPath $root) { throw 'Temporary package cleanup failed.' }
