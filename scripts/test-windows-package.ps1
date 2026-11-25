# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
# CI-only package and disposable signing rehearsal. No installation or service changes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $env:RUNNER_TEMP -or $env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows') {
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
    # Rehearse MSIX packaging and disposable test signing; never install or publish.
    # The SDK is a build-only proprietary Microsoft tool; no SDK binaries shipped.
    $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\10.0.26100.0\x64\makeappx.exe'
    if (-not (Test-Path -LiteralPath $sdk -PathType Leaf)) { throw 'Pinned MakeAppx SDK path unavailable.' }
    $msixStage = Join-Path $root 'msix-stage'
    $msixOut = Join-Path $root 'msix-unpacked'
    $msix = Join-Path $root 'aegis-unsigned-ci.msix'
    New-Item -ItemType Directory -Path $msixStage | Out-Null
    foreach ($name in ($expected + 'SHA256SUMS.txt')) {
        Copy-Item -LiteralPath (Join-Path $stage $name) -Destination $msixStage
    }
    Copy-Item -LiteralPath 'packaging/windows/AppxManifest.xml' -Destination $msixStage
    $assets = Join-Path $msixStage 'Assets'
    New-Item -ItemType Directory -Path $assets | Out-Null
    Add-Type -AssemblyName System.Drawing
    foreach ($entry in @(@{name='StoreLogo.png';size=50}, @{name='Square150.png';size=150}, @{name='Square44.png';size=44})) {
        $bitmap = [System.Drawing.Bitmap]::new([int]$entry.size, [int]$entry.size)
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try { $graphics.Clear([System.Drawing.Color]::DarkSlateBlue) }
            finally { $graphics.Dispose() }
            $bitmap.Save((Join-Path $assets $entry.name), [System.Drawing.Imaging.ImageFormat]::Png)
        } finally { $bitmap.Dispose() }
    }
    # Explicit native exit-code checks also cover the expected-negative invocation.
    $PSNativeCommandUseErrorActionPreference = $false
    & $sdk pack /d $msixStage /p $msix /o
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $msix -PathType Leaf)) {
        throw 'MSIX pack failed.'
    }
    & $sdk unpack /p $msix /d $msixOut /o
    if ($LASTEXITCODE -ne 0) { throw 'MSIX unpack failed.' }
    $payload = $expected + @('SHA256SUMS.txt','AppxManifest.xml','Assets\StoreLogo.png','Assets\Square150.png','Assets\Square44.png')
    foreach ($name in $payload) {
        $a = (Get-FileHash -LiteralPath (Join-Path $msixStage $name) -Algorithm SHA256).Hash
        $b = (Get-FileHash -LiteralPath (Join-Path $msixOut $name) -Algorithm SHA256).Hash
        if ($a -ne $b) { throw 'MSIX payload hash mismatch.' }
    }
    # No install or trust-store modification. Run only the extracted known binary.
    $msixExe = Join-Path $msixOut 'aegis-policy.exe'
    $status = & $msixExe status
    if ($LASTEXITCODE -ne 0 -or (($status -join "`n") -notmatch 'Active protection: unavailable')) {
        throw 'MSIX extracted executable status check failed.'
    }
    Write-Output ("Unsigned MSIX rehearsal SHA256: " + (Get-FileHash -LiteralPath $msix -Algorithm SHA256).Hash)
    # Development signature rehearsal: only on a disposable GitHub-hosted runner.
    # No production keys, PFX export, timestamp service, installation, or upload.
    if ($env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_ACTIONS -cne 'true') {
        throw 'Signing rehearsal requires an ephemeral GitHub-hosted runner.'
    }
    $signTool = Join-Path (Split-Path -Parent $sdk) 'signtool.exe'
    if (-not (Test-Path -LiteralPath $signTool -PathType Leaf)) { throw 'Pinned SignTool unavailable.' }
    $signedMsix = Join-Path $root 'aegis-signed-test-only.msix'
    Copy-Item -LiteralPath $msix -Destination $signedMsix
    & $signTool verify /pa $msix
    if ($LASTEXITCODE -eq 0) { throw 'Unsigned MSIX unexpectedly passed signature verification.' }
    $cert = $null
    $trustedPath = $null
    $personalPath = $null
    $addedTrust = $false
    try {
        $cert = New-SelfSignedCertificate -Type Custom -Subject 'CN=AEGIS AI CI Rehearsal' `
            -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage DigitalSignature `
            -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable `
            -NotAfter (Get-Date).AddHours(6) -FriendlyName 'AEGIS disposable CI signing test' `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
        $personalPath = 'Cert:\CurrentUser\My\' + $cert.Thumbprint
        $trustedPath = 'Cert:\LocalMachine\TrustedPeople\' + $cert.Thumbprint
        if (Test-Path -LiteralPath $trustedPath) { throw 'Unexpected pre-existing trust entry.' }
        & $signTool sign /fd SHA256 /s My /sha1 $cert.Thumbprint $signedMsix
        if ($LASTEXITCODE -ne 0) { throw 'Development MSIX signing failed.' }
        # A valid cryptographic signature alone must not establish publisher trust.
        & $signTool verify /pa /all $signedMsix
        if ($LASTEXITCODE -eq 0) { throw 'Untrusted development signer unexpectedly accepted.' }
        Write-Output 'Untrusted development signer rejected before leaf import.'
        # Trust only the newly generated public leaf certificate, never a root CA.
        $cer = Join-Path $root 'ci-public-leaf.cer'
        Export-Certificate -Cert $cert -FilePath $cer | Out-Null
        # The exact thumbprint was absent before import. Arm cleanup before the call.
        $addedTrust = $true
        Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
        if (-not (Test-Path -LiteralPath $trustedPath)) { throw 'Temporary leaf trust missing.' }
        & $signTool verify /pa /all $signedMsix
        if ($LASTEXITCODE -ne 0) { throw 'Development MSIX signature verification failed.' }
        # Verify expected signer and retain exact payload after signing.
        $signature = Get-AuthenticodeSignature -LiteralPath $signedMsix
        if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
            $signature.SignerCertificate.Thumbprint -cne $cert.Thumbprint) {
            throw 'Development package signer verification failed.'
        }
        $signedOut = Join-Path $root 'signed-unpacked'
        & $sdk unpack /p $signedMsix /d $signedOut /o
        if ($LASTEXITCODE -ne 0) { throw 'Signed MSIX unpack failed.' }
        foreach ($name in $payload) {
            $a = (Get-FileHash -LiteralPath (Join-Path $msixStage $name) -Algorithm SHA256).Hash
            $b = (Get-FileHash -LiteralPath (Join-Path $signedOut $name) -Algorithm SHA256).Hash
            if ($a -ne $b) { throw 'Signed MSIX payload hash mismatch.' }
        }
        # Modify only a disposable copy of the synthetic package, never the original.
        $tampered = Join-Path $root 'tampered-signed-test.msix'
        Copy-Item -LiteralPath $signedMsix -Destination $tampered
        $archive = [System.IO.Compression.ZipFile]::Open($tampered, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            $entry = $archive.GetEntry('LIMITATIONS.txt')
            if ($null -eq $entry) { throw 'Missing synthetic tamper fixture entry.' }
            $entry.Delete()
            $newEntry = $archive.CreateEntry('LIMITATIONS.txt')
            $writer = [System.IO.StreamWriter]::new($newEntry.Open())
            try { $writer.Write('Synthetic integrity regression only.') } finally { $writer.Dispose() }
        } finally { $archive.Dispose() }
        & $signTool verify /pa /all $tampered
        if ($LASTEXITCODE -eq 0) { throw 'Modified signed package unexpectedly verified.' }
        Write-Output 'Development MSIX signed and verified; tampered copy rejected.'
    } finally {
        # Remove only our ephemeral leaf and private key, even on test failure.
        try {
            if ($addedTrust -and (Test-Path -LiteralPath $trustedPath)) {
                Remove-Item -LiteralPath $trustedPath -Force
            }
            if ($addedTrust -and (Test-Path -LiteralPath $trustedPath)) { throw 'Temporary trust cleanup failed.' }
        } finally {
            if ($personalPath -and (Test-Path -LiteralPath $personalPath)) {
                Remove-Item -LiteralPath $personalPath -DeleteKey -Force
            }
            if ($personalPath -and (Test-Path -LiteralPath $personalPath)) { throw 'Temporary signing certificate cleanup failed.' }
        }
        if ($null -ne $cert) { $cert.Dispose() }
    }
    Write-Output 'Temporary signing certificate and trust cleanup passed.'
    # Native verification after cleanup must reject the same package again.
    & $signTool verify /pa /all $signedMsix
    if ($LASTEXITCODE -eq 0) { throw 'Development signer remained trusted after cleanup.' }
    Write-Output 'Development signer rejected after temporary trust removal.'
    # Regression for MakeAppx 0x80080204: a console alias requires multi-instance activation.
    # Modify only the disposable staging manifest, then restore exact original bytes.
    $stagedManifest = Join-Path $msixStage 'AppxManifest.xml'
    $originalManifest = [System.IO.File]::ReadAllBytes($stagedManifest)
    try {
        $manifestText = [System.IO.File]::ReadAllText($stagedManifest)
        $badManifest = $manifestText.Replace(' uap10:SupportsMultipleInstances="true"', '')
        if ($badManifest -ceq $manifestText) { throw 'Console regression fixture not generated.' }
        [System.IO.File]::WriteAllText($stagedManifest, $badManifest, [System.Text.UTF8Encoding]::new($false))
        $badConsole = Join-Path $root 'single-instance-console-negative.msix'
        & $sdk pack /d $msixStage /p $badConsole /o
        if ($LASTEXITCODE -eq 0) { throw 'Console alias without multi-instance declaration was accepted.' }
        Write-Output 'MSIX console multi-instance negative test passed.'
    } finally {
        [System.IO.File]::WriteAllBytes($stagedManifest, $originalManifest)
    }
    Remove-Item -LiteralPath (Join-Path $assets 'Square44.png') -Force
    $badMsix = Join-Path $root 'missing-logo-negative.msix'
    & $sdk pack /d $msixStage /p $badMsix /o
    if ($LASTEXITCODE -eq 0) { throw 'MSIX missing referenced logo was accepted.' }
    Write-Output 'MSIX missing required asset negative test passed.'
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
# GitHub Actions pwsh propagates the last native exit code. The last MakeAppx
# invocation intentionally fails. Only report success after every assertion and
# cleanup completed; any unexpected native failure or exception above still fails.
Write-Output 'All package rehearsal assertions and cleanup passed.'
exit 0
