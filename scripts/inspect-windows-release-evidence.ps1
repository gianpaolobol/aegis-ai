# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
# CI-only read-only evidence collection. Not a license clearance or release gate.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'Run only in the authorized GitHub-hosted Windows evidence environment.'
}
function Get-NoticeDigest([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}
# Synthetic fixtures: missing/empty must never count as evidence; exact bytes must.
$fixture = Join-Path $env:RUNNER_TEMP ('aegis-notice-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    $file = Join-Path $fixture 'notice.txt'
    if ($null -ne (Get-NoticeDigest $file)) { throw 'Missing notice regression.' }
    [IO.File]::WriteAllBytes($file, [byte[]]@())
    if ($null -ne (Get-NoticeDigest $file)) { throw 'Empty notice regression.' }
    [IO.File]::WriteAllBytes($file, [byte[]]@(97,98,99))
    if ((Get-NoticeDigest $file) -cne 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD') { throw 'Notice hash regression.' }
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
Write-Output 'Notice evidence synthetic regressions passed (3 cases).'
$sysroot = & rustc +1.100.0 --print sysroot
if ($LASTEXITCODE -ne 0 -or @($sysroot).Count -ne 1 -or -not (Test-Path -LiteralPath $sysroot -PathType Container)) {
    throw 'Pinned Rust sysroot query failed.'
}
$doc = Join-Path $sysroot 'share/doc/rust'
foreach ($name in @('COPYRIGHT-library.html','COPYRIGHT.html','LICENSE-APACHE','LICENSE-MIT')) {
    $digest = Get-NoticeDigest (Join-Path $doc $name)
    if ($null -eq $digest) {
        Write-Output "Rust notice $name : unavailable or empty; distribution review remains open."
    } else {
        Write-Output "Rust notice $name SHA256: $digest"
    }
}
$exe = 'target/release/aegis-policy.exe'
$before = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
Write-Output "Inspected executable SHA256: $before"
# Inspect direct PE imports only. Do not execute or redistribute imported DLLs.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
    $installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0) { throw 'Visual Studio discovery failed.' }
    if (@($installation).Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($installation)) {
        $versionFile = Join-Path $installation 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt'
        if (Test-Path -LiteralPath $versionFile -PathType Leaf) {
            $version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
            if ($version -cnotmatch '^[0-9]+(\.[0-9]+){1,3}$') { throw 'Unexpected VC tool version format.' }
            $dumpbin = Join-Path $installation "VC/Tools/MSVC/$version/bin/Hostx64/x64/dumpbin.exe"
            if (Test-Path -LiteralPath $dumpbin -PathType Leaf) {
                Write-Output "Inspection tool VC version: $version (not proof of linker identity)"
                Write-Output 'Direct PE dependency report follows:'
                & $dumpbin /DEPENDENTS $exe
                if ($LASTEXITCODE -ne 0) { throw 'PE dependency inspection failed.' }
            } else { Write-Output 'PE dependency inspection tool unavailable.' }
        } else { Write-Output 'VC default version metadata unavailable.' }
    } else { Write-Output 'VC installation unavailable.' }
} else { Write-Output 'Visual Studio discovery tool unavailable.' }
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $before) { throw 'Executable changed during evidence collection.' }
Write-Output 'Distribution review remains OPEN: notice hashes and direct imports are not a complete inventory or legal clearance.'
exit 0
