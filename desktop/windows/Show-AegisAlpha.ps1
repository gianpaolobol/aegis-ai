# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
[CmdletBinding()]
param([switch]$SelfTest)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Get-AegisCommands { @('status','demo-policy','demo-wifi','--version') }
function Test-AegisCommand([string]$Command) { return (Get-AegisCommands) -ccontains $Command }
# Native diagnostic readings are advisory, not AEGIS enforcement.
function Convert-AegisState($Value) {
    if ($Value -is [bool]) {
        if ($Value) { return 'Enabled' } else { return 'Disabled' }
    }
    # NetSecurity exposes GpoBoolean, including NotConfigured.
    if ($Value -is [System.Enum] -or $Value -is [string]) {
        if ([string]$Value -ceq 'True') { return 'Enabled' }
        if ([string]$Value -ceq 'False') { return 'Disabled' }
    }
    return 'Unknown'
}
function Get-AegisProperty($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}
function Get-AegisNativeReport([scriptblock]$ReadDefender, [scriptblock]$ReadFirewall) {
    $lines = @('Windows native protection snapshot (read-only).',
        'Not AEGIS protection; third-party antivirus not assessed.',
        'Unknown means missing, ambiguous or unavailable. Enabled is not proof of safety.')
    $defender = $null
    try {
        $records = @(& $ReadDefender)
        if ($records.Count -eq 1) { $defender = $records[0] }
    } catch { $defender = $null }
    foreach ($key in @('AntivirusEnabled','RealTimeProtectionEnabled','AMServiceEnabled','IsTamperProtected')) {
        $state = Convert-AegisState (Get-AegisProperty $defender $key)
        $lines += "Defender $key : $state"
    }
    $profiles = @()
    try { $profiles = @(& $ReadFirewall) } catch { $profiles = @() }
    foreach ($name in @('Domain','Private','Public')) {
        $matching = @($profiles | Where-Object { (Get-AegisProperty $_ 'Name') -ceq $name })
        $state = 'Unknown'
        if ($matching.Count -eq 1) {
            $state = Convert-AegisState (Get-AegisProperty $matching[0] 'Enabled')
        }
        $lines += "Firewall $name : $state"
    }
    $lines += 'Firewall values are per-profile active policy, not an identification of the current network.'
    return ($lines -join [Environment]::NewLine)
}
function Test-AegisNativeReport {
    $good = { [pscustomobject]@{AntivirusEnabled=$true;RealTimeProtectionEnabled=$false;AMServiceEnabled=$true; ComputerID='SYNTHETIC-PRIVATE'} }
    $firewall = {
        [pscustomobject]@{Name='Domain';Enabled='True'}
        [pscustomobject]@{Name='Private';Enabled='NotConfigured'}
        [pscustomobject]@{Name='Public';Enabled='False'}
    }
    $report = Get-AegisNativeReport $good $firewall
    foreach ($expected in @('Defender AntivirusEnabled : Enabled','Defender RealTimeProtectionEnabled : Disabled','Defender IsTamperProtected : Unknown','Firewall Domain : Enabled','Firewall Private : Unknown','Firewall Public : Disabled')) {
        if (-not $report.Contains($expected)) { throw "Unexpected diagnostic fixture result: $expected" }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'Unexpected private field disclosure' }
    $report = Get-AegisNativeReport { throw 'SYNTHETIC-PRIVATE' } { throw 'SYNTHETIC-PRIVATE' }
    if (($report.Split([char]10) | Where-Object { $_ -match ' : Unknown' }).Count -ne 7 -or $report.Contains('SYNTHETIC-PRIVATE')) { throw 'Provider failure not safely represented' }
    $report = Get-AegisNativeReport { & $good; & $good } { & $firewall; & $firewall }
    if (($report.Split([char]10) | Where-Object { $_ -match ' : Unknown' }).Count -ne 7) { throw 'Duplicate provider records accepted' }
    if ((Convert-AegisState 'false') -ne 'Unknown' -or (Convert-AegisState 1) -ne 'Unknown') { throw 'Ambiguous state accepted' }
    Write-Output 'PASS: native diagnostic synthetic fixtures'
}
if ($SelfTest) {
    foreach ($command in (Get-AegisCommands)) {
        if (-not (Test-AegisCommand $command)) { throw 'Allowlist failure' }
    }
    foreach ($command in @('', 'STATUS', 'scan', 'status extra', 'status;exit')) {
        if (Test-AegisCommand $command) { throw 'Unexpected command accepted' }
    }
    Test-AegisNativeReport
    Write-Output 'PASS: fixed development UI command allowlist'
    return
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows only' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$exe = Join-Path $root 'target\release\aegis-policy.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'Build the reviewed development checkout first: cargo build --release --locked'
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object Windows.Forms.Form
$form.Text = 'AEGIS AI - Development Alpha'
$form.Size = New-Object Drawing.Size(760,520)
$form.MinimumSize = New-Object Drawing.Size(760,520)
$form.StartPosition = 'CenterScreen'
$banner = New-Object Windows.Forms.Label
$banner.Location = New-Object Drawing.Point(18,14)
$banner.Size = New-Object Drawing.Size(700,62)
$banner.Text = @('DEVELOPMENT ONLY - Active protection unavailable.', 'Keep native antivirus and firewall enabled. No scan, VPN or enforcement.', 'Run only from a trusted, reviewed development checkout.') -join [Environment]::NewLine
$form.Controls.Add($banner)
$output = New-Object Windows.Forms.TextBox
$output.Location = New-Object Drawing.Point(18,176)
$output.Size = New-Object Drawing.Size(705,274)
$output.Multiline = $true
$output.ReadOnly = $true
$output.ScrollBars = 'Vertical'
$output.Anchor = 'Top, Bottom, Left, Right'
$output.Text = 'Select a read-only demonstration. No personal data is collected.'
$form.Controls.Add($output)
$commands = @(
    @{Label='Status'; Command='status'},
    @{Label='AI policy demo'; Command='demo-policy'},
    @{Label='Wi-Fi demo'; Command='demo-wifi'},
    @{Label='Version'; Command='--version'}
)
for ($i=0; $i -lt $commands.Count; $i++) {
    $button = New-Object Windows.Forms.Button
    $button.Location = New-Object Drawing.Point((18 + 174*$i),82)
    $button.Size = New-Object Drawing.Size(165,36)
    $button.Text = $commands[$i].Label
    $button.Tag = $commands[$i].Command
    $button.Add_Click({
        param($sender,$eventArgs)
        $command = [string]$sender.Tag
        if (-not (Test-AegisCommand $command)) { $output.Text = 'Command rejected.'; return }
        try {
            $result = & $exe $command 2>&1
            $code = $LASTEXITCODE
            $output.Text = "Exit code: $code" + [Environment]::NewLine + ($result -join [Environment]::NewLine)
        } catch {
            $output.Text = 'Development executable could not be started.'
        }
    })
    $form.Controls.Add($button)
}
$native = New-Object Windows.Forms.Button
$native.Location = New-Object Drawing.Point(18,126)
$native.Size = New-Object Drawing.Size(340,36)
$native.Text = 'Windows native protection (read-only)'
$native.Add_Click({
    try {
        $output.Text = Get-AegisNativeReport {
            Defender\Get-MpComputerStatus -ErrorAction Stop -WarningAction SilentlyContinue
        } {
            NetSecurity\Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop -WarningAction SilentlyContinue
        }
    } catch { $output.Text = 'Native diagnostic unavailable; no changes made.' }
})
$form.Controls.Add($native)
try { [void]$form.ShowDialog() } finally { $form.Dispose() }
