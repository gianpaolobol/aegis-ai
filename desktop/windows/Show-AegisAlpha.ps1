# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
[CmdletBinding()]
param([switch]$SelfTest)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Get-AegisCommands { @('status','demo-policy','demo-wifi','--version') }
function Test-AegisCommand([string]$Command) { return (Get-AegisCommands) -ccontains $Command }
if ($SelfTest) {
    foreach ($command in (Get-AegisCommands)) {
        if (-not (Test-AegisCommand $command)) { throw 'Allowlist failure' }
    }
    foreach ($command in @('', 'STATUS', 'scan', 'status extra', 'status;exit')) {
        if (Test-AegisCommand $command) { throw 'Unexpected command accepted' }
    }
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
$output.Location = New-Object Drawing.Point(18,130)
$output.Size = New-Object Drawing.Size(705,320)
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
try { [void]$form.ShowDialog() } finally { $form.Dispose() }
