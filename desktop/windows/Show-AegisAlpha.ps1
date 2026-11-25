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


# DNS configuration only: no resolution, probes, remote CIM, or changes.
# Counts are per provider row/address occurrence, not unique interfaces or servers.
function Get-AegisDnsReport([scriptblock]$ReadDns) {
    $intro = @('Windows DNS configuration (read-only).',
        'Configured entries only; may include inactive interfaces.',
        'No resolver trust, encryption, filtering, VPN or reachability assessment.')
    try {
        $records = @(& $ReadDns)
        if ($records.Count -eq 0 -or $records.Count -gt 256) { throw 'Unavailable inventory' }
        $configured = 0; $empty = 0; $unknown = 0; $loopback = 0; $other = 0
        foreach ($record in $records) {
            if ($null -eq $record) { $unknown++; continue }
            $property = $record.PSObject.Properties['ServerAddresses']
            if ($null -eq $property -or $null -eq $property.Value) { $unknown++; continue }
            $values = $property.Value
            if ($values -isnot [array] -or $values.Count -gt 32) { $unknown++; continue }
            if ($values.Count -eq 0) { $empty++; continue }
            $localCount = 0; $otherCount = 0; $valid = $true
            foreach ($value in $values) {
                $ip = $null
                if ($value -isnot [string] -or $value.Length -gt 80 -or
                    $value -cnotmatch '\A[0-9a-fA-F:.]+(?:%[0-9]+)?\z' -or
                    -not [Net.IPAddress]::TryParse($value,[ref]$ip)) {
                    $valid = $false; break
                }
                # Reject unspecified addresses, including mapped IPv4 unspecified.
                if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
                if ($ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any)) {
                    $valid = $false; break
                }
                # Reject noncanonical IPv4 shorthand and ambiguous leading zeroes.
                if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
                    $value -notmatch ':' -and $ip.ToString() -cne $value) { $valid = $false; break }
                if ([Net.IPAddress]::IsLoopback($ip)) { $localCount++ } else { $otherCount++ }
            }
            if (-not $valid) { $unknown++; continue }
            $configured++; $loopback += $localCount; $other += $otherCount
        }
        $intro += @("Provider rows with addresses: $configured",
            "Provider rows with empty lists: $empty", "Unknown or malformed rows: $unknown",
            "Loopback address occurrences: $loopback", "Other address occurrences: $other",
            'Empty lists do not prove DNS is absent. A loopback address does not prove local filtering.')
    } catch { $intro += 'DNS inventory unavailable.' }
    return ($intro -join [Environment]::NewLine)
}
function Test-AegisDnsReport {
    $report = Get-AegisDnsReport {
        [pscustomobject]@{ServerAddresses=@('127.0.0.1','::1','192.0.2.1');InterfaceAlias='SYNTHETIC-PRIVATE'}
        [pscustomobject]@{ServerAddresses=@()}
        [pscustomobject]@{ServerAddresses=@('2001:db8::1','invalid')}
        [pscustomobject]@{InterfaceAlias='SYNTHETIC-PRIVATE'}
        [pscustomobject]@{ServerAddresses=@('::ffff:127.0.0.1','2001:db8::2')}
    }
    foreach ($expected in @('Provider rows with addresses: 2','Provider rows with empty lists: 1',
        'Unknown or malformed rows: 2','Loopback address occurrences: 3','Other address occurrences: 2')) {
        if (-not $report.Contains($expected)) { throw 'DNS fixture count mismatch' }
    }
    foreach ($private in @('192.0.2.1','2001:db8','127.0.0.1','SYNTHETIC-PRIVATE','invalid')) {
        if ($report.Contains($private)) { throw 'DNS diagnostic disclosed raw data' }
    }
    $report = Get-AegisDnsReport { throw 'SYNTHETIC-PRIVATE' }
    if (-not $report.Contains('DNS inventory unavailable.') -or $report.Contains('SYNTHETIC-PRIVATE')) { throw 'DNS provider failure mishandled' }
    if (-not (Get-AegisDnsReport {}).Contains('DNS inventory unavailable.')) { throw 'Missing DNS inventory accepted' }
    $report = Get-AegisDnsReport {
        foreach ($value in @('0.0.0.0','::','::ffff:0.0.0.0','127.1','010.0.0.1')) {
            [pscustomobject]@{ServerAddresses=@($value)}
        }
        [pscustomobject]@{ServerAddresses='192.0.2.1'}
        [pscustomobject]@{ServerAddresses=@('192.0.2.1')*33}
    }
    if (-not $report.Contains('Unknown or malformed rows: 7') -or -not $report.Contains('Provider rows with addresses: 0')) { throw 'Malformed DNS row accepted' }
    if (-not (Get-AegisDnsReport { for ($i=0;$i -lt 257;$i++) { [pscustomobject]@{ServerAddresses=@()} } }).Contains('DNS inventory unavailable.')) { throw 'DNS row limit failed' }
    Write-Output 'PASS: minimized DNS configuration synthetic fixtures'
}

# Local file integrity: explicit user selection, no execution or quarantine.
# A matching digest proves equality to the supplied reference, not publisher trust.
function Get-AegisDigestResult([System.IO.Stream]$Stream, [string]$Expected) {
    if ($Expected -cnotmatch '\A[0-9a-fA-F]{64}\z') { return 'Invalid expected SHA-256.' }
    $sha = $null
    try {
        if (-not $Stream.CanRead -or -not $Stream.CanSeek -or $Stream.Position -ne 0) { return 'Unavailable.' }
        if ($Stream.Length -gt 16777216) { return 'File exceeds 16 MiB alpha limit.' }
        $length = [int]$Stream.Length
        $bytes = [byte[]]::new($length)
        $offset = 0
        while ($offset -lt $length) {
            $n = $Stream.Read($bytes, $offset, $length - $offset)
            if ($n -le 0) { return 'File changed or could not be read.' }
            $offset += $n
        }
        if ($Stream.ReadByte() -ne -1) { return 'File changed or could not be read.' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $digest = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')
        if ($digest -ieq $Expected) { return 'MATCH: digest equals supplied reference. Authenticity and malware status not established.' }
        return 'MISMATCH: digest differs. Do not trust the file until independently verified.'
    } catch { return 'Unavailable.' }
    finally { if ($null -ne $sha) { $sha.Dispose() } }
}
function Test-AegisLocalPathSyntax([string]$Path) {
    # Reject UNC, device paths, relative paths, alternate streams, and traversal.
    if ($Path -cnotmatch '\A[A-Za-z]:\\[^\\]+(?:\\[^\\]+)*\z') { return $false }
    if ($Path.Substring(2) -match '[:*?"<>|\x00-\x1f/]') { return $false }
    foreach ($part in $Path.Substring(3).Split([char]92)) {
        if ($part.EndsWith('.') -or $part.EndsWith(' ') -or
            $part -match '\A(?:CON|PRN|AUX|NUL|COM[0-9\u00b9\u00b2\u00b3]|LPT[0-9\u00b9\u00b2\u00b3])(?:\.|\z)') { return $false }
    }
    return $true
}
function Get-AegisFileIntegrity([string]$Path, [string]$Expected) {
    if ($Expected -cnotmatch '\A[0-9a-fA-F]{64}\z') { return 'Invalid expected SHA-256.' }
    if (-not (Test-AegisLocalPathSyntax $Path)) { return 'Only absolute local file paths are supported.' }
    $stream = $null
    try {
        $root = [IO.Path]::GetPathRoot($Path)
        $drive = New-Object IO.DriveInfo($root)
        if ($drive.DriveType -ne [IO.DriveType]::Fixed) { return 'Only fixed local drives are supported.' }
        # Best-effort path checks, not race-free sandboxing. Trusted local checkout/user path only.
        $current = $root
        # Inspect each ancestor before requesting attributes of its child.
        $blocked = [IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Offline -bor [IO.FileAttributes]::Device
        if (([IO.File]::GetAttributes($root) -band $blocked) -ne 0) { return 'Linked, offline or special files are unsupported.' }
        foreach ($part in $Path.Substring(3).Split([char]92)) {
            $current = [IO.Path]::Combine($current,$part)
            $flags = [IO.File]::GetAttributes($current)
            # Include Windows recall-on-open and recall-on-data-access bits.
            if (([int]$flags -band ([int]$blocked -bor 0x00040000 -bor 0x00400000)) -ne 0) {
                return 'Linked, offline or special files are unsupported.'
            }
        }
        if (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory) -ne 0) { return 'A regular file is required.' }
        $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        return (Get-AegisDigestResult $stream $Expected)
    } catch { return 'Unavailable.' }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}
function Test-AegisIntegrity {
    $abc = 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD'
    $empty = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'
    $stream = [IO.MemoryStream]::new([Text.Encoding]::ASCII.GetBytes('abc'))
    try {
        if ((Get-AegisDigestResult $stream $abc.ToLowerInvariant()) -notlike 'MATCH:*') { throw 'Known digest mismatch' }
        $stream.Position = 0
        if ((Get-AegisDigestResult $stream $empty) -notlike 'MISMATCH:*') { throw 'Wrong digest accepted' }
        $stream.Position = 0
        if ((Get-AegisDigestResult $stream ($abc + '0')) -ne 'Invalid expected SHA-256.' -or $stream.Position -ne 0) { throw 'Invalid digest not rejected before read' }
        $stream.Position = 1
        if ((Get-AegisDigestResult $stream $abc) -ne 'Unavailable.') { throw 'Partial stream accepted' }
    } finally { $stream.Dispose() }
    $stream = [IO.MemoryStream]::new()
    try {
        if ((Get-AegisDigestResult $stream $empty) -notlike 'MATCH:*') { throw 'Empty digest mismatch' }
        $stream.SetLength(16777217)
        if ((Get-AegisDigestResult $stream $abc) -ne 'File exceeds 16 MiB alpha limit.' -or $stream.Position -ne 0) { throw 'Size bound failed' }
    } finally { $stream.Dispose() }
    foreach ($bad in @('\\server\share\x','\\?\C:\x','C:x','C:\a\..\x','C:\x:stream','C:\NUL.txt','C:\a.','C:\a\','C:\a/b')) {
        if (Test-AegisLocalPathSyntax $bad) { throw 'Unsupported path syntax accepted' }
    }
    if (-not (Test-AegisLocalPathSyntax 'C:\fixture folder\abc.txt')) { throw 'Local path rejected' }
    # Only disposable synthetic fixture, no native provider calls.
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('aegis-fixture-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($dir)
    try {
        $file = Join-Path $dir 'abc.txt'
        [IO.File]::WriteAllBytes($file,[Text.Encoding]::ASCII.GetBytes('abc'))
        if ((Get-AegisFileIntegrity $file $abc) -notlike 'MATCH:*') { throw 'Synthetic file verification failed' }
        if ((Get-AegisFileIntegrity (Join-Path $dir 'missing.txt') $abc) -ne 'Unavailable.') { throw 'Missing file not safely rejected' }
        if ((Get-AegisFileIntegrity $dir $abc) -ne 'A regular file is required.') { throw 'Directory accepted' }
        if ([IO.File]::ReadAllText($file) -cne 'abc') { throw 'Fixture modified' }
    } finally { [IO.Directory]::Delete($dir,$true) }
    Write-Output 'PASS: local SHA-256 synthetic fixtures'
}

if ($SelfTest) {
    foreach ($command in (Get-AegisCommands)) {
        if (-not (Test-AegisCommand $command)) { throw 'Allowlist failure' }
    }
    foreach ($command in @('', 'STATUS', 'scan', 'status extra', 'status;exit')) {
        if (Test-AegisCommand $command) { throw 'Unexpected command accepted' }
    }
    Test-AegisNativeReport
    Test-AegisIntegrity
    Test-AegisDnsReport
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
$form.Size = New-Object Drawing.Size(760,640)
$form.MinimumSize = New-Object Drawing.Size(760,640)
$form.StartPosition = 'CenterScreen'
$banner = New-Object Windows.Forms.Label
$banner.Location = New-Object Drawing.Point(18,14)
$banner.Size = New-Object Drawing.Size(700,62)
$banner.Text = @('DEVELOPMENT ONLY - Active protection unavailable.', 'Keep native antivirus and firewall enabled. No scan, VPN or enforcement.', 'Run only from a trusted, reviewed development checkout.') -join [Environment]::NewLine
$form.Controls.Add($banner)
$output = New-Object Windows.Forms.TextBox
$output.Location = New-Object Drawing.Point(18,286)
$output.Size = New-Object Drawing.Size(705,274)
$output.Multiline = $true
$output.ReadOnly = $true
$output.ScrollBars = 'Vertical'
$output.Anchor = 'Top, Bottom, Left, Right'
$output.Text = 'Select a read-only demonstration. No background collection or transmission.'
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

$dns = New-Object Windows.Forms.Button
$dns.Location = New-Object Drawing.Point(365,126)
$dns.Size = New-Object Drawing.Size(340,36)
$dns.Text = 'DNS configuration (read-only)'
$dns.Add_Click({
    $output.Text = Get-AegisDnsReport {
        DnsClient\Get-DnsClientServerAddress -ErrorAction Stop -WarningAction SilentlyContinue
    }
})
$form.Controls.Add($dns)

$pathLabel = New-Object Windows.Forms.Label
$pathLabel.Location = New-Object Drawing.Point(18,176)
$pathLabel.Size = New-Object Drawing.Size(125,24)
$pathLabel.Text = 'Local file path'
$form.Controls.Add($pathLabel)
$filePath = New-Object Windows.Forms.TextBox
$filePath.Location = New-Object Drawing.Point(150,174)
$filePath.Size = New-Object Drawing.Size(555,24)
$form.Controls.Add($filePath)
$hashLabel = New-Object Windows.Forms.Label
$hashLabel.Location = New-Object Drawing.Point(18,209)
$hashLabel.Size = New-Object Drawing.Size(125,24)
$hashLabel.Text = 'Expected SHA-256'
$form.Controls.Add($hashLabel)
$expectedHash = New-Object Windows.Forms.TextBox
$expectedHash.Location = New-Object Drawing.Point(150,207)
$expectedHash.Size = New-Object Drawing.Size(555,24)
$expectedHash.MaxLength = 128
$form.Controls.Add($expectedHash)
$verify = New-Object Windows.Forms.Button
$verify.Location = New-Object Drawing.Point(18,240)
$verify.Size = New-Object Drawing.Size(340,36)
$verify.Text = 'Verify local file integrity (16 MiB max)'
$verify.Add_Click({
    $output.Text = Get-AegisFileIntegrity $filePath.Text $expectedHash.Text
})
$form.Controls.Add($verify)

try { [void]$form.ShowDialog() } finally { $form.Dispose() }
