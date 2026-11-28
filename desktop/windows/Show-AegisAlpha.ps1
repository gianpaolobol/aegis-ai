# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
[CmdletBinding()]
param([switch]$SelfTest, [switch]$UiSmokeTest)
if ($SelfTest -and $UiSmokeTest) { throw 'Select only one test mode.' }
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Get-AegisCommands { @('status','demo-policy','demo-wifi','demo-incidents','demo-patches','demo-mail-auth','demo-recovery','--version') }
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
# Validate inside the function before PowerShell can unwrap singleton arrays.
function Get-AegisDefenderFlag($Record,[string]$Name,[string]$TrueLabel,[string]$FalseLabel) {
    if ($null -eq $Record) { return 'Unknown' }
    $property = $Record.PSObject.Properties[$Name]
    if ($null -eq $property -or $property.Value -isnot [bool]) { return 'Unknown' }
    if ($property.Value) { return $TrueLabel }
    return $FalseLabel
}
function Get-AegisDefenderMode($Record) {
    if ($null -eq $Record) { return 'Unknown' }
    $property = $Record.PSObject.Properties['AMRunningMode']
    if ($null -eq $property -or $property.Value -isnot [string]) { return 'Unknown' }
    switch -CaseSensitive -Exact ($property.Value) {
        'Normal' { return 'Reported active mode' }
        'Passive' { return 'Reported passive mode' }
        'Passive Mode' { return 'Reported passive mode' }
        'EDR Block Mode' { return 'Reported EDR block mode' }
        'SxS Passive Mode' { return 'Reported side-by-side passive mode' }
        default { return 'Unknown' }
    }
}
# Provider ages are whole days, not timestamps or proof of successful scanning.
# 65535 and UINT32_MAX are sentinel/unavailable values in Microsoft examples.
function Get-AegisDefenderAge($Record,[string]$Name) {
    if ($null -eq $Record) { return 'Unknown' }
    $property = $Record.PSObject.Properties[$Name]
    if ($null -eq $property) { return 'Unknown' }
    $value = $property.Value
    if ($value -isnot [uint32] -and $value -isnot [int32]) { return 'Unknown' }
    if ($value -lt 0 -or $value -ge 65535) { return 'Unknown' }
    return ('Reported ' + $value.ToString([Globalization.CultureInfo]::InvariantCulture) + ' day(s)')
}
# Only known scalar actions; never interpret numeric values or arrays.
function Convert-AegisFirewallAction($Record,[string]$Name) {
    if ($null -eq $Record) { return 'Unknown' }
    $property = $Record.PSObject.Properties[$Name]
    if ($null -eq $property) { return 'Unknown' }
    $value = $property.Value
    if ($value -is [string] -or $value -is [System.Enum]) {
        if ([string]$value -ceq 'Allow') { return 'Allow' }
        if ([string]$value -ceq 'Block') { return 'Block' }
    }
    return 'Unknown'
}
function Get-AegisNativeReport([scriptblock]$ReadDefender, [scriptblock]$ReadFirewall) {
    $lines = @('Windows native protection snapshot (read-only).',
        'Not AEGIS protection; third-party antivirus not assessed.',
        'Unknown means missing, ambiguous or unavailable. Enabled is not proof of safety.')
    $defender = $null
    try {
        $records = @(& $ReadDefender | Select-Object -First 2)
        if ($records.Count -eq 1) { $defender = $records[0] }
    } catch { $defender = $null }
    foreach ($key in @('AntivirusEnabled','RealTimeProtectionEnabled','AMServiceEnabled','IsTamperProtected','BehaviorMonitorEnabled','IoavProtectionEnabled','OnAccessProtectionEnabled','NISEnabled')) {
        $state = Get-AegisDefenderFlag $defender $key 'Enabled' 'Disabled'
        $lines += "Defender $key : $state"
    }
    $freshnessState = Get-AegisDefenderFlag $defender 'DefenderSignaturesOutOfDate' 'ReportedOutOfDate' 'NotReportedOutOfDate'
    $lines += "Defender signature freshness : $freshnessState"
    foreach ($entry in @(
        @{Name='AntivirusSignatureAge';Label='signature age'},
        @{Name='QuickScanAge';Label='quick scan age'},
        @{Name='FullScanAge';Label='full scan age'}
    )) {
        $age = Get-AegisDefenderAge $defender $entry.Name
        $lines += "Defender $($entry.Label) : $age"
    }
    foreach ($entry in @(
        @{Name='QuickScanOverdue';Label='quick scan overdue'},
        @{Name='FullScanOverdue';Label='full scan overdue'},
        @{Name='FullScanRequired';Label='full scan required'},
        @{Name='RebootRequired';Label='reboot required'}
    )) {
        $state = Get-AegisDefenderFlag $defender $entry.Name 'ReportedYes' 'NotReportedYes'
        $lines += "Defender $($entry.Label) : $state"
    }
    $lines += 'Ages and maintenance flags are provider observations only; no scan, update, restart or health verdict is performed. Sentinel ages remain Unknown.'
    $mode = Get-AegisDefenderMode $defender
    $lines += "Defender operating mode : $mode"
    $lines += 'Mode is provider-reported; passive modes do not establish primary antivirus protection. EDR block mode alone does not identify the primary antivirus.'
    $profiles = @()
    try {
        $profiles = @(& $ReadFirewall | Select-Object -First 4)
        if ($profiles.Count -gt 3) { $profiles = @() }
    } catch { $profiles = @() }
    foreach ($name in @('Domain','Private','Public')) {
        $matching = @($profiles | Where-Object {
            if ($null -eq $_) { return $false }
            $p = $_.PSObject.Properties['Name']
            if ($null -eq $p) { return $false }
            $v = $p.Value
            return (($v -is [string] -or $v -is [System.Enum]) -and ([string]$v -ceq $name))
        })
        $state = 'Unknown'
        $inbound = 'Unknown'
        $outbound = 'Unknown'
        if ($matching.Count -eq 1) {
            $enabled = $matching[0].PSObject.Properties['Enabled']
            if ($null -ne $enabled) { $state = Convert-AegisState $enabled.Value }
            $inbound = Convert-AegisFirewallAction $matching[0] 'DefaultInboundAction'
            $outbound = Convert-AegisFirewallAction $matching[0] 'DefaultOutboundAction'
        }
        $lines += "Firewall $name : $state"
        $lines += "Firewall $name default inbound : $inbound"
        $lines += "Firewall $name default outbound : $outbound"
    }
    $lines += 'Firewall values are per-profile active policy, not an identification of the current network.'
    $lines += 'Reported default actions are not effective packet decisions; rules, exceptions and disabled profiles are not evaluated.'
    return ($lines -join [Environment]::NewLine)
}
function Test-AegisNativeReport {
    $good = { [pscustomobject]@{AntivirusEnabled=$true;RealTimeProtectionEnabled=$false;AMServiceEnabled=$true;BehaviorMonitorEnabled=$true;IoavProtectionEnabled=$false;DefenderSignaturesOutOfDate=$true; AMRunningMode='Normal'; OnAccessProtectionEnabled=$true; NISEnabled=$false; AntivirusSignatureAge=[uint32]3; QuickScanAge=[uint32]0; FullScanAge=[uint32]::MaxValue; QuickScanOverdue=$true; FullScanOverdue=$false; FullScanRequired=$false; RebootRequired=$true; ComputerID='SYNTHETIC-PRIVATE'} }
    $firewall = {
        [pscustomobject]@{Name='Domain';Enabled='True';DefaultInboundAction='Block';DefaultOutboundAction='Allow'}
        [pscustomobject]@{Name='Private';Enabled='NotConfigured';DefaultInboundAction='NotConfigured';DefaultOutboundAction=1}
        [pscustomobject]@{Name='Public';Enabled='False';DefaultInboundAction='Allow';DefaultOutboundAction='Block';LogFileName='SYNTHETIC-PRIVATE'}
    }
    $report = Get-AegisNativeReport $good $firewall
    foreach ($expected in @('Defender AntivirusEnabled : Enabled','Defender RealTimeProtectionEnabled : Disabled','Defender IsTamperProtected : Unknown','Defender BehaviorMonitorEnabled : Enabled','Defender IoavProtectionEnabled : Disabled','Defender signature freshness : ReportedOutOfDate','Defender operating mode : Reported active mode','Defender OnAccessProtectionEnabled : Enabled','Defender NISEnabled : Disabled','Defender signature age : Reported 3 day(s)','Defender quick scan age : Reported 0 day(s)','Defender full scan age : Unknown','Defender quick scan overdue : ReportedYes','Defender full scan overdue : NotReportedYes','Defender full scan required : NotReportedYes','Defender reboot required : ReportedYes','Firewall Domain : Enabled','Firewall Private : Unknown','Firewall Public : Disabled','Firewall Domain default inbound : Block','Firewall Domain default outbound : Allow','Firewall Private default inbound : Unknown','Firewall Private default outbound : Unknown','Firewall Public default inbound : Allow','Firewall Public default outbound : Block')) {
        if (-not $report.Contains($expected)) { throw "Unexpected diagnostic fixture result: $expected" }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'Unexpected private field disclosure' }
    $report = Get-AegisNativeReport { throw 'SYNTHETIC-PRIVATE' } { throw 'SYNTHETIC-PRIVATE' }
    if (($report.Split([char]10) | Where-Object { $_ -match ' : Unknown' }).Count -ne 26 -or $report.Contains('SYNTHETIC-PRIVATE')) { throw 'Provider failure not safely represented' }
    $report = Get-AegisNativeReport { & $good; & $good } { & $firewall; & $firewall }
    if (($report.Split([char]10) | Where-Object { $_ -match ' : Unknown' }).Count -ne 26) { throw 'Duplicate provider records accepted' }
    if ((Convert-AegisState 'false') -ne 'Unknown' -or (Convert-AegisState 1) -ne 'Unknown') { throw 'Ambiguous state accepted' }
    $report = Get-AegisNativeReport { [pscustomobject]@{DefenderSignaturesOutOfDate=$false} } {}
    if (-not $report.Contains('Defender signature freshness : NotReportedOutOfDate')) { throw 'Signature flag inversion' }
    $report = Get-AegisNativeReport { [pscustomobject]@{DefenderSignaturesOutOfDate='False'} } {}
    if (-not $report.Contains('Defender signature freshness : Unknown')) { throw 'Nonboolean signature flag accepted' }
    $report = Get-AegisNativeReport $good {
        [pscustomobject]@{Name='Domain';Enabled=@('True');DefaultInboundAction=@('Block');DefaultOutboundAction='allow'}
        [pscustomobject]@{Name=@('Private');Enabled=$true;DefaultInboundAction='Allow'}
        [pscustomobject]@{Name='Public';DefaultOutboundAction='SYNTHETIC-PRIVATE'}
    }
    foreach ($expected in @('Firewall Domain : Unknown','Firewall Domain default inbound : Unknown','Firewall Domain default outbound : Unknown','Firewall Private default inbound : Unknown','Firewall Public default outbound : Unknown')) {
        if (-not $report.Contains($expected)) { throw 'Malformed firewall metadata accepted' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'Raw firewall value disclosed' }
    $report = Get-AegisNativeReport $good {
        [pscustomobject]@{Name='Domain';DefaultInboundAction='Allow'}
        [pscustomobject]@{Name='Domain';DefaultInboundAction='Block'}
        [pscustomobject]@{Name='Public';DefaultInboundAction='Block'}
    }
    if (-not $report.Contains('Firewall Domain default inbound : Unknown') -or -not $report.Contains('Firewall Public default inbound : Block')) { throw 'Ambiguous firewall profile accepted or unrelated profile suppressed' }
    foreach ($case in @(
        @{Value='Normal'; Expected='Reported active mode'},
        @{Value='Passive'; Expected='Reported passive mode'},
        @{Value='Passive Mode'; Expected='Reported passive mode'},
        @{Value='EDR Block Mode'; Expected='Reported EDR block mode'},
        @{Value='SxS Passive Mode'; Expected='Reported side-by-side passive mode'},
        @{Value=@('Normal'); Expected='Unknown'},
        @{Value=' Normal'; Expected='Unknown'},
        @{Value='normal'; Expected='Unknown'},
        @{Value=1; Expected='Unknown'},
        @{Value=$null; Expected='Unknown'},
        @{Value='SYNTHETIC-PRIVATE'; Expected='Unknown'}
    )) {
        $record = [pscustomobject]@{AMRunningMode=$case.Value}
        if ((Get-AegisDefenderMode $record) -cne $case.Expected) { throw 'Unexpected Defender mode' }
    }
    $report = Get-AegisNativeReport {
        [pscustomobject]@{AntivirusEnabled=@($true);RealTimeProtectionEnabled='True';
            DefenderSignaturesOutOfDate=@($false);AMRunningMode=@('Normal')}
    } {}
    foreach ($expected in @('Defender AntivirusEnabled : Unknown','Defender RealTimeProtectionEnabled : Unknown',
        'Defender signature freshness : Unknown','Defender operating mode : Unknown')) {
        if (-not $report.Contains($expected)) { throw 'Malformed Defender metadata accepted' }
    }
    $report = Get-AegisNativeReport { [pscustomobject]@{AMRunningMode='SYNTHETIC-PRIVATE'} } {}
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'Raw Defender mode disclosed' }
    foreach ($case in @(
        @{Value=[uint32]0;Expected='Reported 0 day(s)'},
        @{Value=[int32]7;Expected='Reported 7 day(s)'},
        @{Value=[uint32]65535;Expected='Unknown'},
        @{Value=[uint32]::MaxValue;Expected='Unknown'},
        @{Value=[uint32]65536;Expected='Unknown'},
        @{Value=-1;Expected='Unknown'},
        @{Value=1.5;Expected='Unknown'},
        @{Value=$true;Expected='Unknown'},
        @{Value='3';Expected='Unknown'},
        @{Value=@([uint32]3);Expected='Unknown'},
        @{Value=$null;Expected='Unknown'},
        @{Value='SYNTHETIC-PRIVATE';Expected='Unknown'}
    )) {
        $record = [pscustomobject]@{AntivirusSignatureAge=$case.Value}
        if ((Get-AegisDefenderAge $record 'AntivirusSignatureAge') -cne $case.Expected) {
            throw 'Unexpected Defender age fixture'
        }
    }
    $report = Get-AegisNativeReport {
        [pscustomobject]@{AntivirusSignatureAge='SYNTHETIC-PRIVATE';QuickScanAge=@([uint32]0);
            FullScanAge=[uint32]65535;QuickScanOverdue=@($true);FullScanOverdue='False';
            FullScanRequired=0;RebootRequired='SYNTHETIC-PRIVATE';OnAccessProtectionEnabled=@($true);NISEnabled='True'}
    } {}
    foreach ($expected in @('Defender signature age : Unknown','Defender quick scan age : Unknown',
        'Defender full scan age : Unknown','Defender quick scan overdue : Unknown',
        'Defender full scan overdue : Unknown','Defender full scan required : Unknown',
        'Defender reboot required : Unknown','Defender OnAccessProtectionEnabled : Unknown',
        'Defender NISEnabled : Unknown')) {
        if (-not $report.Contains($expected)) { throw 'Malformed Defender maintenance metadata accepted' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'Raw Defender maintenance value disclosed' }
    Write-Output 'PASS: native diagnostic synthetic fixtures'
}


# Device Guard is an optional, local, read-only provider; never elevate or change policy.
function Test-AegisDgInteger($Value) {
    return ($Value -is [uint32] -or $Value -is [int32] -or $Value -is [uint16] -or $Value -is [int16] -or $Value -is [byte])
}
function Get-AegisDgScalar($Record,[string]$Name,[string[]]$Labels) {
    if ($null -eq $Record) { return 'Unknown' }
    $p = $Record.PSObject.Properties[$Name]
    if ($null -eq $p) { return 'Unknown' }
    $v = $p.Value
    if (-not (Test-AegisDgInteger $v) -or $v -lt 0 -or $v -ge $Labels.Count) { return 'Unknown' }
    return $Labels[[int]$v]
}
function Get-AegisDgService($Record,[string]$Name,[int]$Service) {
    if ($null -eq $Record) { return 'Unknown' }
    $p = $Record.PSObject.Properties[$Name]
    if ($null -eq $p) { return 'Unknown' }
    $v = $p.Value
    if ($v -isnot [array] -or $v.Rank -ne 1 -or $v.Count -eq 0 -or $v.Count -gt 8) { return 'Unknown' }
    $seen = @{}
    foreach ($item in $v) {
        if (-not (Test-AegisDgInteger $item) -or $item -lt 0 -or $item -gt 7) { return 'Unknown' }
        $key = [int]$item
        if ($seen.ContainsKey($key)) { return 'Unknown' }
        $seen[$key] = $true
    }
    if ($seen.ContainsKey(0) -and $seen.Count -ne 1) { return 'Unknown' }
    if ($seen.ContainsKey($Service)) { return 'Reported present' }
    return 'Reported absent'
}
function Get-AegisDeviceGuardReport([scriptblock]$ReadDeviceGuard) {
    $record = $null
    try {
        $records = @(& $ReadDeviceGuard | Select-Object -First 2)
        if ($records.Count -eq 1) { $record = $records[0] }
    } catch { $record = $null }
    $vbs = Get-AegisDgScalar $record 'VirtualizationBasedSecurityStatus' @('Reported disabled','Reported enabled, not running','Reported running')
    $cgConfigured = Get-AegisDgService $record 'SecurityServicesConfigured' 1
    $hvciConfigured = Get-AegisDgService $record 'SecurityServicesConfigured' 2
    $cgRunning = Get-AegisDgService $record 'SecurityServicesRunning' 1
    $hvciRunning = Get-AegisDgService $record 'SecurityServicesRunning' 2
    $kernel = Get-AegisDgScalar $record 'CodeIntegrityPolicyEnforcementStatus' @('Reported off','Reported audit','Reported enforced')
    $userMode = Get-AegisDgScalar $record 'UsermodeCodeIntegrityPolicyEnforcementStatus' @('Reported off','Reported audit','Reported enforced')
    $note = 'Reported states are not attestation or proof of protection.'
    if (@('Reported disabled','Reported enabled, not running') -ccontains $vbs -and
        ($cgRunning -ceq 'Reported present' -or $hvciRunning -ceq 'Reported present')) {
        $vbs = 'Unknown'; $cgRunning = 'Unknown'; $hvciRunning = 'Unknown'
        $note = 'Conflicting VBS and running-service readings; no positive conclusion.'
    }
    return (@('Windows Device Guard snapshot (read-only, optional provider).',
        "VBS : $vbs",
        "Credential Guard configured : $cgConfigured",
        "Credential Guard running : $cgRunning",
        "Memory integrity configured : $hvciConfigured",
        "Memory integrity running : $hvciRunning",
        "Kernel code integrity policy : $kernel",
        "User-mode code integrity policy : $userMode",
        $note,
        'Access denied or unsupported fields remain Unknown; no elevation or configuration change.') -join [Environment]::NewLine)
}
function Test-AegisDeviceGuardReport {
    $good = {
        [pscustomobject]@{VirtualizationBasedSecurityStatus=[uint32]2;
            SecurityServicesConfigured=[uint32[]]@(1,2);SecurityServicesRunning=[uint32[]]@(2);
            CodeIntegrityPolicyEnforcementStatus=[uint32]2;UsermodeCodeIntegrityPolicyEnforcementStatus=[uint32]1;
            InstanceIdentifier='SYNTHETIC-PRIVATE'}
    }
    $report = Get-AegisDeviceGuardReport $good
    foreach ($expected in @('VBS : Reported running','Credential Guard configured : Reported present',
        'Credential Guard running : Reported absent','Memory integrity configured : Reported present',
        'Memory integrity running : Reported present','Kernel code integrity policy : Reported enforced',
        'User-mode code integrity policy : Reported audit')) {
        if (-not $report.Contains($expected)) { throw 'Device Guard expected state missing' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'Device identifier disclosed' }
    foreach ($provider in @({ throw 'SYNTHETIC-PRIVATE' }, {}, { & $good; & $good })) {
        $report = Get-AegisDeviceGuardReport $provider
        if (@($report.Split([char]10) | Where-Object { $_ -match ' : Unknown' }).Count -ne 7 -or
            $report.Contains('SYNTHETIC-PRIVATE')) { throw 'Device Guard provider failure mishandled' }
    }
    foreach ($bad in @(@{v=@(0,2)},@{v=@(2,2)},@{v=@(2,99)},@{v=@('2')},@{v=2},@{v=@()},@{v=@($true)})) {
        $record = [pscustomobject]@{SecurityServicesRunning=$bad.v}
        if ((Get-AegisDgService $record 'SecurityServicesRunning' 2) -cne 'Unknown') { throw 'Invalid service array accepted' }
    }
    $record = [pscustomobject]@{SecurityServicesRunning=[uint32[]]@(0)}
    if ((Get-AegisDgService $record 'SecurityServicesRunning' 2) -cne 'Reported absent') { throw 'Explicit zero not recognized' }
    foreach ($bad in @('2',$true,2.0,-1,3)) {
        $record = [pscustomobject]@{VirtualizationBasedSecurityStatus=$bad}
        if ((Get-AegisDgScalar $record 'VirtualizationBasedSecurityStatus' @('a','b','c')) -cne 'Unknown') { throw 'Invalid scalar accepted' }
    }
    $report = Get-AegisDeviceGuardReport {
        [pscustomobject]@{VirtualizationBasedSecurityStatus=0;SecurityServicesRunning=[uint32[]]@(2)}
    }
    if (-not $report.Contains('Conflicting VBS') -or -not $report.Contains('Memory integrity running : Unknown') -or
        -not $report.Contains('VBS : Unknown')) { throw 'Contradictory readings accepted' }
    Write-Output 'PASS: Device Guard synthetic fixtures (no native provider invoked)'
}

# DNS configuration only: no resolution, probes, remote CIM, or changes.
# Counts are per provider row/address occurrence, not unique interfaces or servers.
function Get-AegisDnsReport([scriptblock]$ReadDns) {
    $intro = @('Windows DNS configuration (read-only).',
        'Configured entries only; may include inactive interfaces.',
        'No resolver trust, encryption, filtering, VPN or reachability assessment.')
    try {
        $records = @(& $ReadDns | Select-Object -First 257)
        if ($records.Count -eq 0 -or $records.Count -gt 256) { throw 'Unavailable inventory' }
        $configured = 0; $empty = 0; $unknown = 0; $loopback = 0; $other = 0
        $ipv4 = 0; $ipv6 = 0; $linkLocal = 0
        foreach ($record in $records) {
            if ($null -eq $record) { $unknown++; continue }
            $property = $record.PSObject.Properties['ServerAddresses']
            if ($null -eq $property -or $null -eq $property.Value) { $unknown++; continue }
            $values = $property.Value
            if ($values -isnot [array] -or $values.Count -gt 32) { $unknown++; continue }
            if ($values.Count -eq 0) { $empty++; continue }
            $localCount = 0; $otherCount = 0; $valid = $true
            $v4Count = 0; $v6Count = 0; $linkCount = 0
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
                # A configured unicast resolver entry must not be a multicast or limited broadcast destination.
                # Directed broadcast depends on interface prefix and is not determined here.
                if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
                    $octets = $ip.GetAddressBytes()
                    if (($octets[0] -ge 224 -and $octets[0] -le 239) -or $ip.Equals([Net.IPAddress]::Broadcast)) {
                        $valid = $false; break
                    }
                    $v4Count++
                    if ($octets[0] -eq 169 -and $octets[1] -eq 254) { $linkCount++ }
                } elseif ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
                    if ($ip.IsIPv6Multicast) { $valid = $false; break }
                    $v6Count++
                    if ($ip.IsIPv6LinkLocal) { $linkCount++ }
                } else { $valid = $false; break }
                if ([Net.IPAddress]::IsLoopback($ip)) { $localCount++ } else { $otherCount++ }
            }
            if (-not $valid) { $unknown++; continue }
            $configured++; $loopback += $localCount; $other += $otherCount
            $ipv4 += $v4Count; $ipv6 += $v6Count; $linkLocal += $linkCount
        }
        $intro += @("Provider rows with addresses: $configured",
            "Provider rows with empty lists: $empty", "Unknown or malformed rows: $unknown",
            "Loopback address occurrences: $loopback", "Other address occurrences: $other",
            "IPv4 address occurrences (including mapped IPv4): $ipv4", "IPv6 address occurrences (excluding mapped IPv4): $ipv6",
            "Link-local address occurrences (subset): $linkLocal",
            'Empty lists do not prove DNS is absent. A loopback address does not prove local filtering.',
            'Address classes are descriptive, not a security or resolver availability verdict.')
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
    $report = Get-AegisDnsReport {
        [pscustomobject]@{ServerAddresses=@('169.254.20.1','fe80::1%7','::ffff:169.254.20.2','192.0.2.1','2001:db8::1')}
        [pscustomobject]@{ServerAddresses=@('192.0.2.2','224.0.0.1')}
        [pscustomobject]@{ServerAddresses=@('ff02::1%7')}
        [pscustomobject]@{ServerAddresses=@('255.255.255.255')}
        [pscustomobject]@{ServerAddresses=@('::ffff:239.1.2.3')}
        [pscustomobject]@{ServerAddresses=@('::ffff:255.255.255.255')}
    }
    foreach ($expected in @('Provider rows with addresses: 1','Unknown or malformed rows: 5',
        'Loopback address occurrences: 0','Other address occurrences: 5',
        'IPv4 address occurrences (including mapped IPv4): 3','IPv6 address occurrences (excluding mapped IPv4): 2',
        'Link-local address occurrences (subset): 3')) {
        if (-not $report.Contains($expected)) { throw 'DNS address-class fixture mismatch or partial row counted' }
    }
    foreach ($private in @('169.254.20','fe80::','192.0.2.','2001:db8','224.0.0.1','ff02::','255.255.255.255','239.1.2.3')) {
        if ($report.Contains($private)) { throw 'DNS address-class diagnostic disclosed raw address' }
    }
    $report = Get-AegisDnsReport {
        for ($i=0;$i -lt 256;$i++) { [pscustomobject]@{ServerAddresses=@('192.0.2.1')} }
    }
    if (-not $report.Contains('Provider rows with addresses: 256') -or -not $report.Contains('IPv4 address occurrences (including mapped IPv4): 256')) { throw 'DNS exact row limit regression' }
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

# VPN profile configuration only; not a tunnel, traffic or WireGuard detector.
# Do not display profile names, endpoints, identifiers or authentication details.
function Get-AegisVpnScope([scriptblock]$ReadProfiles) {
    try {
        $records = @(& $ReadProfiles | Select-Object -First 129)
        if ($records.Count -gt 128) { return 'Inventory unavailable (limit exceeded).' }
        $connected=0; $disconnected=0; $statusUnknown=0
        $split=0; $noSplit=0; $splitUnknown=0; $pptp=0; $automatic=0; $other=0; $typeUnknown=0
        $encNone=0; $encOptional=0; $encRequired=0; $encMaximum=0; $encUnknown=0
        $rememberYes=0; $rememberNo=0; $rememberUnknown=0
        $logonYes=0; $logonNo=0; $logonUnknown=0
        foreach ($record in $records) {
            $status = $null; $mode = $null; $tunnel = $null
            $encryption = $null; $remember = $null; $logon = $null
            if ($null -ne $record) {
                $prop = $record.PSObject.Properties['ConnectionStatus']
                if ($null -ne $prop) { $status = $prop.Value }
                $prop = $record.PSObject.Properties['SplitTunneling']
                if ($null -ne $prop) { $mode = $prop.Value }
                $prop = $record.PSObject.Properties['TunnelType']
                if ($null -ne $prop) { $tunnel = $prop.Value }
                $prop = $record.PSObject.Properties['EncryptionLevel']
                if ($null -ne $prop) { $encryption = $prop.Value }
                $prop = $record.PSObject.Properties['RememberCredential']
                if ($null -ne $prop) { $remember = $prop.Value }
                $prop = $record.PSObject.Properties['UseWinlogonCredential']
                if ($null -ne $prop) { $logon = $prop.Value }
            }
            if ($status -is [string] -or $status -is [System.Enum]) {
                if ([string]$status -ceq 'Connected') { $connected++ }
                elseif ([string]$status -ceq 'Disconnected') { $disconnected++ }
                else { $statusUnknown++ }
            } else { $statusUnknown++ }
            if ($mode -is [bool]) {
                if ($mode) { $split++ } else { $noSplit++ }
            } else { $splitUnknown++ }
            if ($tunnel -is [string] -or $tunnel -is [System.Enum]) {
                if ([string]$tunnel -ieq 'Pptp') { $pptp++ }
                elseif ([string]$tunnel -ieq 'Automatic') { $automatic++ }
                elseif (@('Ikev2','Sstp','L2tp') -icontains [string]$tunnel) { $other++ }
                else { $typeUnknown++ }
            } else { $typeUnknown++ }
            # Configuration only, not negotiated protection or credential presence.
            if ($encryption -is [string] -or $encryption -is [System.Enum]) {
                switch -CaseSensitive -Exact ([string]$encryption) {
                    'NoEncryption' { $encNone++ }
                    'Optional' { $encOptional++ }
                    'Required' { $encRequired++ }
                    'Maximum' { $encMaximum++ }
                    default { $encUnknown++ }
                }
            } else { $encUnknown++ }
            if ($remember -is [bool]) {
                if ($remember) { $rememberYes++ } else { $rememberNo++ }
            } else { $rememberUnknown++ }
            if ($logon -is [bool]) {
                if ($logon) { $logonYes++ } else { $logonNo++ }
            } else { $logonUnknown++ }
        }
        return (@("Provider profile rows: $($records.Count)",
            "Connection reported connected: $connected; disconnected: $disconnected; unknown: $statusUnknown",
            "Split tunneling configured: $split; disabled: $noSplit; unknown: $splitUnknown",
            "Configured protocol PPTP: $pptp; Automatic: $automatic; other recognized: $other; unknown: $typeUnknown",
            "Configured encryption level NoEncryption: $encNone; Optional: $encOptional; Required: $encRequired; Maximum: $encMaximum; unknown: $encUnknown",
            "Remember credential configured yes: $rememberYes; no: $rememberNo; unknown: $rememberUnknown",
            "Use Windows logon credential configured yes: $logonYes; no: $logonNo; unknown: $logonUnknown") -join [Environment]::NewLine)
    } catch { return 'Inventory unavailable (provider failure).' }
}
function Get-AegisVpnReport([scriptblock]$ReadUser,[scriptblock]$ReadGlobal) {
    return (@('Windows VPN profiles (read-only).',
        'Current user phone book:', (Get-AegisVpnScope $ReadUser),
        'Global phone book:', (Get-AegisVpnScope $ReadGlobal),
        'Counts are provider rows, not unique or verified tunnels.',
        'PPTP configuration merits review. Automatic does not identify the negotiated protocol.',
        'NoEncryption or Optional configuration merits review; Required or Maximum is not proof of negotiated encryption.',
        'Credential flags describe profile settings only; no credential access or authentication-strength assessment.',
        'No route, effective encryption, leak, kill switch or WireGuard assessment. Third-party VPNs may not appear.') -join [Environment]::NewLine)
}
function Test-AegisVpnReport {
    $report = Get-AegisVpnReport {
        [pscustomobject]@{ConnectionStatus='Connected';SplitTunneling=$true;TunnelType='Ikev2';Name='SYNTHETIC-PRIVATE';ServerAddress='192.0.2.12'}
        [pscustomobject]@{ConnectionStatus='Disconnected';SplitTunneling=$false;TunnelType='Pptp'}
        [pscustomobject]@{ConnectionStatus=@('Connected');SplitTunneling='True';TunnelType=@('Automatic')}
        [pscustomobject]@{ConnectionStatus='Connecting';TunnelType='Automatic'}
    } { throw 'SYNTHETIC-PRIVATE' }
    foreach ($expected in @('Provider profile rows: 4','connected: 1; disconnected: 1; unknown: 2',
        'configured: 1; disabled: 1; unknown: 2',
        'PPTP: 1; Automatic: 1; other recognized: 1; unknown: 1',
        'Inventory unavailable (provider failure).')) {
        if (-not $report.Contains($expected)) { throw 'VPN fixture count mismatch' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE') -or $report.Contains('192.0.2.12')) { throw 'VPN report disclosed private field' }
    if (-not (Get-AegisVpnScope {}).Contains('Provider profile rows: 0')) { throw 'Empty successful scope misreported' }
    if ((Get-AegisVpnScope { for ($i=0;$i -lt 129;$i++) { [pscustomobject]@{} } }) -cne 'Inventory unavailable (limit exceeded).') { throw 'VPN scope bound failed' }
    $report = Get-AegisVpnReport { throw 'Unavailable' } { [pscustomobject]@{ConnectionStatus='Connected';SplitTunneling=$false;TunnelType='Sstp'} }
    if (-not $report.Contains('Inventory unavailable (provider failure).') -or -not $report.Contains('connected: 1; disconnected: 0; unknown: 0')) { throw 'VPN scopes not independent' }
    $report = Get-AegisVpnScope { [pscustomobject]@{}; [pscustomobject]@{ConnectionStatus=1;SplitTunneling=0;TunnelType='Unrecognized'} }
    if (-not $report.Contains('connected: 0; disconnected: 0; unknown: 2') -or -not $report.Contains('configured: 0; disabled: 0; unknown: 2') -or -not $report.Contains('other recognized: 0; unknown: 2')) { throw 'Malformed VPN records accepted' }
    $report = Get-AegisVpnScope {
        [pscustomobject]@{EncryptionLevel='NoEncryption';RememberCredential=$true;UseWinlogonCredential=$false}
        [pscustomobject]@{EncryptionLevel='Optional';RememberCredential=$false;UseWinlogonCredential=$true}
        [pscustomobject]@{EncryptionLevel='Required';RememberCredential=$false;UseWinlogonCredential=$false}
        [pscustomobject]@{EncryptionLevel='Maximum';RememberCredential=$true;UseWinlogonCredential=$true}
        [pscustomobject]@{EncryptionLevel=@('Required');RememberCredential=@($true);UseWinlogonCredential='True'}
        [pscustomobject]@{EncryptionLevel='required';RememberCredential=1;UseWinlogonCredential=@($false)}
        [pscustomobject]@{EncryptionLevel='SYNTHETIC-PRIVATE';RememberCredential='SYNTHETIC-PRIVATE'}
        [pscustomobject]@{EncryptionLevel=3;UseWinlogonCredential=0}
        [pscustomobject]@{}
    }
    foreach ($expected in @('NoEncryption: 1; Optional: 1; Required: 1; Maximum: 1; unknown: 5',
        'Remember credential configured yes: 2; no: 2; unknown: 5',
        'Use Windows logon credential configured yes: 2; no: 2; unknown: 5')) {
        if (-not $report.Contains($expected)) { throw 'VPN security configuration fixture mismatch' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'VPN security configuration disclosed raw values' }
    $report = Get-AegisVpnScope { for ($i=0;$i -lt 128;$i++) { [pscustomobject]@{EncryptionLevel='Required'} } }
    if (-not $report.Contains('Provider profile rows: 128') -or -not $report.Contains('Required: 128; Maximum: 0; unknown: 0')) { throw 'VPN exact boundary failed' }
    Write-Output 'PASS: minimized VPN profile synthetic fixtures'
}


# Structural link advisory only. Never resolve, open, transmit or echo a link.
function Get-AegisLinkReport([string]$Link) {
    $intro = 'Offline URL structure advisory; no reputation, DNS, TLS or content verification.'
    $guidance = 'Do not follow unexpected links. Verify the sender or site via a separately known channel.'
    $notes = @()
    if ([string]::IsNullOrEmpty($Link) -or $Link.Length -gt 2048) {
        $notes += 'Input missing or exceeds 2048 characters.'
    } elseif ($Link -cmatch '[^\x21-\x7e]' -or $Link.Contains('\')) {
        $notes += 'Whitespace, non-ASCII or ambiguous characters: unsupported; review independently.'
    } elseif ($Link -notmatch '\Ahttps?://([^/?#]+)') {
        $notes += 'Only explicit absolute HTTP or HTTPS links are supported.'
    } else {
        $authority = $Matches[1]
        $uri = $null
        if ($authority.Contains('%')) {
            $notes += 'Encoded authority: unsupported; review independently.'
        } elseif (-not [Uri]::TryCreate($Link,[UriKind]::Absolute,[ref]$uri) -or
            -not $uri.IsWellFormedOriginalString() -or
            @('http','https') -cnotcontains $uri.Scheme -or
            [string]::IsNullOrEmpty($uri.Host)) {
            $notes += 'Malformed or unsupported URL; review independently.'
        } else {
            if ($uri.Scheme -ceq 'http') { $notes += 'HTTP scheme: transport encryption is not indicated.' }
            if ($authority.Contains('@') -or -not [string]::IsNullOrEmpty($uri.UserInfo)) {
                $notes += 'User information in authority: destination may be misleading.'
            }
            if ($uri.HostNameType -eq [UriHostNameType]::IPv4 -or
                $uri.HostNameType -eq [UriHostNameType]::IPv6) {
                $notes += 'IP-literal destination: verify independently.'
            } elseif ($uri.HostNameType -ne [UriHostNameType]::Dns) {
                $notes += 'Unrecognized host form: verify independently.'
            } elseif ($uri.IdnHost -match '(?:\A|\.)xn--') {
                $notes += 'Internationalized domain encoding: verify the actual domain independently.'
            }
            if (-not $uri.IsDefaultPort) { $notes += 'Non-default port: verify independently.' }
            if ($notes.Count -eq 0) { $notes += 'No selected structural indicator found; safety NOT established.' }
        }
    }
    return (@($intro) + $notes + @($guidance) -join [Environment]::NewLine)
}
function Test-AegisLinkReport {
    $cases = @(
        @('https://example.invalid/path?token=SYNTHETIC-PRIVATE','safety NOT established'),
        @('http://example.invalid','HTTP scheme'),
        @('https://user:pass@example.invalid','User information'),
        @('https://192.0.2.10','IP-literal'),
        @('https://[2001:db8::1]','IP-literal'),
        @('https://xn--bcher-kva.invalid','Internationalized domain'),
        @('https://example.invalid:8443','Non-default port'),
        @('file:///C:/fixture.txt','Only explicit'),
        @('https://exa%6dple.invalid','Encoded authority'),
        @('https://example.invalid\fixture','ambiguous characters'),
        @('https://example.invalid/a b','ambiguous characters'),
        @('https://example.invalid:99999','Malformed or unsupported'),
        @('','Input missing'),
        @(('a' * 2049),'exceeds 2048')
    )
    foreach ($case in $cases) {
        $result = Get-AegisLinkReport $case[0]
        if (-not $result.Contains($case[1]) -or -not $result.Contains('no reputation') -or
            $result.Contains('SYNTHETIC-PRIVATE') -or $result.Contains('user:pass') -or
            $result.Contains('example.invalid') -or $result.Contains('192.0.2.10')) {
            throw 'URL structural advisory fixture failed'
        }
    }
    $result = Get-AegisLinkReport ('https://b' + [char]0x00fc + 'cher.invalid')
    if (-not $result.Contains('non-ASCII')) { throw 'Unicode input not explicitly unsupported' }
    $result = Get-AegisLinkReport 'http://user@example.invalid:8080'
    foreach ($expected in @('HTTP scheme','User information','Non-default port')) {
        if (-not $result.Contains($expected)) { throw 'Combined advisory missing' }
    }
    Write-Output 'PASS: offline URL structure synthetic fixtures'
}


# Local CBS/QFE inventory only. No Windows Update search, download or install.
function Get-AegisPatchReport([scriptblock]$ReadPatches) {
    $lines = @('Windows CBS/QFE patch inventory (read-only).',
        'Partial inventory: not all Windows or application updates are reported.',
        'No missing-patch, vulnerability, KEV, signature or support-status assessment.')
    try {
        $rows = @(& $ReadPatches | Select-Object -First 513)
        if ($rows.Count -gt 512) { throw 'Inventory exceeds alpha limit' }
        $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $unknown = 0; $duplicates = 0
        foreach ($row in $rows) {
            if ($null -eq $row) { $unknown++; continue }
            $property = $row.PSObject.Properties['HotFixID']
            if ($null -eq $property) { $unknown++; continue }
            # Preserve array shape: function pipeline output would unwrap singleton arrays.
            $id = $property.Value
            if ($id -isnot [string] -or $id -cnotmatch '\AKB[0-9]{1,10}\z') { $unknown++; continue }
            if (-not $ids.Add($id)) { $duplicates++ }
        }
        $lines += @("Provider rows: $($rows.Count)", "Unique KB identifiers: $($ids.Count)",
            "Duplicate valid rows: $duplicates", "Unknown or malformed rows: $unknown")
        if ($rows.Count -eq 0) { $lines += 'Empty provider result; installed updates are unknown.' }
        elseif ($ids.Count -gt 0) {
            $visible = @($ids | Sort-Object | Select-Object -First 64)
            $lines += ('Reported KB IDs (up to 64): ' + ($visible -join ', '))
            if ($ids.Count -gt 64) { $lines += 'Displayed identifiers truncated; counts cover the bounded provider result.' }
        }
        $lines += 'Verify update status through Windows Update and official vendor advisories separately.'
    } catch { $lines += 'Patch inventory unavailable or exceeds the alpha limit.' }
    return ($lines -join [Environment]::NewLine)
}
function Test-AegisPatchReport {
    $report = Get-AegisPatchReport {
        [pscustomobject]@{HotFixID='KB123';InstalledBy='SYNTHETIC-PRIVATE'}
        [pscustomobject]@{HotFixID='KB123'}
        [pscustomobject]@{HotFixID='KB456'}
        [pscustomobject]@{HotFixID='SYNTHETIC-PRIVATE'}
        [pscustomobject]@{HotFixID=@('KB789')}
        [pscustomobject]@{Other='SYNTHETIC-PRIVATE'}
        [pscustomobject]@{HotFixID='kb123'}
        [pscustomobject]@{HotFixID='KB12345678901'}
    }
    foreach ($expected in @('Provider rows: 8','Unique KB identifiers: 2','Duplicate valid rows: 1',
        'Unknown or malformed rows: 5','KB123, KB456','No missing-patch')) {
        if (-not $report.Contains($expected)) { throw 'Patch inventory fixture mismatch' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE') -or $report.Contains('KB789')) { throw 'Unexpected field disclosure' }
    if (-not (Get-AegisPatchReport {}).Contains('installed updates are unknown')) { throw 'Empty inventory misrepresented' }
    $report = Get-AegisPatchReport { throw 'SYNTHETIC-PRIVATE' }
    if (-not $report.Contains('inventory unavailable') -or $report.Contains('SYNTHETIC-PRIVATE')) { throw 'Provider failure mishandled' }
    $report = Get-AegisPatchReport { for ($i=1;$i -le 65;$i++) { [pscustomobject]@{HotFixID=('KB' + $i)} } }
    if (-not $report.Contains('Unique KB identifiers: 65') -or -not $report.Contains('identifiers truncated')) { throw 'Display limit failed' }
    $report = Get-AegisPatchReport { for ($i=1;$i -le 513;$i++) { [pscustomobject]@{HotFixID=('KB' + $i)} } }
    if (-not $report.Contains('inventory unavailable') -or $report.Contains('Unique KB identifiers:')) { throw 'Inventory bound failed' }
    Write-Output 'PASS: partial patch inventory synthetic fixtures'
}

# Italian IBAN comparison only. No account lookup, payment or identity verification.
function ConvertTo-AegisItalianIban([string]$Value) {
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 64 -or
        $Value -cnotmatch '\A[A-Za-z0-9 ]+\z') { return $null }
    $normalized = $Value.Replace(' ','').ToUpperInvariant()
    if ($normalized -cnotmatch '\AIT[0-9]{2}[A-Z][0-9]{10}[A-Z0-9]{12}\z') { return $null }
    $check = [int]$normalized.Substring(2,2)
    if ($check -lt 2 -or $check -gt 98) { return $null }
    $remainder = 0
    foreach ($ch in ($normalized.Substring(4) + $normalized.Substring(0,4)).ToCharArray()) {
        $n = [int]$ch
        if ($n -ge 48 -and $n -le 57) {
            $remainder = ($remainder * 10 + $n - 48) % 97
        } else {
            $remainder = ($remainder * 100 + $n - 55) % 97
        }
    }
    if ($remainder -ne 1) { return $null }
    return $normalized
}
function Get-AegisIbanReport([string]$Reference, [string]$Invoice) {
    $a = ConvertTo-AegisItalianIban $Reference
    $b = ConvertTo-AegisItalianIban $Invoice
    if ($null -eq $a -or $null -eq $b) {
        $state = 'Invalid or unsupported Italian IBAN format/checksum. Do not rely on this comparison.'
    } elseif ($a -cne $b) {
        $state = 'IBAN DIFFERENCE: pause payment and contact the supplier via a previously verified channel.'
    } else {
        $state = 'Same normalized IBAN; this does not establish payment safety.'
    }
    return $state + ' Account existence, domestic CIN, ownership and reference authenticity are not verified. Use your bank beneficiary verification.'
}
function Test-AegisIbanReport {
    # Fictional zero bank/branch identifiers; checksum-only fixture, never a payment destination.
    $a = 'IT51X0000000000000000000001'
    $b = 'IT24X0000000000000000000002'
    if (-not (Get-AegisIbanReport $a $a).StartsWith('Same normalized IBAN')) { throw 'IBAN equality failed' }
    $formatted = $a.Substring(0,4).ToLowerInvariant() + ' ' + $a.Substring(4)
    if (-not (Get-AegisIbanReport $formatted $a).StartsWith('Same normalized IBAN')) { throw 'IBAN formatting failed' }
    if (-not (Get-AegisIbanReport $a $b).StartsWith('IBAN DIFFERENCE')) { throw 'IBAN change missed' }
    foreach ($invalid in @('', ('IT00' + $a.Substring(4)), $a.Substring(0,26),
        ('DE' + $a.Substring(2)), ($a + [char]0x200B), ($a + '-'), (' ' * 65 + $a))) {
        if (-not (Get-AegisIbanReport $a $invalid).StartsWith('Invalid or unsupported')) { throw 'Invalid IBAN accepted' }
    }
    $report = Get-AegisIbanReport $a $b
    if ($report.Contains($a) -or $report.Contains($b) -or -not $report.Contains('ownership')) { throw 'IBAN privacy or limitation regression' }
    Write-Output 'PASS: Italian IBAN comparison synthetic fixtures'
}



# Read-only BitLocker provider snapshot; no recovery key/protector lookup.
function Get-AegisEncryptionReport([scriptblock]$ReadVolumes) {
    $unavailable = 'BitLocker inventory unavailable; encryption state unknown. No elevation or settings changes.'
    $suffix = 'Provider snapshot only; coverage, recovery readiness and data security are not established.'
    try {
        $rows = @(& $ReadVolumes | Select-Object -First 129)
        if ($rows.Count -eq 0 -or $rows.Count -gt 128) { return $unavailable }
        $on = 0; $off = 0; $unknown = 0; $transition = 0; $decrypted = 0; $inconsistent = 0
        foreach ($row in $rows) {
            if ($null -eq $row) { $unknown++; continue }
            $pp = $row.PSObject.Properties['ProtectionStatus']
            $cp = $row.PSObject.Properties['ConversionStatus']
            if ($null -eq $pp -or $null -eq $cp) { $unknown++; continue }
            $p = $pp.Value
            $c = $cp.Value
            # Only native UInt32 values are expected; do not coerce null, strings or booleans.
            if ($p -isnot [uint32] -or $c -isnot [uint32] -or $p -gt 2 -or $c -gt 5) {
                $unknown++
                continue
            }
            if ($c -eq 0) { $decrypted++ }
            if ($c -ge 2) { $transition++ }
            if ($p -eq 1 -and $c -ne 1) { $unknown++; $inconsistent++; continue }
            switch ($p) {
                0 { $off++ }
                1 { $on++ }
                2 { $unknown++ }
            }
        }
        return (@("Reported volumes: $($rows.Count)", "Protection on and encrypted reported: $on",
            "Protection off reported: $off", "Protection unknown or inconsistent: $unknown",
            "Fully decrypted reported: $decrypted", "Encryption/decryption in progress or paused: $transition",
            "Inconsistent snapshots: $inconsistent", $suffix) -join [Environment]::NewLine)
    } catch { return $unavailable }
}
function Test-AegisEncryptionReport {
    $report = Get-AegisEncryptionReport {
        [pscustomobject]@{ProtectionStatus=[uint32]1;ConversionStatus=[uint32]1;DeviceID='SYNTHETIC-PRIVATE'}
        [pscustomobject]@{ProtectionStatus=[uint32]0;ConversionStatus=[uint32]1}
        [pscustomobject]@{ProtectionStatus=[uint32]0;ConversionStatus=[uint32]0}
        [pscustomobject]@{ProtectionStatus=[uint32]0;ConversionStatus=[uint32]4}
        [pscustomobject]@{ProtectionStatus=[uint32]2;ConversionStatus=[uint32]1}
        [pscustomobject]@{ProtectionStatus=[uint32]1;ConversionStatus=[uint32]3}
        [pscustomobject]@{ProtectionStatus='1';ConversionStatus=[uint32]1}
        [pscustomobject]@{ProtectionStatus=$null;ConversionStatus=[uint32]1}
        [pscustomobject]@{ProtectionStatus=[uint32]0;ConversionStatus=[uint32]99}
        [pscustomobject]@{ProtectionStatus=@([uint32]1);ConversionStatus=[uint32]1}
        [pscustomobject]@{ConversionStatus=[uint32]1}
    }
    foreach ($expected in @('Reported volumes: 11','Protection on and encrypted reported: 1',
        'Protection off reported: 3','Protection unknown or inconsistent: 7',
        'Fully decrypted reported: 1','Encryption/decryption in progress or paused: 2','Inconsistent snapshots: 1')) {
        if (-not $report.Contains($expected)) { throw 'Encryption fixture mismatch' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE') -or -not $report.Contains('not established')) { throw 'Encryption privacy or limitation regression' }
    foreach ($read in @({}, { throw 'SYNTHETIC-PRIVATE' }, { for ($i=0; $i -lt 129; $i++) { [pscustomobject]@{ProtectionStatus=[uint32]1;ConversionStatus=[uint32]1} } })) {
        $report = Get-AegisEncryptionReport $read
        if (-not $report.Contains('state unknown') -or $report.Contains('SYNTHETIC-PRIVATE')) { throw 'Encryption unavailable handling failed' }
    }
    Write-Output 'PASS: BitLocker snapshot synthetic fixtures'
}


# Local boot trust snapshot: no TPM methods, no key material, no elevation.
function Convert-AegisStrictBoolean($Value) {
    if ($Value -isnot [bool]) { return 'Unknown' }
    if ($Value) { return 'Reported yes' }
    return 'Reported no'
}
function Get-AegisBootTrustReport([scriptblock]$ReadSecureBoot,[scriptblock]$ReadTpm) {
    $secure = 'Unknown'
    $enabled = 'Unknown'
    $activated = 'Unknown'
    try {
        $values = @(& $ReadSecureBoot | Select-Object -First 2)
        if ($values.Count -eq 1) { $secure = Convert-AegisStrictBoolean $values[0] }
    } catch { $secure = 'Unknown' }
    try {
        $records = @(& $ReadTpm | Select-Object -First 2)
        if ($records.Count -eq 1 -and $null -ne $records[0]) {
            $p = $records[0].PSObject.Properties['IsEnabled_InitialValue']
            if ($null -ne $p) { $enabled = Convert-AegisStrictBoolean $p.Value }
            $p = $records[0].PSObject.Properties['IsActivated_InitialValue']
            if ($null -ne $p) { $activated = Convert-AegisStrictBoolean $p.Value }
        }
    } catch { $enabled = 'Unknown'; $activated = 'Unknown' }
    return (@('Boot trust snapshot (read-only).',
        "Secure Boot enabled : $secure",
        "TPM enabled at provider instantiation : $enabled",
        "TPM activated at provider instantiation : $activated",
        'Unknown includes unavailable provider, denied access and unsupported platforms. No elevation attempted.',
        'No hardware attestation, measured boot verification, key access or safety established.') -join [Environment]::NewLine)
}
function Test-AegisBootTrustReport {
    $good = { [pscustomobject]@{IsEnabled_InitialValue=$true;IsActivated_InitialValue=$false;PrivateField='SYNTHETIC-PRIVATE'} }
    $report = Get-AegisBootTrustReport { $true } $good
    foreach ($expected in @('Secure Boot enabled : Reported yes','TPM enabled at provider instantiation : Reported yes','TPM activated at provider instantiation : Reported no','No hardware attestation')) {
        if (-not $report.Contains($expected)) { throw 'Boot trust fixture mismatch' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'Boot trust privacy regression' }
    $report = Get-AegisBootTrustReport { $false } { throw 'SYNTHETIC-PRIVATE' }
    if (-not $report.Contains('Secure Boot enabled : Reported no') -or -not $report.Contains('TPM enabled at provider instantiation : Unknown') -or $report.Contains('SYNTHETIC-PRIVATE')) { throw 'Boot trust provider isolation failed' }
    $report = Get-AegisBootTrustReport { throw 'SYNTHETIC-PRIVATE' } $good
    if (-not $report.Contains('Secure Boot enabled : Unknown') -or -not $report.Contains('TPM enabled at provider instantiation : Reported yes') -or $report.Contains('SYNTHETIC-PRIVATE')) { throw 'Boot trust permission handling failed' }
    foreach ($read in @({}, { 'True' }, { 1 }, { $true; $false }, { $null })) {
        $report = Get-AegisBootTrustReport $read {}
        if (-not $report.Contains('Secure Boot enabled : Unknown')) { throw 'Ambiguous Secure Boot state accepted' }
    }
    foreach ($read in @({}, { & $good; & $good }, { [pscustomobject]@{IsEnabled_InitialValue='True';IsActivated_InitialValue=1} }, { [pscustomobject]@{IsEnabled_InitialValue=@($true);IsActivated_InitialValue=$null} }, { [pscustomobject]@{Other='SYNTHETIC-PRIVATE'} })) {
        $report = Get-AegisBootTrustReport {} $read
        if (-not $report.Contains('TPM enabled at provider instantiation : Unknown') -or -not $report.Contains('TPM activated at provider instantiation : Unknown') -or $report.Contains('SYNTHETIC-PRIVATE')) { throw 'Invalid TPM state accepted' }
    }
    Write-Output 'PASS: boot trust snapshot synthetic fixtures'
}


# UAC policy snapshot: read only the fixed documented DWORDs, never modify policy.
function Read-AegisUacPolicy {
    $base = $null
    $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',$false)
        if ($null -eq $key) { return }
        $values = @{}
        foreach ($name in @('EnableLUA','PromptOnSecureDesktop','ConsentPromptBehaviorAdmin','ConsentPromptBehaviorUser','FilterAdministratorToken','EnableSecureUIAPaths')) {
            try {
                if ($key.GetValueKind($name) -eq [Microsoft.Win32.RegistryValueKind]::DWord) {
                    $values[$name] = $key.GetValue($name,$null)
                }
            } catch { } # Missing, denied or unreadable: do not infer defaults.
        }
        [pscustomobject]$values
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
}
function Get-AegisUacValue($Record,[string]$Name,[hashtable]$Labels) {
    if ($null -eq $Record) { return 'Unknown' }
    $p = $Record.PSObject.Properties[$Name]
    if ($null -eq $p -or $p.Value -isnot [int32]) { return 'Unknown' }
    if (-not $Labels.ContainsKey($p.Value)) { return 'Unknown' }
    return $Labels[$p.Value]
}
function Get-AegisUacReport([scriptblock]$ReadPolicy) {
    $record = $null
    try {
        $records = @(& $ReadPolicy | Select-Object -First 2)
        if ($records.Count -eq 1) { $record = $records[0] }
    } catch { $record = $null }
    $binary = @{0='Reported disabled';1='Reported enabled'}
    $lua = Get-AegisUacValue $record 'EnableLUA' $binary
    $desktop = Get-AegisUacValue $record 'PromptOnSecureDesktop' $binary
    $admin = Get-AegisUacValue $record 'ConsentPromptBehaviorAdmin' @{0='Reported no prompt';1='Reported credentials (secure desktop setting)';2='Reported consent (secure desktop setting)';3='Reported credentials';4='Reported consent';5='Reported consent for non-Windows binaries'}
    $user = Get-AegisUacValue $record 'ConsentPromptBehaviorUser' @{0='Reported automatic denial';1='Reported credentials (secure desktop setting)';3='Reported credentials'}
    $builtin = Get-AegisUacValue $record 'FilterAdministratorToken' $binary
    $paths = Get-AegisUacValue $record 'EnableSecureUIAPaths' $binary
    $review = 'Review configuration; no effective protection conclusion.'
    if ($lua -eq 'Reported disabled') { $review = 'Review required: Admin Approval Mode disabled in registry.' }
    elseif ($admin -eq 'Reported no prompt') { $review = 'Review required: administrator elevation configured without prompt.' }
    elseif ($desktop -eq 'Reported disabled') { $review = 'Review required: secure desktop switch disabled in registry.' }
    elseif ($paths -eq 'Reported disabled') { $review = 'Review required: secure UIAccess path restriction disabled in registry.' }
    return (@('Windows UAC registry policy snapshot (read-only).',
        "Admin Approval Mode : $lua",
        "Secure desktop switch : $desktop",
        "Administrator prompt policy : $admin",
        "Standard user prompt policy : $user",
        "Built-in administrator approval mode : $builtin",
        "Secure UIAccess paths : $paths",
        $review,
        'Unknown includes absent, denied, unsupported or invalid values. Defaults are not inferred.',
        'Registry configuration is not effective runtime policy, elevation proof or safety. No changes made.') -join [Environment]::NewLine)
}
function Test-AegisUacReport {
    $good = { [pscustomobject]@{EnableLUA=1;PromptOnSecureDesktop=1;ConsentPromptBehaviorAdmin=5;ConsentPromptBehaviorUser=0;FilterAdministratorToken=0;EnableSecureUIAPaths=1;PrivateField='SYNTHETIC-PRIVATE'} }
    $report = Get-AegisUacReport $good
    foreach ($expected in @('Admin Approval Mode : Reported enabled','Secure desktop switch : Reported enabled','Administrator prompt policy : Reported consent for non-Windows binaries','Standard user prompt policy : Reported automatic denial','Built-in administrator approval mode : Reported disabled','Secure UIAccess paths : Reported enabled','no effective protection conclusion')) {
        if (-not $report.Contains($expected)) { throw 'UAC fixture mismatch' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'UAC privacy regression' }
    foreach ($read in @({}, { throw 'SYNTHETIC-PRIVATE' }, { & $good; & $good }, { [pscustomobject]@{EnableLUA='1';PromptOnSecureDesktop=$true;ConsentPromptBehaviorAdmin=99;ConsentPromptBehaviorUser=2;FilterAdministratorToken=@(1);EnableSecureUIAPaths=-1} })) {
        $report = Get-AegisUacReport $read
        foreach ($label in @('Admin Approval Mode','Secure desktop switch','Administrator prompt policy','Standard user prompt policy','Built-in administrator approval mode','Secure UIAccess paths')) {
            if (-not $report.Contains($label + ' : Unknown')) { throw 'Invalid UAC value accepted' }
        }
        if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'UAC error disclosure' }
    }
    foreach ($case in @(
        @{Reader={ [pscustomobject]@{EnableLUA=0;ConsentPromptBehaviorAdmin=0;PromptOnSecureDesktop=0} };Expected='Admin Approval Mode disabled in registry'},
        @{Reader={ [pscustomobject]@{EnableLUA=1;ConsentPromptBehaviorAdmin=0} };Expected='administrator elevation configured without prompt'},
        @{Reader={ [pscustomobject]@{EnableLUA=1;PromptOnSecureDesktop=0} };Expected='secure desktop switch disabled in registry'},
        @{Reader={ [pscustomobject]@{EnableLUA=1;EnableSecureUIAPaths=0} };Expected='secure UIAccess path restriction disabled in registry'}
    )) {
        if (-not (Get-AegisUacReport $case.Reader).Contains($case.Expected)) { throw 'UAC review condition missed' }
    }
    for ($i=0;$i -le 5;$i++) {
        if ((Get-AegisUacValue ([pscustomobject]@{Value=$i}) 'Value' @{0='a';1='b';2='c';3='d';4='e';5='f'}) -eq 'Unknown') { throw 'UAC integer mapping failed' }
    }
    Write-Output 'PASS: UAC policy snapshot synthetic fixtures'
}


# SMB signing registry configuration only. No shares, connections, probes or policy changes.
function Read-AegisSmbSigning([ValidateSet('Client','Server')][string]$Side) {
    $base = $null
    $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        $path = if ($Side -ceq 'Client') { 'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters' }
                elseif ($Side -ceq 'Server') { 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' }
                else { return }
        $key = $base.OpenSubKey($path,$false)
        if ($null -eq $key) { return }
        if ($key.GetValueKind('RequireSecuritySignature') -ne [Microsoft.Win32.RegistryValueKind]::DWord) { return }
        $value = $key.GetValue('RequireSecuritySignature',$null)
        [pscustomobject]@{RequireSecuritySignature=$value}
    } catch { } # Missing, denied or unreadable evidence stays unknown.
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
}
function Get-AegisSmbSigningState([scriptblock]$ReadSide) {
    try {
        $rows = @(& $ReadSide | Select-Object -First 2)
        if ($rows.Count -ne 1 -or $null -eq $rows[0]) { return 'Unknown' }
        $p = $rows[0].PSObject.Properties['RequireSecuritySignature']
        if ($null -eq $p -or $p.Value -isnot [int32]) { return 'Unknown' }
        if ($p.Value -eq 1) { return 'Reported required' }
        if ($p.Value -eq 0) { return 'Reported not required' }
    } catch { }
    return 'Unknown'
}
function Get-AegisSmbSigningReport([scriptblock]$ReadClient,[scriptblock]$ReadServer) {
    $client = Get-AegisSmbSigningState $ReadClient
    $server = Get-AegisSmbSigningState $ReadServer
    $review = 'Both local settings report required; no effective protection conclusion.'
    if ($client -eq 'Reported not required' -or $server -eq 'Reported not required') {
        $review = 'Review required: at least one local setting does not require signing.'
    } elseif ($client -eq 'Unknown' -or $server -eq 'Unknown') {
        $review = 'Incomplete evidence; review configuration.'
    }
    return (@('Windows SMB signing registry snapshot (read-only).',
        "Client signing requirement : $client",
        "Server signing requirement : $server",
        $review,
        'Unknown includes absent, denied, unsupported or invalid values; defaults are not inferred.',
        'This does not establish active session signing, SMB encryption, protocol version or peer security. No changes made.') -join [Environment]::NewLine)
}
function Test-AegisSmbSigningReport {
    $required = { [pscustomobject]@{RequireSecuritySignature=1;PrivateField='SYNTHETIC-PRIVATE'} }
    $optional = { [pscustomobject]@{RequireSecuritySignature=0} }
    $report = Get-AegisSmbSigningReport $required $required
    foreach ($expected in @('Client signing requirement : Reported required','Server signing requirement : Reported required','no effective protection conclusion')) {
        if (-not $report.Contains($expected)) { throw 'SMB signing positive fixture mismatch' }
    }
    if ($report.Contains('SYNTHETIC-PRIVATE')) { throw 'SMB signing privacy regression' }
    foreach ($case in @(
        @{Client=$optional;Server=$required;Expected='Client signing requirement : Reported not required'},
        @{Client=$required;Server=$optional;Expected='Server signing requirement : Reported not required'},
        @{Client=$optional;Server=$optional;Expected='Server signing requirement : Reported not required'},
        @{Client=$optional;Server={};Expected='Server signing requirement : Unknown'}
    )) {
        $report = Get-AegisSmbSigningReport $case.Client $case.Server
        if (-not $report.Contains($case.Expected) -or -not $report.Contains('Review required:')) { throw 'SMB signing review condition missed' }
    }
    foreach ($bad in @({}, { throw 'SYNTHETIC-PRIVATE' }, { & $required; & $required },
        { [pscustomobject]@{} }, { [pscustomobject]@{RequireSecuritySignature='1'} },
        { [pscustomobject]@{RequireSecuritySignature=$true} }, { [pscustomobject]@{RequireSecuritySignature=@(1)} },
        { [pscustomobject]@{RequireSecuritySignature=[int64]1} }, { [pscustomobject]@{RequireSecuritySignature=2} },
        { [pscustomobject]@{RequireSecuritySignature=-1} })) {
        $report = Get-AegisSmbSigningReport $bad $required
        if (-not $report.Contains('Client signing requirement : Unknown') -or
            -not $report.Contains('Server signing requirement : Reported required') -or
            -not $report.Contains('Incomplete evidence') -or $report.Contains('SYNTHETIC-PRIVATE')) {
            throw 'SMB signing invalid or unavailable evidence accepted'
        }
        $report = Get-AegisSmbSigningReport $required $bad
        if (-not $report.Contains('Client signing requirement : Reported required') -or
            -not $report.Contains('Server signing requirement : Unknown') -or
            -not $report.Contains('Incomplete evidence') -or $report.Contains('SYNTHETIC-PRIVATE')) {
            throw 'SMB signing asymmetric evidence regression'
        }
    }
    Write-Output 'PASS: SMB signing registry snapshot synthetic fixtures'
}


if ($SelfTest) {
    foreach ($command in (Get-AegisCommands)) {
        if (-not (Test-AegisCommand $command)) { throw 'Allowlist failure' }
    }
    foreach ($command in @('', 'STATUS', 'scan', 'status extra', 'status;exit')) {
        if (Test-AegisCommand $command) { throw 'Unexpected command accepted' }
    }
    Test-AegisNativeReport
    Test-AegisDeviceGuardReport
    Test-AegisBootTrustReport
    Test-AegisUacReport
    Test-AegisSmbSigningReport
    Test-AegisIntegrity
    Test-AegisDnsReport
    Test-AegisVpnReport
    Test-AegisLinkReport
    Test-AegisPatchReport
    Test-AegisIbanReport
    Test-AegisEncryptionReport
    Write-Output 'PASS: fixed development UI command allowlist'
    return
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows only' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$exe = Join-Path $root 'target\release\aegis-policy.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'Build the reviewed development checkout first: cargo build --release --locked'
}
# Shared fixed-command bridge used by the UI and noninteractive smoke test.
function Get-AegisCliReport([string]$Command) {
    if (-not (Test-AegisCommand $Command)) { return 'Command rejected.' }
    try {
        $result = & $exe $Command 2>&1
        $code = $LASTEXITCODE
        return ("Exit code: $code" + [Environment]::NewLine + ($result -join [Environment]::NewLine))
    } catch {
        return 'Development executable could not be started.'
    }
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object Windows.Forms.Form
$form.Text = 'AEGIS AI - Development Alpha'
$form.Size = New-Object Drawing.Size(760,772)
$form.MinimumSize = New-Object Drawing.Size(760,772)
$form.StartPosition = 'CenterScreen'
$banner = New-Object Windows.Forms.Label
$banner.Location = New-Object Drawing.Point(18,14)
$banner.Size = New-Object Drawing.Size(700,62)
$banner.Text = @('DEVELOPMENT ONLY - Active protection unavailable.', 'Keep native antivirus and firewall enabled. No scan, VPN or enforcement.', 'Run only from a trusted, reviewed development checkout.') -join [Environment]::NewLine
$form.Controls.Add($banner)
$output = New-Object Windows.Forms.TextBox
$output.Location = New-Object Drawing.Point(18,462)
$output.Size = New-Object Drawing.Size(705,230)
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
        $output.Text = Get-AegisCliReport $command
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
        $output.Text += [Environment]::NewLine + [Environment]::NewLine + (Get-AegisDeviceGuardReport {
            CimCmdlets\Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -Property VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning,CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus -OperationTimeoutSec 5 -ErrorAction Stop -WarningAction SilentlyContinue
        })
        $output.Text += [Environment]::NewLine + [Environment]::NewLine + (Get-AegisBootTrustReport {
            SecureBoot\Confirm-SecureBootUEFI -ErrorAction Stop -WarningAction SilentlyContinue
        } {
            CimCmdlets\Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -Property IsEnabled_InitialValue,IsActivated_InitialValue -OperationTimeoutSec 5 -ErrorAction Stop -WarningAction SilentlyContinue
        })
        $output.Text += [Environment]::NewLine + [Environment]::NewLine + (Get-AegisUacReport { Read-AegisUacPolicy })
        $output.Text += [Environment]::NewLine + [Environment]::NewLine + (Get-AegisSmbSigningReport { Read-AegisSmbSigning 'Client' } { Read-AegisSmbSigning 'Server' })
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

$incidents = New-Object Windows.Forms.Button
$incidents.Location = New-Object Drawing.Point(365,240)
$incidents.Size = New-Object Drawing.Size(340,36)
$incidents.Text = 'Incident correlation (synthetic)'
$incidents.Add_Click({
    $output.Text = Get-AegisCliReport 'demo-incidents'
})
$form.Controls.Add($incidents)


$vpn = New-Object Windows.Forms.Button
$vpn.Location = New-Object Drawing.Point(18,284)
$vpn.Size = New-Object Drawing.Size(340,36)
$vpn.Text = 'Windows VPN profiles (read-only)'
$vpn.Add_Click({
    $output.Text = Get-AegisVpnReport {
        VpnClient\Get-VpnConnection -ErrorAction Stop -WarningAction SilentlyContinue
    } {
        VpnClient\Get-VpnConnection -AllUserConnection -ErrorAction Stop -WarningAction SilentlyContinue
    }
})
$form.Controls.Add($vpn)


$linkCheck = New-Object Windows.Forms.Button
$linkCheck.Location = New-Object Drawing.Point(365,284)
$linkCheck.Size = New-Object Drawing.Size(340,36)
$linkCheck.Text = 'Suspicious link (offline advisory)'
$linkCheck.Add_Click({
    $dialog = New-Object Windows.Forms.Form
    try {
        $dialog.Text = 'Offline link advisory - no navigation'
        $dialog.ClientSize = New-Object Drawing.Size(610,140)
        $dialog.StartPosition = 'CenterParent'
        $dialog.FormBorderStyle = 'FixedDialog'
        $dialog.MaximizeBox = $false
        $dialog.MinimizeBox = $false
        $hint = New-Object Windows.Forms.Label
        $hint.Location = New-Object Drawing.Point(12,10)
        $hint.Size = New-Object Drawing.Size(580,42)
        $hint.Text = 'Paste a link without passwords, tokens or personal data. No request will be sent. This is not a reputation or safety check.'
        $dialog.Controls.Add($hint)
        $entry = New-Object Windows.Forms.TextBox
        $entry.Location = New-Object Drawing.Point(12,56)
        $entry.Size = New-Object Drawing.Size(580,24)
        # One extra character allows the evaluator to reject oversized input.
        $entry.MaxLength = 2049
        $dialog.Controls.Add($entry)
        $check = New-Object Windows.Forms.Button
        $check.Location = New-Object Drawing.Point(12,94)
        $check.Size = New-Object Drawing.Size(180,32)
        $check.Text = 'Check structure'
        $check.DialogResult = [Windows.Forms.DialogResult]::OK
        $dialog.AcceptButton = $check
        $dialog.Controls.Add($check)
        if ($dialog.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK) {
            $output.Text = Get-AegisLinkReport $entry.Text
        }
        $entry.Clear()
    } catch { $output.Text = 'Offline link advisory unavailable.' }
    finally { $dialog.Dispose() }
})
$form.Controls.Add($linkCheck)

$patches = New-Object Windows.Forms.Button
$patches.Location = New-Object Drawing.Point(18,328)
$patches.Size = New-Object Drawing.Size(340,36)
$patches.Text = 'Windows patch inventory (partial)'
$patches.Add_Click({
    $output.Text = Get-AegisPatchReport {
        Microsoft.PowerShell.Management\Get-HotFix -ErrorAction Stop -WarningAction SilentlyContinue
    }
})
$form.Controls.Add($patches)

$ibanCheck = New-Object Windows.Forms.Button
$ibanCheck.Location = New-Object Drawing.Point(365,328)
$ibanCheck.Size = New-Object Drawing.Size(340,36)
$ibanCheck.Text = 'Invoice IBAN comparison (offline, IT)'
$ibanCheck.Add_Click({
    $dialog = New-Object Windows.Forms.Form
    $referenceEntry = $null
    $invoiceEntry = $null
    try {
        $dialog.Text = 'Invoice payment advisory - Italy only'
        $dialog.ClientSize = New-Object Drawing.Size(610,226)
        $dialog.StartPosition = 'CenterParent'
        $dialog.FormBorderStyle = 'FixedDialog'
        $dialog.MaximizeBox = $false
        $dialog.MinimizeBox = $false
        $hint = New-Object Windows.Forms.Label
        $hint.Location = New-Object Drawing.Point(12,10)
        $hint.Size = New-Object Drawing.Size(580,44)
        $hint.Text = 'Use a reference obtained independently of the invoice. No lookup or payment. A match does not prove the beneficiary is genuine.'
        $dialog.Controls.Add($hint)
        $refLabel = New-Object Windows.Forms.Label
        $refLabel.Location = New-Object Drawing.Point(12,58)
        $refLabel.Size = New-Object Drawing.Size(580,22)
        $refLabel.Text = 'Previously verified Italian IBAN'
        $dialog.Controls.Add($refLabel)
        $referenceEntry = New-Object Windows.Forms.TextBox
        $referenceEntry.Location = New-Object Drawing.Point(12,82)
        $referenceEntry.Size = New-Object Drawing.Size(580,24)
        $referenceEntry.MaxLength = 65
        $dialog.Controls.Add($referenceEntry)
        $invoiceLabel = New-Object Windows.Forms.Label
        $invoiceLabel.Location = New-Object Drawing.Point(12,112)
        $invoiceLabel.Size = New-Object Drawing.Size(580,22)
        $invoiceLabel.Text = 'Italian IBAN on invoice'
        $dialog.Controls.Add($invoiceLabel)
        $invoiceEntry = New-Object Windows.Forms.TextBox
        $invoiceEntry.Location = New-Object Drawing.Point(12,136)
        $invoiceEntry.Size = New-Object Drawing.Size(580,24)
        $invoiceEntry.MaxLength = 65
        $dialog.Controls.Add($invoiceEntry)
        $compare = New-Object Windows.Forms.Button
        $compare.Location = New-Object Drawing.Point(12,174)
        $compare.Size = New-Object Drawing.Size(180,32)
        $compare.Text = 'Compare offline'
        $compare.DialogResult = [Windows.Forms.DialogResult]::OK
        $dialog.AcceptButton = $compare
        $dialog.Controls.Add($compare)
        if ($dialog.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK) {
            $output.Text = Get-AegisIbanReport $referenceEntry.Text $invoiceEntry.Text
        }
    } catch { $output.Text = 'Offline invoice advisory unavailable.' }
    finally {
        if ($null -ne $referenceEntry) { $referenceEntry.Clear() }
        if ($null -ne $invoiceEntry) { $invoiceEntry.Clear() }
        $dialog.Dispose()
    }
})
$form.Controls.Add($ibanCheck)

$encryption = New-Object Windows.Forms.Button
$encryption.Location = New-Object Drawing.Point(18,372)
$encryption.Size = New-Object Drawing.Size(340,36)
$encryption.Text = 'Windows disk encryption (read-only)'
$encryption.Add_Click({
    $output.Text = Get-AegisEncryptionReport {
        CimCmdlets\Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Property ProtectionStatus,ConversionStatus -ErrorAction Stop -WarningAction SilentlyContinue
    }
})
$form.Controls.Add($encryption)

$patchPriority = New-Object Windows.Forms.Button
$patchPriority.Location = New-Object Drawing.Point(365,372)
$patchPriority.Size = New-Object Drawing.Size(340,36)
$patchPriority.Text = 'Patch priority (synthetic)'
$patchPriority.Add_Click({
    $output.Text = Get-AegisCliReport 'demo-patches'
})
$form.Controls.Add($patchPriority)

$mailAuth = New-Object Windows.Forms.Button
$mailAuth.Location = New-Object Drawing.Point(18,416)
$mailAuth.Size = New-Object Drawing.Size(340,36)
$mailAuth.Text = 'Mail authentication (synthetic)'
$mailAuth.Add_Click({
    $output.Text = Get-AegisCliReport 'demo-mail-auth'
})
$form.Controls.Add($mailAuth)

$recovery = New-Object Windows.Forms.Button
$recovery.Location = New-Object Drawing.Point(365,416)
$recovery.Size = New-Object Drawing.Size(340,36)
$recovery.Text = 'Backup recovery readiness (synthetic)'
$recovery.Add_Click({
    $output.Text = Get-AegisCliReport 'demo-recovery'
})
$form.Controls.Add($recovery)


try {
    if ($UiSmokeTest) {
        # Construct real controls but do not display a window or call native providers.
        $buttons = @($form.Controls | Where-Object { $_ -is [Windows.Forms.Button] })
        $labels = @('Status','AI policy demo','Wi-Fi demo','Version',
            'Windows native protection (read-only)','DNS configuration (read-only)',
            'Verify local file integrity (16 MiB max)','Incident correlation (synthetic)',
            'Windows VPN profiles (read-only)','Suspicious link (offline advisory)',
            'Windows patch inventory (partial)','Invoice IBAN comparison (offline, IT)',
            'Windows disk encryption (read-only)','Patch priority (synthetic)','Mail authentication (synthetic)','Backup recovery readiness (synthetic)')
        if ($buttons.Count -ne $labels.Count) { throw 'Unexpected GUI button count.' }
        foreach ($label in $labels) {
            if (@($buttons | Where-Object { $_.Text -ceq $label }).Count -ne 1) {
                throw 'Required GUI control missing or duplicated.'
            }
        }
        if (-not $output.ReadOnly -or -not $banner.Text.Contains('Active protection unavailable')) {
            throw 'GUI safety labels or output restriction missing.'
        }
        foreach ($command in (Get-AegisCommands)) {
            $report = Get-AegisCliReport $command
            if (-not $report.StartsWith('Exit code: 0' + [Environment]::NewLine)) {
                throw 'Fixed CLI bridge smoke failed.'
            }
        }
        if (-not (Get-AegisCliReport 'status').Contains('Active protection: unavailable')) {
            throw 'CLI limitation missing.'
        }
        if ((Get-AegisCliReport 'scan') -cne 'Command rejected.') {
            throw 'Invalid command bridge regression.'
        }
        Write-Output 'PASS: GUI constructed; sixteen controls, safety labels, eight CLI calls and denied command.'
    } else {
        [void]$form.ShowDialog()
    }
} finally { $form.Dispose() }
