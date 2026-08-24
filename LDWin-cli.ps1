# LDWin-cli.ps1
# Cross-platform command-line LDWin variant for PowerShell.
#
# Examples:
#   pwsh ./LDWin-cli.ps1 -ListInterfaces
#   pwsh ./LDWin-cli.ps1 -Interface "Ethernet 6"
#   pwsh ./LDWin-cli.ps1 -Interface eth0 -TimeoutSeconds 60
#   pwsh ./LDWin-cli.ps1

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$ListInterfaces,
    [string]$Interface,
    [int]$TimeoutSeconds = 60,
    [string]$TcpdumpPath,
    [switch]$Raw
)

$ErrorActionPreference = 'Stop'

function Test-Windows {
    return [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Test-Administrator {
    if (-not (Test-Windows)) {
        return ([System.Environment]::UserName -eq 'root')
    }

    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-Tcpdump {
    param([string]$Path)

    if ($Path) {
        if (Test-Path -LiteralPath $Path) { return (Resolve-Path -LiteralPath $Path).Path }
        throw "tcpdump was not found at: $Path"
    }

    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $localTcpdump = Join-Path $scriptDir $(if (Test-Windows) { 'tcpdump.exe' } else { 'tcpdump' })
    if (Test-Path -LiteralPath $localTcpdump) { return $localTcpdump }

    $command = Get-Command $(if (Test-Windows) { 'tcpdump.exe' } else { 'tcpdump' }) -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    throw 'tcpdump was not found. On Windows, place tcpdump.exe beside this script or pass -TcpdumpPath. On Linux, install tcpdump or pass -TcpdumpPath.'
}

function Test-TcpdumpWrapper([string]$Path) {
    if (-not (Test-Windows) -or -not (Test-Path -LiteralPath $Path)) { return $false }

    $versionInfo = (Get-Item -LiteralPath $Path).VersionInfo
    return $versionInfo.FileDescription -like '*wrapper*' -or
        $versionInfo.ProductName -like '*for Windows*wrapper*' -or
        $versionInfo.CompanyName -like '*rkeene*'
}

function Get-ValueAfterLastColon([string]$line) {
    $index = $line.LastIndexOf(':')
    if ($index -lt 0 -or $index + 1 -ge $line.Length) { return '' }

    return $line.Substring($index + 1).Trim()
}

function Get-IPv4Address([string]$line) {
    if ($line -match '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b') {
        return $matches[0]
    }

    return ''
}

function Get-TlvValue([string[]]$lines, [int]$index) {
    $line = $lines[$index]
    $value = Get-ValueAfterLastColon $line
    if ($value -and $value -notmatch '^$|^length\s+\d+$') { return $value }

    for ($offset = 1; $offset -le 3 -and ($index + $offset) -lt $lines.Count; $offset++) {
        $nextLine = $lines[$index + $offset].Trim()
        if (-not $nextLine) { continue }

        $nextValue = Get-ValueAfterLastColon $nextLine
        if ($nextValue) { return $nextValue }

        return $nextLine
    }

    return ''
}

function Parse-LinkData([string[]]$lines) {
    $r = [ordered]@{
        SwitchName  = ''
        SwitchPort  = ''
        VLAN        = ''
        SwitchIP    = ''
        SwitchModel = ''
        Duplex      = ''
        VTP         = ''
    }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        if ($line -like '*Device-ID (0x01)*') {
            if ($line -match "'([^']*)'") { $r.SwitchName = $matches[1].ToUpperInvariant() }
        }
        elseif ($line -like '*Port-ID (0x03)*') {
            if ($line -match "'([^']*)'") { $r.SwitchPort = $matches[1].Trim() }
        }
        elseif ($line -like '*VLAN ID (0x0a)*') {
            $r.VLAN = Get-ValueAfterLastColon $line
        }
        elseif ($line -like '*Address (0x02)*') {
            $ipAddress = Get-IPv4Address $line
            if ($ipAddress) {
                $r.SwitchIP = $ipAddress
            }
            else {
                $r.SwitchIP = Get-ValueAfterLastColon $line
            }
        }
        elseif ($line -like '*Platform (0x06)*') {
            if ($line -match "'([^']*)'") {
                $r.SwitchModel = $matches[1].ToUpperInvariant()
                if ($r.SwitchModel -like 'CISCO*') { $r.SwitchModel = $r.SwitchModel.Substring(5).TrimStart() }
            }
        }
        elseif ($line -like '*Duplex (0x0b)*') {
            $duplex = Get-ValueAfterLastColon $line
            if ($duplex) { $r.Duplex = (Get-Culture).TextInfo.ToTitleCase($duplex.ToLowerInvariant()) }
        }
        elseif ($line -like '*VTP Management Domain (0x09)*') {
            if ($line -match "'([^']*)'") { $r.VTP = $matches[1].Trim() }
        }
        elseif ($line -like '*System Name TLV (5)*' -or $line -match '\bsystem\s+name\b') {
            $value = Get-TlvValue $lines $i
            if ($value) { $r.SwitchName = $value.ToUpperInvariant() }
        }
        elseif ($line -like '*Chassis ID TLV (1)*') {
            $value = Get-TlvValue $lines $i
            if ($value -and -not $r.SwitchName) { $r.SwitchName = $value }
        }
        elseif ($line -like '*Port ID TLV (2)*') {
            $value = Get-TlvValue $lines $i
            if ($value) { $r.SwitchPort = $value }
        }
        elseif ($line -like '*Port Description TLV (4)*') {
            $value = Get-TlvValue $lines $i
            if ($value) { $r.SwitchPort = $value }
        }
        elseif ($line -like '*port vlan id (PVID)*' -or $line -match '\bport\s+vlan\s+id\b') {
            $value = Get-TlvValue $lines $i
            if ($value) { $r.VLAN = $value }
        }
        elseif ($line -like '*Management Address TLV (8)*') {
            $value = Get-TlvValue $lines $i
            $ipAddress = Get-IPv4Address $value
            if ($ipAddress) {
                $r.SwitchIP = $ipAddress
            }
            elseif ($value) {
                $r.SwitchIP = $value.ToUpperInvariant()
            }
        }
        elseif ($line -like '*System Description TLV (6)*') {
            $value = Get-TlvValue $lines $i
            if ($value) { $r.SwitchModel = $value }
        }
        elseif ($line -like '*PMD autoneg capability*' -or $line -like '*MAU type*') {
            if ($line -match '\b(fdx|full[-\s]?duplex)\b') {
                $r.Duplex = 'Full'
            }
            elseif ($line -match '\b(hdx|half[-\s]?duplex)\b') {
                $r.Duplex = 'Half'
            }
        }
    }

    return [pscustomobject]$r
}

function Join-ProcessArguments([string[]]$Arguments) {
    return (($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + ($_.Replace('\', '\\').Replace('"', '\"')) + '"'
        }
        else {
            $_
        }
    }) -join ' ')
}

function Join-ShellCommand {
    param(
        [string]$FileName,
        [string[]]$Arguments,
        [string]$StdoutPath,
        [string]$StderrPath
    )

    if (Test-Windows) {
        return ('"{0}" {1} > "{2}" 2> "{3}"' -f $FileName, (Join-ProcessArguments $Arguments), $StdoutPath, $StderrPath)
    }

    $quote = {
        param([string]$Value)
        return "'" + $Value.Replace("'", "'\''") + "'"
    }

    $quotedArguments = ($Arguments | ForEach-Object { & $quote $_ }) -join ' '
    return ('{0} {1} > {2} 2> {3}' -f (& $quote $FileName), $quotedArguments, (& $quote $StdoutPath), (& $quote $StderrPath))
}

function Get-FriendlyTcpdumpError([string]$output) {
    if ($output -match 'marked for deletion') {
        return 'Npcap/WinPcap driver is marked for deletion. Reboot Windows, then run LDWin again. If it persists, repair or reinstall Npcap.'
    }

    if ($output -match 'Access is denied') {
        return 'Packet capture access was denied. Re-run PowerShell as Administrator, or verify that Npcap permits this user to capture packets.'
    }

    if ($output -match 'service cannot be started|1058|NPF Failed') {
        return 'Npcap/WinPcap driver cannot be started. Check that Npcap is installed, enabled, and running; a reboot or Npcap repair may be required.'
    }

    if ($output -match 'pcap_loop: read error|PacketReceivePacket failed') {
        return 'Packet capture failed while reading from the adapter. Reconnect the adapter, verify Npcap is healthy, or try another interface.'
    }

    if ($output -match '0 packets captured') {
        return 'No CDP/LLDP frames were captured before the capture stopped. Check that the selected interface is connected to a port sending CDP or LLDP.'
    }

    return $output.Trim()
}

function Get-TcpdumpDevice([string]$settingId, [string]$Tcpdump) {
    if (-not (Test-Windows)) { return $settingId }

    $escapedSettingId = [regex]::Escape($settingId)
    if ($escapedSettingId) {
        try {
            $interfaces = & $Tcpdump -D 2>$null
            foreach ($line in $interfaces) {
                if ($line -match $escapedSettingId -and $line -match '^\d+\.(?<device>\\Device\\[^\s]+)') {
                    return $matches.device
                }
            }
        }
        catch {
        }
    }

    return "\Device\NPF_$settingId"
}

function Stop-ProcessTree {
    param([Diagnostics.Process]$Process)

    if (-not $Process -or $Process.HasExited) { return }

    if (Test-Windows) {
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($Process.Id)" -ErrorAction SilentlyContinue)
        foreach ($child in $children) {
            try {
                $childProcess = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
                if ($childProcess) { Stop-ProcessTree $childProcess }
            }
            catch {
            }
        }
    }

    try {
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
    }
}

function Get-AdapterIPAddress([string]$interfaceName, [int]$interfaceIndex = 0) {
    if (Test-Windows) {
        $ipAddresses = @()
        if ($interfaceIndex -gt 0) {
            $ipAddresses += @(Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        }
        if ($interfaceName) {
            $ipAddresses += @(Get-NetIPAddress -InterfaceAlias $interfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        }

        $ipv4Address = $ipAddresses | Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress -First 1
        return $ipv4Address
    }

    $ipCommand = Get-Command ip -ErrorAction SilentlyContinue
    if (-not $ipCommand) { return '' }

    $output = & $ipCommand.Source -o -4 addr show dev $interfaceName 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $output) { return '' }

    if ($output -match '\binet\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})/') { return $matches.ip }
    return ''
}

function Get-WindowsInterfaces {
    $adapterConfigurations = @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue)
    $netAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Name })

    foreach ($adapter in $netAdapters) {
        $cfg = $adapterConfigurations | Where-Object {
                $_.SettingID -eq $adapter.InterfaceGuid.Guid -or
                $_.InterfaceIndex -eq $adapter.InterfaceIndex -or
                $_.Description -eq $adapter.InterfaceDescription
            } | Select-Object -First 1

        [pscustomobject]@{
            Name          = $adapter.Name
            Description   = $adapter.InterfaceDescription
            IPAddress     = Get-AdapterIPAddress $adapter.Name $adapter.InterfaceIndex
            MACAddress    = if ($adapter.MacAddress) { $adapter.MacAddress.Replace('-', ':') } else { '' }
            LinkStatus    = $adapter.Status
            SettingID     = if ($cfg -and $cfg.SettingID) { $cfg.SettingID } else { $adapter.InterfaceGuid.ToString() }
            InterfaceId   = if ($cfg -and $cfg.SettingID) { $cfg.SettingID } else { $adapter.InterfaceGuid.ToString() }
            InterfaceName = $adapter.Name
            CaptureName   = if ($cfg -and $cfg.SettingID) { "\Device\NPF_$($cfg.SettingID)" } else { "\Device\NPF_$($adapter.InterfaceGuid.ToString())" }
            Platform      = 'Windows'
        }
    }
}

function Get-LinuxInterfaces {
    $sysClassNet = '/sys/class/net'
    if (-not (Test-Path -LiteralPath $sysClassNet)) {
        throw '/sys/class/net was not found. This Linux adapter discovery path is unavailable.'
    }

    foreach ($path in Get-ChildItem -LiteralPath $sysClassNet -Directory) {
        $name = $path.Name
        $statePath = Join-Path $path.FullName 'operstate'
        $macPath = Join-Path $path.FullName 'address'
        $descriptionPath = Join-Path $path.FullName 'device/uevent'

        $state = if (Test-Path -LiteralPath $statePath) { (Get-Content -LiteralPath $statePath -Raw).Trim() } else { '' }
        $mac = if (Test-Path -LiteralPath $macPath) { (Get-Content -LiteralPath $macPath -Raw).Trim().ToUpperInvariant() } else { '' }
        $description = $name
        if (Test-Path -LiteralPath $descriptionPath) {
            $driver = Get-Content -LiteralPath $descriptionPath | Where-Object { $_ -like 'DRIVER=*' } | Select-Object -First 1
            if ($driver) { $description = "$name ($($driver.Substring(7)))" }
        }

        [pscustomobject]@{
            Name          = $name
            Description   = $description
            IPAddress     = Get-AdapterIPAddress $name
            MACAddress    = $mac
            LinkStatus    = if ($state -eq 'up') { 'Up' } elseif ($state) { $state } else { 'Unknown' }
            SettingID     = $name
            InterfaceId   = $name
            InterfaceName = $name
            CaptureName   = $name
            Platform      = 'Linux'
        }
    }
}

function Get-NetworkInterfaces {
    if (Test-Windows) { return @(Get-WindowsInterfaces) }
    return @(Get-LinuxInterfaces)
}

function Resolve-WindowsCaptureNames {
    param(
        [object[]]$Interfaces,
        [string]$Tcpdump
    )

    if (-not (Test-Windows)) { return $Interfaces }

    $tcpdumpInterfaces = @(& $Tcpdump -D 2>$null)
    foreach ($interface in $Interfaces) {
        if (-not $interface.SettingID) { continue }

        $escapedGuid = [regex]::Escape($interface.SettingID)
        $match = $tcpdumpInterfaces | Where-Object { $_ -match $escapedGuid -and $_ -match '^\d+\.(?<device>\\Device\\[^\s]+)' } | Select-Object -First 1
        if ($match -and $match -match '^\d+\.(?<device>\\Device\\[^\s]+)') {
            $interface.CaptureName = $matches.device
        }
    }

    return $Interfaces
}

function Show-Interfaces {
    param([object[]]$Interfaces)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('{0,6}  {1,-35}  {2,-15}  {3,-12}  {4,-17}  {5}' -f 'Number', 'Name', 'IPAddress', 'LinkStatus', 'MACAddress', 'Description'))
    $lines.Add(('{0,6}  {1,-35}  {2,-15}  {3,-12}  {4,-17}  {5}' -f '------', '----', '---------', '----------', '----------', '-----------'))

    for ($i = 0; $i -lt $Interfaces.Count; $i++) {
        $interface = $Interfaces[$i]
        $description = if ($interface.Description -and $interface.Description.Length -gt 45) {
            $interface.Description.Substring(0, 42) + '...'
        }
        else {
            $interface.Description
        }

        $lines.Add(('{0,6}  {1,-35}  {2,-15}  {3,-12}  {4,-17}  {5}' -f ($i + 1), $interface.Name, $interface.IPAddress, $interface.LinkStatus, $interface.MACAddress, $description))
    }

    foreach ($line in $lines) { Write-Host $line }
}

function Select-Interface {
    param(
        [object[]]$Interfaces,
        [string]$Name
    )

    if ($Name) {
        $selected = $Interfaces | Where-Object { $_.Name -eq $Name -or $_.InterfaceName -eq $Name -or $_.CaptureName -eq $Name } | Select-Object -First 1
        if (-not $selected) { throw "Interface was not found: $Name" }
        return $selected
    }

    [void](Show-Interfaces $Interfaces)
    $choice = Read-Host 'Select interface number'
    $number = 0
    if (-not [int]::TryParse($choice, [ref]$number) -or $number -lt 1 -or $number -gt $Interfaces.Count) {
        throw "Invalid interface selection: $choice"
    }

    $selectedIndex = $number - 1
    return ($Interfaces | Select-Object -Index $selectedIndex)
}

function Invoke-LinkCapture {
    param(
        [object]$SelectedInterface,
        [string]$Tcpdump,
        [int]$Timeout,
        [switch]$ShowRaw
    )

    if ($SelectedInterface.LinkStatus -and $SelectedInterface.LinkStatus -notin @('Up', 'Unknown')) {
        throw "Interface '$($SelectedInterface.Name)' is $($SelectedInterface.LinkStatus). Connect the interface before getting link data."
    }

    $arguments = "-i `"$($SelectedInterface.CaptureName)`" -nn -v -s 1500 -c 1 `"(ether[12:2]==0x88cc or ether[20:2]==0x2000)`""

    Write-Host "Listening on $($SelectedInterface.Name) ($($SelectedInterface.CaptureName)) for CDP/LLDP, up to $Timeout seconds..."

    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Tcpdump
    $psi.Arguments = $arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()

    $timedOut = $false
    if (-not $process.WaitForExit($Timeout * 1000)) {
        $timedOut = $true
        Stop-ProcessTree $process
        [void]$process.WaitForExit(1000)
    }

    if ($timedOut) {
        $rawOutputPath = Join-Path ([IO.Path]::GetTempPath()) 'LDWin-cli-raw.txt'
        Set-Content -LiteralPath $rawOutputPath -Value "tcpdump timed out after $Timeout seconds and was terminated." -Encoding UTF8
        throw "No CDP/LLDP frames were captured within $Timeout seconds. tcpdump was terminated. Raw output saved to: $rawOutputPath"
    }

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $rawOutput = @(
        '--- STDOUT ---'
        if ($stdout) { $stdout } else { '<empty>' }
        '--- STDERR ---'
        if ($stderr) { $stderr } else { '<empty>' }
    ) -join [Environment]::NewLine
    $rawOutputPath = Join-Path ([IO.Path]::GetTempPath()) 'LDWin-cli-raw.txt'
    Set-Content -LiteralPath $rawOutputPath -Value $rawOutput -Encoding UTF8

    if ($ShowRaw) {
        Write-Host ''
        Write-Host "Raw tcpdump output saved to: $rawOutputPath"
        Write-Host $rawOutput
    }

    $combinedOutput = "$stdout`n$stderr"
    if ($process.ExitCode -ne 0 -or $combinedOutput -match 'Error opening adapter|NPF Failed|Access is denied|service cannot be started|marked for deletion|child process exited abnormally|child killed|pcap_loop: read error|PacketReceivePacket failed') {
        throw "$(Get-FriendlyTcpdumpError $combinedOutput) Raw output saved to: $rawOutputPath"
    }

    if ($timedOut) {
        throw "No CDP/LLDP frames were captured within $Timeout seconds. Raw output saved to: $rawOutputPath"
    }

    if ($combinedOutput -match '0 packets captured' -and $combinedOutput -notmatch 'LLDP|CDP|Device-ID|TLV') {
        throw "$(Get-FriendlyTcpdumpError $combinedOutput) Raw output saved to: $rawOutputPath"
    }

    if (-not $stdout.Trim()) {
        if ($stderr.Trim()) { throw $stderr.Trim() }
        throw 'No CDP/LLDP frames were captured.'
    }

    $result = Parse-LinkData ($stdout -split "`r?`n")
    if (($result.PSObject.Properties.Value | Where-Object { $_ -and $_.ToString().Trim() }).Count -eq 0) {
        throw "A CDP/LLDP frame was captured, but no supported fields were parsed. Raw output saved to: $rawOutputPath"
    }

    return $result
}

try {
    $interfaces = Get-NetworkInterfaces

    if ($ListInterfaces) {
        Show-Interfaces $interfaces
        return
    }

    if (-not (Test-Administrator)) {
        Write-Warning 'Packet capture usually requires Administrator/root privileges. Re-run elevated if tcpdump fails.'
    }

    $selectedInterface = Select-Interface -Interfaces $interfaces -Name $Interface

    $tcpdump = Find-Tcpdump $TcpdumpPath
    $selectedName = $selectedInterface.Name
    $interfaces = Resolve-WindowsCaptureNames -Interfaces $interfaces -Tcpdump $tcpdump
    $resolvedInterface = $interfaces | Where-Object { $_.Name -eq $selectedName } | Select-Object -First 1
    if ($resolvedInterface) { $selectedInterface = $resolvedInterface }
    $selectedInterface.CaptureName = Get-TcpdumpDevice $selectedInterface.SettingID $tcpdump

    Write-Host ''
    Write-Host 'Selected interface:'
    [pscustomobject]@{
        Name        = $selectedInterface.Name
        IPAddress   = $selectedInterface.IPAddress
        LinkStatus  = $selectedInterface.LinkStatus
        MACAddress   = $selectedInterface.MACAddress
        Description = $selectedInterface.Description
    } | Format-List

    $linkData = Invoke-LinkCapture -SelectedInterface $selectedInterface -Tcpdump $tcpdump -Timeout $TimeoutSeconds -ShowRaw:$Raw

    Write-Host ''
    Write-Host 'Link data:'
    $linkData | Format-List
}
catch {
    [Console]::Error.WriteLine("Error: $($_.Exception.Message)")
    exit 1
}
