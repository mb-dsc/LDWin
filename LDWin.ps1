# LDWin.ps1
# PowerShell-port of LDWin 2.2 (AutoIt) by Chris Hall.
# Requires Windows PowerShell 5.1+ or PowerShell 7+ and an Npcap/WinPcap-compatible
# tcpdump.exe placed next to this script.
#
# Run elevated:
#   powershell.exe -ExecutionPolicy Bypass -File .\LDWin.ps1

#Requires -Version 5.1

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    [System.Windows.Forms.MessageBox]::Show(
        'This program requires Local Administrator rights.',
        'Exiting',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$tcpdump = Join-Path $scriptDir 'tcpdump.exe'
$tempDir = [IO.Path]::GetTempPath()
$saveData = Join-Path $tempDir 'SaveData.txt'
$dataOut  = Join-Path $tempDir 'Data_Out.txt'
$script:activeTcpdumpProcess = $null

if (-not (Test-Path $tcpdump)) {
    [System.Windows.Forms.MessageBox]::Show(
        "tcpdump.exe was not found next to this script.`r`n`r`nPlace a Windows/Npcap-compatible tcpdump.exe in:`r`n$scriptDir",
        'LDWin - tcpdump missing',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}

function Get-NetworkAdapters {
    $adapterConfigurations = @(Get-CimInstance Win32_NetworkAdapterConfiguration)

    try {
        $netAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Name })
        foreach ($a in $netAdapters) {
            $cfg = $adapterConfigurations |
                Where-Object {
                    $_.SettingID -eq $a.InterfaceGuid.Guid -or
                    $_.InterfaceIndex -eq $a.InterfaceIndex -or
                    $_.Description -eq $a.InterfaceDescription
                } |
                Select-Object -First 1
            $ipAddress = Get-AdapterIPAddress $cfg $a.Name $a.InterfaceIndex

            [pscustomobject]@{
                Name        = $a.Name
                DisplayName = $a.Name
                ProductName = $a.InterfaceDescription
                SettingID   = if ($cfg -and $cfg.SettingID) { $cfg.SettingID } else { $a.InterfaceGuid.Guid }
                IPAddress   = $ipAddress
                MACAddress  = if ($a.MacAddress) { $a.MacAddress.Replace('-', ':') } else { '' }
                Index       = $a.InterfaceIndex
                LinkStatus  = $a.Status
            }
        }

        return
    }
    catch {
        # Fall back to Win32_NetworkAdapter below for older systems.
    }

    $adapters = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionID }

    foreach ($a in $adapters) {
        $cfg = $adapterConfigurations |
            Where-Object {
                $_.SettingID -eq $a.GUID -or
                $_.Index -eq $a.DeviceID -or
                $_.InterfaceIndex -eq $a.InterfaceIndex
            } |
            Select-Object -First 1
        $ipAddress = Get-AdapterIPAddress $cfg $a.NetConnectionID $a.InterfaceIndex

        [pscustomobject]@{
            Name        = $a.NetConnectionID
            DisplayName = $a.NetConnectionID
            ProductName = $a.ProductName
            SettingID   = if ($cfg -and $cfg.SettingID) { $cfg.SettingID } else { $a.GUID }
            IPAddress   = $ipAddress
            MACAddress  = $a.MACAddress
            Index       = $a.Index
            LinkStatus  = if ($a.NetConnectionStatus -eq 2) { 'Up' } else { 'Disconnected' }
        }
    }
}

function New-Label($parent, [string]$text, [int]$x, [int]$y, [int]$w, [int]$h = 20) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $text
    $l.Location = New-Object Drawing.Point($x,$y)
    $l.Size = New-Object Drawing.Size($w,$h)
    $parent.Controls.Add($l)
    return $l
}

function New-ValueBox($parent, [int]$x, [int]$y, [int]$w, [int]$h = 22) {
    $t = New-Object Windows.Forms.TextBox
    $t.Location = New-Object Drawing.Point($x,$y)
    $t.Size = New-Object Drawing.Size($w,$h)
    $t.ReadOnly = $true
    $t.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    $t.BackColor = [Drawing.SystemColors]::Window
    if ($h -gt 22) {
        $t.Multiline = $true
        $t.ScrollBars = [Windows.Forms.ScrollBars]::Vertical
    }
    $parent.Controls.Add($t)
    return $t
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

function Get-TcpdumpDevice([string]$settingId) {
    $escapedSettingId = [regex]::Escape($settingId)

    try {
        $interfaces = & $tcpdump -D 2>$null
        foreach ($line in $interfaces) {
            if ($line -match $escapedSettingId -and $line -match '^\d+\.(?<device>\\Device\\[^\s]+)') {
                return $matches.device
            }
        }
    }
    catch {
        # Fall back to the common Npcap/WinPcap naming convention below.
    }

    return "\Device\NPF_$settingId"
}

function Get-PacketCaptureDriverProblem {
    $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('npcap', 'npf') })

    if ($drivers.Count -eq 0) {
        return 'Npcap/WinPcap packet driver was not found. Install or repair Npcap, then restart LDWin.'
    }

    $disabledDriver = $drivers | Where-Object { $_.StartMode -eq 'Disabled' } | Select-Object -First 1
    if ($disabledDriver) {
        return "Packet driver '$($disabledDriver.Name)' is disabled. Enable or repair Npcap, then restart LDWin."
    }

    $runningDriver = $drivers | Where-Object { $_.State -eq 'Running' } | Select-Object -First 1
    if (-not $runningDriver) {
        return 'Npcap/WinPcap packet driver is installed but not running. Start the Npcap service or reboot Windows.'
    }

    return ''
}

function Get-FriendlyTcpdumpError([string]$stderr) {
    if ($stderr -match 'marked for deletion') {
        return 'Npcap/WinPcap driver is marked for deletion. Reboot Windows, then run LDWin again. If it persists, repair or reinstall Npcap.'
    }

    if ($stderr -match 'service cannot be started|1058|NPF Failed') {
        return 'Npcap/WinPcap driver cannot be started. Check that Npcap is installed, enabled, and running; a reboot or Npcap repair may be required.'
    }

    return $stderr.Trim()
}

function Get-AdapterIPAddress($adapterConfiguration, [string]$interfaceAlias, [int]$interfaceIndex = 0) {
    try {
        $ipAddresses = @()
        if ($interfaceIndex -gt 0) {
            $ipAddresses += @(Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        }

        if ($interfaceAlias) {
            $ipAddresses += @(Get-NetIPAddress -InterfaceAlias $interfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        }

        $ipv4Address = $ipAddresses |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -ExpandProperty IPAddress -First 1

        if ($ipv4Address) { return $ipv4Address }
    }
    catch {
        # Fall back to Win32_NetworkAdapterConfiguration below.
    }

    if ($adapterConfiguration -and $adapterConfiguration.IPAddress) {
        $ipv4Address = $adapterConfiguration.IPAddress |
            Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '169.254.*' } |
            Select-Object -First 1

        if ($ipv4Address) { return $ipv4Address }

        return ($adapterConfiguration.IPAddress | Select-Object -First 1)
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

        # CDP
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

        # LLDP
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

function Set-ResultLabels($result) {
    $lblSwitch.Text = $result.SwitchName
    $lblPort.Text   = $result.SwitchPort
    $lblVlan.Text   = $result.VLAN
    $txtSwitchIp.Text = $result.SwitchIP
    $lblModel.Text  = $result.SwitchModel
    $lblDuplex.Text = $result.Duplex
    $lblVtp.Text    = $result.VTP
}

function Clear-Results {
    Set-ResultLabels ([pscustomobject]@{
        SwitchName=''; SwitchPort=''; VLAN=''; SwitchIP=''; SwitchModel=''; Duplex=''; VTP=''
    })
    $status.Text = ''
}

function Get-SelectedAdapter {
    $selected = $combo.SelectedItem
    if ($selected -and $selected.PSObject.Properties['IPAddress']) { return $selected }

    return ($adapters | Where-Object {
        $_.Name -eq $combo.Text -or $_.DisplayName -eq $combo.Text -or $_.Name -eq $selected
    } | Select-Object -First 1)
}

function Update-SelectedAdapterDetails {
    $selected = Get-SelectedAdapter
    if (-not $selected) { return }

    $txtAdapterHardware.Text = if ($selected.ProductName) { $selected.ProductName.ToString() } else { '' }
    $txtAdapterMac.Text = if ($selected.MACAddress) { $selected.MACAddress.ToString() } else { '' }
    $txtAdapterIp.Text = if ($selected.IPAddress) { $selected.IPAddress.ToString() } else { '' }
    Clear-Results
}

function Stop-Tcpdump([Diagnostics.Process]$process = $script:activeTcpdumpProcess) {
    if (-not $process) { return $true }

    try {
        if (-not $process.HasExited) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) {
                if (Get-Variable -Name status -Scope Script -ErrorAction SilentlyContinue) {
                    $status.Text = 'tcpdump did not exit after timeout; capture was abandoned.'
                }

                return $false
            }
        }

        return $true
    }
    catch {
        $statusMessage = $_.Exception.Message
        if (Get-Variable -Name status -Scope Script -ErrorAction SilentlyContinue) {
            $status.Text = "Unable to stop tcpdump: $statusMessage"
        }

        return $false
    }
    finally {
        if ($script:activeTcpdumpProcess -and $script:activeTcpdumpProcess.Id -eq $process.Id) {
            $script:activeTcpdumpProcess = $null
        }
    }
}

function Get-LinkData($adapter) {
    Clear-Results

    if ($adapter.LinkStatus -and $adapter.LinkStatus -ne 'Up') {
        $status.Text = "Adapter '$($adapter.Name)' is $($adapter.LinkStatus). Connect the adapter before getting link data."
        return
    }

    $driverProblem = Get-PacketCaptureDriverProblem
    if ($driverProblem) {
        $status.Text = $driverProblem
        return
    }

    Set-Content -LiteralPath $saveData -Value @(
        $adapter.Name
        "($($adapter.ProductName), $($adapter.MACAddress), $($adapter.IPAddress)) is connected to:"
        '------------------------------------------------------'
    ) -Encoding Default

    Remove-Item $dataOut -Force -ErrorAction SilentlyContinue

    $getButton.Enabled = $false
    $saveButton.Enabled = $false
    $helpButton.Enabled = $false

    try {
        $status.Text = 'Running ... May take up to 60 seconds between link announcements ...'
        $status.Refresh()

        # Same Ethernet filters as the original:
        #   0x88cc = LLDP
        #   0x2000 = Cisco CDP
        #
        # Resolve the adapter GUID through tcpdump -D when possible because
        # Npcap commonly exposes interfaces as \Device\NPF_{GUID}.
        $device = Get-TcpdumpDevice $adapter.SettingID
        $arguments = "-i `"$device`" -nn -v -s 1500 -c 1 `"(ether[12:2]==0x88cc or ether[20:2]==0x2000)`""

        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $tcpdump
        $psi.Arguments = $arguments
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $proc = New-Object Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $script:activeTcpdumpProcess = $proc

        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $proc.HasExited -and $sw.Elapsed.TotalSeconds -lt 60) {
            $status.Text = "Listening for CDP/LLDP... $([int]$sw.Elapsed.TotalSeconds) seconds elapsed"
            $status.Refresh()
            [Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 200
        }

        if (-not $proc.HasExited) {
            if (-not (Stop-Tcpdump $proc)) { return }
        }

        if (-not $proc.HasExited) {
            $status.Text = 'tcpdump did not exit cleanly; no link data was collected.'
            return
        }

        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $stdout | Set-Content -LiteralPath $dataOut -Encoding Default

        if (-not $stdout.Trim()) {
            if ($stderr.Trim()) {
                $status.Text = "tcpdump error: $(Get-FriendlyTcpdumpError $stderr)"
                return
            }

            $status.Text = 'NO LINK DATA FOUND ... !'
            return
        }

        $result = Parse-LinkData ($stdout -split "`r?`n")

        if (($result.PSObject.Properties.Value | Where-Object { $_ -and $_.ToString().Trim() }).Count -eq 0) {
            if ($stderr.Trim()) {
                $status.Text = "No CDP/LLDP fields parsed. tcpdump said: $(Get-FriendlyTcpdumpError $stderr)"
                return
            }

            $status.Text = "No CDP/LLDP fields parsed. Raw output saved to: $dataOut"
            return
        }

        Set-ResultLabels $result

        Add-Content -LiteralPath $saveData -Value "Switch Name:`t$($result.SwitchName)"
        Add-Content -LiteralPath $saveData -Value "Switch Port:`t$($result.SwitchPort)"
        Add-Content -LiteralPath $saveData -Value "VLAN ID:`t$($result.VLAN)"
        Add-Content -LiteralPath $saveData -Value "Switch IP:`t$($result.SwitchIP)"
        Add-Content -LiteralPath $saveData -Value "Switch Model:`t$($result.SwitchModel)"
        Add-Content -LiteralPath $saveData -Value "Switch Duplex:`t$($result.Duplex)"
        Add-Content -LiteralPath $saveData -Value "VTP Mgmt:`t$($result.VTP)"

        $status.Text = 'Link data received.'
    }
    catch {
        $status.Text = "Error: $($_.Exception.Message)"
    }
    finally {
        [void](Stop-Tcpdump $proc)
        $getButton.Enabled = $true
        $saveButton.Enabled = $true
        $helpButton.Enabled = $true
    }
}

function Save-LinkData {
    if (-not (Test-Path $saveData)) {
        [Windows.Forms.MessageBox]::Show(
            'No link data has been collected yet.',
            'Save Link Data',
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return
    }

    $dialog = New-Object Windows.Forms.SaveFileDialog
    $dialog.Title = 'Save Link Data to'
    $dialog.Filter = 'Text Documents (*.txt)|*.txt|All files (*.*)|*.*'
    $dialog.DefaultExt = 'txt'
    $dialog.AddExtension = $true

    if ($dialog.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
        Copy-Item $saveData $dialog.FileName -Force
    }
}

function Show-Help {
    [Windows.Forms.MessageBox]::Show(
@"
Link Discovery for Windows

This PowerShell version discovers directly connected network-device
information using CDP (Cisco Discovery Protocol) and LLDP
(Link Layer Discovery Protocol).

1. Select the network adapter.
2. Click "Get Link Data".
3. The script listens for a CDP/LLDP announcement for up to 60 seconds.
4. The discovered switch information is displayed.
5. "Save Link Data" saves the result to a text file.

Requirements:
- Run as Administrator.
- tcpdump.exe compatible with Npcap/WinPcap must be beside this script.
- The selected adapter must be visible to tcpdump.

CDP and LLDP are multicast protocols, so a normal TCP/IP address is
not required to receive the discovery frames.
"@,
        'LDWin PowerShell - Help',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
}

# ---------------------------------------------------------------------------
# Main GUI
# ---------------------------------------------------------------------------

$adapters = @(Get-NetworkAdapters)

if ($adapters.Count -eq 0) {
    [Windows.Forms.MessageBox]::Show(
        'No network adapters with a Network Connection ID were found.',
        'LDWin',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}

$form = New-Object Windows.Forms.Form
$form.Text = 'Link Discovery for Windows - PowerShell'
$form.Size = New-Object Drawing.Size(760, 535)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false

$selection = New-Object Windows.Forms.GroupBox
$selection.Text = 'Selection'
$selection.Location = New-Object Drawing.Point(15,10)
$selection.Size = New-Object Drawing.Size(715,133)
$form.Controls.Add($selection)

[void](New-Label $selection 'Network Connection' 15 25 155)
$combo = New-Object Windows.Forms.ComboBox
$combo.Location = New-Object Drawing.Point(180,23)
$combo.Size = New-Object Drawing.Size(510,21)
$combo.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
$combo.DisplayMember = 'DisplayName'
[void]$combo.Items.AddRange([object[]]$adapters)
$selection.Controls.Add($combo)

[void](New-Label $selection 'Network Card' 15 52 155)
$txtAdapterHardware = New-Label $selection '' 180 50 510
[void](New-Label $selection 'MAC Address' 15 79 155)
$txtAdapterMac = New-Label $selection '' 180 77 140
[void](New-Label $selection 'IP Address' 350 79 90)
$txtAdapterIp = New-Label $selection '' 450 77 180

$getButton = New-Object Windows.Forms.Button
$getButton.Text = 'Get Link Data'
$getButton.Location = New-Object Drawing.Point(135,104)
$getButton.Size = New-Object Drawing.Size(115,25)
$selection.Controls.Add($getButton)

$saveButton = New-Object Windows.Forms.Button
$saveButton.Text = 'Save Link Data'
$saveButton.Location = New-Object Drawing.Point(260,104)
$saveButton.Size = New-Object Drawing.Size(115,25)
$selection.Controls.Add($saveButton)

$helpButton = New-Object Windows.Forms.Button
$helpButton.Text = 'Help'
$helpButton.Location = New-Object Drawing.Point(385,104)
$helpButton.Size = New-Object Drawing.Size(100,25)
$selection.Controls.Add($helpButton)

$cancelButton = New-Object Windows.Forms.Button
$cancelButton.Text = 'Cancel'
$cancelButton.Location = New-Object Drawing.Point(495,104)
$cancelButton.Size = New-Object Drawing.Size(85,25)
$selection.Controls.Add($cancelButton)

$results = New-Object Windows.Forms.GroupBox
$results.Text = 'Results'
$results.Location = New-Object Drawing.Point(15,153)
$results.Size = New-Object Drawing.Size(715,230)
$form.Controls.Add($results)

[void](New-Label $results 'Switch Name' 15 25 135)
$lblSwitch = New-ValueBox $results 160 22 530

[void](New-Label $results 'Port Identifier' 15 55 135)
$lblPort = New-ValueBox $results 160 52 530

[void](New-Label $results 'VLAN Identifier' 15 85 135)
$lblVlan = New-ValueBox $results 160 82 530

[void](New-Label $results 'Switch IP Address' 15 115 135)
$txtSwitchIp = New-ValueBox $results 160 112 530

[void](New-Label $results 'Switch Model' 15 145 135)
$lblModel = New-ValueBox $results 160 142 530 45

[void](New-Label $results 'Port Duplex' 15 195 135)
$lblDuplex = New-ValueBox $results 160 192 180

[void](New-Label $results 'VTP Mgmt Domain' 355 195 140)
$lblVtp = New-ValueBox $results 505 192 185

$statusGroup = New-Object Windows.Forms.GroupBox
$statusGroup.Text = 'Status'
$statusGroup.Location = New-Object Drawing.Point(15,393)
$statusGroup.Size = New-Object Drawing.Size(715,65)
$form.Controls.Add($statusGroup)

$status = New-Label $statusGroup '' 15 23 680

$version = New-Label $form 'LDWin - PowerShell Port - v2.2' 525 465 205
$version.TextAlign = [Windows.Forms.HorizontalAlignment]::Right

$combo.Add_SelectedIndexChanged({ Update-SelectedAdapterDetails })

$getButton.Add_Click({
    if (-not $combo.SelectedItem) {
        [Windows.Forms.MessageBox]::Show(
            'Please select a network card using the dropdown.',
            'Invalid Selection',
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return
    }

    $selected = Get-SelectedAdapter

    Get-LinkData $selected
})

$saveButton.Add_Click({ Save-LinkData })
$helpButton.Add_Click({ Show-Help })
$cancelButton.Add_Click({ $form.Close() })
$form.Add_FormClosing({ [void](Stop-Tcpdump) })

# Select first adapter just like a normal usable UI default.
$combo.SelectedIndex = 0
Update-SelectedAdapterDetails

[void]$form.ShowDialog()

# Cleanup.
[void](Stop-Tcpdump)
Remove-Item $saveData, $dataOut -Force -ErrorAction SilentlyContinue
