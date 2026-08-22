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
    # Equivalent to the original WMI enumeration of Win32_NetworkAdapter and
    # Win32_NetworkAdapterConfiguration.
    $adapters = Get-CimInstance Win32_NetworkAdapter |
        Where-Object { $_.NetConnectionID }

    foreach ($a in $adapters) {
        $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "Index=$($a.Index)" |
            Select-Object -First 1

        [pscustomobject]@{
            Name        = $a.NetConnectionID
            ProductName = $a.ProductName
            SettingID   = $cfg.SettingID
            IPAddress   = if ($cfg.IPAddress) { $cfg.IPAddress[0] } else { '' }
            MACAddress  = $a.MACAddress
            Index       = $a.Index
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
        elseif ($line -like '*System Name TLV (5)*') {
            $p = $line.Split(':',2)
            if ($p.Count -eq 2) { $r.SwitchName = $p[1].Trim().ToUpperInvariant() }
        }
        elseif ($line -like '*Chassis ID TLV (1)*') {
            $p = $line.Split(':',2)
            if ($p.Count -eq 2 -and $p[1].Trim()) {
                $r.SwitchName = $p[1].Trim()
            }
            elseif ($i + 1 -lt $lines.Count) {
                $r.SwitchName = $lines[$i+1].Split(':',2)[-1].Trim()
            }
        }
        elseif ($line -like '*Port ID TLV (2)*') {
            $p = $line.Split(':',2)
            if ($p.Count -eq 2 -and $p[1].Trim()) {
                $r.SwitchPort = $p[1].Trim()
            }
            elseif ($i + 1 -lt $lines.Count) {
                $r.SwitchPort = $lines[$i+1].Split(':',2)[-1].Trim()
            }
        }
        elseif ($line -like '*Port Description TLV (4)*') {
            $p = $line.Split(':',2)
            if ($p.Count -eq 2) { $r.SwitchPort = $p[1].Trim() }
        }
        elseif ($line -like '*port vlan id (PVID)*') {
            $p = $line.Split(':',2)
            if ($p.Count -eq 2) { $r.VLAN = $p[1].Trim() }
        }
        elseif ($line -like '*Management Address TLV (8)*') {
            $p = $line.Split(':',2)
            if ($p.Count -eq 2 -and $p[1].Trim()) {
                $r.SwitchIP = $p[1].Trim().ToUpperInvariant()
            }
            elseif ($i + 1 -lt $lines.Count) {
                $r.SwitchIP = $lines[$i+1].Split(':',2)[-1].Trim().ToUpperInvariant()
            }
        }
        elseif ($line -like '*System Description TLV (6)*') {
            $p = $line.Split(':',2)
            if ($p.Count -eq 2 -and $p[1].Trim()) {
                $r.SwitchModel = $p[1].Trim()
            }
            elseif ($i + 1 -lt $lines.Count) {
                $r.SwitchModel = $lines[$i+1].Trim()
            }
        }
    }

    return [pscustomobject]$r
}

function Set-ResultLabels($result) {
    $lblSwitch.Text = $result.SwitchName
    $lblPort.Text   = $result.SwitchPort
    $lblVlan.Text   = $result.VLAN
    $lblIP.Text     = $result.SwitchIP
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

function Stop-Tcpdump([Diagnostics.Process]$process = $script:activeTcpdumpProcess) {
    if (-not $process) { return }

    try {
        if (-not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit()
        }
    }
    catch {
        $statusMessage = $_.Exception.Message
        if (Get-Variable -Name status -Scope Script -ErrorAction SilentlyContinue) {
            $status.Text = "Unable to stop tcpdump: $statusMessage"
        }
    }
    finally {
        if ($script:activeTcpdumpProcess -and $script:activeTcpdumpProcess.Id -eq $process.Id) {
            $script:activeTcpdumpProcess = $null
        }
    }
}

function Get-LinkData($adapter) {
    Clear-Results

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
            Stop-Tcpdump $proc
        }

        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $stdout | Set-Content -LiteralPath $dataOut -Encoding Default

        if (-not $stdout.Trim()) {
            if ($stderr.Trim()) {
                $status.Text = "tcpdump error: $($stderr.Trim())"
                return
            }

            $status.Text = 'NO LINK DATA FOUND ... !'
            return
        }

        $result = Parse-LinkData ($stdout -split "`r?`n")

        if (($result.PSObject.Properties.Value | Where-Object { $_ -and $_.ToString().Trim() }).Count -eq 0) {
            if ($stderr.Trim()) {
                $status.Text = "No CDP/LLDP fields parsed. tcpdump said: $($stderr.Trim())"
                return
            }

            $status.Text = 'No CDP/LLDP fields were parsed from tcpdump output.'
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
        Stop-Tcpdump $proc
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

New-Label $selection 'Network Connection:' 15 25 120
$combo = New-Object Windows.Forms.ComboBox
$combo.Location = New-Object Drawing.Point(130,23)
$combo.Size = New-Object Drawing.Size(560,21)
$combo.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
[void]$combo.Items.AddRange([object[]]($adapters.Name))
$selection.Controls.Add($combo)

New-Label $selection 'Network Card:' 15 52 100
$lblHardware = New-Label $selection '' 130 50 560
New-Label $selection 'MAC Address:' 15 79 100
$lblMac = New-Label $selection '' 130 77 120
New-Label $selection 'IP Address:' 255 79 100
$lblIp = New-Label $selection '' 360 77 160

$getButton = New-Object Windows.Forms.Button
$getButton.Text = 'Get Link Data'
$getButton.Location = New-Object Drawing.Point(75,104)
$getButton.Size = New-Object Drawing.Size(100,25)
$selection.Controls.Add($getButton)

$saveButton = New-Object Windows.Forms.Button
$saveButton.Text = 'Save Link Data'
$saveButton.Location = New-Object Drawing.Point(185,104)
$saveButton.Size = New-Object Drawing.Size(100,25)
$selection.Controls.Add($saveButton)

$helpButton = New-Object Windows.Forms.Button
$helpButton.Text = 'Help'
$helpButton.Location = New-Object Drawing.Point(295,104)
$helpButton.Size = New-Object Drawing.Size(100,25)
$selection.Controls.Add($helpButton)

$cancelButton = New-Object Windows.Forms.Button
$cancelButton.Text = 'Cancel'
$cancelButton.Location = New-Object Drawing.Point(405,104)
$cancelButton.Size = New-Object Drawing.Size(75,25)
$selection.Controls.Add($cancelButton)

$results = New-Object Windows.Forms.GroupBox
$results.Text = 'Results'
$results.Location = New-Object Drawing.Point(15,153)
$results.Size = New-Object Drawing.Size(715,230)
$form.Controls.Add($results)

New-Label $results 'Switch Name:' 15 25 100
$lblSwitch = New-ValueBox $results 130 22 560

New-Label $results 'Port Identifier:' 15 55 100
$lblPort = New-ValueBox $results 130 52 560

New-Label $results 'VLAN Identifier:' 15 85 100
$lblVlan = New-ValueBox $results 130 82 560

New-Label $results 'Switch IP Address:' 15 115 110
$lblIP = New-ValueBox $results 130 112 560

New-Label $results 'Switch Model:' 15 145 100
$lblModel = New-ValueBox $results 130 142 560 45

New-Label $results 'Port Duplex:' 15 195 100
$lblDuplex = New-ValueBox $results 130 192 190

New-Label $results 'VTP Mgmt Domain:' 360 195 110
$lblVtp = New-ValueBox $results 475 192 215

$statusGroup = New-Object Windows.Forms.GroupBox
$statusGroup.Text = 'Status'
$statusGroup.Location = New-Object Drawing.Point(15,393)
$statusGroup.Size = New-Object Drawing.Size(715,65)
$form.Controls.Add($statusGroup)

$status = New-Label $statusGroup '' 15 23 680

$version = New-Label $form 'LDWin - PowerShell Port - v2.2' 525 465 205
$version.TextAlign = [Windows.Forms.HorizontalAlignment]::Right

$combo.Add_SelectedIndexChanged({
    $selected = $adapters | Where-Object Name -eq $combo.SelectedItem | Select-Object -First 1
    if ($selected) {
        $lblHardware.Text = $selected.ProductName
        $lblMac.Text = $selected.MACAddress
        $lblIp.Text = $selected.IPAddress
        Clear-Results
    }
})

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

    $selected = $adapters | Where-Object Name -eq $combo.SelectedItem | Select-Object -First 1
    Get-LinkData $selected
})

$saveButton.Add_Click({ Save-LinkData })
$helpButton.Add_Click({ Show-Help })
$cancelButton.Add_Click({ $form.Close() })
$form.Add_FormClosing({ Stop-Tcpdump })

# Select first adapter just like a normal usable UI default.
$combo.SelectedIndex = 0

[void]$form.ShowDialog()

# Cleanup.
Stop-Tcpdump
Remove-Item $saveData, $dataOut -Force -ErrorAction SilentlyContinue
