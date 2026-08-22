# Test-LDWin.ps1
# Run elevated from this folder:
#   powershell.exe -ExecutionPolicy Bypass -File .\Test-LDWin.ps1

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot 'LDWin.ps1'
$tcpdumpPath = Join-Path $PSScriptRoot 'tcpdump.exe'

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-Result([string]$Name, [bool]$Passed, [string]$Details = '') {
    [pscustomobject]@{
        Test    = $Name
        Result  = if ($Passed) { 'PASS' } else { 'FAIL' }
        Details = $Details
    }
}

$results = New-Object System.Collections.Generic.List[object]

$results.Add((Add-Result 'LDWin.ps1 exists' (Test-Path -LiteralPath $scriptPath) $scriptPath))
$results.Add((Add-Result 'tcpdump.exe exists beside script' (Test-Path -LiteralPath $tcpdumpPath) $tcpdumpPath))
$results.Add((Add-Result 'Running as Administrator' (Test-Administrator) 'Required for live packet capture'))

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
$results.Add((Add-Result 'PowerShell syntax' ($parseErrors.Count -eq 0) (($parseErrors | ForEach-Object { $_.Message }) -join ' | ')))

if (Test-Path -LiteralPath $tcpdumpPath) {
    try {
        $interfaces = & $tcpdumpPath -D 2>&1
        $results.Add((Add-Result 'tcpdump -D' ($LASTEXITCODE -eq 0 -and $interfaces) (($interfaces | Select-Object -First 5) -join ' | ')))
    }
    catch {
        $results.Add((Add-Result 'tcpdump -D' $false $_.Exception.Message))
    }
}

$functionNames = @('Get-ValueAfterLastColon', 'Get-IPv4Address', 'Parse-LinkData')
foreach ($functionName in $functionNames) {
    $functionAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true)
    if ($functionAst) {
        Invoke-Expression $functionAst.Extent.Text
    }

    $results.Add((Add-Result "$functionName found" ($null -ne $functionAst)))
}

if (Get-Command Parse-LinkData -ErrorAction SilentlyContinue) {
    $cdpSample = @(
        "Device-ID (0x01), length: 7 bytes: 'SW01'",
        "Address (0x02), length: 13 bytes: IPv4 (1) 192.168.1.1",
        "Port-ID (0x03), length: 16 bytes: 'GigabitEthernet1/0/24'",
        "Platform (0x06), length: 19 bytes: 'cisco WS-C2960X-48FPS-L'",
        "VTP Management Domain (0x09), length: 4 bytes: 'CORP'",
        "VLAN ID (0x0a), length: 2 bytes: 20",
        "Duplex (0x0b), length: 1 byte: full"
    )
    $cdp = Parse-LinkData $cdpSample
    $cdpOk = $cdp.SwitchName -eq 'SW01' -and
        $cdp.SwitchPort -eq 'GigabitEthernet1/0/24' -and
        $cdp.VLAN -eq '20' -and
        $cdp.SwitchIP -eq '192.168.1.1' -and
        $cdp.SwitchModel -eq 'WS-C2960X-48FPS-L' -and
        $cdp.Duplex -eq 'Full' -and
        $cdp.VTP -eq 'CORP'
    $results.Add((Add-Result 'CDP parser sample' $cdpOk ($cdp | ConvertTo-Json -Compress)))

    $lldpSample = @(
        'System Name TLV (5): sw-lldp-01',
        'Port ID TLV (2): Gi1/0/10',
        'port vlan id (PVID): 30',
        'Management Address TLV (8): 10.0.0.1',
        'System Description TLV (6): Cisco IOS Software, C9300'
    )
    $lldp = Parse-LinkData $lldpSample
    $lldpOk = $lldp.SwitchName -eq 'SW-LLDP-01' -and
        $lldp.SwitchPort -eq 'Gi1/0/10' -and
        $lldp.VLAN -eq '30' -and
        $lldp.SwitchIP -eq '10.0.0.1' -and
        $lldp.SwitchModel -eq 'Cisco IOS Software, C9300'
    $results.Add((Add-Result 'LLDP parser sample' $lldpOk ($lldp | ConvertTo-Json -Compress)))
}

$results | Format-Table -AutoSize

if ($results.Result -contains 'FAIL') {
    exit 1
}
