param([Parameter(Mandatory=$true)][string]$Assembly, [Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$out = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($out) | Out-Null
$id = [guid]::NewGuid().ToString('N')
$name = 'zaprethub-test-' + $id + '.invalid'
$marker = 'ZapretHub.AiDns.Integration:' + $id
$ready = Join-Path $out ($id + '.ready')
$stop = Join-Path $out ($id + '.stop')
function AdapterSnapshot {
    return (Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 5 -Compress)
}
function PolicySnapshot {
    return (@(Get-DnsClientNrptRule -ErrorAction Stop | Sort-Object Name | Select-Object Name,Namespace,NameServers,DisplayName,Comment) | ConvertTo-Json -Depth 5 -Compress)
}
$adapters = AdapterSnapshot
$policies = PolicySnapshot
$start = [Diagnostics.ProcessStartInfo]::new('dotnet')
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
foreach ($arg in @([IO.Path]::GetFullPath($Assembly), '--aidns-testserver', $ready, $stop, $name)) { $start.ArgumentList.Add($arg) }
$start.Environment['ZAPRETHUB_DATA'] = Join-Path $out 'data'
$process = [Diagnostics.Process]::Start($start)
$passed = $false
try {
    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    while (-not [IO.File]::Exists($ready)) {
        if ($process.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Test DNS listener did not start' }
        Start-Sleep -Milliseconds 100
    }
    Add-DnsClientNrptRule -Namespace $name -NameServers '127.0.0.2' -DisplayName 'Zapret Hub isolated test' -Comment $marker -ErrorAction Stop | Out-Null
    $effective = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Where-Object { $name -in @($_.Namespace) })
    if ($effective.Count -ne 1 -or '127.0.0.2' -notin @(([string]$effective[0].NameServers) -split '[,;\s]+')) { throw 'Local NRPT is not effective on this computer' }
    $answers = @(Resolve-DnsName -Name $name -Type A -DnsOnly -NoHostsFile -ErrorAction Stop | Where-Object { $_.IPAddress -eq '203.0.113.2' })
    if ($answers.Count -ne 1) { throw 'Windows DNS did not route the isolated query through the relay' }
    Write-Output 'PASS Windows NRPT -> local relay -> DNS response for isolated .invalid name'
    $passed = $true
} finally {
    foreach ($rule in @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -eq $marker -and $name -in @($_.Namespace) })) {
        Remove-DnsClientNrptRule -Name $rule.Name -Force -Confirm:$false -ErrorAction Stop
    }
    [IO.File]::WriteAllText($stop, 'stop')
    if (-not $process.WaitForExit(5000)) { $process.Kill($true); $process.WaitForExit() }
    $process.Dispose()
    if ((AdapterSnapshot) -ne $adapters) { throw 'Adapter DNS differs from the snapshot; inspect external network changes' }
    if ((PolicySnapshot) -ne $policies) { throw 'NRPT differs from the snapshot after cleanup' }
    Write-Output 'PASS adapter DNS and existing policies unchanged after cleanup'
}
if (-not $passed) { exit 1 }
