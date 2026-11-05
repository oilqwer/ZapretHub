$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$log = Join-Path $root '.test-results\watchdog-admin.txt'
$result = Join-Path $root '.test-results\watchdog-admin.exit'
$lines = [Collections.Generic.List[string]]::new()
$parent = $null; $watchdog = $null
function Snapshot {
    return (@(Get-DnsClientNrptRule -ErrorAction Stop | Sort-Object Name | Select-Object Name,Namespace,NameServers,Comment) | ConvertTo-Json -Depth 5 -Compress)
}
try {
    $before = Snapshot
    $dummy = [Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
    $dummy.UseShellExecute = $false; $dummy.CreateNoWindow = $true
    foreach ($arg in @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30')) { $dummy.ArgumentList.Add($arg) }
    $parent = [Diagnostics.Process]::Start($dummy)
    $ticks = $parent.StartTime.ToUniversalTime().Ticks
    $token = $parent.Id.ToString() + ':' + $ticks.ToString() + ':' + [guid]::NewGuid().ToString('N')
    $start = [Diagnostics.ProcessStartInfo]::new((Join-Path $root 'test-ready\ZapretHub-AiDnsTest.exe'))
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.Environment.Remove('ZAPRETHUB_DATA') | Out-Null
    $start.Environment.Remove('__COMPAT_LAYER') | Out-Null
    foreach ($arg in @('--aidns-watchdog', $parent.Id.ToString(), $ticks.ToString(), $token)) { $start.ArgumentList.Add($arg) }
    $watchdog = [Diagnostics.Process]::Start($start)
    Start-Sleep -Milliseconds 700
    if ($watchdog.HasExited) { throw 'Watchdog exited before its parent' }
    $lines.Add('PASS packaged watchdog waits while parent is alive')
    $parent.Kill(); $parent.WaitForExit()
    if (-not $watchdog.WaitForExit(15000)) { throw 'Watchdog did not finish after parent termination' }
    if ($watchdog.ExitCode -ne 0) { throw ('Watchdog cleanup returned ' + $watchdog.ExitCode) }
    $lines.Add('PASS packaged watchdog handles abrupt parent termination and completes cleanup')
    if ((Snapshot) -ne $before) { throw 'Existing NRPT policies changed' }
    $lines.Add('PASS existing Windows DNS policies unchanged; no rule was installed by this test')
    [IO.File]::WriteAllText($result, '0')
} catch {
    $lines.Add('FAIL ' + ($_ | Out-String))
    [IO.File]::WriteAllText($result, '1')
} finally {
    foreach ($process in @($parent, $watchdog)) {
        if ($null -ne $process) { if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }; $process.Dispose() }
    }
    [IO.File]::WriteAllLines($log, $lines, [Text.UTF8Encoding]::new($false))
}
