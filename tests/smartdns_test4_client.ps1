$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$env:ZAPRETHUB_DATA = Join-Path $repo '.test-results\provider-cycle'
$asm = [Reflection.Assembly]::LoadFrom((Join-Path $repo 'src\ZapretHub\bin\Release\net8.0-windows10.0.17763.0\win-x64\ZapretHub-AiDnsTest4.dll'))
$flags = [Reflection.BindingFlags]'NonPublic,Static'
$wire = $asm.GetType('ZapretHub.DnsWire')
$exchangeType = $asm.GetType('ZapretHub.DnsExchange')
$probe = $asm.GetType('ZapretHub.AiServiceProbe').GetMethod('Check', $flags)
$rows = @()
foreach ($server in @([ZapretHub.AiDns]::MalwPrimary(), [ZapretHub.AiDns]::MalwGateway(), [ZapretHub.AiDns]::BezmezhauPrimary())) {
    $exchange = [Activator]::CreateInstance($exchangeType, [Reflection.BindingFlags]'Instance,NonPublic', $null, @($server), $null)
    try {
        foreach ($hostName in @('chatgpt.com','gemini.google.com')) {
            foreach ($kind in @(1,28)) {
                $clock = [Diagnostics.Stopwatch]::StartNew()
                $ct = [Threading.CancellationTokenSource]::new(8000)
                try {
                    $q = $wire.GetMethod('Query', $flags).Invoke($null, @($hostName, [ushort]$kind))
                    $answer = $exchange.Query($q, $ct.Token).GetAwaiter().GetResult()
                    $ips = $wire.GetMethod('Addresses', $flags).Invoke($null, @($q,$answer))
                    $rows += [pscustomobject]@{ provider=$server.address; endpoint=$server.template; host=$hostName; type=$kind; ms=$clock.ElapsedMilliseconds; addresses=@($ips | ForEach-Object ToString); error=$null }
                } catch { $rows += [pscustomobject]@{ provider=$server.address; host=$hostName; type=$kind; error=$_.Exception.ToString() } }
                finally { $ct.Dispose() }
            }
            try {
                $probe.Invoke($null, @($hostName,$exchange,[Threading.CancellationToken]::None)).GetAwaiter().GetResult()
                $rows += [pscustomobject]@{ provider=$server.address; host=$hostName; health='DNS_AND_PINNED_HTTPS_PASSED'; applicationAccess='UNVERIFIED'; vpnAbsence='NOT_CONFIRMED: active Wintun' }
            } catch { $rows += [pscustomobject]@{ provider=$server.address; host=$hostName; health='FAILED'; error=$_.Exception.ToString() } }
        }
    } finally { $exchange.Dispose() }
}
$rows | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $env:ZAPRETHUB_DATA 'test4-dotnet.json') -Encoding UTF8
$rows | Select-Object provider,host,type,addresses,health,error | Format-Table -Wrap
