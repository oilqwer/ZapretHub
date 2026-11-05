$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$dir=Join-Path $repo '.test-results\test6-live-data'
$env:ZAPRETHUB_DATA=$dir
$asm=[Reflection.Assembly]::LoadFrom((Join-Path $repo '.test-results\test6-dev\ZapretHub-AiDnsDev6.dll'))
$flags=[Reflection.BindingFlags]'Static,NonPublic'
$network=$asm.GetType('ZapretHub.AiNetwork')
$snapshot=$network.GetMethod('Snapshot',$flags).Invoke($null,@())
$snapshot.routes | Select-Object destination,index,source,gateway,adapter,tunnel | Format-Table
$owner=@(Get-NetUDPEndpoint -LocalAddress 127.0.0.2 -LocalPort 53 -ErrorAction SilentlyContinue | Select-Object OwningProcess)
$policy=@(Get-DnsClientNrptPolicy -Effective | Where-Object { @($_.Namespace) -contains '.chatgpt.com' -or @($_.Namespace) -contains 'chatgpt.com' } | Select-Object Namespace,NameServers)
$wire=$asm.GetType('ZapretHub.DnsWire')
$rows=@()
foreach($hostName in @('chatgpt.com','files.oaiusercontent.com','gemini.google.com')){
    $q=$wire.GetMethod('Query',$flags).Invoke($null,@($hostName,[ushort]1))
    $udp=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $ct=[Threading.CancellationTokenSource]::new(8000)
    try{
        $udp.Connect('127.0.0.2',53)
        $udp.Send($q,$q.Length) | Out-Null
        $packet=$udp.ReceiveAsync($ct.Token).GetAwaiter().GetResult().Buffer
        $ips=$wire.GetMethod('Addresses',$flags).Invoke($null,@($q,$packet))
        $rows+=[pscustomobject]@{host=$hostName;rcode=($packet[3]-band 15);addresses=@($ips | ForEach-Object ToString)}
    }catch{$rows+=[pscustomobject]@{host=$hostName;error=$_.Exception.GetBaseException().GetType().Name}}
    finally{$ct.Dispose();$udp.Dispose()}
}
$samples=@();for($n=0;$n-lt 8;$n++){$samples+=$network.GetProperty('Generation',$flags).GetValue($null);Start-Sleep -Milliseconds 400}
$processes=@(Get-Process -ErrorAction SilentlyContinue | Where-Object ProcessName -Match '^winws$|^ZapretHub' | Select-Object Id,ProcessName)
$browserPath=Join-Path $env:LOCALAPPDATA 'Yandex\YandexBrowser\User Data\Local State'
$secureDns=$null;if(Test-Path $browserPath){$secureDns=(Get-Content $browserPath -Raw | ConvertFrom-Json).dns_over_https | Select-Object mode}
$report=[ordered]@{utc=[DateTime]::UtcNow;relayOwner=$owner;processes=$processes;effectiveAiRule=$policy;relayQueries=$rows;generationSamples=$samples;secureDns=$secureDns;networkReadOnly=$true;browserRuntime='UNVERIFIED'}
$report | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $repo '.test-results\test6-observed-state.json') -Encoding UTF8
$rows | Format-Table
$owner | Format-Table
$policy | Format-List
$processes | Format-Table
$samples
