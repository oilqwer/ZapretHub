$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$known=@('31.31.207.68','159.194.200.33','179.254.166.171','164.5.224.81','179.254.166.174','162.159.36.5','162.159.36.20','181.215.40.49','31.58.216.201','1.1.1.1','8.8.8.8')
$rows=@()
foreach($p in @(Get-CimInstance Win32_Process | Where-Object Name -Match '^(ChatGPT|browser|msedge|msedgewebview2|chrome|gemini|chatgptcom)\.exe$')){
    $cmd=[string]$p.CommandLine
    $matchesAi=@(Get-NetTCPConnection -OwningProcess $p.ProcessId -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -in $known -or ($_.RemoteAddress -in @('127.0.0.1','::1') -and $_.RemotePort -eq 10801) } | Select-Object RemoteAddress,RemotePort)
    $rows+=[pscustomobject]@{pid=$p.ProcessId;parent=$p.ParentProcessId;name=$p.Name;proxyServerFlag=($cmd-match '--proxy-server');proxyPacFlag=($cmd-match '--proxy-pac-url');noProxyFlag=($cmd-match '--no-proxy-server');secureDnsFlag=($cmd-match '--dns-over-https');resolverOverrideFlag=($cmd-match '--host-resolver-rules');webAppFlag=($cmd-match '--app-id|--app=');connections=$matchesAi}
}
$policies=@()
foreach($key in @('HKCU:\Software\Policies\YandexBrowser','HKLM:\Software\Policies\YandexBrowser','HKCU:\Software\Policies\Google\Chrome','HKLM:\Software\Policies\Google\Chrome','HKCU:\Software\Policies\Microsoft\Edge','HKLM:\Software\Policies\Microsoft\Edge')){
    if(Test-Path $key){$v=Get-ItemProperty $key;$policies+=[pscustomobject]@{scope=($key -replace 'HKCU:','User' -replace 'HKLM:','Machine');dnsMode=$v.DnsOverHttpsMode;dnsTemplateConfigured=!!$v.DnsOverHttpsTemplates;proxyMode=$v.ProxyMode;proxyConfigured=!!$v.ProxyServer}}
}
$rules=@(Get-DnsClientNrptPolicy -Effective | Where-Object { @($_.Namespace) | Where-Object {$_ -in @('.chatgpt.com','chatgpt.com','.oaiusercontent.com','oaiusercontent.com','.gemini.google.com','gemini.google.com','.generativelanguage.googleapis.com','generativelanguage.googleapis.com')} } | Select-Object Namespace,NameServers)
$wininet=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$report=[ordered]@{utc=[DateTime]::UtcNow;processes=$rows;policies=$policies;effectiveAiRules=$rules;wininet=[pscustomobject]@{enabled=$wininet.ProxyEnable;configured=!!$wininet.ProxyServer;pacConfigured=!!$wininet.AutoConfigURL};winhttp=@(netsh winhttp show proxy);note='Process flags and IP connections do not identify request hostname or effective browser DNS. No command lines, account profiles, tokens, cookies or request bodies exported.'}
$report | ConvertTo-Json -Depth 7 | Set-Content (Join-Path $repo '.test-results\test6-client-state.json') -Encoding UTF8
$rows | Where-Object { $_.connections.Count -or $_.name -match '^ChatGPT|^gemini|^chatgptcom' -or $_.webAppFlag } | Format-List
$rules | Format-Table
$report.wininet | ConvertTo-Json
$report.winhttp
