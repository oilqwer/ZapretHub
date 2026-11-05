# Recover the earlier portable artifact after SDK publish cleanup; keep Test4 sources and EXE.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$stash = Join-Path $repo '.test-results\test4-preserved'
New-Item -ItemType Directory -Path $stash -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repo 'test-ready\ZapretHub-AiDnsTest4.exe') -Destination $stash
$files = @('AiDns.cs','AiDnsRelay.cs','AiDnsTests.cs','ui\index.html')
$saved = @{}
foreach($file in $files){ $path=Join-Path $repo ('src\ZapretHub\'+$file); $saved[$file]=[IO.File]::ReadAllBytes($path) }
try {
    $path=Join-Path $repo 'src\ZapretHub\AiDns.cs'
    $s=[IO.File]::ReadAllText($path)
    $s=[regex]::Replace($s, '    public static DnsServer MalwPrimary\(\).*?    public static DnsServer BezmezhauPrimary\(\)[^\r\n]*\r?\n', '', [Text.RegularExpressions.RegexOptions]::Singleline)
    $s=$s.Replace(', MalwPrimary(), MalwGateway(), BezmezhauPrimary()', '')
    [IO.File]::WriteAllText($path,$s)
    $path=Join-Path $repo 'src\ZapretHub\AiDnsRelay.cs'
    $s=[IO.File]::ReadAllText($path)
    $s=[regex]::Replace($s, '                using var request = new HttpRequestMessage\(HttpMethod.Post, _server.template\)\s*\{\s*Content = new ByteArrayContent\(query\),\s*Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,\s*\};', '                using var request = new HttpRequestMessage(HttpMethod.Post, _server.template) { Content = new ByteArrayContent(query) };')
    [IO.File]::WriteAllText($path,$s)
    $path=Join-Path $repo 'src\ZapretHub\AiDnsTests.cs'
    $s=[IO.File]::ReadAllText($path)
    $s=[regex]::Replace($s, '            var auto = AiDns.Candidates\(AiDns.DefaultConfig\(\)\);.*?            Check\("Manual provider selection excludes automatic reserves", AiDns.Candidates\(manual\).Count == 2\);\r?\n', '', [Text.RegularExpressions.RegexOptions]::Singleline)
    [IO.File]::WriteAllText($path,$s)
    $path=Join-Path $repo 'src\ZapretHub\ui\index.html'
    $s=[IO.File]::ReadAllText($path).Replace('DNS-AI, WebShift, GeoHide, Malw.link и Bezmezhau', 'DNS-AI, WebShift и GeoHide')
    [IO.File]::WriteAllText($path,$s)
    & dotnet publish (Join-Path $repo 'src\ZapretHub\ZapretHub.csproj') -c Release --no-restore -p:AssemblyName=ZapretHub-AiDnsTest3 -p:InformationalVersion=2.0.2-ai-dns-test3 -o (Join-Path $stash 'test3')
    if($LASTEXITCODE -ne 0){ throw 'Test3 recovery build failed' }
    $exe=Join-Path $stash 'test3\ZapretHub-AiDnsTest3.exe'
    $expected=(Get-Content (Join-Path $repo 'test-ready\SHA256SUMS-Test3.txt') | Select-Object -First 1).Split(' ')[0]
    $actual=(Get-FileHash $exe -Algorithm SHA256).Hash
    if($expected -ne $actual){ throw "Recovered Test3 differs: expected $expected actual $actual" }
    Copy-Item -LiteralPath $exe -Destination (Join-Path $repo 'test-ready\ZapretHub-AiDnsTest3.exe')
    'PASS recovered Test3 matches its original SHA256 exactly'
} finally {
    foreach($file in $files){ [IO.File]::WriteAllBytes((Join-Path $repo ('src\ZapretHub\'+$file)), $saved[$file]) }
    Copy-Item -LiteralPath (Join-Path $stash 'ZapretHub-AiDnsTest4.exe') -Destination (Join-Path $repo 'test-ready\ZapretHub-AiDnsTest4.exe')
}
