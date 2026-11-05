$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$env:ZAPRETHUB_DATA=Join-Path $repo '.test-results\gemini7-probe-data'
New-Item -ItemType Directory -Path $env:ZAPRETHUB_DATA -Force | Out-Null
$asm=[Reflection.Assembly]::LoadFrom((Join-Path $repo 'src\ZapretHub\bin\Release\net8.0-windows10.0.17763.0\win-x64\ZapretHub-AiDnsTest6.dll'))
$flags=[Reflection.BindingFlags]'NonPublic,Static'
$wire=$asm.GetType('ZapretHub.DnsWire')
$exchange=$asm.GetType('ZapretHub.DnsExchange')
Add-Type -TypeDefinition @'
using System; using System.Net; using System.Net.Http; using System.Net.Sockets; using System.Threading; using System.Threading.Tasks; using System.IO; using System.Text.RegularExpressions;
public static class GeminiPinned7 {
 public static async Task<object> Get(string host,string ip,string path){
 string stage="TCP",source=""; using var stop=new CancellationTokenSource(8000);
 try { using var h=new SocketsHttpHandler{UseProxy=false,UseCookies=false,AllowAutoRedirect=false,AutomaticDecompression=DecompressionMethods.All,ConnectTimeout=TimeSpan.FromSeconds(3)};
 h.ConnectCallback=async(ctx,ct)=>{var s=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);try{await s.ConnectAsync(IPAddress.Parse(ip),443,ct);source=((IPEndPoint)s.LocalEndPoint).Address.ToString();stage="TLS";return new NetworkStream(s,true);}catch{s.Dispose();throw;}};
 h.PlaintextStreamFilter=(ctx,ct)=>{stage="HTTP";return ValueTask.FromResult(ctx.PlaintextStream);};
 using var c=new HttpClient(h){Timeout=Timeout.InfiniteTimeSpan};using var q=new HttpRequestMessage(HttpMethod.Get,"https://"+host+path){Version=HttpVersion.Version20,VersionPolicy=HttpVersionPolicy.RequestVersionOrLower};
 q.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36");q.Headers.AcceptLanguage.ParseAdd("en");
 using var r=await c.SendAsync(q,HttpCompletionOption.ResponseHeadersRead,stop.Token);var loc=r.Headers.Location;Uri dest=loc==null?null:new Uri(new Uri("https://"+host+path),loc);
 using var reader=new StreamReader(await r.Content.ReadAsStreamAsync(stop.Token));var b=new char[1024*1024];int n=0,k;while(n<b.Length&&(k=await reader.ReadAsync(b.AsMemory(n),stop.Token))>0)n+=k;string body=new string(b,0,n);
 string visible=Regex.Replace(body,@"<(script|style)\b[^>]*>.*?</\1\s*>","",RegexOptions.IgnoreCase|RegexOptions.Singleline);visible=WebUtility.HtmlDecode(Regex.Replace(visible,"<[^>]+>"," "));visible=Regex.Replace(visible,@"\s+"," ");
 return new {host,ip,path,status=(int)r.StatusCode,version=r.Version.ToString(),locationHost=dest?.Host,locationPath=dest?.AbsolutePath,region=Regex.IsMatch(visible,@"not (currently )?(available|supported) in your (country|region)|isn.t (currently )?(available|supported) in your country|не поддерживается в вашей стране|недоступен в вашей стране",RegexOptions.IgnoreCase),unusualTraffic=visible.Contains("unusual traffic",StringComparison.OrdinalIgnoreCase),stage,bodyChars=n};
 }catch(Exception e){return new {host,ip,path,stage,error=e.GetBaseException().GetType().Name};}
 }
}
'@
$rows=[Collections.Generic.List[object]]::new()
$servers=@([ZapretHub.AiDns]::RecPrimary(),[ZapretHub.DnsServer]@{address='1.1.1.1';doh=$true;template='https://cloudflare-dns.com/dns-query';fallback=$false})
foreach($s in $servers){
 $x=[Activator]::CreateInstance($exchange,[Reflection.BindingFlags]'Instance,NonPublic',$null,@($s,$null),$null)
 try {foreach($hostName in @('gemini.google.com','accounts.google.com','jnn-pa.googleapis.com','waa-pa.clients6.google.com')){
  $ips=@();foreach($kind in @(1,28)){$ct=[Threading.CancellationTokenSource]::new(5000);try{$q=$wire.GetMethod('Query',$flags).Invoke($null,@($hostName,[ushort]$kind));$a=$x.Query($q,$ct.Token).GetAwaiter().GetResult();$values=@($wire.GetMethod('Addresses',$flags).Invoke($null,@($q,$a))|ForEach-Object ToString);$rows.Add([pscustomobject]@{provider=$s.address;host=$hostName;type=$kind;addresses=$values;rcode=($a[3]-band 15)});if($kind-eq 1){$ips=$values}}catch{$rows.Add([pscustomobject]@{provider=$s.address;host=$hostName;type=$kind;error=$_.Exception.GetBaseException().GetType().Name})}finally{$ct.Dispose()}}
  if($ips.Count){foreach($path in $(if($hostName-eq 'gemini.google.com'){@('/','/app?hl=en')}else{@('/')})){$rows.Add([GeminiPinned7]::Get($hostName,$ips[0],$path).GetAwaiter().GetResult())}}
 }}finally{$x.Dispose()}
}
$out=Join-Path $repo '.test-results\gemini7-route.json';$rows|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $out -Encoding utf8;$rows|ConvertTo-Json -Depth 5
