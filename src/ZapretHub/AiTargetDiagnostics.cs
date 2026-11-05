using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretHub;

// Queries only assigned providers and known covered hosts. Never uploads a file,
// follows an account redirect, installs NRPT or modifies network configuration.
internal static class AiTargetDiagnostics
{
    internal static int Run(string path, string settingsPath)
    {
        try { RunCore(path,settingsPath).GetAwaiter().GetResult(); return 0; }
        catch(Exception e){File.WriteAllText(path,JsonSerializer.Serialize(new{error=e.GetType().Name}));return 1;}
    }
    private static bool? BoundTunnel(string source)
    {
        if(source.Length==0)return null;
        var nic=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n=>n.GetIPProperties().UnicastAddresses.Any(a=>a.Address.ToString()==source));
        return nic is null ? null : AiNetwork.IsTunnel(nic);
    }
    private static async Task RunCore(string path,string settingsPath)
    {
        var cfg=AiDnsCatalog.Normalize(File.Exists(settingsPath)?JsonNode.Parse(File.ReadAllText(settingsPath))?["aidns"]?.Deserialize<AiCfg>()??AiDns.DefaultConfig():AiDns.DefaultConfig());
        AiDnsCatalog.Validate(cfg);
        var plan=AiDnsCatalog.Plan(cfg);
        var candidates=AiDnsCatalog.Candidates(cfg);
        var jobs=new[]{"chatgpt.com","gemini.google.com"}.SelectMany(group=>
        {
            var keys=plan is null?candidates.Select(AiDnsCatalog.Key).Take(2):plan[group];
            return keys.Select(k=>(group,server:candidates.First(s=>AiDnsCatalog.Key(s)==k)));
        }).ToArray();
        var results=new List<object>();using var limit=new SemaphoreSlim(2);using var budget=new CancellationTokenSource(90_000);
        try { await Task.WhenAll(jobs.Select(async job=>
        {
            await limit.WaitAsync(budget.Token);
            try
            {
                using var exchange=new DnsExchange(job.server);
                foreach(string host in job.group=="chatgpt.com"?new[]{"chatgpt.com","files.oaiusercontent.com","auth.openai.com"}:new[]{"gemini.google.com","generativelanguage.googleapis.com"})
                {
                    long network=AiNetwork.Generation; string[] a=Array.Empty<string>(),aaaa=Array.Empty<string>();
                    string transport="",dnsVersion="",kind="",stage="",ipv6Status="Не проверено";int status=0,dnsRcode=-1;bool dns=false,head=false;bool? dnsTunnel=null,httpsTunnel=null;
                    var watch=System.Diagnostics.Stopwatch.StartNew();
                    try
                    {
                        await AiProbeFailure.WithinDeadline(async ct=>{
                            var q=DnsWire.Query(host);var r=await exchange.QueryObserved(q,ct);
                            a=DnsWire.Addresses(q,r.Wire).Select(x=>x.ToString()).ToArray();transport=r.Transport;dnsVersion=r.Version;dns=true;dnsRcode=r.Wire[3]&15;dnsTunnel=BoundTunnel(r.Source);
                        },budget.Token);
                    }
                    catch(Exception e){var failure=AiProbeFailure.Classify("DNS/DoH",e);kind=failure.Kind;stage=failure.Stage;}
                    long dnsMs=watch.ElapsedMilliseconds;
                    if(dns)
                    {
                        using(var v6=CancellationTokenSource.CreateLinkedTokenSource(budget.Token))
                        {
                            v6.CancelAfter(3000);
                            try{var q=DnsWire.Query(host,28);var r=await exchange.Query(q,v6.Token);aaaa=DnsWire.Addresses(q,r).Select(ip=>ip.ToString()).ToArray();ipv6Status="RCODE "+(r[3]&15);}
                            catch(Exception e){ipv6Status=AiProbeFailure.Classify("DNS AAAA",e).Kind;}
                        }
                        if(a.FirstOrDefault(ip=>IPAddress.TryParse(ip,out var parsed)&&!Net.Bogus(parsed)) is string target)
                        {
                            var observation=new AiProbeObservation();
                            try{await AiProbeFailure.WithinDeadline(ct=>AiServiceProbe.CheckHttps(host,IPAddress.Parse(target),ct,observation,true),budget.Token);status=observation.httpStatus;head=true;stage="HEAD / ответ получен";}
                            catch(Exception e){var failure=AiProbeFailure.Classify("HTTPS",e);kind=failure.Kind;stage=failure.Stage;}
                            httpsTunnel=BoundTunnel(observation.httpsSource);
                        }
                    }
                    lock(results)results.Add(new{provider=job.server.address,host,group=job.group,nrptCovered=AiDnsPolicy.IsAiHost(host),dns,dnsRcode,a,aaaa,ipv6Status,transport,dnsVersion,dnsMs,stage,kind,httpStatus=status,headRootOnly=head,dnsBoundToTunnel=dnsTunnel,httpsBoundToTunnel=httpsTunnel,currentNetwork=network==AiNetwork.Generation});
                    if(!dns)break; // one transport failure per endpoint, no repeated failed handshakes
                }
            }
            finally{limit.Release();}
        })); }catch(OperationCanceledException)when(budget.IsCancellationRequested){}
        File.WriteAllText(path,JsonSerializer.Serialize(new{utc=DateTime.UtcNow,mode=cfg.selectionMode,network=AiNetwork.SafeSnapshot(),budgetExpired=budget.IsCancellationRequested,results,note="HEAD / не проверяет загрузку файла или запрос ИИ. Источник сокета определяется без cookies/токенов; WFP может дополнительно обработать поток. Общий вход accounts.google.com вне NRPT; не перенаправлялся."},Json.Indented));
    }
}
