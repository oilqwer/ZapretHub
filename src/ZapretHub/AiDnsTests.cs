using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ZapretHub;

internal static class AiDnsTests
{
    private sealed class DohHandler : HttpMessageHandler
    {
        internal bool Closed;
        internal bool CorrectRequest;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var q = await request.Content!.ReadAsByteArrayAsync(ct);
            CorrectRequest=request.Method==HttpMethod.Post&&request.Version.Major==2&&request.Content.Headers.ContentType?.MediaType=="application/dns-message"&&request.Headers.Accept.Any(a=>a.MediaType=="application/dns-message");
            var content=new ByteArrayContent(Answer(q));content.Headers.ContentType=new("application/dns-message");
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK){Version=new Version(2,0),Content=content};
        }
        protected override void Dispose(bool disposing){Closed=true;base.Dispose(disposing);}
    }
    internal static int Serve(string ready, string stop, string testHost)
    {
        if (!testHost.EndsWith(".invalid", StringComparison.Ordinal)) return 2;
        var pool = new DnsFailover(new[] { AiDns.DnsAiPrimary() }, _ => new Fake(), (_, _, _) => Task.CompletedTask, h => h == testHost, h => h);
        using var relay = new AiDnsRelay(pool, AiDnsPolicy.ListenAddress);
        File.WriteAllText(ready, "ready");
        long until = Environment.TickCount64 + 30_000;
        while (Environment.TickCount64 < until && !File.Exists(stop)) Thread.Sleep(100);
        return 0;
    }
    private sealed class Fake : IDnsExchange
    {
        internal int Calls;
        internal Func<byte[], byte[]> Reply = q => Answer(q);
        public Task<byte[]> Query(byte[] q, CancellationToken ct) { ct.ThrowIfCancellationRequested(); Interlocked.Increment(ref Calls); return Task.FromResult(Reply(q)); }
        public void Dispose() { }
    }
    internal static byte[] Answer(byte[] q, int code = 0, bool v6 = false, int padding = 0)
    {
        DnsWire.Question(q, out _, out int end);
        var r = new byte[end + (code == 0 ? (v6 ? 28 : 16) : 0) + padding];
        Array.Copy(q, r, end); r[2] = 0x81; r[3] = (byte)(0x80 | code);
        DnsWire.Put(r, 6, (ushort)(code == 0 ? 1 : 0)); DnsWire.Put(r, 8, 0); DnsWire.Put(r, 10, 0);
        if (code == 0)
        {
            r[end] = 0xc0; r[end + 1] = 12; DnsWire.Put(r, end + 2, (ushort)(v6 ? 28 : 1)); DnsWire.Put(r, end + 4, 1);
            DnsWire.Put(r, end + 10, (ushort)(v6 ? 16 : 4));
            (v6 ? IPAddress.Parse("2606:4700::1111") : IPAddress.Parse("203.0.113.2")).GetAddressBytes().CopyTo(r, end + 12);
        }
        return r;
    }
    private static DnsFailover Pool(Fake first, Fake? second = null)
    {
        var servers = new[] { AiDns.DnsAiPrimary(), AiDns.DnsAiAlternate() };
        return new DnsFailover(servers.Take(second is null ? 1 : 2), s => s.address == servers[0].address ? first : second!, (_, _, _) => Task.CompletedTask);
    }
    internal static int RunLifecycle(string report)
    {
        var lines=new List<string>();int failures=0;
        void Check(string name,bool value){lines.Add((value?"PASS ":"FAIL ")+name);if(!value)failures++;}
        async Task Test()
        {
            Check("Windows ICMP connection reset is transient",AiDnsRelay.Transient(SocketError.ConnectionReset));
            Check("Invalid socket is fatal, not an endless retry",!AiDnsRelay.Transient(SocketError.NotSocket));
            Check("Google sorry redirect is challenge, not DNS or region",AiServiceProbe.GoogleChallenge(new Uri("https://www.google.com/sorry/index?continue=https://gemini.google.com/"))&&!AiServiceProbe.GoogleChallenge(new Uri("https://www.google.com.evil.test/sorry/index")));
            var fake=new Fake();
            using(var relay=new AiDnsRelay(Pool(fake),IPAddress.Loopback,0))
            {
                using(var abandoned=new UdpClient(0)){await abandoned.SendAsync(DnsWire.Query("chatgpt.com"),new IPEndPoint(IPAddress.Loopback,relay.Port));}
                await Task.Delay(300);
                Check("Closed UDP client does not kill Relay",relay.Running);
                using var live=new UdpClient(0);using var timeout=new CancellationTokenSource(3000);var q=DnsWire.Query("chatgpt.com");await live.SendAsync(q,new IPEndPoint(IPAddress.Loopback,relay.Port),timeout.Token);var answer=await live.ReceiveAsync(timeout.Token);
                Check("UDP Relay answers after closed client ICMP",DnsWire.Reply(q,answer.Buffer));
                fake.Reply=q=>throw new IOException("temporary provider outage");await live.SendAsync(q,new IPEndPoint(IPAddress.Loopback,relay.Port),timeout.Token);answer=await live.ReceiveAsync(timeout.Token);
                Check("Provider failure returns SERVFAIL while Relay stays active",(answer.Buffer[3]&15)==2&&relay.Running);
                int calls=fake.Calls;await live.SendAsync(q,new IPEndPoint(IPAddress.Loopback,relay.Port),timeout.Token);await live.ReceiveAsync(timeout.Token);
                Check("Provider outage uses cooldown",fake.Calls==calls);
                fake.Reply=q=>Answer(q);AiNetwork.ForceChangeForTest();await live.SendAsync(q,new IPEndPoint(IPAddress.Loopback,relay.Port),timeout.Token);answer=await live.ReceiveAsync(timeout.Token);
                Check("Network change recovers provider without stopping listener",(answer.Buffer[3]&15)==0&&relay.Running);
            }
            int installs=0,removes=0;
            using(var runtime=new AiDnsRuntime(_=>installs++,_=>removes++,_=>null,IPAddress.Loopback,0,_=>{}))
            {
                runtime.Start(new[]{AiDns.DnsAiPrimary()});Check("Runtime starts with owned policy",runtime.Running&&installs==1);
                var relay=(AiDnsRelay)typeof(AiDnsRuntime).GetField("_relay",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.GetValue(runtime)!;
                var tcp=(TcpListener)typeof(AiDnsRelay).GetField("_tcp",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.GetValue(relay)!;tcp.Stop();
                for(int i=0;i<40&&removes==0;i++)await Task.Delay(50);
                Check("Fatal listener failure removes only owned NRPT",removes==1&&!runtime.Running);
                var state=System.Text.Json.JsonSerializer.SerializeToNode(runtime.State)!;
                Check("Stopped Relay exposes lifecycle error",state["listenerRunning"]!.GetValue<bool>()==false&&state["lifecycleError"]!.ToString().Length>0);
                runtime.Start(new[]{AiDns.DnsAiPrimary()});Check("Manual restart after fatal failure succeeds",runtime.Running&&installs==2);
                runtime.Stop();await Task.Delay(100);Check("Explicit stop is not repeated by observer",removes==2&&!runtime.Running);
            }
            int attempts=0;
            using(var runtime=new AiDnsRuntime(_=>{},_=>{if(Interlocked.Increment(ref attempts)==1)throw new IOException("temporary policy failure");},_=>null,IPAddress.Loopback,0,_=>{}))
            {
                runtime.Start(new[]{AiDns.DnsAiPrimary()});var relay=(AiDnsRelay)typeof(AiDnsRuntime).GetField("_relay",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.GetValue(runtime)!;
                ((TcpListener)typeof(AiDnsRelay).GetField("_tcp",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.GetValue(relay)!).Stop();
                for(int i=0;i<70&&attempts<2;i++)await Task.Delay(50);
                Check("Fatal listener rollback retries bounded temporary cleanup failure",attempts==2&&!runtime.Running);
            }
        }
        try{Test().GetAwaiter().GetResult();}catch(Exception e){lines.Add("FAIL "+e);failures++;}
        lines.Add("Failures: "+failures);File.WriteAllLines(report,lines,new UTF8Encoding(false));return failures==0?0:1;
    }
    internal static int Run(string report)
    {
        var lines = new List<string>(); int fails = 0;
        void Check(string name, bool ok) { lines.Add((ok ? "PASS " : "FAIL ") + name); if (!ok) fails++; }
        async Task Tests()
        {
            Check("AI namespace boundary", AiDnsPolicy.IsAiHost("chatgpt.com") && AiDnsPolicy.IsAiHost("cdn.chatgpt.com") && !AiDnsPolicy.IsAiHost("evilchatgpt.com") && !AiDnsPolicy.IsAiHost("chatgpt.com.evil.test"));
            Check("Corporate DNS and other Google services excluded", !AiDnsPolicy.IsAiHost("nr-dc02.nau-ra.local") && !AiDnsPolicy.IsAiHost("printer.local") && !AiDnsPolicy.IsAiHost("mail.google.com"));
            Check("Regional restrictions recognised", AiServiceProbe.RegionBlocked("<p>Gemini пока не поддерживается в вашей стране.</p>") && AiServiceProbe.RegionBlocked("{\"code\":\"unsupported_country\"}"));
            Check("Unused translations do not mark a working page blocked", !AiServiceProbe.RegionBlocked("<script>var s='not supported in your country';</script><p>Welcome</p>"));
            Check("ChatGPT denial page is not a successful HTTP response", AiServiceProbe.PageFailure("<h1>Unable to load site</h1><p>If you are using a VPN, try turning it off.</p>") == "service_rejected" && AiServiceProbe.PageFailure("Не удается загрузить сайт") == "service_rejected");
            Check("Error classes distinguish DNS, TLS and connection", AiProbeFailure.Classify("DNS/DoH", new IOException("bad packet")).Kind == "dns" && AiProbeFailure.Classify("HTTPS", new System.Security.Authentication.AuthenticationException()).Kind == "tls" && AiProbeFailure.Classify("HTTPS", new SocketException()).Kind == "connection");
            Check("Region/IP rejection has bounded extended cooldown", AiProbeFailure.Cooldown(new AiProbeFailure("region", "blocked")) == 600_000 && AiProbeFailure.Cooldown(new IOException("offline")) == 30_000);
            try { await AiProbeFailure.WithinDeadline(_ => Task.FromException(new TaskCanceledException("ConnectTimeout")), default); Check("Transport timeout is not labelled eight-second deadline", false); }
            catch (AiProbeFailure e) { Check("Transport timeout is not labelled eight-second deadline", e.Kind == "timeout" && e.Message.Contains("ConnectTimeout") && !e.Message.Contains("(8 с)")); }
            var mandatory = AiDns.DnsAiPrimary(); mandatory.fallback = true; bool disallowed = false;
            try { AiDns.Validate(mandatory, false, "DNS-AI"); } catch (ArgumentException) { disallowed = true; }
            Check("DNS-AI cannot enable plaintext fallback", disallowed);
            var auto = AiDns.Candidates(AiDns.DefaultConfig());
            Check("Verified Smart DNS reserves are encrypted and ordinary DNS excluded", auto.Any(s => s.template.Contains("5u35p8m9i7.cloudflare-gateway.com") && s.doh && !s.fallback) && auto.Any(s => s.template.Contains("dns.bezmezhau.com") && s.doh && !s.fallback) && auto.All(s => s.address != "1.1.1.1"));
            var manual = AiDns.DefaultConfig(); manual.autoSwitch = false;
            Check("Manual provider selection excludes automatic reserves", AiDns.Candidates(manual).Count == 2);
            Check("Bundled unused country error is not a regional denial", !AiServiceProbe.RegionBlocked("<script>const code='unsupported_country';</script><p>Welcome</p>"));
            var panelCfg = AiDnsCatalog.Normalize(AiDns.DefaultConfig());
            Check("All six named providers appear in panel", AiDnsCatalog.Entries(panelCfg).Count == 6);
            Check("Files and nested upload hosts inherit ChatGPT without broad cloud rules", AiDnsPolicy.IsAiHost("files.oaiusercontent.com")&&AiServiceProbe.Group("files.oaiusercontent.com")=="chatgpt.com"&&AiServiceProbe.Group("sub.files.oaiusercontent.com")=="chatgpt.com"&&!AiDnsPolicy.IsAiHost("storage.blob.core.windows.net")&&!AiDnsPolicy.IsAiHost("accounts.google.com"));
            Check("Network fingerprint ignores enumeration ordering",AiNetwork.StableSet(new[]{"iface-b","iface-a"})==AiNetwork.StableSet(new[]{"iface-a","iface-b"}));
            var handlers=new List<DohHandler>();
            using(var pooled = new DnsExchange(AiDns.DnsAiPrimary(),()=>{var h=new DohHandler();handlers.Add(h);return new HttpClient(h);}))
            {
                var uploadQuery=DnsWire.Query("files.oaiusercontent.com");
                typeof(DnsExchange).GetField("_plaintextFallback",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Instance)!.SetValue(pooled,1);
                var encrypted=await pooled.QueryObserved(uploadQuery,default);
                Check("Fresh encrypted upload DNS reply is not marked historical UDP fallback", encrypted.Transport=="DoH"&&pooled.HadPlaintextFallback&&encrypted.Wire.SequenceEqual(Answer(uploadQuery)));
                Check("DoH request preserves wire format and HTTP/2 negotiation",handlers[0].CorrectRequest);
                AiNetwork.Changed();pooled.RefreshNetwork();
                Check("Duplicate network notification preserves usable DoH connection pool",handlers.Count==1&&!handlers[0].Closed);
                AiNetwork.ForceChangeForTest();pooled.RefreshNetwork();
                Check("Real network epoch change closes old DoH pool",handlers.Count==2&&handlers[0].Closed&&!pooled.HadPlaintextFallback);
            }
            panelCfg.selectionMode = "manual"; panelCfg.manualChatgpt = "webshift@31.31.207.68"; panelCfg.manualGemini = "gateway@162.159.36.5";
            panelCfg.fallbackChatgpt = panelCfg.fallbackGemini = "";
            var assigned = AiDnsCatalog.Candidates(panelCfg); var plan = AiDnsCatalog.Plan(panelCfg)!;
            var assignedFakes = assigned.ToDictionary(AiDnsCatalog.Key, _ => new Fake());
            using (var assignedPool = new DnsFailover(assigned, s => assignedFakes[AiDnsCatalog.Key(s)], (_,_,_) => Task.CompletedTask, plan:plan))
            {
                await assignedPool.Query(DnsWire.Query("chatgpt.com"), default);
                Check("Manual ChatGPT uses only its explicit IP", assignedFakes[plan["chatgpt.com"][0]].Calls == 1 && assignedFakes[plan["gemini.google.com"][0]].Calls == 0);
                var fileQuery=DnsWire.Query("files.oaiusercontent.com"); var fileReply=await assignedPool.Query(fileQuery,default);
                Check("File DNS follows selected ChatGPT provider and retains special reply",assignedFakes[plan["chatgpt.com"][0]].Calls==2&&assignedFakes[plan["gemini.google.com"][0]].Calls==0&&fileReply.SequenceEqual(Answer(fileQuery)));
                assignedFakes[plan["chatgpt.com"][0]].Reply = _ => throw new IOException("offline");
                var rejected = await assignedPool.Query(DnsWire.Query("chatgpt.com"), default);
                Check("Manual failure never silently selects Gemini or automatic provider", (rejected[3]&15)==2 && assignedFakes[plan["gemini.google.com"][0]].Calls == 0);
                Check("Gemini remains independent of failed ChatGPT assignment", DnsWire.Addresses(DnsWire.Query("gemini.google.com"), Array.Empty<byte>()).Count == 0 && (await assignedPool.Query(DnsWire.Query("gemini.google.com"), default))[3] == 0x80);
            }
            panelCfg.fallbackChatgpt = "bezmezhau@181.215.40.49";
            var explicitServers = AiDnsCatalog.Candidates(panelCfg);
            using (var explicitPool = new DnsFailover(explicitServers, s => new Fake { Reply = s.address == "31.31.207.68" ? _ => throw new IOException("offline") : q0 => Answer(q0) }, (_,_,_) => Task.CompletedTask, plan:AiDnsCatalog.Plan(panelCfg)))
                Check("Manual explicit backup is used", (await explicitPool.Query(DnsWire.Query("chatgpt.com"), default))[3] == 0x80);
            panelCfg.customServers.Add(new() { id="custom-test", name="My DNS", custom=true, servers=new(){ new(){ address="203.0.113.10", doh=true, template="https://example.test/dns-query?token=SECRET" } } });
            panelCfg.manualGemini = "custom-test@203.0.113.10"; AiDnsCatalog.Validate(panelCfg);
            var roundtrip = System.Text.Json.JsonSerializer.Deserialize<AiCfg>(System.Text.Json.JsonSerializer.Serialize(panelCfg))!;
            Check("Custom records and distinct manual assignments survive save/load", roundtrip.customServers.Count == 1 && roundtrip.manualGemini == panelCfg.manualGemini);
            panelCfg.selectionMode = "auto"; AiDnsCatalog.Validate(panelCfg); panelCfg.selectionMode = "manual";
            Check("Mode switching retains manual settings and custom entries", panelCfg.manualGemini == "custom-test@203.0.113.10" && panelCfg.customServers.Count == 1);
            var invalidCustom = System.Text.Json.JsonSerializer.Deserialize<AiCfg>(System.Text.Json.JsonSerializer.Serialize(panelCfg))!;
            invalidCustom.customServers[0].servers[0].address="127.0.0.2";
            bool loopDenied=false; try{AiDnsCatalog.Validate(invalidCustom);}catch(ArgumentException){loopDenied=true;}
            Check("Custom DNS cannot loop back into relay", loopDenied);
            int rechecks=0;
            using (var networkPool = new DnsFailover(new[]{AiDns.DnsAiPrimary()}, _=>new Fake(), (_,_,_)=>{Interlocked.Increment(ref rechecks);return Task.CompletedTask;}))
            {
                await networkPool.Query(DnsWire.Query("chatgpt.com"),default); await networkPool.Query(DnsWire.Query("chatgpt.com"),default);
                Check("Health cache reused on unchanged network",rechecks==1);
                long stable=AiNetwork.Generation;
                for(int n=0;n<10;n++)AiNetwork.Changed();
                await networkPool.Query(DnsWire.Query("chatgpt.com"),default);
                Check("Duplicate Windows notifications do not invalidate real health cache",AiNetwork.Generation==stable&&rechecks==1);
                AiNetwork.ForceChangeForTest(); await networkPool.Query(DnsWire.Query("chatgpt.com"),default);
                Check("Network change invalidates health cache",rechecks==2);
            }
            using(var partial = new DnsFailover(new[]{AiDns.DnsAiPrimary()}, _=>new Fake(), (h,_,_)=>h=="chatgpt.com"?Task.FromException(new IOException("offline")):Task.CompletedTask))
            {
                await partial.Warmup(); var partialState=System.Text.Json.JsonSerializer.SerializeToNode(partial.State)!;
                Check("One failed service does not block healthy service activation",partialState["routes"]!.AsArray().Count(r=>r!["error"]!.ToString().Length==0)==1);
            }
            int activeChecks=0, peak=0;
            var cancelMonitor = new AiDnsMonitor(_=>new Fake(), async (_,_,token)=>{int n=Interlocked.Increment(ref activeChecks);peak=Math.Max(peak,n);try{await Task.Delay(5000,token);}finally{Interlocked.Decrement(ref activeChecks);}});
            cancelMonitor.Start(AiDnsCatalog.Candidates(AiDnsCatalog.Normalize(AiDns.DefaultConfig())));
            await Task.Delay(100);cancelMonitor.Cancel();await Task.Delay(200);
            Check("Provider checks are bounded to three and cancellable", peak<=3 && activeChecks==0 && System.Text.Json.JsonSerializer.SerializeToNode(cancelMonitor.State)!["checking"]!.GetValue<bool>()==false);
            string safe=System.Text.Json.JsonSerializer.Serialize(cancelMonitor.Export(null,panelCfg));
            Check("Export excludes settings, custom tokens and manual IDs", !safe.Contains("SECRET") && !safe.Contains("custom-test") && !safe.Contains("example.test"));
            var stableMonitor=new AiDnsMonitor(_=>new Fake(),(_,_,_)=>Task.CompletedTask);
            using(var fake=new Fake())await stableMonitor.Check("chatgpt.com",AiDns.DnsAiPrimary(),fake,default);
            for(int n=0;n<10;n++)AiNetwork.Changed();
            var liveExport=System.Text.Json.JsonSerializer.SerializeToNode(stableMonitor.Export(null,panelCfg))!;
            Check("Fresh report stays current after spurious Windows notifications",liveExport["results"]!.AsArray().All(r=>r!["currentNetwork"]!.GetValue<bool>()));
            AiNetwork.ForceChangeForTest();var oldExport=System.Text.Json.JsonSerializer.SerializeToNode(stableMonitor.Export(null,panelCfg))!;
            Check("Historical reports stay stale after real network change",oldExport["results"]!.AsArray().All(r=>!r!["currentNetwork"]!.GetValue<bool>()));
            var testApiSettings = new Settings(); var testApi = new Api(testApiSettings, new Engine(), (_,_)=>{});
            var panelSave=testApi.Call("aidns_panel_save",new System.Text.Json.Nodes.JsonArray(System.Text.Json.JsonSerializer.SerializeToNode(panelCfg)));
            Check("Panel settings save through API without system changes",panelSave["ok"]!.GetValue<bool>() && testApi.Call("aidns_panel",new())["cfg"]!["manualGemini"]!.ToString()==panelCfg.manualGemini);
            byte[] q = DnsWire.Query("chatgpt.com");
            Check("Smart DNS comparison never claims proxy use", AiDnsDiagnostic.Compare(new[] { "203.0.113.2" }, new[] { "203.0.113.2" }) == "SAME_ADDRESSES_NOT_PROOF_OF_PROXY" && AiDnsDiagnostic.Compare(new[] { "203.0.113.2" }, new[] { "104.18.32.47" }) == "DIFFERENT_ADDRESSES_NOT_PROOF_OF_PROXY" && AiDnsDiagnostic.Compare(Array.Empty<string>(), new[] { "104.18.32.47" }) == "NO_COMPARISON");
            using (var rawPool = Pool(new Fake()))
                Check("Smart DNS reply retained byte for byte", (await rawPool.Query(q, default)).SequenceEqual(Answer(q)));
            Check("Valid compressed answer", DnsWire.Reply(q, Answer(q)) && DnsWire.Addresses(q, Answer(q)).Count == 1);
            var upper = Answer(q); upper[13] = (byte)'C'; Check("DNS label case is insensitive", DnsWire.Reply(q, upper));
            var broken = Answer(q); broken[0] ^= 1; Check("Mismatched DNS transaction rejected", !DnsWire.Reply(q, broken));
            Check("Truncated record rejected", !DnsWire.Reply(q, Answer(q)[..^1]));
            for (int n = 0; n < q.Length; n++) { var shortQ = q[..n]; DnsWire.Question(shortQ, out _, out _); DnsWire.Error(shortQ, 1); DnsWire.Reply(q, shortQ); }
            Check("Truncated packets handled without exceptions", true);
            var first = new Fake { Reply = _ => throw new IOException("offline") }; var second = new Fake();
            using (var pool = Pool(first, second))
            {
                Check("Failed primary switches to alternate", DnsWire.U16(await pool.Query(q, default), 6) == 1 && first.Calls == 1 && second.Calls == 1);
                await pool.Query(q, default); Check("Healthy alternate remains active", first.Calls == 1 && second.Calls == 2);
                var local = DnsWire.Query("nr-dc02.nau-ra.local"); var denied = await pool.Query(local, default);
                Check("Corporate query never reaches external DNS", (denied[3] & 15) == 5 && first.Calls == 1 && second.Calls == 2);
                var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => pool.Query(q, default)));
                Check("Concurrent queries preserve DNS transaction", results.All(x => DnsWire.Reply(q, x)));
            }
            first = new Fake { Reply = _ => new byte[12] }; second = new Fake();
            using (var pool = Pool(first, second)) Check("Malformed reply triggers failover", DnsWire.Addresses(q, await pool.Query(q, default)).Count == 1 && second.Calls == 1);
            first = new Fake(); second = new Fake();
            var choices = new[] { AiDns.DnsAiPrimary(), AiDns.DnsAiAlternate() };
            using (var pool = new DnsFailover(choices.Take(1), _ => new Fake(), async (_, _, ct) => await Task.Delay(6000, ct)))
            {
                await pool.Warmup();
                Check("Activation accepts six-second health checks under unified eight-second deadline", true);
            }
            var warmPrimary = new Fake(); var warmBackup = new Fake();
            using (var pool = new DnsFailover(choices, s => s.address == choices[0].address ? warmPrimary : warmBackup, (_, exchange, _) => ReferenceEquals(exchange, warmBackup) ? Task.FromException(new IOException("backup offline")) : Task.CompletedTask))
            {
                await pool.Warmup();
                var state = System.Text.Json.JsonSerializer.SerializeToNode(pool.State)!;
                Check("Failed inactive backup does not leave a false error on a healthy route", state["error"]!.GetValue<string>() == "" && state["routes"]!.AsArray().All(r => r!["error"]!.GetValue<string>() == ""));
            }
            int healthCalls = 0;
            using (var pool = new DnsFailover(choices.Take(1), _ => new Fake(), async (_, _, ct) =>
            {
                Interlocked.Increment(ref healthCalls); await Task.Delay(30, ct); throw new AiProbeFailure("region", "blocked");
            }))
            {
                await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => pool.Query(q, default)));
                Check("Concurrent denied queries perform only one provider probe", healthCalls == 1);
                var evidence = System.Text.Json.JsonSerializer.SerializeToNode(pool.State)!;
                Check("Observed DNS queries do not claim real application access", evidence["observedQueries"]!.GetValue<long>() == 20 && evidence["applicationAccess"]!.GetValue<string>() == "НЕ ПРОВЕРЕНО");
            }
            using (var pool = new DnsFailover(choices, s => s.address == choices[0].address ? first : second, (group, exchange, _) =>
            {
                if (group == "gemini.google.com" && ReferenceEquals(exchange, first)) throw new IOException("region blocked");
                return Task.CompletedTask;
            }))
            {
                await pool.Query(DnsWire.Query("gemini.google.com"), default);
                await pool.Query(q, default);
                Check("Gemini can fail over independently of ChatGPT", first.Calls == 1 && second.Calls == 1);
            }
            using (var pool = new DnsFailover(choices, _ => new Fake(), (_, _, _) => throw new IOException("all offline")))
            {
                bool rejected = false; try { await pool.Warmup(); } catch (IOException) { rejected = true; }
                Check("No available service is detected before installing Windows rules", rejected);
            }
            first = new Fake { Reply = x => Answer(x, 3) }; second = new Fake();
            using (var pool = Pool(first, second)) Check("Valid NXDOMAIN is returned without provider hopping", ((await pool.Query(q, default))[3] & 15) == 3 && second.Calls == 0);
            first = new Fake { Reply = x => Answer(x, 2) }; second = new Fake { Reply = _ => throw new IOException("offline") };
            using (var pool = Pool(first, second))
            {
                Check("All failed endpoints produce SERVFAIL", ((await pool.Query(q, default))[3] & 15) == 2);
                await pool.Query(q, default); Check("Failed endpoints use cooldown", first.Calls == 1 && second.Calls == 1);
            }
            first = new Fake(); using (var pool = Pool(first))
            {
                using var cancel = new CancellationTokenSource(); cancel.Cancel();
                bool cancelled = false; try { await pool.Query(q, cancel.Token); } catch (OperationCanceledException) { cancelled = true; }
                Check("Shutdown cancellation is respected", cancelled && first.Calls == 0);
            }
            first = new Fake { Reply = x => Answer(x, v6: DnsWire.U16(x, x.Length - 4) == 28) };
            using (var relay = new AiDnsRelay(Pool(first), IPAddress.Loopback, 0))
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var udp = new UdpClient(AddressFamily.InterNetwork); udp.Connect(IPAddress.Loopback, relay.Port);
                var v6q = DnsWire.Query("gemini.google.com", 28); await udp.SendAsync(v6q, timeout.Token);
                var packet = await udp.ReceiveAsync(timeout.Token);
                Check("IPv6 questions are routed through the same relay", DnsWire.Addresses(v6q, packet.Buffer).Single().AddressFamily == AddressFamily.InterNetworkV6);
                using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, relay.Port, timeout.Token);
                for (int i = 0; i < 2; i++)
                {
                    var len = new byte[2]; DnsWire.Put(len, 0, (ushort)q.Length); var stream = tcp.GetStream();
                    await stream.WriteAsync(len, timeout.Token); await stream.WriteAsync(q, timeout.Token);
                    await stream.ReadExactlyAsync(len, timeout.Token); var answer = new byte[DnsWire.U16(len, 0)]; await stream.ReadExactlyAsync(answer, timeout.Token);
                    Check("TCP query " + (i + 1) + " on reused connection", DnsWire.Reply(q, answer));
                }
            }
            int installs = 0, removes = 0;
            using (var runtime = new AiDnsRuntime(_ => installs++, _ => removes++, _ => null, IPAddress.Loopback, 0, _ => { }))
            {
                runtime.Start(new[] { AiDns.DnsAiPrimary() }); Check("Runtime installs rule after binding listener", runtime.Running && installs == 1);
                runtime.Stop(); Check("Disable removes rule and closes listener", !runtime.Running && removes == 1);
                runtime.Stop(); Check("Repeated disable is idempotent", removes == 1);
                runtime.Start(new[] { AiDns.DnsAiPrimary() }); runtime.Stop(); Check("Enable after disable", installs == 2 && removes == 2);
            }
            removes = 0;
            int deniedInstall = 0;
            var occupied = new TcpListener(IPAddress.Loopback, 0); occupied.Start();
            int occupiedPort = ((IPEndPoint)occupied.LocalEndpoint).Port;
            using (var runtime = new AiDnsRuntime(_ => deniedInstall++, _ => { }, _ => null, IPAddress.Loopback, occupiedPort, _ => { }))
            {
                bool rejected = false; try { runtime.Start(new[] { AiDns.DnsAiPrimary() }); } catch (SocketException) { rejected = true; }
                Check("Busy listener port does not install any DNS policy", rejected && deniedInstall == 0 && !runtime.Running);
                occupied.Stop();
                runtime.Start(new[] { AiDns.DnsAiPrimary() }); runtime.Stop();
                Check("Failed bind releases UDP socket for retry", deniedInstall == 1 && !runtime.Running);
            }
            using (var runtime = new AiDnsRuntime(_ => throw new IOException("policy denied"), _ => removes++, _ => null, IPAddress.Loopback, 0, _ => { }))
            {
                try { runtime.Start(new[] { AiDns.DnsAiPrimary() }); } catch (IOException) { }
                Check("Failed rule installation rolls back listener and rule", !runtime.Running && removes == 1);
            }
            bool refuse = true;
            using (var runtime = new AiDnsRuntime(_ => { }, _ => { if (refuse) throw new IOException("busy"); }, _ => null, IPAddress.Loopback, 0, _ => { }))
            {
                runtime.Start(new[] { AiDns.DnsAiPrimary() });
                try { runtime.Stop(); } catch (IOException) { }
                Check("Failed cleanup keeps DNS listener alive", runtime.Running);
                refuse = false; runtime.Stop(); Check("Cleanup can be retried", !runtime.Running);
            }
        }
        try { Tests().GetAwaiter().GetResult(); } catch (Exception e) { lines.Add("FAIL unhandled: " + e); fails++; }
        lines.Add("Failures: " + fails);
        File.WriteAllLines(report, lines, new UTF8Encoding(false));
        return fails == 0 ? 0 : 1;
    }
}
