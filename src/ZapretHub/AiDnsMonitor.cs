using System.Text.Json;

namespace ZapretHub;

internal sealed class AiProbeObservation
{
    public string key { get; set; } = "";
    public string address { get; set; } = "";
    public string service { get; set; } = "";
    public string stage { get; set; } = "Не проверено";
    public string error { get; set; } = "";
    public string kind { get; set; } = "";
    public string target { get; set; } = "";
    public string httpVersion { get; set; } = "Не проверено";
    public string smart { get; set; } = "Не установлено";
    public string dnsTransport { get; set; } = "Не проверено";
    public string dnsSource { get; set; } = "";
    public string httpsSource { get; set; } = "";
    public int httpStatus { get; set; }
    public string accessState { get; set; } = "Не проверено";
    public string[] ipv4 { get; set; } = Array.Empty<string>();
    public string[] ipv6 { get; set; } = Array.Empty<string>();
    public string ipv6Status { get; set; } = "Не проверено";
    public long dnsMs { get; set; }
    public bool dns { get; set; }
    public bool https { get; set; }
    public bool fallback { get; set; }
    public string checkedAt { get; set; } = "";
    public string lastSuccess { get; set; } = "";
    public long network { get; set; }
    public string applicationAccess { get; set; } = "НЕ ПРОВЕРЕНО";
}

internal sealed class AiDnsMonitor
{
    private readonly object _sync = new();
    private readonly Dictionary<string, AiProbeObservation> _results = new();
    private CancellationTokenSource? _checks;
    private bool _checking;
    private int _done, _total;
    private readonly SemaphoreSlim _gate = new(3);
    private readonly Func<DnsServer, IDnsExchange> _factory;
    private readonly Func<string, IDnsExchange, CancellationToken, Task>? _testCheck;
    private readonly Dictionary<string, string[]> _baseline = new();
    private long _baselineNetwork;
    internal AiDnsMonitor(Func<DnsServer, IDnsExchange>? factory = null, Func<string, IDnsExchange, CancellationToken, Task>? testCheck = null)
    { _factory = factory ?? (s => new DnsExchange(s)); _testCheck = testCheck; }
    internal object State { get { lock (_sync) return new { checking = _checking, done = _done, total = _total, network = AiNetwork.Generation, results = _results.Values.ToArray() }; } }
    internal async Task Check(string host, DnsServer server, IDnsExchange exchange, CancellationToken ct)
    {
        var result = new AiProbeObservation { key = AiDnsCatalog.Key(server), address = server.address, service = host, network = AiNetwork.Generation };
        Exception? failed = null;
        try { await AiProbeFailure.WithinDeadline(token => _testCheck is null ? AiServiceProbe.CheckObserved(host, exchange, token, result) : _testCheck(host, exchange, token), ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception e)
        {
            var error = AiProbeFailure.Classify(result.dns ? "HTTPS" : "DNS/DoH", e);
            result.error = error.Message; result.kind = error.Kind; result.stage = error.Stage;
            result.target = error.Target; failed = error;
        }
        if (!result.dns && exchange is DnsExchange actual) result.httpVersion = actual.HttpVersion;
        // Same address for different unrelated services is a hint, never proof of a foreign exit.
        lock (_sync) result.smart = result.ipv4.Length == 0 ? "Нет A-ответа" : _baselineNetwork != result.network || !_baseline.TryGetValue(host, out var baseline) || baseline.Length == 0 ? "Нет эталона; тип ответа не установлен" : result.ipv4.ToHashSet().SetEquals(baseline) ? "Совпадает с обычным DNS; прокси не доказан" : "Отличается от обычного DNS; возможен прокси, не доказано";
        result.checkedAt = DateTime.UtcNow.ToString("O");
        if (result.https) result.lastSuccess = result.checkedAt;
        lock (_sync)
        {
            string id = result.key + "|" + host;
            if (_results.TryGetValue(id, out var old) && result.lastSuccess.Length == 0) result.lastSuccess = old.lastSuccess;
            _results[id] = result;
        }
        if (failed is not null) throw failed;
    }
    internal void Start(IEnumerable<DnsServer> servers)
    {
        CancellationTokenSource cts;
        lock (_sync)
        {
            if (_checking) throw new InvalidOperationException("Проверка уже выполняется; дождитесь завершения или отмените её");
            _checks?.Dispose(); cts = _checks = new(); _checking = true; _done = 0;
            _total = servers.Count() * 2;
        }
        _ = Task.Run(async () =>
        {
            try
            {
                if (_testCheck is null) await Baseline(cts.Token);
                await Task.WhenAll(servers.SelectMany(s => new[] { "chatgpt.com", "gemini.google.com" }.Select(async host =>
                {
                    await _gate.WaitAsync(cts.Token);
                    try
                    {
                        using var exchange = _factory(s);
                        try { await Check(host, s, exchange, cts.Token); } catch (OperationCanceledException) { throw; } catch { }
                        // AAAA is diagnostic only. It never vetoes a successful IPv4 health check.
                        using var ipv6 = CancellationTokenSource.CreateLinkedTokenSource(cts.Token); ipv6.CancelAfter(3000);
                        try
                        {
                            var q = DnsWire.Query(host, 28); var reply = await exchange.Query(q, ipv6.Token);
                            lock (_sync) if (_results.TryGetValue(AiDnsCatalog.Key(s) + "|" + host, out var result)) { result.ipv6 = DnsWire.Addresses(q, reply).Select(ip => ip.ToString()).ToArray(); result.ipv6Status = (reply[3] & 15) == 0 ? result.ipv6.Length == 0 ? "Пустой ответ AAAA (NOERROR)" : "Ответ получен" : "DNS RCODE " + (reply[3] & 15); }
                        }
                        catch (Exception e) { lock (_sync) if (_results.TryGetValue(AiDnsCatalog.Key(s) + "|" + host, out var result)) result.ipv6Status = cts.IsCancellationRequested ? "Отменено" : "Ошибка AAAA: " + AiProbeFailure.Classify("DNS AAAA", e).Kind; }
                    }
                    finally { _gate.Release(); lock (_sync) _done++; }
                })));
            }
            catch (OperationCanceledException) { }
            catch (Exception e) { Log.Warn("AI DNS проверка: " + e.Message); }
            finally { lock (_sync) _checking = false; }
        });
    }
    internal void Cancel() { lock (_sync) _checks?.Cancel(); }
    private async Task Baseline(CancellationToken ct)
    {
        long network = AiNetwork.Generation;
        using var ordinary = new DnsExchange(new() { address="1.1.1.1", doh=true, template="https://cloudflare-dns.com/dns-query" });
        await Task.WhenAll(new[]{"chatgpt.com","gemini.google.com"}.Select(async host =>
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(3000);
            try { var q=DnsWire.Query(host); var reply=await ordinary.Query(q,deadline.Token); lock(_sync){ _baseline[host]=DnsWire.Addresses(q,reply).Select(a=>a.ToString()).ToArray();_baselineNetwork=network; } }
            catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
            catch { lock(_sync) { _baseline[host]=Array.Empty<string>();_baselineNetwork=network; } }
        }));
    }
    internal object Export(object? runtime, AiCfg cfg)
    {
        string SafeIp(string value) => System.Net.IPAddress.TryParse(value, out var ip) && !Net.Bogus(ip) && !ip.IsIPv6LinkLocal && (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6 || (ip.GetAddressBytes()[0] & 0xfe) != 0xfc) ? value : "[внутренний адрес скрыт]";
        var state = JsonSerializer.SerializeToNode(runtime);
        long network = AiNetwork.Generation;
        lock (_sync) return new {
            utc = DateTime.UtcNow, mode = cfg.selectionMode, network = AiNetwork.SafeSnapshot(network),
            observedQueries = state?["observedQueries"]?.GetValue<long>() ?? 0,
            selectedRoutes = state?["routes"]?.AsArray().Select(r => new { service = r?["service"]?.ToString(), address = SafeIp(r?["address"]?.ToString() ?? ""), lastSuccess = r?["lastSuccess"]?.ToString(), currentNetwork = state?["network"]?.GetValue<long>() == network }).ToArray(),
            events = state?["events"]?.AsArray().Select(e => new { utc = e?["utc"]?.ToString(), service = e?["service"]?.ToString(), address = SafeIp(e?["address"]?.ToString() ?? "") }).ToArray(),
            applicationAccess = "НЕ ПРОВЕРЕНО", results = _results.Values.Select(x => new {
                provider = SafeIp(x.address), x.service, x.stage, x.kind, x.dns, x.dnsMs, ipv4 = x.ipv4.Select(SafeIp).ToArray(), ipv6 = x.ipv6.Select(SafeIp).ToArray(), x.ipv6Status, x.httpVersion, x.dnsTransport, x.https, x.httpStatus, x.accessState, x.fallback, x.checkedAt, x.smart,
                currentNetwork = x.network == network,
            }).ToArray(),
            note = "Без cookies, токенов, настроек, внутренних DNS и имён. HTTPS не доказывает работу ИИ в браузере."
        };
    }
    internal static int Diagnose(string path)
    {
        var monitor = new AiDnsMonitor(); var cfg = AiDnsCatalog.Normalize(AiDns.DefaultConfig());
        monitor.Start(AiDnsCatalog.Candidates(cfg));
        long until = Environment.TickCount64 + 120_000;
        while (System.Text.Json.JsonSerializer.SerializeToNode(monitor.State)?["checking"]?.GetValue<bool>() == true && Environment.TickCount64 < until) Thread.Sleep(100);
        monitor.Cancel();
        File.WriteAllText(path, JsonSerializer.Serialize(monitor.Export(null, cfg), Json.Indented));
        return 0;
    }
}
