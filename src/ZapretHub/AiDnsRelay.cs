using System.Net;
using System.Net.Sockets;

namespace ZapretHub;

internal interface IDnsExchange : IDisposable
{
    Task<byte[]> Query(byte[] query, CancellationToken ct);
}

internal sealed class DnsExchange : IDnsExchange
{
    internal sealed record Response(byte[] Wire, string Transport, string Version, string Source);
    private readonly DnsServer _server;
    private HttpClient? _http;
    private readonly object _clientSync = new();
    private long _clientNetwork;
    private bool _disposed;
    private readonly Func<HttpClient>? _testClient;
    private int _plaintextFallback;
    internal string HttpVersion { get; private set; } = "Не проверено";
    private sealed class Trace { internal string Stage = "DoH HTTP"; internal string Source = ""; }
    private static readonly HttpRequestOptionsKey<Trace> TraceKey = new("AiDnsTrace");
    internal bool HadPlaintextFallback => Volatile.Read(ref _plaintextFallback) != 0;
    internal DnsExchange(DnsServer server, Func<HttpClient>? testClient = null)
    {
        AiDns.Validate(server, false, "AI DNS");
        _server = server.Clone();
        _testClient = testClient;
        if (!server.doh) return;
        _clientNetwork = AiNetwork.Generation;
        _http = CreateClient();
    }
    private HttpClient CreateClient()
    {
        if (_testClient is not null) return _testClient();
        var handler = new SocketsHttpHandler
        {
            UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(3),
            PooledConnectionLifetime = TimeSpan.FromMinutes(3),
            PlaintextStreamFilter = (context, ct) =>
            {
                if (context.InitialRequestMessage.Options.TryGetValue(TraceKey, out var trace)) trace.Stage = "DoH HTTP";
                return ValueTask.FromResult(context.PlaintextStream);
            },
            ConnectCallback = async (context, ct) =>
            {
                context.InitialRequestMessage.Options.TryGetValue(TraceKey, out var trace);
                if (trace is not null) trace.Stage = "DoH TCP";
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try { await socket.ConnectAsync(IPAddress.Parse(_server.address), context.DnsEndPoint.Port, ct); if (trace is not null) { trace.Source = (socket.LocalEndPoint as IPEndPoint)?.Address.ToString() ?? ""; trace.Stage = "DoH TLS"; } return new NetworkStream(socket, true); }
                catch (Exception e) { socket.Dispose(); e.Data["AiDnsStage"] = "DoH TCP connect " + _server.address + ":" + context.DnsEndPoint.Port + " (connect limit 3s; check limit 8s)"; throw; }
            },
        };
        return new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
    }
    internal void RefreshNetwork()
    {
        long network = AiNetwork.Generation;
        lock (_clientSync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_http is not null && _clientNetwork != network)
            {
                _http.Dispose(); _http = CreateClient(); _clientNetwork = network;
                HttpVersion = "Не проверено"; Interlocked.Exchange(ref _plaintextFallback, 0);
            }
        }
    }
    public async Task<byte[]> Query(byte[] query, CancellationToken ct) => (await QueryObserved(query, ct)).Wire;
    internal async Task<Response> QueryObserved(byte[] query, CancellationToken ct)
    {
        RefreshNetwork();
        var http = _http;
        if (http is not null)
        {
            var trace = new Trace();
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, _server.template)
                {
                    Content = new ByteArrayContent(query),
                    Version = System.Net.HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
                };
                request.Options.Set(TraceKey, trace);
                request.Content.Headers.ContentType = new("application/dns-message"); request.Headers.Accept.ParseAdd("application/dns-message");
                using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                HttpVersion = "HTTP/" + response.Version;
                response.EnsureSuccessStatusCode();
                if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/dns-message", StringComparison.OrdinalIgnoreCase))
                    throw new IOException("DoH вернул неверный тип ответа");
                using var stream = await response.Content.ReadAsStreamAsync(ct);
                using var ms = new MemoryStream();
                var buffer = new byte[4096]; int n;
                while ((n = await stream.ReadAsync(buffer, ct)) > 0)
                {
                    if (ms.Length + n > 65535) throw new IOException("Слишком большой ответ DoH");
                    ms.Write(buffer, 0, n);
                }
                var bytes = ms.ToArray();
                if (!DnsWire.Reply(query, bytes) || (bytes[2] & 2) != 0) throw new IOException("Некорректный ответ DoH");
                return new(bytes, "DoH", "HTTP/" + response.Version, trace.Source);
            }
            catch (Exception e)
            {
                AiProbeFailure.At(e, trace.Stage, _server.address + ":" + new Uri(_server.template).Port);
                if (!_server.fallback || ct.IsCancellationRequested) throw;
                Interlocked.Exchange(ref _plaintextFallback, 1);
                Log.Warn("AI DNS " + _server.address + ": DoH -> UDP fallback: " + AiProbeFailure.Classify("DNS/DoH", e).Message);
            }
        }
        try
        {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(_server.address, 53);
        await udp.SendAsync(query, ct);
        var packet = await udp.ReceiveAsync(ct);
        if (packet.Buffer.Length >= 12 && (packet.Buffer[2] & 2) != 0)
        {
            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            await tcp.ConnectAsync(IPAddress.Parse(_server.address), 53, ct);
            using var stream = tcp.GetStream();
            var size = new byte[2]; DnsWire.Put(size, 0, (ushort)query.Length);
            await stream.WriteAsync(size, ct); await stream.WriteAsync(query, ct);
            await stream.ReadExactlyAsync(size, ct);
            var answer = new byte[DnsWire.U16(size, 0)]; await stream.ReadExactlyAsync(answer, ct);
            if (!DnsWire.Reply(query, answer)) throw new IOException("Некорректный ответ DNS TCP");
            return new(answer, http is null ? "TCP" : "TCP fallback", "", (tcp.Client.LocalEndPoint as IPEndPoint)?.Address.ToString() ?? "");
        }
        if (!DnsWire.Reply(query, packet.Buffer)) throw new IOException("Некорректный ответ DNS UDP");
        return new(packet.Buffer, http is null ? "UDP" : "UDP fallback", "", (udp.Client.LocalEndPoint as IPEndPoint)?.Address.ToString() ?? "");
        }
        catch (Exception e) { throw AiProbeFailure.At(e, "DNS UDP/TCP", _server.address + ":53"); }
    }
    public void Dispose() { lock (_clientSync) { _disposed=true; _http?.Dispose(); } }
}

internal sealed class DnsFailover : IDisposable
{
    private sealed class Route
    {
        internal int Active;
        internal string Error = "";
        internal long Queries;
        internal string LastHost = "";
        internal readonly string[] LastSuccess;
        internal string Reason = "Ещё не выбран";
        internal readonly long[] Retry, Checked;
        internal readonly Exception?[] Failures;
        internal readonly SemaphoreSlim[] Gates;
        internal Route(int count) { Retry = new long[count]; Checked = new long[count]; Failures = new Exception?[count]; LastSuccess = new string[count]; Gates = Enumerable.Range(0, count).Select(_ => new SemaphoreSlim(1)).ToArray(); }
    }
    private readonly (DnsServer server, IDnsExchange exchange)[] _servers;
    private readonly Dictionary<string, Route> _routes = new();
    private readonly Func<string, IDnsExchange, CancellationToken, Task> _health;
    private readonly Func<string, bool> _allowed;
    private readonly Func<string, string> _group;
    private readonly object _sync = new();
    private int _active;
    private string _error = "";
    private readonly IReadOnlyDictionary<string, string[]>? _plan;
    private readonly SemaphoreSlim _healthGate = new(3);
    private long _network = AiNetwork.Generation;
    private readonly Queue<object> _events = new();
    internal DnsFailover(IEnumerable<DnsServer> servers, Func<DnsServer, IDnsExchange>? factory = null, Func<string, IDnsExchange, CancellationToken, Task>? health = null, Func<string, bool>? allowed = null, Func<string, string>? group = null, IReadOnlyDictionary<string, string[]>? plan = null, AiDnsMonitor? monitor = null)
    {
        _servers = servers.Select(s => (s.Clone(), (factory ?? (x => new DnsExchange(x)))(s))).ToArray();
        if (_servers.Length == 0) throw new ArgumentException("Нет DNS-серверов");
        _health = health ?? (monitor is null ? AiServiceProbe.CheckCore : (h, e, ct) => monitor.Check(h, _servers.First(x => ReferenceEquals(x.exchange, e)).server, e, ct));
        _allowed = allowed ?? AiDnsPolicy.IsAiHost; _group = group ?? AiServiceProbe.Group;
        _plan = plan;
    }
    internal object State { get { lock (_sync) return new { address = _servers[_active].server.address, error = _error, network = _network, events = _events.ToArray(), applicationAccess = "НЕ ПРОВЕРЕНО", observedQueries = _routes.Values.Sum(x => x.Queries), routes = _routes.Select(x => new { service = x.Key, address = x.Value.LastSuccess[x.Value.Active] is not null ? _servers[x.Value.Active].server.address : "", key = AiDnsCatalog.Key(_servers[x.Value.Active].server), reason = x.Value.Reason, lastSuccess = x.Value.LastSuccess[x.Value.Active], next = Order(x.Key).Where(i => i != x.Value.Active && x.Value.Retry[i] <= Environment.TickCount64).Select(i => _servers[i].server.address).FirstOrDefault(), error = x.Value.Error, observedQueries = x.Value.Queries, lastHost = x.Value.LastHost, plaintextFallbackObserved = (_servers[x.Value.Active].exchange as DnsExchange)?.HadPlaintextFallback == true, candidates = Order(x.Key).Select(i => new { address = _servers[i].server.address, error = x.Value.Failures[i]?.Message, kind = (x.Value.Failures[i] as AiProbeFailure)?.Kind, stage = (x.Value.Failures[i] as AiProbeFailure)?.Stage, lastSuccess = x.Value.LastSuccess[i] }).ToArray() }).ToArray() }; } }
    private int[] Order(string group)
    {
        if (_plan is null) return Enumerable.Range(0, _servers.Length).ToArray();
        var keys = _plan.TryGetValue(group, out var selected) ? selected : _plan["chatgpt.com"];
        return keys.Select(k => Array.FindIndex(_servers, s => AiDnsCatalog.Key(s.server) == k)).Where(i => i >= 0).Distinct().ToArray();
    }
    internal void InvalidateNetwork()
    {
        lock (_sync)
        {
            _network = AiNetwork.Generation;
            foreach (var route in _routes.Values) { Array.Clear(route.Checked); Array.Clear(route.Retry); Array.Clear(route.Failures); route.Reason = "Сеть изменилась: прежняя проверка недействительна"; }
        }
    }
    private void CheckNetwork() { if (_network != AiNetwork.Generation) InvalidateNetwork(); }
    private void Selected(int i, string group, Route route)
    {
        string reason = route.Active == i ? "DNS и HTTPS проверены; первый доступный в порядке выбора" : "Переключение после отказа предыдущего: " + route.Error;
        if (route.Active != i || route.Reason == "Ещё не выбран") { _events.Enqueue(new { utc = DateTime.UtcNow, service = group, address = _servers[i].server.address, reason }); while (_events.Count > 30) _events.Dequeue(); }
        route.Active = _active = i; route.Reason = reason; route.Error = "";
    }
    private Route GetRoute(string group) { lock (_sync) { if (!_routes.TryGetValue(group, out var route)) _routes[group] = route = new Route(_servers.Length); return route; } }
    private void Failed(int i, string group, Route route, Exception error)
    {
        error = error as AiProbeFailure ?? AiProbeFailure.Classify("DNS/DoH", error);
        lock (_sync)
        {
            // Waiting clients must not extend the cooldown or launch another probe of the same failed endpoint.
            if (route.Retry[i] > Environment.TickCount64) return;
            route.Retry[i] = Environment.TickCount64 + AiProbeFailure.Cooldown(error);
            route.Checked[i] = 0; route.Failures[i] = error;
            route.Error = _error = group + " · " + _servers[i].server.address + " [" + (error as AiProbeFailure)?.Kind + "]: " + error.Message;
            Log.Warn("AI DNS: " + route.Error);
        }
    }
    private async Task Healthy(int i, string group, Route route, CancellationToken ct)
    {
        long network = 0;
        await route.Gates[i].WaitAsync(ct);
        try
        {
            CheckNetwork(); network = _network;
            lock (_sync)
            {
                if (route.Retry[i] > Environment.TickCount64) throw route.Failures[i] ?? new IOException("DNS временно исключён");
                if (route.Checked[i] > Environment.TickCount64) return;
            }
            await _healthGate.WaitAsync(ct);
            try { await AiProbeFailure.WithinDeadline(token => _health(group, _servers[i].exchange, token), ct); }
            finally { _healthGate.Release(); }
            if (network != AiNetwork.Generation) throw new AiProbeFailure("network", "Сеть изменилась во время проверки; требуется новая проверка");
            lock (_sync) { route.Checked[i] = Environment.TickCount64 + 120_000; route.LastSuccess[i] = DateTime.UtcNow.ToString("O"); route.Retry[i] = 0; route.Failures[i] = null; }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception e) { if (network == AiNetwork.Generation) Failed(i, group, route, e); throw; }
        finally { route.Gates[i].Release(); }
    }
    internal async Task Warmup(CancellationToken ct = default)
    {
        var errors = new List<string>();
        await Task.WhenAll(new[] { "chatgpt.com", "gemini.google.com" }.Select(async group =>
        {
            var route = GetRoute(group);
            var order = Order(group);
            var checks = order.Select(async i =>
            {
                try
                {
                    await Healthy(i, group, route, ct); return true;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch { return false; }
            }).ToArray();
            var results = await Task.WhenAll(checks);
            int first = Array.FindIndex(results, x => x);
            lock (_sync)
            {
                if (first >= 0) { Selected(order[first], group, route); }
                else
                {
                    var kinds = route.Failures.Select(e => (e as AiProbeFailure)?.Kind ?? "connection").Distinct();
                    route.Error = "Нет подтверждённого маршрута к " + group + " (" + string.Join(", ", kinds) + "); подробности в журнале";
                    _error = route.Error; errors.Add(route.Error);
                }
            }
        }));
        lock (_sync) _error = string.Join("; ", _routes.Values.Select(x => x.Error).Where(x => x.Length > 0));
        if (errors.Count == 2) throw new IOException(string.Join("; ", errors) + ". Настройки DNS сети не изменены. Проверьте доступность провайдера DNS и маршрут VPN.");
    }
    internal async Task<byte[]> Query(byte[] query, CancellationToken ct)
    {
        if (!DnsWire.Question(query, out var host, out _)) return DnsWire.Error(query, 1);
        CheckNetwork();
        if (!_allowed(host)) return DnsWire.Error(query, 5);
        string group = _group(host); var route = GetRoute(group);
        int active; lock (_sync)
        {
            active = route.Active; route.Queries++; route.LastHost = host;
            if (route.Queries == 1) Log.Info("AI DNS: получен DNS-запрос " + host + "; использование конкретным браузером НЕ ПРОВЕРЕНО");
        }
        var available = Order(group);
        var order = available.Contains(active) ? new[] { active }.Concat(available.Where(i => i != active)).ToArray() : available;
        // A known failing endpoint is retried after a cooldown; it cannot delay every browser query.
        foreach (int i in order)
        {
            lock (_sync) { if (route.Retry[i] > Environment.TickCount64) continue; }
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                await Healthy(i, group, route, ct);
                timeout.CancelAfter(AiProbeFailure.Timeout);
                var reply = await _servers[i].exchange.Query(query, timeout.Token);
                if (!DnsWire.Reply(query, reply) || (reply[3] & 15) is 2 or 5) throw new IOException("Сервер не разрешил запрос");
                if (DnsWire.Addresses(query, reply).Any(ip => IPAddress.Any.Equals(ip) || IPAddress.IPv6Any.Equals(ip) || IPAddress.IsLoopback(ip)))
                    throw new IOException("DNS вернул заблокированный адрес");
                lock (_sync) { if (route.Retry[i] <= Environment.TickCount64) { Selected(i, group, route); _error = string.Join("; ", _routes.Values.Select(x => x.Error).Where(x => x.Length > 0)); route.Retry[i] = 0; } }
                return reply;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception e)
            {
                Failed(i, group, route, e is OperationCanceledException ? AiProbeFailure.Classify("DNS/DoH", e) : e);
            }
        }
        return DnsWire.Error(query, 2);
    }
    public void Dispose() { foreach (var s in _servers) s.exchange.Dispose(); }
}

internal sealed class AiDnsRelay : IDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly SemaphoreSlim _slots = new(64);
    private readonly UdpClient _udp;
    private readonly TcpListener _tcp;
    private readonly DnsFailover _upstreams;
    private readonly List<Task> _loops = new();
    internal bool Running => _loops.Count == 2 && _loops.All(t => !t.IsCompleted);
    internal Task Completion => Task.WhenAny(_loops);
    internal string Failure => _loops.FirstOrDefault(t => t.IsFaulted)?.Exception?.GetBaseException().GetType().Name ?? "Цикл приёма завершился";
    internal static bool Transient(SocketError error) => error is SocketError.ConnectionReset or SocketError.ConnectionRefused or SocketError.NetworkReset or SocketError.NetworkDown or SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.Interrupted or SocketError.NoBufferSpaceAvailable or SocketError.TimedOut;
    internal int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
    internal object State => _upstreams.State;
    internal AiDnsRelay(DnsFailover upstreams, IPAddress address, int port = 53)
    {
        _upstreams = upstreams;
        _udp = new UdpClient(AddressFamily.InterNetwork);
        _udp.Client.ExclusiveAddressUse = true;
        try
        {
            _udp.Client.Bind(new IPEndPoint(address, port));
            // Windows reports ICMP from an already closed DNS client on the next
            // receive. This must not terminate the shared UDP listener.
            if (OperatingSystem.IsWindows()) _udp.Client.IOControl(unchecked((IOControlCode)0x9800000C), new byte[4], null);
            _tcp = new TcpListener(address, Port); _tcp.Server.ExclusiveAddressUse = true; _tcp.Start(64);
        }
        catch { _udp.Dispose(); _tcp?.Stop(); throw; }
        _loops.Add(UdpLoop()); _loops.Add(TcpLoop());
    }
    private async Task UdpLoop()
    {
        long nextLog = 0;
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                UdpReceiveResult packet;
                try { packet = await _udp.ReceiveAsync(_stop.Token); }
                catch (SocketException e) when (Transient(e.SocketErrorCode) && !_stop.IsCancellationRequested)
                {
                    if (Environment.TickCount64 >= nextLog) { Log.Warn("AI DNS UDP: временная ошибка " + e.SocketErrorCode + "; listener сохранён"); nextLog=Environment.TickCount64+30_000; }
                    await Task.Delay(250, _stop.Token); continue;
                }
                if (!_slots.Wait(0)) continue;
                _ = HandleUdp(packet);
            }
        }
        catch (Exception) when (_stop.IsCancellationRequested) { }
    }
    private async Task HandleUdp(UdpReceiveResult packet)
    {
        try
        {
            var reply = await _upstreams.Query(packet.Buffer, _stop.Token);
            if (reply.Length > 512) { reply = DnsWire.Error(packet.Buffer, 0); reply[2] |= 2; }
            await _udp.SendAsync(reply, packet.RemoteEndPoint, _stop.Token);
        }
        catch (Exception) { }
        finally { _slots.Release(); }
    }
    private async Task TcpLoop()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _tcp.AcceptTcpClientAsync(_stop.Token);
                if (!_slots.Wait(0)) { client.Dispose(); continue; }
                _ = HandleTcp(client);
            }
        }
        catch (Exception) when (_stop.IsCancellationRequested) { }
    }
    private async Task HandleTcp(TcpClient client)
    {
        try
        {
            using (client)
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token))
            {
                timeout.CancelAfter(TimeSpan.FromSeconds(30));
                var stream = client.GetStream(); var size = new byte[2];
                // Windows may reuse a TCP connection for more than one DNS query.
                while (!timeout.IsCancellationRequested)
                {
                    await stream.ReadExactlyAsync(size, timeout.Token);
                    int len = DnsWire.U16(size, 0); if (len < 12) break;
                    var query = new byte[len]; await stream.ReadExactlyAsync(query, timeout.Token);
                    var reply = await _upstreams.Query(query, timeout.Token);
                    DnsWire.Put(size, 0, (ushort)reply.Length); await stream.WriteAsync(size, timeout.Token); await stream.WriteAsync(reply, timeout.Token);
                }
            }
        }
        catch (Exception) { }
        finally { _slots.Release(); }
    }
    public void Dispose()
    {
        _stop.Cancel(); _udp.Dispose(); _tcp.Stop();
        try { Task.WaitAll(_loops.ToArray(), 2000); } catch { }
        // In-flight requests own linked cancellation tokens; shared state stays alive until they finish.
        _upstreams.Dispose();
    }
}
