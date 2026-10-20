using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ZapretHub;

/// <summary>AES-256-CTR (счётчик — 128-бит big-endian), как в cryptography.hazmat modes.CTR.</summary>
internal sealed class AesCtr : IDisposable
{
    private readonly ICryptoTransform _ecb;
    private readonly byte[] _counter = new byte[16];
    private byte[] _ks = new byte[16];
    private int _ksPos = 16;

    public AesCtr(byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key;
        _ecb = aes.CreateEncryptor();
        Array.Copy(iv, _counter, 16);
    }

    private void Increment()
    {
        for (int i = 15; i >= 0; i--) if (++_counter[i] != 0) break;
    }

    public byte[] Update(ReadOnlySpan<byte> data)
    {
        var res = new byte[data.Length];
        int pos = 0;
        while (pos < data.Length && _ksPos < 16) { res[pos] = (byte)(data[pos] ^ _ks[_ksPos++]); pos++; }
        int remaining = data.Length - pos;
        if (remaining > 0)
        {
            int blocks = (remaining + 15) / 16;
            var ctrs = new byte[blocks * 16];
            for (int b = 0; b < blocks; b++) { Array.Copy(_counter, 0, ctrs, b * 16, 16); Increment(); }
            var ks = new byte[blocks * 16];
            _ecb.TransformBlock(ctrs, 0, ctrs.Length, ks, 0);
            for (int i = 0; i < remaining; i++) res[pos + i] = (byte)(data[pos + i] ^ ks[i]);
            int used = remaining % 16;
            if (used != 0) { _ks = ks[^16..]; _ksPos = used; }
            else _ksPos = 16;
        }
        return res;
    }

    public void Dispose() => _ecb.Dispose();
}

internal sealed class CryptoCtx : IDisposable
{
    public AesCtr CltDec = null!, CltEnc = null!, TgEnc = null!, TgDec = null!;
    public void Dispose() { CltDec?.Dispose(); CltEnc?.Dispose(); TgEnc?.Dispose(); TgDec?.Dispose(); }
}

/// <summary>WebSocket поверх TLS: рукопожатие и кадры вручную (нужен SNI, отличный от Host, и подключение по IP).</summary>
internal sealed class RawWs : IDisposable
{
    private readonly Stream _stream;
    private readonly TcpClient _tcp;
    private readonly SemaphoreSlim _wlock = new(1, 1);
    private readonly List<byte> _frag = new();
    public bool Closed { get; private set; }
    public DateTime Created = DateTime.UtcNow;

    private RawWs(TcpClient tcp, Stream s) { _tcp = tcp; _stream = s; }

    public int LocalPort => (_tcp.Client.LocalEndPoint as System.Net.IPEndPoint)?.Port ?? 0;
    public bool Stale => Closed || !_tcp.Connected || (_tcp.Client.Poll(0, SelectMode.SelectRead) && _tcp.Client.Available == 0);

    /// <summary>TCP-подключение с «эстафетой»: при потере SYN (в этой сети отвечает лишь ~40% попыток, и успешные подключаются за <150 мс)
    /// каждые 250 мс стартует ещё одна попытка, побеждает первая; остальные закрываются.</summary>
    public static async Task<TcpClient> ConnectHedged(string host, int port, double totalSec, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(totalSec));
        var winner = new TaskCompletionSource<TcpClient>(TaskCreationOptions.RunContinuationsAsynchronously);
        var all = new List<TcpClient>();
        Exception? lastError = null;
        int finished = 0, launched = 0;
        const int MaxAttempts = 10;
        void Launch()
        {
            var c = new TcpClient { NoDelay = true };
            lock (all) all.Add(c);
            Interlocked.Increment(ref launched);
            _ = Task.Run(async () =>
            {
                try
                {
                    await c.ConnectAsync(host, port, cts.Token);
                    if (!winner.TrySetResult(c)) c.Dispose();
                }
                catch (Exception e)
                {
                    lastError = e;
                    c.Dispose();
                    // все запущенные попытки закончились ошибкой (например, отказ в соединении) — дальше ждать нечего
                    if (Interlocked.Increment(ref finished) >= MaxAttempts) winner.TrySetException(e);
                }
            });
        }
        try
        {
            for (int i = 0; i < MaxAttempts && !winner.Task.IsCompleted; i++)
            {
                Launch();
                await Task.WhenAny(winner.Task, Task.Delay(250, cts.Token));
            }
            using var reg = cts.Token.Register(() => winner.TrySetCanceled());
            var tcp = await winner.Task;
            tcp.ReceiveBufferSize = 256 * 1024; tcp.SendBufferSize = 256 * 1024;
            return tcp;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TimeoutException($"нет соединения с {host}:{port} за {totalSec:F0} с (попыток: {launched})"); }
        finally
        {
            cts.Cancel();
            lock (all) foreach (var c in all) if (!winner.Task.IsCompletedSuccessfully || winner.Task.Result != c) { try { c.Dispose(); } catch { } }
        }
    }

    public static async Task<RawWs> Connect(string host, string domain, double timeoutSec = 10, string path = "/apiws", string? sni = null, bool secure = true, int port = 0)
    {
        // TCP — эстафетой (до ~60% бюджета), затем TLS и HTTP-апгрейд в оставшееся время
        double tcpBudget = Math.Max(1.5, Math.Min(timeoutSec, 10) * 0.6);
        var tcp = await ConnectHedged(host, port != 0 ? port : secure ? 443 : 80, tcpBudget);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(2.5, Math.Min(timeoutSec, 10) - tcpBudget + 1.5)));
        try
        {
            Stream stream = tcp.GetStream();
            if (secure)
            {
                bool fronted = sni != null;
                var ssl = new SslStream(stream, false, (_, _, _, errors) =>
                    errors == SslPolicyErrors.None || (fronted && errors == SslPolicyErrors.RemoteCertificateNameMismatch));
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = sni ?? domain }, cts.Token);
                stream = ssl;
            }
            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var req = $"GET {path} HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(req), cts.Token);
            await stream.FlushAsync(cts.Token);

            // читаем заголовки ответа до пустой строки
            var head = new List<byte>();
            var one = new byte[1];
            while (true)
            {
                int n = await stream.ReadAsync(one, cts.Token);
                if (n == 0) throw new IOException("empty response");
                head.Add(one[0]);
                int c = head.Count;
                if (c >= 4 && head[c - 4] == '\r' && head[c - 3] == '\n' && head[c - 2] == '\r' && head[c - 1] == '\n') break;
                if (c > 16384) throw new IOException("handshake too large");
            }
            string first = Encoding.UTF8.GetString(head.ToArray()).Split("\r\n")[0];
            var parts = first.Split(' ', 3);
            if (parts.Length < 2 || parts[1] != "101") throw new IOException($"HTTP {first}");
            return new RawWs(tcp, stream);
        }
        catch { tcp.Dispose(); throw; }
    }
    private static byte[] BuildFrame(int opcode, ReadOnlySpan<byte> data)
    {
        int len = data.Length;
        var mask = RandomNumberGenerator.GetBytes(4);
        int hdr = len < 126 ? 6 : len < 65536 ? 8 : 14;
        var f = new byte[hdr + len];
        f[0] = (byte)(0x80 | opcode);
        int p;
        if (len < 126) { f[1] = (byte)(0x80 | len); p = 2; }
        else if (len < 65536) { f[1] = 0x80 | 126; BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(2), (ushort)len); p = 4; }
        else { f[1] = 0x80 | 127; BinaryPrimitives.WriteUInt64BigEndian(f.AsSpan(2), (ulong)len); p = 10; }
        Array.Copy(mask, 0, f, p, 4); p += 4;
        for (int i = 0; i < len; i++) f[p + i] = (byte)(data[i] ^ mask[i & 3]);
        return f;
    }

    private async Task WriteAsync(byte[] frame, CancellationToken ct)
    {
        await _wlock.WaitAsync(ct);
        try { await _stream.WriteAsync(frame, ct); await _stream.FlushAsync(ct); }
        finally { _wlock.Release(); }
    }

    public Task Send(byte[] data, CancellationToken ct)
    {
        if (Closed) throw new IOException("WebSocket closed");
        return WriteAsync(BuildFrame(0x2, data), ct);
    }

    public async Task SendBatch(List<byte[]> parts, CancellationToken ct)
    {
        if (Closed) throw new IOException("WebSocket closed");
        var all = new MemoryStream();
        foreach (var p in parts) all.Write(BuildFrame(0x2, p));
        await WriteAsync(all.ToArray(), ct);
    }

    private async Task ReadExact(byte[] buf, int count, CancellationToken ct)
    {
        int got = 0;
        while (got < count)
        {
            int n = await _stream.ReadAsync(buf.AsMemory(got, count - got), ct);
            if (n == 0) throw new IOException("connection closed");
            got += n;
        }
    }

    public async Task<byte[]?> Recv(CancellationToken ct)
    {
        var hdr = new byte[8];
        while (!Closed)
        {
            await ReadExact(hdr, 2, ct);
            bool fin = (hdr[0] & 0x80) != 0;
            int opcode = hdr[0] & 0x0F;
            bool masked = (hdr[1] & 0x80) != 0; // читаем ДО расширенной длины: она перезаписывает hdr
            long len = hdr[1] & 0x7F;
            if (len == 126) { await ReadExact(hdr, 2, ct); len = BinaryPrimitives.ReadUInt16BigEndian(hdr); }
            else if (len == 127) { await ReadExact(hdr, 8, ct); len = (long)BinaryPrimitives.ReadUInt64BigEndian(hdr); }
            if (len > 16 * 1024 * 1024) throw new IOException("WS frame too large");
            byte[]? mask = null;
            if (masked) { mask = new byte[4]; await ReadExact(mask, 4, ct); }
            var payload = new byte[len];
            await ReadExact(payload, (int)len, ct);
            if (mask != null) for (int i = 0; i < payload.Length; i++) payload[i] ^= mask[i & 3];

            switch (opcode)
            {
                case 0x8:
                    Closed = true;
                    try { await WriteAsync(BuildFrame(0x8, payload.Length >= 2 ? payload.AsSpan(0, 2) : ReadOnlySpan<byte>.Empty), ct); } catch { }
                    return null;
                case 0x9:
                    try { await WriteAsync(BuildFrame(0xA, payload), ct); } catch { }
                    continue;
                case 0xA: continue;
                case 0x0: case 0x1: case 0x2:
                    if (fin && _frag.Count == 0) return payload;
                    _frag.AddRange(payload);
                    if (_frag.Count > 16 * 1024 * 1024) throw new IOException("WS message too large");
                    if (!fin) continue;
                    var msg = _frag.ToArray(); _frag.Clear();
                    return msg;
            }
        }
        return null;
    }

    public void Dispose()
    {
        if (!Closed)
        {
            Closed = true;
            try { WriteAsync(BuildFrame(0x8, ReadOnlySpan<byte>.Empty), CancellationToken.None).Wait(500); } catch { }
        }
        try { _stream.Dispose(); } catch { }
        try { _tcp.Dispose(); } catch { }
    }
}

/// <summary>Режет поток на пакеты транспорта MTProto, чтобы каждый уходил отдельным WS-кадром.</summary>
internal sealed class MsgSplitter
{
    private readonly uint _proto;
    private readonly List<byte> _cipher = new();
    private readonly List<byte> _plain = new();
    private bool _disabled;

    public MsgSplitter(uint proto) { _proto = proto; }

    public List<byte[]> Split(byte[] chunk, byte[] plain)
    {
        var parts = new List<byte[]>();
        if (chunk.Length == 0) return parts;
        if (_disabled) { parts.Add(chunk); return parts; }
        _cipher.AddRange(chunk); _plain.AddRange(plain);
        int offset = 0, bufLen = _cipher.Count;
        while (offset < bufLen)
        {
            int? pl = NextLen(offset, bufLen - offset);
            if (pl is null) break;
            if (pl <= 0)
            {
                parts.Add(_cipher.GetRange(offset, bufLen - offset).ToArray());
                offset = bufLen; _disabled = true;
                break;
            }
            parts.Add(_cipher.GetRange(offset, pl.Value).ToArray());
            offset += pl.Value;
        }
        if (offset > 0) { _cipher.RemoveRange(0, offset); _plain.RemoveRange(0, offset); }
        return parts;
    }

    public byte[]? Flush()
    {
        if (_cipher.Count == 0) return null;
        var tail = _cipher.ToArray(); _cipher.Clear(); _plain.Clear();
        return tail;
    }

    private int? NextLen(int offset, int avail)
    {
        if (avail <= 0) return null;
        if (_proto == 0xEFEFEFEF)
        {
            int first = _plain[offset], payload, header;
            if (first is 0x7F or 0xFF)
            {
                if (avail < 4) return null;
                payload = (_plain[offset + 1] | (_plain[offset + 2] << 8) | (_plain[offset + 3] << 16)) * 4;
                header = 4;
            }
            else { payload = (first & 0x7F) * 4; header = 1; }
            if (payload <= 0) return 0;
            int total = header + payload;
            return avail < total ? null : total;
        }
        if (_proto is 0xEEEEEEEE or 0xDDDDDDDD)
        {
            if (avail < 4) return null;
            uint p = (uint)(_plain[offset] | (_plain[offset + 1] << 8) | (_plain[offset + 2] << 16) | (_plain[offset + 3] << 24)) & 0x7FFFFFFF;
            if (p == 0) return 0;
            long total = 4L + p;
            return avail < total ? null : (int)total;
        }
        return 0;
    }
}

public sealed partial class TgProxy
{
    public static bool Installed => true;
    public static string? LocalVersion => "встроенный";

    // ---------- константы протокола ----------
    private const int HandshakeLen = 64, SkipLen = 8, PrekeyLen = 32, IvLen = 16, ProtoTagPos = 56, DcIdxPos = 60;
    private static readonly byte[] TagAbridged = { 0xEF, 0xEF, 0xEF, 0xEF }, TagIntermediate = { 0xEE, 0xEE, 0xEE, 0xEE }, TagSecure = { 0xDD, 0xDD, 0xDD, 0xDD };
    private static readonly Dictionary<int, string> DcDefaultIps = new()
    {
        [1] = "149.154.175.50", [2] = "149.154.167.51", [3] = "149.154.175.100", [4] = "149.154.167.91", [5] = "149.154.171.5", [203] = "91.105.192.100",
    };
    private static readonly Dictionary<int, string> DcTestIps = new() { [1] = "149.154.175.10", [2] = "149.154.167.40", [3] = "149.154.175.117" };
    private static readonly string[] CfDomainsUrls =
    {
        "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt",
        "https://cdn.jsdelivr.net/gh/Flowseal/tg-ws-proxy@main/.github/cfproxy-domains.txt",
    };
    private static readonly string[] CfEnc =
    {
        "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com", "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com",
        "bxaxtxmrw.com", "dmohrsgmohcrwb.com", "vwbmtmoi.com", "khgrre.com", "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com", "orgcnunpj.com",
        "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
    };

    private static string DecodeCf(string s)
    {
        if (!s.EndsWith(".com")) return s;
        string p = s[..^4];
        int n = p.Count(char.IsLetter);
        var sb = new StringBuilder();
        foreach (char c in p)
        {
            if (char.IsLetter(c))
            {
                int b = c > '`' ? 97 : 65;
                sb.Append((char)((((c - b - n) % 26) + 26) % 26 + b));
            }
            else sb.Append(c);
        }
        return sb + ".co.uk";
    }

    private static List<string> WsDomains(int dc, bool media)
    {
        if (dc == 203) dc = 2;
        return media ? new() { $"kws{dc}-1.web.telegram.org", $"kws{dc}.web.telegram.org" } : new() { $"kws{dc}.web.telegram.org" };
    }

    // ---------- состояние ----------
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private TgCfg _cfg = new();
    private byte[] _secret = Array.Empty<byte>();
    private Dictionary<int, string> _dcRedirects = new();
    private readonly ConcurrentDictionary<(int, bool, bool), ConcurrentQueue<RawWs>> _idle = new();
    private readonly ConcurrentDictionary<(int, bool, bool), long> _refillAfter = new();
    private readonly ConcurrentDictionary<(int, bool, bool), int> _refilling = new();
    private readonly ConcurrentDictionary<(string, int), (int fails, long retryAt)> _tcpBackoff = new();
    private List<string> _cfDomains = new();
    private readonly Dictionary<int, string> _dcToDomain = new();
    private bool _tryFrontingFirst;
    private readonly ConcurrentDictionary<(string, bool), int> _wsFailLogged = new();
    private long _connTotal, _connWs, _connCf, _connTcp, _connBad, _bytesUp, _bytesDown, _active, _wsOnDemand, _noRoute;
    private readonly ConcurrentDictionary<int, long> _cfCooldown = new();

    public bool Running => _listener != null && _cts is { IsCancellationRequested: false };

    public void Start(TgCfg cfg)
    {
        lock (Lock)
        {
            Stop();
            _cfg = cfg;
            _secret = Convert.FromHexString(cfg.secret);
            _dcRedirects = new();
            foreach (var e in cfg.dc_ip)
            {
                var parts = e.Split(':', 2);
                _dcRedirects[int.Parse(parts[0])] = parts[1];
            }
            _idle.Clear(); _refillAfter.Clear(); _refilling.Clear(); _tcpBackoff.Clear();
            _cfDomains = CfEnc.Select(DecodeCf).ToList();
            _dcToDomain.Clear();
            foreach (var dc in new[] { 1, 2, 3, 4, 5, 203 }) _dcToDomain[dc] = _cfDomains[Random.Shared.Next(_cfDomains.Count)];

            var listener = new TcpListener(IPAddress.Loopback, cfg.port);
            try { listener.Start(256); }
            catch (SocketException e) { throw new InvalidOperationException($"Не удалось занять порт {cfg.port}: {e.Message}"); }
            _listener = listener;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            Log.Info($"Telegram-прокси запущен на 127.0.0.1:{cfg.port}");
            _ = Task.Run(() => AcceptLoop(listener, ct));
            _ = Task.Run(() => MaintenanceLoop(ct));
            foreach (var kv in _dcRedirects)
                foreach (bool media in new[] { false, true }) ScheduleRefill((kv.Key, media, false), kv.Value);
        }
    }

    public void Stop()
    {
        lock (Lock)
        {
            if (_cts == null) return;
            try { _cts.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            foreach (var q in _idle.Values) while (q.TryDequeue(out var ws)) ws.Dispose();
            _listener = null; _cts = null;
        }
    }

    private async Task AcceptLoop(TcpListener l, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var c = await l.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => HandleClient(c, ct));
            }
        }
        catch { }
    }

    private async Task MaintenanceLoop(CancellationToken ct)
    {
        long lastCf = 0, lastStats = Environment.TickCount64;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(2000, ct);
                foreach (var key in _idle.Keys)
                    if (_dcRedirects.TryGetValue(key.Item1, out var ip)) ScheduleRefill(key, ip);
                long now = Environment.TickCount64;
                if (now - lastStats > 60_000)
                {
                    lastStats = now;
                    string pools = string.Join(" ", _idle.OrderBy(k => k.Key).Select(k => $"DC{k.Key.Item1}{(k.Key.Item2 ? "m" : "")}={k.Value.Count}"));
                    Log.Info($"Telegram-прокси: подключений {_connTotal} (активных {_active}), WS {_connWs} (новых {_wsOnDemand}), CF {_connCf}, TCP {_connTcp}, без маршрута {_noRoute}, неверных {_connBad}; ↑{Human(_bytesUp)} ↓{Human(_bytesDown)}; пул: {pools}");
                }
                if (lastCf == 0 || now - lastCf > 3_600_000)
                {
                    lastCf = now;
                    _ = Task.Run(RefreshCfDomains);
                }
            }
        }
        catch { }
    }

    private static List<string> ParseCfDomains(byte[] bytes) =>
        Encoding.UTF8.GetString(bytes).Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).Select(DecodeCf)
            .Select(d => d.ToLowerInvariant()).Where(d => d.Contains('.') && d.Length <= 253 && d.All(c => char.IsLetterOrDigit(c) || c is '.' or '-')).Distinct().ToList();

    private async Task RefreshCfDomains()
    {
        try
        {
            var (bytes, source) = await Task.Run(() => Net.FetchFirst(CfDomainsUrls, b => ParseCfDomains(b).Count >= 3, 10));
            var pool = ParseCfDomains(bytes);
            _cfDomains = pool;
            Log.Info($"Список CF-доменов обновлён ({pool.Count}, источник {Net.Host(source)})");
        }
        catch (Exception e) { Log.Warn("Не удалось обновить список CF-доменов: " + e.Message); }
    }
    // ---------- WS-пул ----------

    private const int PoolSize = 4;
    private const double PoolMaxAge = 120;

    private void ScheduleRefill((int, bool, bool) key, string ip)
    {
        if (Environment.TickCount64 < _refillAfter.GetValueOrDefault(key, 0)) return;
        if (!_refilling.TryAdd(key, 1)) return;
        var ct = _cts?.Token ?? CancellationToken.None;
        _ = Task.Run(async () =>
        {
            try
            {
                var q = _idle.GetOrAdd(key, _ => new());
                while (q.TryPeek(out var old) && (old.Stale || (DateTime.UtcNow - old.Created).TotalSeconds > PoolMaxAge))
                    if (q.TryDequeue(out var d)) d.Dispose();
                int needed = PoolSize - q.Count;
                if (needed <= 0 || ct.IsCancellationRequested) return;
                var tasks = Enumerable.Range(0, needed).Select(_ => ConnectOne(ip, WsDomains(key.Item1, key.Item2), key.Item3 ? "/apiws_test" : "/apiws")).ToList();
                int connected = 0;
                foreach (var t in tasks)
                {
                    var ws = await t;
                    if (ws != null) { q.Enqueue(ws); connected++; }
                }
                if (connected == 0)
                {
                    _refillAfter[key] = Environment.TickCount64 + 2000;
                }
            }
            catch { }
            finally { _refilling.TryRemove(key, out _); }
        });
    }

#if MANIFEST_TEST
    /// <summary>ТОЛЬКО тестовая сборка: вместо WS-шлюза Telegram — локальный имитатор (host, port), обычный ws:// без TLS.</summary>
    public static (string host, int port)? MockWs;
#endif

    private async Task<RawWs?> ConnectOne(string ip, List<string> domains, string path, double budgetSec = 20)
    {
#if MANIFEST_TEST
        if (MockWs is { } mock)
        {
            try { return await RawWs.Connect(mock.host, domains[0], 5, path, null, secure: false, port: mock.port); }
            catch { return null; }
        }
#endif
        long deadline = Environment.TickCount64 + (long)(budgetSec * 1000);
        foreach (var domain in domains)
        {
            foreach (bool fronted in _tryFrontingFirst ? new[] { true, false } : new[] { false, true })
            {
                double left = (deadline - Environment.TickCount64) / 1000.0;
                if (left < 1.2) return null;
                try
                {
                    var ws = await RawWs.Connect(ip, domain, Math.Min(left, fronted ? 7 : 8), path, fronted ? "sprinthost.ru" : null);
                    _tryFrontingFirst = fronted;
                    return ws;
                }
                catch (Exception e)
                {
                    if (_wsFailLogged.TryAdd((domain, fronted), 1))
                        Log.Info($"WS-пул: {domain} через {ip} (маскировка={fronted}): {e.Message}");
                }
            }
        }
        return null;
    }

    /// <summary>WS к Telegram: из пула, а при промахе — сразу новое подключение (эстафетой), а не запасной путь.</summary>
    private async Task<(RawWs? ws, bool fresh)> GetWs(int dc, bool media, bool test)
    {
        var ws = PoolGet(dc, media, test);
        if (ws != null) return (ws, false);
        if (!_dcRedirects.TryGetValue(dc, out var ip)) return (null, false);
        ws = await ConnectOne(ip, WsDomains(dc, media), test ? "/apiws_test" : "/apiws", 7);
        return (ws, ws != null);
    }
    private RawWs? PoolGet(int dc, bool media, bool test)
    {
        if (!_dcRedirects.TryGetValue(dc, out var ip)) return null;
        var key = (dc, media, test);
        var q = _idle.GetOrAdd(key, _ => new());
        RawWs? found = null;
        while (q.TryDequeue(out var ws))
        {
            if (ws.Stale || (DateTime.UtcNow - ws.Created).TotalSeconds >= PoolMaxAge) { ws.Dispose(); continue; }
            found = ws; break;
        }
        ScheduleRefill(key, ip);
        return found;
    }

    // ---------- рукопожатие ----------

    private (int dc, bool media, byte[] tag, byte[] prekeyIv)? TryHandshake(byte[] hs)
    {
        var prekeyIv = hs.AsSpan(SkipLen, PrekeyLen + IvLen).ToArray();
        var decKey = SHA256.HashData(prekeyIv.AsSpan(0, PrekeyLen).ToArray().Concat(_secret).ToArray());
        using var ctr = new AesCtr(decKey, prekeyIv[PrekeyLen..]);
        var dec = ctr.Update(hs);
        var tag = dec[ProtoTagPos..(ProtoTagPos + 4)];
        if (!tag.AsSpan().SequenceEqual(TagAbridged) && !tag.AsSpan().SequenceEqual(TagIntermediate) && !tag.AsSpan().SequenceEqual(TagSecure)) return null;
        short dcIdx = BinaryPrimitives.ReadInt16LittleEndian(dec.AsSpan(DcIdxPos, 2));
        return (Math.Abs((int)dcIdx), dcIdx < 0, tag, prekeyIv);
    }

    private static byte[] GenerateRelayInit(byte[] tag, int dcIdx)
    {
        byte[] rnd;
        while (true)
        {
            rnd = RandomNumberGenerator.GetBytes(HandshakeLen);
            if (rnd[0] == 0xEF) continue;
            uint start = BinaryPrimitives.ReadUInt32BigEndian(rnd);
            if (start is 0x48454144 or 0x504F5354 or 0x47455420 or 0xEEEEEEEE or 0xDDDDDDDD or 0x16030102 or 0x4F505449) continue;
            if (rnd[4] == 0 && rnd[5] == 0 && rnd[6] == 0 && rnd[7] == 0) continue;
            break;
        }
        using var enc = new AesCtr(rnd[SkipLen..(SkipLen + PrekeyLen)], rnd[(SkipLen + PrekeyLen)..(SkipLen + PrekeyLen + IvLen)]);
        var full = enc.Update(rnd);
        var tail = new byte[8];
        Array.Copy(tag, tail, 4);
        BinaryPrimitives.WriteInt16LittleEndian(tail.AsSpan(4), (short)dcIdx);
        RandomNumberGenerator.Fill(tail.AsSpan(6, 2));
        var res = (byte[])rnd.Clone();
        for (int i = 0; i < 8; i++) res[56 + i] = (byte)(tail[i] ^ (full[56 + i] ^ rnd[56 + i]));
        return res;
    }

    private CryptoCtx BuildCtx(byte[] cltPrekeyIv, byte[] relayInit)
    {
        byte[] Key(byte[] prekey) => SHA256.HashData(prekey.Concat(_secret).ToArray());
        var cltDec = new AesCtr(Key(cltPrekeyIv[..PrekeyLen]), cltPrekeyIv[PrekeyLen..]);
        var rev = cltPrekeyIv.Reverse().ToArray();
        var cltEnc = new AesCtr(Key(rev[..PrekeyLen]), rev[PrekeyLen..]);
        cltDec.Update(new byte[64]);

        var relayKey = relayInit[SkipLen..(SkipLen + PrekeyLen)];
        var relayIv = relayInit[(SkipLen + PrekeyLen)..(SkipLen + PrekeyLen + IvLen)];
        var relayRev = relayInit[SkipLen..(SkipLen + PrekeyLen + IvLen)].Reverse().ToArray();
        var tgEnc = new AesCtr(relayKey, relayIv);
        var tgDec = new AesCtr(relayRev[..32], relayRev[32..]);
        tgEnc.Update(new byte[64]);
        return new CryptoCtx { CltDec = cltDec, CltEnc = cltEnc, TgEnc = tgEnc, TgDec = tgDec };
    }

    private static async Task ReadExact(Stream s, byte[] buf, int count, CancellationToken ct)
    {
        int got = 0;
        while (got < count)
        {
            int n = await s.ReadAsync(buf.AsMemory(got, count - got), ct);
            if (n == 0) throw new EndOfStreamException();
            got += n;
        }
    }

    // ---------- клиент ----------

    private async Task HandleClient(TcpClient client, CancellationToken ct)
    {
        Interlocked.Increment(ref _connTotal); Interlocked.Increment(ref _active);
        string label = client.Client.RemoteEndPoint?.ToString() ?? "?";
        client.NoDelay = true;
        try
        {
            var s = client.GetStream();
            var hs = new byte[HandshakeLen];
            using (var hsCts = CancellationTokenSource.CreateLinkedTokenSource(ct)) { hsCts.CancelAfter(10_000); await ReadExact(s, hs, HandshakeLen, hsCts.Token); }
            var r = TryHandshake(hs);
            if (r is null)
            {
                Interlocked.Increment(ref _connBad);
                Log.Warn($"[{label}] неверное рукопожатие (секрет или протокол)");
                var junk = new byte[4096];
                try { while (await s.ReadAsync(junk, ct) > 0) { } } catch { }
                return;
            }
            var (dc, media, tag, prekeyIv) = r.Value;
            bool test = dc >= 10000;
            if (test) dc -= 10000;
            uint protoInt = tag[0] switch { 0xEF => 0xEFEFEFEFu, 0xEE => 0xEEEEEEEEu, _ => 0xDDDDDDDDu };
            int dcIdx = media ? -dc : dc;
            var relayInit = GenerateRelayInit(tag, dcIdx);
            using var ctx = BuildCtx(prekeyIv, relayInit);
            string mt = media ? " media" : "";

            var sw0 = System.Diagnostics.Stopwatch.StartNew();
            var (ws, fresh) = await GetWs(dc, media, test);
            if (ws == null)
            {
                Log.Info($"[{label}] DC{dc}{mt}: прямой WS недоступен ({sw0.ElapsedMilliseconds} мс) -> запасной путь");
                bool ok = await Fallback(s, relayInit, label, dc, test, media, ctx, new MsgSplitter(protoInt), ct);
                if (!ok) { Interlocked.Increment(ref _noRoute); Log.Warn($"[{label}] DC{dc}{mt}: запасных путей нет ({sw0.ElapsedMilliseconds} мс)"); }
                return;
            }
            Interlocked.Increment(ref _connWs);
            if (fresh) Interlocked.Increment(ref _wsOnDemand);
            Log.Info($"[{label}] DC{dc}{mt} -> WS ({(fresh ? "новое" : "из пула")}, {sw0.ElapsedMilliseconds} мс, ws-порт {ws.LocalPort})");
            await ws.Send(relayInit, ct);
            await BridgeWs(s, ws, label, ctx, dc, media, new MsgSplitter(protoInt), ct);
        }
        catch (OperationCanceledException) { }
        catch (EndOfStreamException) { }
        catch (IOException) { }
        catch (Exception e) { Log.Warn($"[{label}] ошибка: {e.Message}"); }
        finally
        {
            Interlocked.Decrement(ref _active);
            try { client.Dispose(); } catch { }
        }
    }

    private async Task BridgeWs(NetworkStream clt, RawWs ws, string label, CryptoCtx ctx, int dc, bool media, MsgSplitter? splitter, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = cts.Token;
        long up = 0, down = 0, upPk = 0, downPk = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();

        async Task TcpToWs()
        {
            var buf = new byte[65536];
            try
            {
                while (true)
                {
                    int n = await clt.ReadAsync(buf, token);
                    if (n == 0)
                    {
                        var tail = splitter?.Flush();
                        if (tail != null) await ws.Send(tail, token);
                        break;
                    }
                    Interlocked.Add(ref _bytesUp, n); up += n; upPk++;
                    var plain = ctx.CltDec.Update(buf.AsSpan(0, n));
                    var chunk = ctx.TgEnc.Update(plain);
                    if (splitter != null)
                    {
                        var parts = splitter.Split(chunk, plain);
                        if (parts.Count == 0) continue;
                        if (parts.Count > 1) await ws.SendBatch(parts, token); else await ws.Send(parts[0], token);
                    }
                    else await ws.Send(chunk, token);
                }
            }
            catch { }
        }

        async Task WsToTcp()
        {
            try
            {
                while (true)
                {
                    var data = await ws.Recv(token);
                    if (data == null) break;
                    Interlocked.Add(ref _bytesDown, data.Length); down += data.Length; downPk++;
                    var plain = ctx.TgDec.Update(data);
                    var enc = ctx.CltEnc.Update(plain);
                    await clt.WriteAsync(enc, token);
                }
            }
            catch { }
        }

        try { await Task.WhenAny(TcpToWs(), WsToTcp()); }
        finally
        {
            cts.Cancel();
            ws.Dispose();
            Log.Info($"[{label}] DC{dc}{(media ? "m" : "")}: сеанс закрыт ↑{Human(up)} ({upPk} пак.) ↓{Human(down)} ({downPk} пак.) за {sw.Elapsed.TotalSeconds:F1} с");
        }
    }

    private static string Human(long n)
    {
        double v = n;
        foreach (var u in new[] { "B", "KB", "MB", "GB" }) { if (Math.Abs(v) < 1024) return $"{v:F1}{u}"; v /= 1024; }
        return $"{v:F1}TB";
    }

    // ---------- запасные пути: CF-прокси и прямой TCP ----------

    private IEnumerable<string> CfDomainsForDc(int dc)
    {
        _dcToDomain.TryGetValue(dc, out var cur);
        if (cur != null) yield return cur;
        foreach (var d in _cfDomains.OrderBy(_ => Random.Shared.Next())) if (d != cur) yield return d;
    }

    private async Task<bool> Fallback(NetworkStream clt, byte[] relayInit, string label, int dc, bool test, bool media, CryptoCtx ctx, MsgSplitter splitter, CancellationToken ct)
    {
        var table = test ? DcTestIps : DcDefaultIps;
        table.TryGetValue(dc, out var dst);
        if (_cfg.cfproxy && !test && Environment.TickCount64 >= _cfCooldown.GetValueOrDefault(dc, 0))
        {
            // CF-домены пробуем пачками по 3 параллельно (не по одному с 10-секундным ожиданием), не более 2 пачек; затем пауза для этого DC
            var doms = CfDomainsForDc(dc).Take(6).ToList();
            RawWs? ws = null; string? chosen = null; string lastErr = "";
            for (int i = 0; i < doms.Count && ws == null; i += 3)
            {
                var tasks = doms.Skip(i).Take(3).Select(async d =>
                {
                    string host = $"kws{dc}.{d}";
                    try { return (d, w: (RawWs?)await RawWs.Connect(host, host, 5)); }
                    catch (Exception e) { lastErr = e.Message; return (d, w: (RawWs?)null); }
                }).ToList();
                var pending = tasks.ToList();
                while (pending.Count > 0 && ws == null)
                {
                    var done = await Task.WhenAny(pending);
                    pending.Remove(done);
                    var r = await done;
                    if (r.w != null) { ws = r.w; chosen = r.d; }
                }
                foreach (var p in pending) _ = p.ContinueWith(x => { if (x.IsCompletedSuccessfully) x.Result.w?.Dispose(); });
            }
            if (ws != null)
            {
                _dcToDomain[dc] = chosen!;
                Interlocked.Increment(ref _connCf);
                Log.Info($"[{label}] DC{dc}: через CF-прокси");
                await ws.Send(relayInit, ct);
                await BridgeWs(clt, ws, label, ctx, dc, media, splitter, ct);
                return true;
            }
            _cfCooldown[dc] = Environment.TickCount64 + 30_000;
            Log.Info($"[{label}] DC{dc}: CF-прокси недоступен ({lastErr}); пауза 30 с");
        }
        if (dst != null) return await TcpFallback(clt, dst, 443, relayInit, label, ctx, ct);
        return false;
    }

    private async Task<bool> TcpFallback(NetworkStream clt, string dst, int port, byte[] relayInit, string label, CryptoCtx ctx, CancellationToken ct)
    {
        var key = (dst, port);
        if (_tcpBackoff.TryGetValue(key, out var b) && Environment.TickCount64 < b.retryAt) return false;
        TcpClient rc;
        try
        {
            rc = await RawWs.ConnectHedged(dst, port, 4, ct);
            await rc.GetStream().WriteAsync(relayInit, ct);
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            int fails = _tcpBackoff.TryGetValue(key, out var prev) ? prev.fails + 1 : 1;
            double delay = Math.Min(30 * Math.Pow(2, Math.Min(fails - 1, 7)), 3600);
            _tcpBackoff[key] = (fails, Environment.TickCount64 + (long)(delay * 1000));
            Log.Warn($"[{label}] TCP-запасной путь к {dst}:{port} не удался ({e.Message}); повтор через {delay:F0} с");
            return false;
        }
        try
        {
            var rs = rc.GetStream();
            _tcpBackoff.TryRemove(key, out _);
            Interlocked.Increment(ref _connTcp);
            Log.Info($"[{label}] TCP-запасной путь к {dst}:{port}");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            async Task Fwd(Stream src, Stream dstS, bool upDir)
            {
                var buf = new byte[65536];
                try
                {
                    while (true)
                    {
                        int n = await src.ReadAsync(buf, cts.Token);
                        if (n == 0) break;
                        byte[] data;
                        if (upDir) { Interlocked.Add(ref _bytesUp, n); data = ctx.TgEnc.Update(ctx.CltDec.Update(buf.AsSpan(0, n))); }
                        else { Interlocked.Add(ref _bytesDown, n); data = ctx.CltEnc.Update(ctx.TgDec.Update(buf.AsSpan(0, n))); }
                        await dstS.WriteAsync(data, cts.Token);
                    }
                }
                catch { }
            }
            await Task.WhenAny(Fwd(clt, rs, true), Fwd(rs, clt, false));
            cts.Cancel();
            return true;
        }
        finally { rc.Dispose(); }
    }
}