using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace ZapretHub;

/// <summary>Сеть приложения: только HTTPS с проверкой сертификата по имени хоста, редиректы поддерживаются (https→http не принимается).
/// Если системный DNS подменяет адрес (loopback/приватный/нулевой — так отвечает часть DNS для raw.githubusercontent.com),
/// адрес запрашивается по DoH (Cloudflare, затем Google); подключение идёт на полученный IP, а TLS-проверка остаётся по имени хоста.</summary>
public sealed class RateLimitException : Exception
{
    public RateLimitException() : base("Лимит запросов GitHub API исчерпан — повторите проверку позже") { }
}

public static class Net
{
    public static readonly HttpClient Http = Make();
    private static readonly HttpClient DohHttp = new(new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(5) }) { Timeout = TimeSpan.FromSeconds(7) };
    private static readonly string[] DohEndpoints = { "https://1.1.1.1/dns-query", "https://8.8.8.8/resolve", "https://1.0.0.1/dns-query" };
    private static readonly Dictionary<string, (DateTime at, List<IPAddress> ips)> DohCache = new();
    private static readonly Dictionary<string, DateTime> Warned = new();

    private static HttpClient Make()
    {
        var h = new HttpClient(new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All, ConnectTimeout = TimeSpan.FromSeconds(15),
            AllowAutoRedirect = true, MaxAutomaticRedirections = 5, ConnectCallback = ConnectAsync,
        }) { Timeout = TimeSpan.FromMinutes(10) };
        h.DefaultRequestHeaders.UserAgent.ParseAdd("ZapretHub/" + P.AppVersion);
        h.DefaultRequestHeaders.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoCache = true };
        return h;
    }

    // ---------- DNS-подмена ----------

    public static bool Bogus(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || (ip.GetAddressBytes()[0] & 0xFE) == 0xFC;
        var b = ip.GetAddressBytes();
        return b[0] is 0 or 10 or >= 224 || (b[0] == 100 && b[1] is >= 64 and <= 127) || (b[0] == 169 && b[1] == 254)
            || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168);
    }

    private static async Task<List<IPAddress>> DohResolve(string host, CancellationToken ct)
    {
        lock (DohCache)
            if (DohCache.TryGetValue(host, out var c) && DateTime.UtcNow - c.at < TimeSpan.FromMinutes(10)) return c.ips;
        foreach (var ep in DohEndpoints)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"{ep}?name={Uri.EscapeDataString(host)}&type=A");
                req.Headers.Accept.ParseAdd("application/dns-json");
                using var resp = await DohHttp.SendAsync(req, ct);
                resp.EnsureSuccessStatusCode();
                var json = JsonNode.Parse(await resp.Content.ReadAsStringAsync(ct));
                var ips = new List<IPAddress>();
                foreach (var a in json?["Answer"]?.AsArray() ?? new JsonArray())
                    if (a?["type"]?.GetValue<int>() == 1 && IPAddress.TryParse(a["data"]?.GetValue<string>(), out var ip) && !Bogus(ip)) ips.Add(ip);
                if (ips.Count == 0) continue;
                lock (DohCache) DohCache[host] = (DateTime.UtcNow, ips);
                return ips;
            }
            catch (Exception) when (!ct.IsCancellationRequested) { }
        }
        return new();
    }

    private static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext ctx, CancellationToken ct)
    {
        string host = ctx.DnsEndPoint.Host;
        int port = ctx.DnsEndPoint.Port;
        IPAddress[] addrs;
        try { addrs = await Dns.GetHostAddressesAsync(host, ct); }
        catch (SocketException) { addrs = Array.Empty<IPAddress>(); }
        if ((addrs.Length == 0 || addrs.All(Bogus)) && !IPAddress.TryParse(host, out _))
        {
            var alt = await DohResolve(host, ct);
            if (alt.Count > 0)
            {
                bool warn;
                lock (Warned) { warn = !Warned.TryGetValue(host, out var t) || DateTime.UtcNow - t > TimeSpan.FromMinutes(10); if (warn) Warned[host] = DateTime.UtcNow; }
                if (warn) Log.Warn($"Системный DNS вернул недопустимый адрес для {host} ({string.Join(",", addrs.Select(a => a.ToString()))}); адрес получен по DoH, проверка TLS — по имени хоста");
                addrs = alt.ToArray();
            }
        }
        if (addrs.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
        Exception? last = null;
        foreach (var a in addrs)
        {
            var s = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await s.ConnectAsync(new IPEndPoint(a, port), ct);
                return new NetworkStream(s, ownsSocket: true);
            }
            catch (Exception e) { s.Dispose(); last = e; if (ct.IsCancellationRequested) throw; }
        }
        throw last ?? new SocketException((int)SocketError.HostUnreachable);
    }

    // ---------- загрузка ----------

#if MANIFEST_TEST
    // Только тестовая сборка: локальные file:/// вместо сети (проверка манифеста без обращения к GitHub).
    private static bool IsLocal(string url) => url.StartsWith("file:///", StringComparison.OrdinalIgnoreCase);
#else
    private static bool IsLocal(string url) => false;
#endif

    private static void RequireHttps(string url)
    {
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Разрешены только HTTPS-адреса: " + url);
    }

    public static async Task<byte[]> FetchAsync(string url, int timeoutSec = 15)
    {
        if (IsLocal(url)) return await File.ReadAllBytesAsync(new Uri(url).LocalPath);
        RequireHttps(url);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        return await Http.GetByteArrayAsync(url, cts.Token);
    }

    public static byte[] Fetch(string url, int timeoutSec = 15) => FetchAsync(url, timeoutSec).GetAwaiter().GetResult();

    /// <summary>Запрос к GitHub REST API (только HTTPS на api.github.com). Возвращает JSON-текст; HTTP-ошибки — HttpRequestException со StatusCode,
    /// исчерпанный лимит запросов — RateLimitException.</summary>
    public static string FetchGitHubApi(string url, int timeoutSec = 20)
    {
        if (IsLocal(url)) return File.ReadAllText(new Uri(url).LocalPath);
        RequireHttps(url);
        if (!string.Equals(Host(url), "api.github.com", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Недопустимый адрес API: " + url);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd("application/vnd.github+json");
        req.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
        using var resp = Http.SendAsync(req, cts.Token).GetAwaiter().GetResult();
        if (resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests
            && resp.Headers.TryGetValues("x-ratelimit-remaining", out var rem) && rem.FirstOrDefault() == "0")
            throw new RateLimitException();
        resp.EnsureSuccessStatusCode();
        return resp.Content.ReadAsStringAsync(cts.Token).GetAwaiter().GetResult();
    }

    /// <summary>Пробует источники по очереди; принимает первый, чьё содержимое прошло validate. Возвращает данные и использованный адрес.</summary>
    public static (byte[] data, string source) FetchFirst(IEnumerable<string> urls, Func<byte[], bool> validate, int timeoutSec = 15)
    {
        var errors = new List<string>();
        foreach (var u in urls)
        {
            try
            {
                var data = Fetch(u, timeoutSec);
                if (validate(data)) return (data, u);
                errors.Add($"{Host(u)}: содержимое не прошло проверку");
            }
            catch (Exception e) { errors.Add($"{Host(u)}: {e.Message}"); }
        }
        throw new IOException("Не удалось получить данные ни из одного источника: " + string.Join("; ", errors));
    }

    public static string Host(string url) { try { return new Uri(url).Host; } catch { return url; } }

    public static void Download(string url, string dest, Action<long, long>? progress)
    {
        if (IsLocal(url)) { File.Copy(new Uri(url).LocalPath, dest, true); progress?.Invoke(1, 1); return; }
        RequireHttps(url);
        using var resp = Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
        resp.EnsureSuccessStatusCode();
        long total = resp.Content.Headers.ContentLength ?? 0;
        using var src = resp.Content.ReadAsStream();
        using var dst = File.Create(dest);
        var buf = new byte[64 * 1024];
        long done = 0;
        int n;
        while ((n = src.Read(buf, 0, buf.Length)) > 0)
        {
            dst.Write(buf, 0, n);
            done += n;
            progress?.Invoke(done, total);
        }
    }
}
