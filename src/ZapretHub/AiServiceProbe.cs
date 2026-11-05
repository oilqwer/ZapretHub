using System.Net;
using System.Net.Sockets;

namespace ZapretHub;

internal static class AiServiceProbe
{
    internal static string Group(string host)
    {
        if (new[] { "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com" }.Any(d => host == d || host.EndsWith("." + d))) return "chatgpt.com";
        if (new[] { "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com" }.Any(d => host == d || host.EndsWith("." + d))) return "gemini.google.com";
        return AiDnsPolicy.Domains.First(d => host == d || host.EndsWith("." + d));
    }
    internal static bool RegionBlocked(string text)
    {
        string visible = System.Text.RegularExpressions.Regex.Replace(text, @"<(script|style)\b[^>]*>.*?</\1\s*>", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Singleline, TimeSpan.FromMilliseconds(200));
        visible = WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Replace(visible, "<[^>]+>", " ", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromMilliseconds(200)));
        visible = System.Text.RegularExpressions.Regex.Replace(visible.Replace('\u2019', '\''), @"\s+", " ", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromMilliseconds(200));
        return visible.Contains("unsupported_country", StringComparison.OrdinalIgnoreCase) || new[]
        {
            "country is not supported", "not supported in your country", "isn't supported in your country",
            "isn't currently supported in your country", "is not currently supported in your country", "isn't available in your country",
            "is not available in your country", "not available in your region",
            "пока не поддерживается в вашей стране", "недоступен в вашей стране",
        }.Any(s => visible.Contains(s, StringComparison.OrdinalIgnoreCase));
    }

    internal static string? PageFailure(string text)
    {
        if (RegionBlocked(text)) return "region";
        string visible = System.Text.RegularExpressions.Regex.Replace(text, @"<(script|style)\b[^>]*>.*?</\1\s*>", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Singleline, TimeSpan.FromMilliseconds(200));
        visible = WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Replace(visible, "<[^>]+>", " ", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromMilliseconds(200)));
        visible = System.Text.RegularExpressions.Regex.Replace(visible, @"\s+", " ", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromMilliseconds(200));
        return new[] { "unable to load site", "не удается загрузить сайт", "не удаётся загрузить сайт", "you have been blocked", "your access has been blocked" }
            .Any(s => visible.Contains(s, StringComparison.OrdinalIgnoreCase)) ? "service_rejected" : null;
    }

    internal static Task Check(string host, IDnsExchange exchange, CancellationToken ct) =>
        AiProbeFailure.WithinDeadline(token => CheckCore(host, exchange, token), ct);

    internal static Task CheckCore(string host, IDnsExchange exchange, CancellationToken ct) => CheckObserved(host, exchange, ct, null);
    internal static async Task CheckObserved(string host, IDnsExchange exchange, CancellationToken ct, AiProbeObservation? observation)
    {
        if (host != "chatgpt.com" && host != "gemini.google.com") return;
        var query = DnsWire.Query(host);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        if (observation is not null) observation.stage = "DNS/DoH";
        byte[] answer;
        try
        {
            if (exchange is DnsExchange actual)
            {
                var reply = await actual.QueryObserved(query, ct); answer = reply.Wire;
                if (observation is not null) { observation.httpVersion = reply.Version; observation.fallback = reply.Transport.Contains("fallback"); observation.dnsTransport = reply.Transport; observation.dnsSource = reply.Source; }
            }
            else answer = await exchange.Query(query, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { throw AiProbeFailure.Classify("DNS/DoH", e); }
        var ips = DnsWire.Addresses(query, answer).Where(ip => ip.AddressFamily == AddressFamily.InterNetwork && !Net.Bogus(ip)).ToArray();
        if (observation is not null) { observation.dnsMs = clock.ElapsedMilliseconds; observation.ipv4 = ips.Select(x => x.ToString()).ToArray(); observation.dns = true; observation.stage = "HTTPS"; }
        if (ips.Length == 0) throw new AiProbeFailure("dns", "DNS не дал доступный адрес для " + host);
        Log.Info("AI DNS проверка " + host + ": DNS -> " + string.Join(",", ips.Select(ip => ip.ToString())) + "; HTTPS напрямую к этому адресу (маршрут VPN сохраняется)");
        Exception? last = null;
        foreach (var ip in ips.Take(2))
        {
            try { await CheckHttps(host, ip, ct, observation); if (observation is not null) { observation.https = true; observation.target = ip.ToString(); observation.stage = "HTTPS проверен"; } return; }
            catch (OperationCanceledException) { throw; }
            catch (Exception e)
            {
                var classified = AiProbeFailure.Classify("HTTPS " + host + " -> " + ip, e);
                if (last is not AiProbeFailure { Kind: "region" or "service_rejected" }) last = classified;
            }
        }
        throw last ?? new AiProbeFailure("https", "Нет доступа к " + host);
    }
    internal static async Task CheckHttps(string host, IPAddress ip, CancellationToken ct, AiProbeObservation? observation = null, bool transportOnly = false)
    {
        string phase = "HTTPS TCP";
        try
        {
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false, AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.All,
            PlaintextStreamFilter = (context, token) => { phase = "HTTPS HTTP"; return ValueTask.FromResult(context.PlaintextStream); },
            ConnectCallback = async (context, token) =>
            {
                var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try { await socket.ConnectAsync(ip, context.DnsEndPoint.Port, token); if (observation is not null) observation.httpsSource = (socket.LocalEndPoint as IPEndPoint)?.Address.ToString() ?? ""; phase = "HTTPS TLS"; return new NetworkStream(socket, true); }
                catch { socket.Dispose(); throw; }
            },
        };
        using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        var url = new Uri("https://" + host + (host == "gemini.google.com" ? "/app?hl=en" : "/"));
        for (int redirect = 0; redirect < 4; redirect++)
        {
            using var request = new HttpRequestMessage(transportOnly ? HttpMethod.Head : HttpMethod.Get, url);
            request.Headers.AcceptLanguage.ParseAdd("en"); request.Headers.UserAgent.ParseAdd("Mozilla/5.0");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (observation is not null) { observation.httpStatus=(int)response.StatusCode; observation.accessState=response.StatusCode==HttpStatusCode.Unauthorized ? "Нужна авторизация (HTTP 401)" : "Проверена только страница, не запрос ИИ"; }
            // Diagnostics only: a HEAD response, including 401/403/404, measures transport.
            // Runtime health checks always use the strict default path below.
            if (transportOnly) return;
            if ((int)response.StatusCode >= 500 || (int)response.StatusCode is 400 or 404 or 451) throw new AiProbeFailure((int)response.StatusCode >= 500 ? "http_server" : "service_rejected", "Сервис вернул HTTP " + (int)response.StatusCode);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
            {
                var next = new Uri(url, location);
                if (next.Scheme != "https" || next.Port != 443) throw new IOException("Небезопасное перенаправление");
                if (GoogleChallenge(next)) throw new AiProbeFailure("browser_challenge", "Google перенаправил на /sorry/: проверка/ограничение IP прокси, не ошибка DNS и не подтверждённый региональный отказ");
                // A redirect to the account service proves connectivity; no account/cookies are sent by this probe.
                if (RegionBlocked(next.AbsoluteUri)) throw new AiProbeFailure("region", "Сервис ограничил регион");
                if (!next.Host.Equals(host, StringComparison.OrdinalIgnoreCase))
                {
                    if (next.Host is "accounts.google.com" or "auth.openai.com" or "auth0.openai.com") { if(observation is not null)observation.accessState="Переход к входу; авторизация не проверена"; return; }
                    throw new IOException("Сервис перенаправил запрос на " + next.Host);
                }
                url = next; continue;
            }
            using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var reader = new StreamReader(stream);
            var buffer = new char[512 * 1024]; int used = 0, n;
            while (used < buffer.Length && (n = await reader.ReadAsync(buffer.AsMemory(used), ct)) > 0) used += n;
            string body = new string(buffer, 0, used);
            if (PageFailure(body) is { } failure) throw new AiProbeFailure(failure, failure == "region" ? "Сервис ограничил регион/IP; это не ошибка DNS" : "Сервис вернул страницу отказа; это не успешный доступ");
            if (response.StatusCode == HttpStatusCode.Forbidden && !body.Contains("challenge-platform", StringComparison.OrdinalIgnoreCase) && !response.Headers.Contains("cf-mitigated"))
                throw new AiProbeFailure("service_rejected", "Сервис отклонил запрос (HTTP 403)");
            if(observation is not null && response.StatusCode==HttpStatusCode.Forbidden)observation.accessState="Требуется проверка браузера (HTTP 403)";
            // TLS/HTTP reachability cannot establish eligibility of a signed-in account.
            return;
        }
        throw new IOException("Слишком много перенаправлений");
        }
        catch (Exception e) { throw AiProbeFailure.At(e, phase, host + " → " + ip + ":443"); }
    }
    internal static bool GoogleChallenge(Uri uri) => uri.Scheme=="https" && uri.Host.Equals("www.google.com",StringComparison.OrdinalIgnoreCase) && uri.AbsolutePath.StartsWith("/sorry/",StringComparison.Ordinal);
}
