using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretHub;

// Read-only: no relay listener, NRPT, cache flush, adapter writes, browser or proxy connections.
internal static class AiDnsDiagnostic
{
    internal static readonly string[] Hosts = {
        "chatgpt.com", "api.openai.com", "auth.openai.com", "auth0.openai.com",
        "cdn.oaistatic.com", "files.oaiusercontent.com", "challenges.cloudflare.com",
        "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
        "accounts.google.com", "alkalimakersuite-pa.clients6.google.com"
    };
    internal sealed record Result(string Provider, string Transport, string Host, string Type,
        long Milliseconds, string[] Addresses, int? Rcode, string? Error, string? Https);

    internal static string Compare(IEnumerable<string> smart, IEnumerable<string> ordinary) =>
        !smart.Any() || !ordinary.Any() ? "NO_COMPARISON" :
        smart.ToHashSet().SetEquals(ordinary) ? "SAME_ADDRESSES_NOT_PROOF_OF_PROXY" : "DIFFERENT_ADDRESSES_NOT_PROOF_OF_PROXY";

    internal static int Run(string report, string settingsPath)
    {
        try { RunCore(report, settingsPath).GetAwaiter().GetResult(); return 0; }
        catch (Exception e) { File.WriteAllText(report, JsonSerializer.Serialize(new { error = e.Message })); return 1; }
    }
    private static async Task RunCore(string report, string settingsPath)
    {
        var cfg = AiDns.DefaultConfig();
        if (File.Exists(settingsPath))
            cfg = JsonNode.Parse(File.ReadAllText(settingsPath))?["aidns"]?.Deserialize<AiCfg>() ?? cfg;
        var providers = AiDns.Candidates(cfg).ToList();
        // Baseline for comparison only. Never enters the application's Smart DNS failover pool.
        var baseline = new DnsServer { address = "1.1.1.1", doh = true, template = "https://cloudflare-dns.com/dns-query" };
        var jobs = providers.SelectMany(s => new[] { (s, "DoH-strict"), (s, "UDP-explicit") })
            .Where(x => x.Item2 != "UDP-explicit" || x.s.fallback || !x.s.doh)
            .Append((baseline, "DoH-baseline")).ToArray();
        var rows = new List<Result>();
        // One serial stream per provider/transport; no concurrent probe storm.
        await Task.WhenAll(jobs.Select(async job =>
        {
            var server = job.Item1.Clone();
            server.doh = job.Item2 != "UDP-explicit";
            server.fallback = false;
            using var exchange = new DnsExchange(server);
            bool transportFailed = false;
            foreach (var host in Hosts)
            foreach (ushort type in new ushort[] { 1, 28 })
            {
                var watch = Stopwatch.StartNew();
                string[] addresses = Array.Empty<string>(); int? rcode = null; string? error = null, https = null;
                if (transportFailed) { lock (rows) rows.Add(new(server.address, job.Item2, host, type == 1 ? "A" : "AAAA", 0, addresses, null, "SKIPPED_AFTER_TRANSPORT_FAILURE", null)); continue; }
                try
                {
                    byte[] query = DnsWire.Query(host, type), answer = Array.Empty<byte>();
                    await AiProbeFailure.WithinDeadline(async ct => answer = await exchange.Query(query, ct), default);
                    addresses = DnsWire.Addresses(query, answer).Select(x => x.ToString()).ToArray(); rcode = answer[3] & 15;
                }
                catch (Exception e) { error = Describe("DNS/DoH", e); transportFailed = true; }
                long dnsMs = watch.ElapsedMilliseconds;
                if (host is "chatgpt.com" or "gemini.google.com")
                {
                    var probes = new List<string>();
                    foreach (var address in addresses.Take(2))
                    {
                        var ip = IPAddress.Parse(address);
                        if (Net.Bogus(ip)) { probes.Add(address + " REJECTED_NON_PUBLIC"); continue; }
                        try
                        {
                            await AiProbeFailure.WithinDeadline(ct => AiServiceProbe.CheckHttps(host, ip, ct), default);
                            probes.Add(address + " TLS_HTTP_REACHABLE; APP_REQUEST_UNVERIFIED");
                        }
                        catch (Exception e) { probes.Add(address + " " + Describe("HTTPS pinned endpoint", e)); }
                    }
                    https = string.Join("; ", probes);
                }
                lock (rows) rows.Add(new(server.address, job.Item2, host, type == 1 ? "A" : "AAAA", dnsMs, addresses, rcode, error, https));
            }
        }));
        var comparisons = rows.Where(x => x.Transport != "DoH-baseline").Select(x => new {
            x.Provider, x.Transport, x.Host, x.Type,
            comparison = Compare(x.Addresses, rows.FirstOrDefault(b => b.Transport == "DoH-baseline" && b.Host == x.Host && b.Type == x.Type)?.Addresses ?? Array.Empty<string>()),
            nrptCovered = AiDnsPolicy.IsAiHost(x.Host)
        }).ToArray();
        var adapters = NetworkInterface.GetAllNetworkInterfaces().Where(x => x.OperationalStatus == OperationalStatus.Up)
            .Select(x => new { x.Name, x.Description, type = x.NetworkInterfaceType.ToString(), dns = x.GetIPProperties().DnsAddresses.Select(a => a.ToString()).ToArray() }).ToArray();
        File.WriteAllText(report, JsonSerializer.Serialize(new {
            utc = DateTime.UtcNow, vpnAbsence = "NOT_VERIFIED: direct sockets still follow OS/VPN routes; user must disable VPN manually",
            applicationAccess = "NOT_VERIFIED: requires signed-in browser requests to both services",
            notes = "No system DNS substitution; DoH and UDP are separate. SAME/DIFFERENT IP sets do not prove proxy use. AAAA may take a different path. No settings changed.",
            adapters, providers, rows = rows.OrderBy(x => x.Provider).ThenBy(x => x.Transport).ThenBy(x => x.Host).ThenBy(x => x.Type), comparisons
        }, new JsonSerializerOptions { WriteIndented = true }));
    }
    private static string Describe(string stage, Exception e)
    {
        var failure = AiProbeFailure.Classify(stage, e);
        string detail = "";
        for (Exception? cause = e; cause is not null; cause = cause.InnerException)
            if (cause.Data["AiDnsStage"] is string value) { detail = " | " + value; break; }
        return failure.Kind + ": " + failure.Message + " | " + e.GetBaseException().Message + detail;
    }
}
