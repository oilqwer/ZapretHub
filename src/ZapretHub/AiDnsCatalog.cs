namespace ZapretHub;

public sealed class AiDnsEntry
{
    public string id { get; set; } = "";
    public string name { get; set; } = "";
    public bool custom { get; set; }
    public List<DnsServer> servers { get; set; } = new();
}

internal static class AiDnsCatalog
{
    internal static string Key(DnsServer s) => s.address + "|" + s.template + "|" + s.doh + "|" + s.fallback;
    private static DnsServer At(DnsServer s, string ip) { s.address = ip; return s; }
    internal static List<AiDnsEntry> Entries(AiCfg cfg) => new List<AiDnsEntry> {
        new() { id="dnsai", name="DNS-AI", servers=new() { AiDns.DnsAiPrimary(), AiDns.DnsAiAlternate() } },
        new() { id="webshift", name="WebShift", servers=new() { AiDns.RecPrimary() } },
        new() { id="geohide", name="GeoHide", servers=new() { AiDns.RecAlternate() } },
        new() { id="malw", name="Malw.link", servers=new() { AiDns.MalwPrimary(), At(AiDns.MalwPrimary(), "164.5.224.81") } },
        new() { id="gateway", name="Malw.link Cloudflare Gateway", servers=new() { AiDns.MalwGateway(), At(AiDns.MalwGateway(), "162.159.36.20") } },
        new() { id="bezmezhau", name="Bezmezhau", servers=new() { AiDns.BezmezhauPrimary(), At(AiDns.BezmezhauPrimary(), "31.58.216.201") } },
    }.Concat(cfg.customServers).ToList();

    internal static AiCfg Normalize(AiCfg cfg)
    {
        cfg.customServers ??= new();
        if (cfg.selectionMode.Length == 0)
        {
            cfg.selectionMode = cfg.autoSwitch ? "auto" : "manual";
            // Keep legacy user edits and explicit alternate as selectable entries.
            var entries = Entries(cfg);
            string Import(DnsServer server, string id)
            {
                var match = entries.FirstOrDefault(e => e.servers.Any(s => Key(s) == Key(server)));
                if (match is not null) return match.id + "@" + server.address;
                cfg.customServers.Add(new() { id=id, name="Сохранённый DNS", custom=true, servers=new() { server.Clone() } });
                return id;
            }
            cfg.manualChatgpt = cfg.manualGemini = Import(cfg.primary, "custom-legacy-primary");
            if (cfg.alternate.address.Length > 0) cfg.fallbackChatgpt = cfg.fallbackGemini = Import(cfg.alternate, "custom-legacy-alternate");
        }
        return cfg;
    }
    internal static void Validate(AiCfg cfg)
    {
        if (cfg.selectionMode is not ("auto" or "manual")) throw new ArgumentException("Выберите автоматический или ручной режим");
        if (cfg.customServers.Count > 12) throw new ArgumentException("Не больше 12 пользовательских DNS");
        foreach (var e in cfg.customServers)
        {
            if (!e.custom || !e.id.StartsWith("custom-", StringComparison.Ordinal) || e.id.Length > 80 || e.name.Length is < 1 or > 80 || e.servers.Count is < 1 or > 2)
                throw new ArgumentException("Некорректная пользовательская запись DNS");
            foreach (var s in e.servers) AiDns.Validate(s, false, e.name);
        }
        var entries = Entries(cfg);
        if (entries.Select(e => e.id).Distinct().Count() != entries.Count) throw new ArgumentException("Повтор идентификатора DNS");
        foreach (var id in new[] { cfg.manualChatgpt, cfg.manualGemini, cfg.fallbackChatgpt, cfg.fallbackGemini }.Where(x => x.Length > 0))
            if (!entries.Any(e => e.id == id.Split('@')[0] && (!id.Contains('@') || e.servers.Any(s => s.address == id.Split('@')[1])))) throw new ArgumentException("Выбранный DNS отсутствует в списке: " + id);
        if (cfg.manualChatgpt.Length == 0 || cfg.manualGemini.Length == 0) throw new ArgumentException("Назначьте DNS обоим сервисам");
    }
    internal static Dictionary<string, string[]>? Plan(AiCfg cfg)
    {
        if (cfg.selectionMode != "manual") return null;
        var entries = Entries(cfg);
        IEnumerable<DnsServer> Endpoint(string id) => id.Length == 0 ? Array.Empty<DnsServer>() : entries.Where(e => e.id == id.Split('@')[0]).SelectMany(e => e.servers).Where(s => !id.Contains('@') || s.address == id.Split('@')[1]).Take(1);
        string[] Keys(string id, string backup) => Endpoint(id).Concat(Endpoint(backup)).Select(Key).Distinct().ToArray();
        return new() { ["chatgpt.com"] = Keys(cfg.manualChatgpt, cfg.fallbackChatgpt), ["gemini.google.com"] = Keys(cfg.manualGemini, cfg.fallbackGemini) };
    }
    internal static List<DnsServer> Candidates(AiCfg cfg)
    {
        Validate(cfg);
        var entries = Entries(cfg);
        var plan = Plan(cfg);
        return entries.SelectMany(e => e.servers).Where(s => plan is null || plan.Values.Any(keys => keys.Contains(Key(s))))
            .DistinctBy(Key).Select(s => s.Clone()).ToList();
    }
}
