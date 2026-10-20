using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace ZapretHub;

public sealed class DnsServer
{
    public string address { get; set; } = "";
    public bool doh { get; set; }
    public string template { get; set; } = "";
    public bool fallback { get; set; }
    public DnsServer Clone() => new() { address = address, doh = doh, template = template, fallback = fallback };
}

public sealed class AiCfg
{
    public bool enabled { get; set; }
    public DnsServer primary { get; set; } = new();
    public DnsServer alternate { get; set; } = new();
    public List<string>? adapters { get; set; }
    public Dictionary<string, string> backup { get; set; } = new();
    public bool imported { get; set; }
}

public sealed class AdapterInfo
{
    public string id { get; set; } = "";
    public string name { get; set; } = "";
    public string description { get; set; } = "";
    public bool physical { get; set; }
    public string current { get; set; } = "";
    public bool selected { get; set; }
}

public sealed record ProbeResult(int level, string text);

/// <summary>AI DNS: DNS-серверы, открывающие ИИ-сервисы, на выбранных адаптерах (SetInterfaceDnsSettings, как в Параметрах Windows 11).</summary>
public static class AiDns
{
    public const string ProbeName = "api.openai.com";
    public const int DohAttempts = 3;
    public static readonly string[] Services = { "ChatGPT", "Gemini", "Claude", "Grok", "Copilot", "Perplexity" };

    public static DnsServer RecPrimary() => new() { address = "31.31.207.68", doh = true, template = "https://d.webshiftvpn.ru/dns-query", fallback = true };
    public static DnsServer RecAlternate() => new() { address = "159.194.200.33", doh = true, template = "https://geohide.ru/dns-query", fallback = true };

    public static readonly string StandaloneIni = Path.Combine(Environment.GetEnvironmentVariable("APPDATA") ?? "", "AI DNS", "settings.ini");

    // ---------- Windows API ----------

    [StructLayout(LayoutKind.Sequential)]
    private struct DNS_INTERFACE_SETTINGS3
    {
        public uint Version; public ulong Flags; public IntPtr Domain; public IntPtr NameServer; public IntPtr SearchList;
        public uint RegistrationEnabled, RegisterAdapterName, EnableLLMNR, QueryAdapterName;
        public IntPtr ProfileNameServer; public uint DisableUnconstrainedQueries; public IntPtr SupplementalSearchList;
        public uint cServerProperties; public IntPtr ServerProperties; public uint cProfileServerProperties; public IntPtr ProfileServerProperties;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DNS_SERVER_PROPERTY { public uint Version; public uint ServerIndex; public int Type; public IntPtr DohSettings; }

    [StructLayout(LayoutKind.Sequential)]
    private struct DNS_DOH_SERVER_SETTINGS { public IntPtr Template; public ulong Flags; }

    private const uint V1 = 1, V3 = 3;
    private const ulong SettingNameServer = 0x0002, SettingDoh = 0x1000, DohEnable = 0x0002, DohFallback = 0x0004;

    [DllImport("iphlpapi.dll")]
    private static extern uint SetInterfaceDnsSettings(Guid iface, ref DNS_INTERFACE_SETTINGS3 settings);
    [DllImport("dnsapi.dll")]
    private static extern int DnsFlushResolverCache();

    private static void SetSettings(string adapterId, ref DNS_INTERFACE_SETTINGS3 s)
    {
        uint rc = SetInterfaceDnsSettings(Guid.Parse(adapterId), ref s);
        if (rc != 0) throw new IOException($"{new System.ComponentModel.Win32Exception((int)rc).Message} (код {rc})");
        try { DnsFlushResolverCache(); } catch { }
    }

    public static void Apply(string adapterId, List<DnsServer> servers)
    {
        P.Need("смена DNS адаптеров");
        var toFree = new List<IntPtr>();
        try
        {
            var props = new List<DNS_SERVER_PROPERTY>();
            for (int i = 0; i < servers.Count; i++)
            {
                if (!servers[i].doh) continue;
                var tpl = Marshal.StringToHGlobalUni(servers[i].template.Trim()); toFree.Add(tpl);
                var doh = new DNS_DOH_SERVER_SETTINGS { Template = tpl, Flags = DohEnable | (servers[i].fallback ? DohFallback : 0) };
                var pd = Marshal.AllocHGlobal(Marshal.SizeOf<DNS_DOH_SERVER_SETTINGS>()); toFree.Add(pd);
                Marshal.StructureToPtr(doh, pd, false);
                props.Add(new DNS_SERVER_PROPERTY { Version = V1, ServerIndex = (uint)i, Type = 1, DohSettings = pd });
            }
            IntPtr arr = IntPtr.Zero;
            if (props.Count > 0)
            {
                int sz = Marshal.SizeOf<DNS_SERVER_PROPERTY>();
                arr = Marshal.AllocHGlobal(sz * props.Count); toFree.Add(arr);
                for (int i = 0; i < props.Count; i++) Marshal.StructureToPtr(props[i], arr + i * sz, false);
            }
            var ns = Marshal.StringToHGlobalUni(string.Join(",", servers.Select(s => s.address.Trim()))); toFree.Add(ns);
            var settings = new DNS_INTERFACE_SETTINGS3
            {
                Version = V3, Flags = SettingNameServer | SettingDoh, NameServer = ns,
                cServerProperties = (uint)props.Count, ServerProperties = arr,
            };
            SetSettings(adapterId, ref settings);
        }
        finally { foreach (var p in toFree) Marshal.FreeHGlobal(p); }
    }

    /// <summary>Возвращает прежние статические DNS адаптера, а если их не было — автоматические (DHCP).</summary>
    public static void Restore(string adapterId, string? previous)
    {
        P.Need("возврат DNS адаптеров");
        string ns = (previous ?? "").Trim();
        var nsPtr = Marshal.StringToHGlobalUni(ns);
        try
        {
            var settings = new DNS_INTERFACE_SETTINGS3 { Version = V3, Flags = SettingNameServer | (ns.Length > 0 ? SettingDoh : 0), NameServer = nsPtr };
            SetSettings(adapterId, ref settings);
        }
        finally { Marshal.FreeHGlobal(nsPtr); }
    }

    public static string StaticServers(string adapterId)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{adapterId}");
            return ((k?.GetValue("NameServer") as string) ?? "").Trim();
        }
        catch { return ""; }
    }

    public static List<AdapterInfo> Adapters()
    {
        var result = new List<AdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var kind = nic.NetworkInterfaceType;
            if (kind is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            if (nic.OperationalStatus != OperationalStatus.Up || !nic.Supports(NetworkInterfaceComponent.IPv4)) continue;
            string d = nic.Description.ToLowerInvariant();
            bool virt = new[] { "virtual", "hyper-v", "vpn", "tap-", "wintun", "wireguard", "vmware", "virtualbox" }.Any(d.Contains);
            bool physical = !virt && kind is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211;
            result.Add(new AdapterInfo { id = nic.Id, name = nic.Name, description = nic.Description, physical = physical, current = StaticServers(nic.Id) });
        }
        return result;
    }

    // ---------- проверка сервера ----------

    private static byte[] Query(string name, ushort qid)
    {
        var ms = new MemoryStream();
        void U16(ushort v) { ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)v); }
        U16(qid); U16(0x0100); U16(1); U16(0); U16(0); U16(0);
        foreach (var part in name.Split('.')) { ms.WriteByte((byte)part.Length); ms.Write(Encoding.ASCII.GetBytes(part)); }
        ms.WriteByte(0); U16(1); U16(1);
        return ms.ToArray();
    }

    private static int SkipName(byte[] b, int pos)
    {
        while (true)
        {
            int n = b[pos];
            if (n == 0) return pos + 1;
            if ((n & 0xC0) == 0xC0) return pos + 2;
            pos += n + 1;
        }
    }

    private static string? FirstA(byte[] b, int len, ushort qid)
    {
        if (len < 12 || ((b[0] << 8) | b[1]) != qid) return null;
        int qd = (b[4] << 8) | b[5], an = (b[6] << 8) | b[7];
        int pos = 12;
        for (int i = 0; i < qd; i++) pos = SkipName(b, pos) + 4;
        for (int i = 0; i < an; i++)
        {
            pos = SkipName(b, pos);
            int rtype = (b[pos] << 8) | b[pos + 1], rdlen = (b[pos + 8] << 8) | b[pos + 9];
            pos += 10;
            if (rtype == 1 && rdlen == 4) return $"{b[pos]}.{b[pos + 1]}.{b[pos + 2]}.{b[pos + 3]}";
            pos += rdlen;
        }
        return null;
    }

    private static string? QueryA(string server, string name)
    {
        ushort qid = (ushort)Random.Shared.Next(0x10000);
        using var udp = new UdpClient();
        udp.Client.ReceiveTimeout = 2500;
        udp.Connect(server, 53);
        var q = Query(name, qid);
        udp.Send(q, q.Length);
        IPEndPoint? ep = null;
        var resp = udp.Receive(ref ep);
        return FirstA(resp, resp.Length, qid);
    }

    private static bool TlsOk(string ip, string sni)
    {
        try
        {
            using var tcp = new TcpClient();
            if (!tcp.ConnectAsync(ip, 443).Wait(4000)) return false;
            using var ssl = new SslStream(tcp.GetStream());
            ssl.ReadTimeout = ssl.WriteTimeout = 4000;
            ssl.AuthenticateAsClient(sni);
            return true;
        }
        catch { return false; }
    }

    private static bool DohOk(string server, string template)
    {
        try
        {
            var u = new Uri(template);
            string dns = Convert.ToBase64String(Query("example.com", 0)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            string path = (u.AbsolutePath.Length > 0 ? u.AbsolutePath : "/") + (u.Query.Length > 1 ? u.Query + "&" : "?") + "dns=" + dns;
            using var tcp = new TcpClient();
            if (!tcp.ConnectAsync(server, u.Port).Wait(5000)) return false;
            using var ssl = new SslStream(tcp.GetStream());
            ssl.ReadTimeout = ssl.WriteTimeout = 6000;
            ssl.AuthenticateAsClient(u.Host);
            var req = Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: {u.Host}\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n");
            ssl.Write(req); ssl.Flush();
            var buf = new byte[64];
            int n = ssl.Read(buf, 0, buf.Length);
            return Encoding.ASCII.GetString(buf, 0, n).StartsWith("HTTP/1.1 200");
        }
        catch { return false; }
    }

    public static ProbeResult Check(DnsServer server)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        string? proxy;
        try { proxy = QueryA(server.address, ProbeName); }
        catch { return new(2, "Не отвечает на DNS-запросы"); }
        long dnsMs = sw.ElapsedMilliseconds;
        if (proxy is null) return new(2, "Не дал адрес для ChatGPT");
        if (proxy == "0.0.0.0") return new(2, "Блокирует ИИ-сервисы (отдаёт 0.0.0.0)");
        bool proxyOk = TlsOk(proxy, ProbeName);
        string text = $"DNS {dnsMs} мс · прокси {(proxyOk ? "работает" : "не отвечает")}";
        int level = proxyOk ? 0 : 2;
        if (server.doh)
        {
            var tasks = Enumerable.Range(0, DohAttempts).Select(_ => Task.Run(() => DohOk(server.address, server.template))).ToArray();
            int ok = tasks.Count(t => t.GetAwaiter().GetResult());
            text += $" · DoH {ok} из {DohAttempts}";
            if (ok < DohAttempts && level == 0) level = 1;
            if (ok < DohAttempts && !server.fallback) text += " — включите возврат к открытому тексту";
        }
        return new(level, text);
    }

    // ---------- настройки ----------

    public static void Validate(DnsServer s, bool optional, string name)
    {
        string a = s.address.Trim();
        if (a.Length == 0 && optional) return;
        if (!(IPAddress.TryParse(a, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork && a.Count(c => c == '.') == 3))
            throw new ArgumentException($"Неверный IP-адрес {name} (нужен IPv4, например 31.31.207.68)");
        if (s.doh && !s.template.Trim().StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Шаблон {name} должен начинаться с https://");
    }

    public static AiCfg DefaultConfig() => new() { primary = RecPrimary(), alternate = RecAlternate() };

    public static AiCfg? ImportStandalone()
    {
        string[] lines;
        try { lines = File.ReadAllText(StandaloneIni, Encoding.UTF8).TrimStart('﻿').Split('\n'); } catch { return null; }
        var d = new Dictionary<string, string>();
        foreach (var l in lines)
        {
            int eq = l.IndexOf('=');
            if (eq > 0) d[l[..eq].Trim()] = l[(eq + 1)..].Trim();
        }
        bool Flag(string k, bool def) => (d.TryGetValue(k, out var v) ? v : def.ToString()).Equals("true", StringComparison.OrdinalIgnoreCase);
        var cfg = DefaultConfig();
        foreach (var (key, s) in new[] { ("primary", cfg.primary), ("alternate", cfg.alternate) })
        {
            s.address = d.GetValueOrDefault($"{key}.address", s.address);
            s.doh = Flag($"{key}.doh", s.doh);
            s.template = d.GetValueOrDefault($"{key}.template", s.template);
            s.fallback = Flag($"{key}.fallback", s.fallback);
        }
        if (d.TryGetValue("adapters", out var ad)) cfg.adapters = ad.Split(';').Where(a => a.Length > 0).ToList();
        foreach (var kv in d.Where(kv => kv.Key.StartsWith("backup."))) cfg.backup[kv.Key[7..]] = kv.Value;
        cfg.enabled = Flag("enabled", false);
        cfg.imported = true;
        return cfg;
    }

    public static List<DnsServer> ServersOf(AiCfg cfg) =>
        new[] { cfg.primary }.Concat(cfg.alternate.address.Trim().Length > 0 ? new[] { cfg.alternate } : Array.Empty<DnsServer>()).ToList();

    public static void ApplyToSelected(AiCfg cfg, IEnumerable<string> selected)
    {
        var servers = ServersOf(cfg);
        string ours = string.Join(",", servers.Select(s => s.address));
        foreach (var id in selected)
        {
            if (!cfg.backup.ContainsKey(id))
            {
                string cur = StaticServers(id);
                // Свои же серверы (например, после сбоя) не сохраняем — тогда при выключении вернётся «автоматически».
                cfg.backup[id] = cur.Replace(" ", ",") == ours ? "" : cur;
            }
            Apply(id, servers);
        }
    }
}
