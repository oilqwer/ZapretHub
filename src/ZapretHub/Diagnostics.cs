using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace ZapretHub;

public sealed class DiagItem
{
    public string id { get; set; } = "";
    public string title { get; set; } = "";
    public string status { get; set; } = "";
    public string detail { get; set; } = "";
    public string? fix { get; set; }
    public string? fix_label { get; set; }
}

public static class Diagnostics
{
    private static readonly string[] Conflicting = { "GoodbyeDPI", "discordfix_zapret", "winws1", "winws2" };
    private static readonly string Hosts = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32", "drivers", "etc", "hosts");
    private const string HostsBegin = "# >>> zapret-hub", HostsEnd = "# <<< zapret-hub";

    private static List<string> ActiveServices()
    {
        var (_, output) = Sys.Run("sc", new[] { "query" }, 20);
        var names = Regex.Matches(output, @"SERVICE_NAME:\s*(.+)").Select(m => m.Groups[1].Value.Trim()).ToList();
        var displays = Regex.Matches(output, @"DISPLAY_NAME:\s*(.+)").Select(m => m.Groups[1].Value.Trim()).ToList();
        return names.Zip(displays, (n, d) => $"{n} | {d}").ToList();
    }

    private static bool ProcessRunning(string image) =>
        System.Diagnostics.Process.GetProcessesByName(Path.GetFileNameWithoutExtension(image)).Length > 0;

    private static bool DohConfigured()
    {
        bool Walk(RegistryKey? key)
        {
            if (key is null) return false;
            using (key)
            {
                try { if (key.GetValue("DohFlags") is int f && f > 0) return true; } catch { }
                foreach (var sub in key.GetSubKeyNames())
                    if (Walk(key.OpenSubKey(sub))) return true;
            }
            return false;
        }
        try { return Walk(Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters")); }
        catch { return false; }
    }

    private static string? Proxy()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (k?.GetValue("ProxyEnable") is int e && e == 1) return (k.GetValue("ProxyServer") as string) is { Length: > 0 } s ? s : "?";
        }
        catch { }
        return null;
    }

    public static List<DiagItem> RunAll()
    {
        var items = new List<DiagItem>();
        void Add(string id, string title, string status, string detail, string? fix = null, string? label = null) =>
            items.Add(new DiagItem { id = id, title = title, status = status, detail = detail, fix = fix, fix_label = label });

        var missing = new[] { "winws.exe", "WinDivert.dll", "WinDivert64.sys" }.Where(f => !File.Exists(Path.Combine(P.Bin, f))).ToList();
        if (missing.Count > 0)
            Add("files", "Файлы движка", "fail", $"Отсутствуют: {string.Join(", ", missing)}. Скорее всего, их удалил антивирус.", "reinstall", "Переустановить");
        else Add("files", "Файлы движка", "ok", "winws.exe и драйвер WinDivert на месте");

        if (EngineFiles.ServiceState("BFE") == "RUNNING") Add("bfe", "Base Filtering Engine", "ok", "Служба фильтрации Windows работает");
        else Add("bfe", "Base Filtering Engine", "fail", "Служба BFE не запущена — без неё zapret не работает");

        var proxy = Proxy();
        if (proxy != null) Add("proxy", "Системный прокси", "warn", $"Включён прокси {proxy}. Если вы им не пользуетесь — отключите.", "proxy_settings", "Открыть настройки");
        else Add("proxy", "Системный прокси", "ok", "Прокси не используется");

        var (_, tcp) = Sys.Run("netsh", "interface", "tcp", "show", "global");
        if (Regex.IsMatch(tcp, @"(timestamps|метки)[^\n]*:\s*(enabled|включ)", RegexOptions.IgnoreCase)) Add("tcp", "TCP timestamps", "ok", "Включены");
        else Add("tcp", "TCP timestamps", "warn", "Не удалось подтвердить, что временные метки TCP включены", "tcp_timestamps", "Включить");

        var services = ActiveServices();
        List<string> Found(params string[] words) => services.Where(s => words.All(w => s.Contains(w, StringComparison.OrdinalIgnoreCase))).ToList();

        var conflicts = new (string id, string title, List<string> hits, string text)[]
        {
            ("adguard", "AdGuard", ProcessRunning("AdguardSvc.exe") ? new() { "adguard" } : new(), "AdGuard может мешать работе Discord"),
            ("killer", "Killer Network", Found("killer"), "Сервисы Killer конфликтуют с zapret — удалите или отключите их"),
            ("intel", "Intel Connectivity Network", Found("intel", "connectivity", "network"), "Служба Intel Connectivity конфликтует с zapret"),
            ("checkpoint", "Check Point", Found("tracsrvwrapper").Concat(Found("epwd")).ToList(), "Check Point конфликтует с zapret — удалите его"),
            ("smartbyte", "SmartByte", Found("smartbyte"), "SmartByte конфликтует с zapret — отключите службу в services.msc"),
        };
        foreach (var (id, title, hits, text) in conflicts)
            if (hits.Count > 0) Add(id, title, "fail", text); else Add(id, title, "ok", "Не обнаружено");

        var vpn = Found("vpn");
        if (vpn.Count > 0)
            Add("vpn", "VPN", "warn", $"Найдены службы VPN: {string.Join(", ", vpn.Take(4).Select(s => s.Split(" | ")[0]))}. Включённый VPN может конфликтовать с zapret.");
        else Add("vpn", "VPN", "ok", "Активных VPN-служб нет");

        if (DohConfigured()) Add("dns", "Безопасный DNS", "ok", "DNS-over-HTTPS настроен в Windows");
        else Add("dns", "Безопасный DNS", "warn",
            "Включите зашифрованный DNS (DoH) в параметрах Windows или в браузере — без него провайдер подменяет адреса", "dns_settings", "Открыть настройки");

        string hosts;
        try { hosts = File.ReadAllText(Hosts).ToLowerInvariant(); } catch { hosts = ""; }
        if (Regex.IsMatch(hosts, @"^[^#\n]*\b(youtube\.com|youtu\.be)", RegexOptions.Multiline))
            Add("hosts", "Файл hosts", "warn", "В hosts есть записи для youtube.com / youtu.be — они могут ломать YouTube");
        else Add("hosts", "Файл hosts", "ok", "Посторонних записей YouTube нет");

        if (EngineFiles.WinwsPids().Count == 0 && EngineFiles.ServiceState("WinDivert") is "RUNNING" or "STOP_PENDING")
            Add("windivert", "Драйвер WinDivert", "warn", "WinDivert активен, хотя zapret не запущен — его держит другая программа", "remove_windivert", "Выгрузить");
        else Add("windivert", "Драйвер WinDivert", "ok", "Конфликтов нет");

        var other = Conflicting.Where(s => EngineFiles.ServiceState(s) != null).ToList();
        if (other.Count > 0) Add("bypass", "Другие обходы", "fail", $"Установлены конфликтующие службы: {string.Join(", ", other)}", "remove_conflicts", "Удалить службы");
        else Add("bypass", "Другие обходы", "ok", "GoodbyeDPI и другие обходы не установлены");

        if (File.Exists(Path.Combine(Environment.SystemDirectory, "curl.exe"))) Add("curl", "curl.exe", "ok", "Есть — автоподбор стратегий доступен");
        else Add("curl", "curl.exe", "fail", "Не найден curl.exe — автоподбор не сможет проверять сайты");
        return items;
    }

    private static string ClearDiscordCache()
    {
        string appdata = Environment.GetEnvironmentVariable("APPDATA") ?? "";
        var variants = new[] { ("Discord.exe", "discord"), ("DiscordPTB.exe", "discordptb"), ("DiscordCanary.exe", "discordcanary"), ("DiscordDevelopment.exe", "discorddevelopment") };
        int cleared = 0;
        foreach (var (exe, folder) in variants)
        {
            string b = Path.Combine(appdata, folder);
            if (!Directory.Exists(b)) continue;
            Sys.Run("taskkill", "/IM", exe, "/F");
            Thread.Sleep(500);
            foreach (var sub in new[] { "Cache", "Code Cache", "GPUCache" }) Updater.TryDelete(Path.Combine(b, sub));
            cleared++;
        }
        if (cleared == 0) throw new InvalidOperationException("Discord не найден");
        return "Кэш Discord очищен — запустите Discord заново";
    }

    // Пока в подписанном манифесте нет компонента hosts, обновление отключено (кнопка в интерфейсе неактивна).
    private static readonly bool HostsUpdateAvailable = false;

    private static string UpdateHosts()
    {
        if (!HostsUpdateAvailable) throw new InvalidOperationException("Обновление hosts временно недоступно: подписанный список записей ещё не опубликован");
        // hosts пишется в системный файл от имени администратора, поэтому принимается только содержимое, хэш которого подписан автором.
        string url, sha;
        try { (_, url, sha) = Integrity.Approved(Integrity.LoadManifest(), "hosts"); }
        catch (IntegrityException e) { throw new IntegrityException("Обновление hosts недоступно: " + e.Message); }
        var bytes = Net.Fetch(url);
        if (bytes.Length > 1_000_000 || !string.Equals(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)), sha, StringComparison.OrdinalIgnoreCase))
            throw new IntegrityException("Содержимое hosts не совпадает с подписанным");
        string remote = System.Text.Encoding.UTF8.GetString(bytes).Trim();
        if (remote.Length == 0) throw new InvalidOperationException("Не удалось скачать hosts из репозитория");
        foreach (var l in remote.Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0 && !x.StartsWith('#')))
            if (!Regex.IsMatch(l, @"^\d{1,3}(\.\d{1,3}){3}\s+[A-Za-z0-9._-]+(\s+[A-Za-z0-9._-]+)*\s*(#.*)?$"))
                throw new IntegrityException("В hosts есть недопустимая строка: " + l);
        string current = File.ReadAllText(Hosts);
        string cleaned = Regex.Replace(current, $@"\n?{Regex.Escape(HostsBegin)}.*?{Regex.Escape(HostsEnd)}\n?", "\n", RegexOptions.Singleline);
        var lines = remote.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#'));
        if (lines.All(cleaned.Contains) && cleaned == current) return "Файл hosts уже актуален";
        Directory.CreateDirectory(P.Root);
        File.Copy(Hosts, Path.Combine(P.Root, "hosts.backup"), true);
        File.SetAttributes(Hosts, FileAttributes.Normal);
        File.WriteAllText(Hosts, cleaned.TrimEnd() + $"\n\n{HostsBegin}\n{remote}\n{HostsEnd}\n");
        Sys.Run("ipconfig", "/flushdns");
        return "hosts обновлён (копия старого — в hosts.backup)";
    }

    public static string? Fix(string action)
    {
        switch (action)
        {
            case "proxy_settings": Sys.OpenShell("ms-settings:network-proxy"); return null;
            case "dns_settings": Sys.OpenShell("ms-settings:network"); return null;
            case "open_engine": Sys.OpenShell(Directory.Exists(P.Engine) ? P.Engine : P.Root); return null;
        }
        P.Need("исправление системы");
        switch (action)
        {
            case "tcp_timestamps":
                Sys.Run("netsh", "interface", "tcp", "set", "global", "timestamps=enabled");
                return "Временные метки TCP включены";
            case "remove_windivert":
                foreach (var n in new[] { "WinDivert", "WinDivert14" }) EngineFiles.RemoveService(n);
                return "Драйвер WinDivert выгружен";
            case "remove_conflicts":
                foreach (var n in Conflicting) EngineFiles.RemoveService(n);
                return "Конфликтующие службы удалены";
            case "clear_discord_cache": return ClearDiscordCache();
            case "update_hosts": return UpdateHosts();
        }
        throw new ArgumentException("Неизвестное действие: " + action);
    }
}
