using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace ZapretHub;

/// <summary>Стратегии — оригинальные general*.bat от Flowseal: после обновления движка они перечитываются.</summary>
public static class Strategies
{
    private static string NaturalKey(string name) =>
        Regex.Replace(Regex.Replace(name.ToLowerInvariant(), @"[()]", ""), @"\d+", m => m.Value.PadLeft(8, '0'));

    public static List<string> List()
    {
        if (!Directory.Exists(P.Engine)) return new();
        return Directory.GetFiles(P.Engine, "*.bat")
            .Select(Path.GetFileNameWithoutExtension).Cast<string>()
            .Where(n => !n.StartsWith("service", StringComparison.OrdinalIgnoreCase))
            .OrderBy(NaturalKey, StringComparer.Ordinal).ToList();
    }

    /// <summary>Как cmd.exe: вне кавычек ^X превращается в X.</summary>
    private static string CmdUnescape(string s)
    {
        var sb = new StringBuilder();
        bool quoted = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '"') quoted = !quoted;
            else if (c == '^' && !quoted && i + 1 < s.Length) { i++; c = s[i]; }
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>Аргументы winws.exe (без пути к exe) из .bat: склеиваем строки с ^ и подставляем %BIN%, %LISTS%, %GameFilter*%.</summary>
    public static string BuildArgs(string name, Dictionary<string, string> gameVars)
    {
        string text = File.ReadAllText(Path.Combine(P.Engine, name + ".bat"), Encoding.UTF8);
        text = Regex.Replace(text, @"\^[ \t]*\r?\n", " ");
        string? line = text.Split('\n').Select(l => l.TrimEnd('\r')).FirstOrDefault(l => l.Contains("winws.exe", StringComparison.OrdinalIgnoreCase));
        if (line is null) throw new InvalidOperationException($"В стратегии «{name}» не найден запуск winws.exe");
        int idx = line.IndexOf("winws.exe", StringComparison.OrdinalIgnoreCase) + "winws.exe".Length;
        string args = CmdUnescape(line[idx..].TrimStart('"').Trim());

        args = args.Replace("%~dp0", P.Engine + "\\");
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["bin"] = P.Bin + "\\", ["lists"] = P.Lists + "\\",
        };
        foreach (var kv in gameVars) values[kv.Key] = kv.Value;
        args = Regex.Replace(args, @"%(\w+)%", m =>
        {
            if (!values.TryGetValue(m.Groups[1].Value, out var v))
                throw new InvalidOperationException($"Неизвестная переменная %{m.Groups[1].Value}% в стратегии «{name}»");
            return v;
        });
        return args;
    }

    public static string BuildCommand(string name, Dictionary<string, string> gameVars) =>
        $"\"{Path.Combine(P.Bin, "winws.exe")}\" {BuildArgs(name, gameVars)}";
}

public sealed record GameFilterCfg(string mode, string tcp, string udp);
public sealed record FakesInfo(List<string> files, string? discord, string? game);

public static class EngineFiles
{
    public const string Service = "zapret";
    public const string ServiceKey = @"System\CurrentControlSet\Services\zapret";
    public const string IpsetPlaceholder = "203.0.113.113/32";
    public static string Ipset => Path.Combine(P.Lists, "ipset-all.txt");
    public static string IpsetBackup => Path.Combine(P.Lists, "ipset-all.txt.backup");
    public static string GameFlag => Path.Combine(P.Utils, "game_filter.enabled");
    public static readonly Dictionary<string, string> FakeTargets = new() { ["discord"] = "ACTIVE_DISCORD_UDP.bin", ["game"] = "ACTIVE_GAME_UDP.bin" };
    public static readonly Dictionary<string, (string file, string def)> UserLists = new()
    {
        ["general"] = ("list-general-user.txt", "# Never leave this file empty\ndomain.example.abc\n"),
        ["exclude"] = ("list-exclude-user.txt", "domain.example.abc\n"),
        ["ipset_exclude"] = ("ipset-exclude-user.txt", IpsetPlaceholder + "\n"),
    };
    private static readonly HashSet<string> Placeholders = new() { "domain.example.abc", IpsetPlaceholder };

    public static bool Installed() => File.Exists(Path.Combine(P.Bin, "winws.exe"));

    // ---------- процессы и службы ----------

    public static List<int> WinwsPids()
    {
        var res = new List<int>();
        foreach (var p in Process.GetProcessesByName("winws")) { res.Add(p.Id); p.Dispose(); }
        return res;
    }

    public static void KillWinws()
    {
        if (P.Sandbox) return; // в тестовом режиме чужие winws.exe не трогаем
        foreach (var p in Process.GetProcessesByName("winws"))
        {
            try { p.Kill(true); } catch { }
            p.Dispose();
        }
    }

    public static string? ServiceState(string name)
    {
        var (code, output) = Sys.Run("sc", "query", name);
        if (code != 0) return null;
        var m = Regex.Match(output, @":\s*\d+\s+(RUNNING|STOPPED|START_PENDING|STOP_PENDING|PAUSED)");
        return m.Success ? m.Groups[1].Value : "UNKNOWN";
    }

    public static void RemoveService(string name)
    {
        if (P.Sandbox) return;
        if (ServiceState(name) is null) return;
        Sys.Run("sc", "stop", name);
        for (int i = 0; i < 20; i++)
        {
            var st = ServiceState(name);
            if (st is null or "STOPPED") break;
            Thread.Sleep(250);
        }
        Sys.Run("sc", "delete", name);
    }

    public static string? ServiceStrategy()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(ServiceKey);
            return k?.GetValue("zapret-discord-youtube") as string;
        }
        catch { return null; }
    }

    // ---------- Game Filter ----------

    public static bool ValidPorts(string? value)
    {
        value = (value ?? "").Replace(" ", "");
        if (value.Length == 0) return false;
        foreach (var item in value.Split(','))
        {
            var m = Regex.Match(item, @"^([1-9]\d{0,4})(?:-([1-9]\d{0,4}))?$");
            if (!m.Success) return false;
            int start = int.Parse(m.Groups[1].Value), end = m.Groups[2].Success ? int.Parse(m.Groups[2].Value) : start;
            if (end > 65535 || start > end) return false;
        }
        return true;
    }

    public static GameFilterCfg GameFilter()
    {
        string mode = "disabled", tcp = "1024-65535", udp = "1024-65535";
        string[] lines;
        try { lines = File.ReadAllText(GameFlag, Encoding.UTF8).Split('\n'); }
        catch { return new(mode, tcp, udp); }
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            int eq = line.IndexOf('=');
            string key = (eq < 0 ? line : line[..eq]).ToLowerInvariant();
            string val = eq < 0 ? "" : line[(eq + 1)..].Trim();
            if (key == "mode") mode = val.ToLowerInvariant();
            else if (key == "all") mode = "all";
            else if (key is "tcp" or "udp")
            {
                if (val.Length == 0) mode = key; // старый формат файла
                else if (ValidPorts(val)) { if (key == "tcp") tcp = val.Replace(" ", ""); else udp = val.Replace(" ", ""); }
            }
        }
        if (mode is not ("all" or "tcp" or "udp")) mode = "disabled";
        return new(mode, tcp, udp);
    }

    public static void SetGameFilter(string mode, string tcp, string udp)
    {
        if (mode is not ("disabled" or "all" or "tcp" or "udp")) throw new ArgumentException("Неизвестный режим Game Filter");
        if (!ValidPorts(tcp)) throw new ArgumentException("Неверные TCP-порты: используйте формат 1024-65535 или 1024-1934,1936-65535");
        if (!ValidPorts(udp)) throw new ArgumentException("Неверные UDP-порты: используйте формат 1024-65535 или 1024-1934,1936-65535");
        Directory.CreateDirectory(P.Utils);
        File.WriteAllText(GameFlag, $"mode={mode}\ntcp={tcp.Replace(" ", "")}\nudp={udp.Replace(" ", "")}\n", new UTF8Encoding(false));
    }

    /// <summary>Значения переменных так же, как их выставляет service.bat (12 — заглушка «фильтр выключен»).</summary>
    public static Dictionary<string, string> GameFilterVars()
    {
        var gf = GameFilter();
        string tcp = gf.mode is "all" or "tcp" ? gf.tcp : "12";
        string udp = gf.mode is "all" or "udp" ? gf.udp : "12";
        return new() { ["GameFilter"] = gf.mode == "udp" ? udp : tcp, ["GameFilterTCP"] = tcp, ["GameFilterUDP"] = udp };
    }

    // ---------- IPSet ----------

    public static string IpsetMode()
    {
        string raw;
        try { raw = File.ReadAllText(Ipset, Encoding.UTF8); } catch { return "none"; }
        if (raw.Trim().Length == 0) return "any";
        return raw.Contains(IpsetPlaceholder) ? "none" : "loaded";
    }

    public static int IpsetCount()
    {
        try { return File.ReadAllLines(IpsetBackup).Count(l => l.Trim().Length > 0); } catch { return 0; }
    }

    public static void SetIpsetMode(string mode)
    {
        string current = IpsetMode();
        if (mode == current) return;
        if (current == "loaded") File.Copy(Ipset, IpsetBackup, true); // сохраняем список, чтобы вернуться к нему
        switch (mode)
        {
            case "none": File.WriteAllText(Ipset, IpsetPlaceholder + "\n"); break;
            case "any": File.WriteAllText(Ipset, ""); break;
            case "loaded":
                if (!File.Exists(IpsetBackup)) throw new InvalidOperationException("Список IP ещё не загружен — нажмите «Обновить список IP»");
                File.Copy(IpsetBackup, Ipset, true);
                break;
            default: throw new ArgumentException("Неизвестный режим IPSet");
        }
    }

    private static bool ValidIpsetLine(string l)
    {
        var parts = l.Split('/');
        if (parts.Length > 2 || !System.Net.IPAddress.TryParse(parts[0], out var ip)) return false;
        bool v4 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        if (parts[0].Contains(':') == v4) return false;
        if (parts.Length == 2 && !(int.TryParse(parts[1], out var bits) && bits >= 0 && bits <= (v4 ? 32 : 128))) return false;
        if (System.Net.IPAddress.IsLoopback(ip) || ip.IsIPv6Multicast || ip.IsIPv6LinkLocal) return false;
        if (v4)
        {
            var b = ip.GetAddressBytes();
            if (b[0] is 0 or 10 or 127 or >= 224 || (b[0] == 169 && b[1] == 254) || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)) return false;
        }
        return true;
    }

    public static bool IpsetTextValid(string text)
    {
        var lines = text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        return text.Length <= 8_000_000 && lines.Count >= 10 && lines.Count <= 300_000 && lines.All(ValidIpsetLine);
    }

    public static int SaveIpsetList(string text)
    {
        // Список влияет только на то, к каким адресам применяется обход, но проверяем каждую строку: только IP или подсеть,
        // без петли/локальных/групповых адресов, ограниченный размер.
        var lines = text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        if (text.Length > 8_000_000 || lines.Count < 10 || lines.Count > 300_000 || !lines.All(ValidIpsetLine))
            throw new InvalidOperationException("Скачанный список IP повреждён или содержит недопустимые записи");
        Directory.CreateDirectory(P.Lists);
        File.WriteAllText(IpsetBackup, string.Join("\n", lines) + "\n");
        if (IpsetMode() == "loaded") File.Copy(IpsetBackup, Ipset, true);
        return lines.Count;
    }

    // ---------- fake-пакеты ----------

    private static string Sha(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    public static FakesInfo Fakes()
    {
        var files = Directory.Exists(P.Bin)
            ? Directory.GetFiles(P.Bin, "*.bin").Where(p => !Path.GetFileNameWithoutExtension(p).StartsWith("ACTIVE_", StringComparison.OrdinalIgnoreCase))
                .OrderBy(p => Path.GetFileNameWithoutExtension(p).ToLowerInvariant(), StringComparer.Ordinal).ToList()
            : new List<string>();
        var hashes = files.ToDictionary(p => Path.GetFileNameWithoutExtension(p), Sha);
        string? Find(string target)
        {
            string path = Path.Combine(P.Bin, target);
            if (!File.Exists(path)) return null;
            string h = Sha(path);
            return hashes.FirstOrDefault(kv => kv.Value == h).Key;
        }
        return new(hashes.Keys.ToList(), Find(FakeTargets["discord"]), Find(FakeTargets["game"]));
    }

    public static void SetFake(string kind, string name)
    {
        if (!FakeTargets.ContainsKey(kind) || !Fakes().files.Contains(name)) throw new ArgumentException("Неизвестный fake-файл");
        File.Copy(Path.Combine(P.Bin, name + ".bin"), Path.Combine(P.Bin, FakeTargets[kind]), true);
    }

    // ---------- пользовательские списки ----------

    public static void EnsureUserLists()
    {
        Directory.CreateDirectory(P.Lists);
        foreach (var (file, def) in UserLists.Values)
        {
            string path = Path.Combine(P.Lists, file);
            if (!File.Exists(path)) File.WriteAllText(path, def);
        }
    }

    public static string ReadUserList(string key)
    {
        if (!UserLists.TryGetValue(key, out var info)) throw new ArgumentException("Неизвестный список");
        string[] lines;
        try { lines = File.ReadAllLines(Path.Combine(P.Lists, info.file), Encoding.UTF8); } catch { return ""; }
        return string.Join("\n", lines.Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#') && !Placeholders.Contains(l)));
    }

    private static string NormalizeEntry(string key, string entry)
    {
        entry = entry.Trim().ToLowerInvariant();
        if (key != "ipset_exclude")
        {
            entry = Regex.Replace(entry, @"^[a-z]+://", "");
            entry = entry.Split('/')[0].Split(':')[0];
            if (entry.StartsWith("www.") && entry.Count(c => c == '.') > 1) entry = entry[4..];
        }
        return entry;
    }

    public static List<string> WriteUserList(string key, string text)
    {
        if (!UserLists.TryGetValue(key, out var info)) throw new ArgumentException("Неизвестный список");
        var entries = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            string e = NormalizeEntry(key, raw);
            if (e.Length > 0 && !e.StartsWith('#') && !entries.Contains(e)) entries.Add(e);
        }
        // Пустой файл ломает winws — как и service.bat, оставляем заглушку.
        Directory.CreateDirectory(P.Lists);
        File.WriteAllText(Path.Combine(P.Lists, info.file), entries.Count > 0 ? string.Join("\n", entries) + "\n" : info.def);
        return entries;
    }
}

public sealed record EngineStatus(bool running, string? mode, string? strategy, bool external);

public sealed class Engine
{
    private Process? _proc;
    private string? _strategy;
    public readonly object Lock = new();

    private bool OwnAlive => _proc is { HasExited: false };

    public EngineStatus Status()
    {
        if (!P.Sandbox)
        {
            var svc = EngineFiles.ServiceState(EngineFiles.Service);
            if (svc is "RUNNING" or "START_PENDING")
                return new(true, "service", EngineFiles.ServiceStrategy(), false);
            if (EngineFiles.WinwsPids().Count > 0)
            {
                bool own = OwnAlive;
                return new(true, "app", own ? _strategy : null, !own);
            }
            return new(false, null, null, false);
        }
        return OwnAlive ? new(true, "app", _strategy, false) : new(false, null, null, false);
    }

    public void Start(string name, string mode = "app", bool quiet = false)
    {
        if (!EngineFiles.Installed()) throw new InvalidOperationException("Движок zapret не установлен");
        if (!Strategies.List().Contains(name)) throw new InvalidOperationException($"Стратегия «{name}» не найдена");
        lock (Lock)
        {
            EngineFiles.EnsureUserLists();
            string args = Strategies.BuildArgs(name, EngineFiles.GameFilterVars());
            Stop();
            if (!P.Sandbox) Sys.Run("netsh", "interface", "tcp", "set", "global", "timestamps=enabled");
            if (mode == "service") StartService($"\"{Path.Combine(P.Bin, "winws.exe")}\" {args}", name);
            else Spawn(args);
            _strategy = name;
            if (!quiet) Log.Info($"Обход запущен: {name} ({(mode == "service" ? "служба Windows" : "приложение")})");
        }
    }

    private void Spawn(string args)
    {
        var psi = new ProcessStartInfo(Path.Combine(P.Bin, "winws.exe"))
        {
            Arguments = args, WorkingDirectory = P.Bin, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
        };
        Directory.CreateDirectory(P.Root);
        var logw = new StreamWriter(new FileStream(P.WinwsLog, FileMode.Create, FileAccess.Write, FileShare.ReadWrite)) { AutoFlush = true };
        var p = Process.Start(psi) ?? throw new InvalidOperationException("Не удалось запустить winws.exe");
        p.StandardInput.Close();
        p.OutputDataReceived += (_, e) => { if (e.Data != null) lock (logw) { try { logw.WriteLine(e.Data); } catch { } } };
        p.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (logw) { try { logw.WriteLine(e.Data); } catch { } } };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        _proc = p;
        Thread.Sleep(1200);
        if (p.HasExited)
        {
            _proc = null;
            string tail = "";
            try { tail = File.ReadAllText(P.WinwsLog).Trim(); if (tail.Length > 500) tail = tail[^500..]; } catch { }
            throw new InvalidOperationException("winws.exe завершился сразу после запуска" + (tail.Length > 0 ? ":\n" + tail : ""));
        }
    }

    private static void StartService(string cmd, string name)
    {
        P.Need("служба Windows");
        var (code, output) = Sys.Run("sc", "create", EngineFiles.Service, "binPath=", cmd, "DisplayName=", "zapret", "start=", "auto");
        if (code != 0) throw new InvalidOperationException("Не удалось создать службу: " + output.Trim());
        Sys.Run("sc", "description", EngineFiles.Service, "Zapret DPI bypass software");
        using (var k = Registry.LocalMachine.OpenSubKey(EngineFiles.ServiceKey, true))
            k?.SetValue("zapret-discord-youtube", name, RegistryValueKind.String);
        (code, output) = Sys.Run("sc", "start", EngineFiles.Service);
        if (code != 0) throw new InvalidOperationException("Служба zapret не запустилась: " + output.Trim());
    }

    public void Stop()
    {
        lock (Lock)
        {
            if (_proc is { HasExited: false })
            {
                try { _proc.Kill(true); _proc.WaitForExit(3000); } catch { }
            }
            _proc = null;
            _strategy = null;
            EngineFiles.RemoveService(EngineFiles.Service);
            EngineFiles.KillWinws();
        }
    }

    /// <summary>Остановка только того, что запущено этим приложением (при выходе служба и чужие winws не трогаем).</summary>
    public void StopOwn()
    {
        lock (Lock)
        {
            if (_proc is { HasExited: false })
            {
                try { _proc.Kill(true); _proc.WaitForExit(3000); } catch { }
            }
            _proc = null;
            _strategy = null;
        }
    }

    /// <summary>Перед обновлением движка: останавливает только то, чем управляет приложение — свой процесс, свою службу и winws.exe из папки
    /// движка (он держит файлы). Чужие winws из других папок не трогаем. Затем выгружает драйвер WinDivert, иначе .sys заблокирован.</summary>
    public void StopForUpdate()
    {
        lock (Lock)
        {
            if (_proc is { HasExited: false })
            {
                try { _proc.Kill(true); _proc.WaitForExit(3000); } catch { }
            }
            _proc = null;
            _strategy = null;
            if (P.Sandbox) return;
            EngineFiles.RemoveService(EngineFiles.Service);
            string ours = Path.GetFullPath(Path.Combine(P.Bin, "winws.exe"));
            foreach (var p in Process.GetProcessesByName("winws"))
            {
                try
                {
                    string? path = p.MainModule?.FileName;
                    if (path != null && string.Equals(Path.GetFullPath(path), ours, StringComparison.OrdinalIgnoreCase)) { p.Kill(true); p.WaitForExit(3000); }
                }
                catch { }
                p.Dispose();
            }
            foreach (var n in new[] { "WinDivert", "WinDivert14" }) EngineFiles.RemoveService(n);
        }
    }

    /// <summary>Перед заменой файлов движка: ещё и выгружаем драйвер WinDivert, иначе .sys заблокирован.</summary>
    public void FullStop()
    {
        lock (Lock)
        {
            Stop();
            foreach (var n in new[] { "WinDivert", "WinDivert14" }) EngineFiles.RemoveService(n);
        }
    }
}
