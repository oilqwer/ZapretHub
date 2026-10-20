using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ZapretHub;

public sealed class Target
{
    public string name = "", group = "", host = ""; public string? url;
}

public sealed class GroupResult { public int ok { get; set; } public int total { get; set; } }

public sealed class CheckSummary
{
    public int ok { get; set; }
    public int total { get; set; }
    public int? ms { get; set; }
    public Dictionary<string, GroupResult> groups { get; set; } = new();
    public string? name { get; set; }
    public string? error { get; set; }
}

public sealed class TestState
{
    public bool running { get; set; }
    public string phase { get; set; } = "baseline";
    public int index { get; set; }
    public int total { get; set; }
    public string? current { get; set; }
    public CheckSummary? baseline { get; set; }
    public List<CheckSummary> results { get; set; } = new();
    public string? best { get; set; }
    public List<string> groups { get; set; } = new();
    public string? error { get; set; }
}

/// <summary>Методика как в utils/test zapret.ps1 от Flowseal: curl по HTTP, TLS 1.2 и TLS 1.3 к адресам из targets.txt.</summary>
public static class Tester
{
    private static readonly (string, string[])[] Checks =
    {
        ("HTTP", new[] { "--http1.1" }),
        ("TLS1.2", new[] { "--tlsv1.2", "--tls-max", "1.2" }),
        ("TLS1.3", new[] { "--tlsv1.3", "--tls-max", "1.3" }),
    };
    private const int CurlTimeout = 4;

    private static readonly (string, string)[] Fallback =
    {
        ("Discord", "https://discord.com"), ("Discord", "https://gateway.discord.gg"),
        ("Discord", "https://cdn.discordapp.com"), ("Discord", "https://updates.discord.com"),
        ("YouTube", "https://www.youtube.com"), ("YouTube", "https://youtu.be"),
        ("YouTube", "https://i.ytimg.com"), ("YouTube", "https://redirector.googlevideo.com"),
        ("Google", "https://www.google.com"), ("Google", "https://www.gstatic.com"),
        ("Cloudflare", "https://www.cloudflare.com"), ("Cloudflare", "https://cdnjs.cloudflare.com"),
    };

    private static string HostOf(string url) => Regex.Replace(url, @"^https?://|/.*$", "");

    public static List<Target> LoadTargets()
    {
        var targets = new List<Target>();
        string group = "Другое";
        string[] lines;
        try { lines = File.ReadAllLines(Path.Combine(P.Utils, "targets.txt")); } catch { lines = Array.Empty<string>(); }
        foreach (var line in lines)
        {
            if (line.StartsWith("###"))
            {
                string g = Regex.Replace(line.Trim('#', ' ', '\t'), @"\(.*?\)", "").Trim();
                if (g.Length > 0) group = g;
                continue;
            }
            var m = Regex.Match(line, "^\\s*(\\w+)\\s*=\\s*\"(.+)\"\\s*$");
            if (!m.Success) continue;
            string name = m.Groups[1].Value, value = m.Groups[2].Value;
            if (value.StartsWith("PING:", StringComparison.OrdinalIgnoreCase))
                targets.Add(new Target { name = name, group = group, url = null, host = value[5..].Trim() });
            else
                targets.Add(new Target { name = name, group = group, url = value, host = HostOf(value) });
        }
        if (targets.Count == 0)
            targets = Fallback.Select(f => new Target { name = f.Item2, group = f.Item1, url = f.Item2, host = HostOf(f.Item2) }).ToList();
        return targets;
    }

    public static List<string> Groups()
    {
        var seen = new List<string>();
        foreach (var t in LoadTargets())
            if (t.url != null && !seen.Contains(t.group)) seen.Add(t.group);
        return seen;
    }

    private static (string status, int? ms) Curl(string url, string[] extra)
    {
        var psi = new ProcessStartInfo("curl.exe")
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
        };
        foreach (var a in new[] { "-I", "-s", "-S", "-m", CurlTimeout.ToString(), "--connect-timeout", "2", "-o", "NUL", "-w", "%{http_code} %{time_total}" })
            psi.ArgumentList.Add(a);
        foreach (var a in extra) psi.ArgumentList.Add(a);
        psi.ArgumentList.Add(url);
        try
        {
            using var p = Process.Start(psi)!;
            p.StandardInput.Close();
            var so = p.StandardOutput.ReadToEndAsync();
            var se = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit((CurlTimeout + 4) * 1000))
            {
                try { p.Kill(true); } catch { }
                return ("fail", null);
            }
            string stdout = so.GetAwaiter().GetResult(), err = se.GetAwaiter().GetResult();
            if (p.ExitCode == 0)
            {
                var m = Regex.Match(stdout, @"\s([\d.]+)\s*$");
                return ("ok", m.Success ? (int)Math.Round(double.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) * 1000) : null);
            }
            if (p.ExitCode == 35 || Regex.IsMatch(err, "not supported|unsupported|unrecognized option|unknown option", RegexOptions.IgnoreCase))
                return ("unsup", null);
            return ("fail", null);
        }
        catch { return ("fail", null); }
    }

    /// <summary>Все проверки параллельно: ok/total по HTTP-проверкам, по группам и средняя задержка.</summary>
    public static CheckSummary Check(IEnumerable<Target> targets)
    {
        var jobs = new List<(Target t, Task<(string status, int? ms)> task)>();
        using var gate = new SemaphoreSlim(32);
        foreach (var t in targets.Where(t => t.url != null))
            foreach (var (_, extra) in Checks)
            {
                var tt = t; var ex = extra;
                jobs.Add((tt, Task.Run(() => { gate.Wait(); try { return Curl(tt.url!, ex); } finally { gate.Release(); } })));
            }
        var summary = new CheckSummary();
        var times = new List<int>();
        foreach (var (t, task) in jobs)
        {
            var (status, ms) = task.GetAwaiter().GetResult();
            if (status == "unsup") continue;
            if (!summary.groups.TryGetValue(t.group, out var g)) summary.groups[t.group] = g = new GroupResult();
            g.total++; summary.total++;
            if (status == "ok")
            {
                g.ok++; summary.ok++;
                if (ms != null) times.Add(ms.Value);
            }
        }
        if (times.Count > 0) summary.ms = (int)Math.Round(times.Average());
        return summary;
    }

    public static TestState AutoSelect(Engine eng, List<string> names, List<string> wantedGroups, bool quick, CancellationToken cancel, Action<TestState> emit)
    {
        var targets = LoadTargets().Where(t => t.url != null && (wantedGroups.Count == 0 || wantedGroups.Contains(t.group))).ToList();
        if (targets.Count == 0) throw new InvalidOperationException("Не выбрано ни одного сервиса для проверки");
        var state = new TestState { running = true, phase = "baseline", total = names.Count, groups = wantedGroups };
        emit(state);

        eng.Stop();
        state.baseline = Check(targets);
        emit(state);

        for (int i = 0; i < names.Count; i++)
        {
            if (cancel.IsCancellationRequested) break;
            state.phase = "testing"; state.index = i; state.current = names[i];
            emit(state);
            CheckSummary result;
            try
            {
                eng.Start(names[i], "app", true);
                Thread.Sleep(600);
                result = Check(targets);
            }
            catch (Exception e) { result = new CheckSummary { error = e.Message }; }
            finally { eng.Stop(); }
            result.name = names[i];
            state.results.Add(result);
            emit(state);
            if (quick && result.total > 0 && result.ok == result.total) break;
        }

        var ranked = state.results.Where(r => r.total > 0)
            .OrderBy(r => -(double)r.ok / r.total).ThenBy(r => r.ms ?? 1_000_000).ToList();
        if (ranked.Count > 0 && ranked[0].ok > 0) state.best = ranked[0].name;
        state.running = false; state.phase = cancel.IsCancellationRequested ? "cancelled" : "done"; state.current = null;
        emit(state);
        return state;
    }
}
