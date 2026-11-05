using System.Diagnostics;
using System.Net;
using System.Text;

namespace ZapretHub;

internal static class AiDnsPolicy
{
    internal static readonly IPAddress ListenAddress = IPAddress.Parse("127.0.0.2");
    // Google-wide, corporate and local namespaces deliberately never enter this list.
    internal static readonly string[] Domains =
    {
        "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
        "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
        "claude.ai", "anthropic.com", "grok.com", "x.ai", "copilot.microsoft.com", "perplexity.ai",
    };
    private const string Marker = "ZapretHub.AiDns.Split.v1:";
    internal static bool IsAiHost(string host) => Domains.Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
    internal static string NewToken() => Environment.ProcessId + ":" + Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks + ":" + Guid.NewGuid().ToString("N");

    private static bool ValidToken(string token)
    {
        var parts = token.Split(':');
        return parts.Length == 3 && int.TryParse(parts[0], out int pid) && pid > 0 && long.TryParse(parts[1], out long ticks) && ticks > 0 && Guid.TryParseExact(parts[2], "N", out _);
    }

    private static string Script(string? token)
    {
        if (token is not null && !ValidToken(token)) throw new ArgumentException("Неверный идентификатор DNS");
        string domains = string.Join(",", Domains.SelectMany(d => new[] { "'" + d + "'", "'." + d + "'" }));
        return $$"""
            $ErrorActionPreference = 'Stop'
            [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
            $names = @({{domains}})
            $marker = '{{Marker}}'
            $owner = '{{(token is null ? "" : Marker + token)}}'
            function Owned($rule) {
                if ($rule.DisplayName -ne 'Zapret Hub AI DNS' -or -not ([string]$rule.Comment).StartsWith($marker)) { return $false }
                if ($owner -and $rule.Comment -ne $owner) { return $false }
                if (-not $owner) {
                    $parts = ([string]$rule.Comment).Substring($marker.Length).Split(':')
                    if ($parts.Count -ne 3) { return $false }
                    try {
                        $other = Get-Process -Id ([int]$parts[0]) -ErrorAction Stop
                        if ($other.StartTime.ToUniversalTime().Ticks -eq [long]$parts[1]) { return $false }
                    } catch [Microsoft.PowerShell.Commands.ProcessCommandException] { }
                }
                $ns = @($rule.Namespace)
                $servers = @(([string]$rule.NameServers) -split '[,;\s]+' | Where-Object { $_ })
                return $servers.Count -eq 1 -and $servers[0] -eq '127.0.0.2' -and
                    $ns.Count -eq $names.Count -and @($ns | Where-Object { $_ -notin $names }).Count -eq 0
            }
            function Cleanup {
                $changed = $false
                foreach ($rule in @(Get-DnsClientNrptRule -ErrorAction Stop)) {
                    if (Owned $rule) { Remove-DnsClientNrptRule -Name $rule.Name -Force -Confirm:$false -ErrorAction Stop; $changed = $true }
                }
                if ($owner -and @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -eq $owner -and '127.0.0.2' -in @(([string]$_.NameServers) -split '[,;\s]+') }).Count -gt 0) {
                    throw 'AI DNS rule was modified externally; relay remains available so cleanup can be retried'
                }
                if ($changed) { Clear-DnsClientCache -ErrorAction Stop }
            }
            """;
    }

    internal static string InstallScript(string token) => Script(token) + "\n" + """
        if (@(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -eq $owner }).Count -gt 0) { throw 'DNS rule already exists' }
        # Existing specific rules remain owned by their creator. Refuse to shadow them.
        foreach ($policy in @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)) {
            foreach ($n in @($policy.Namespace)) {
                if ($n -eq '.') { continue }
                $d = ([string]$n).TrimStart('.').ToLowerInvariant()
                foreach ($ours in $names) {
                    $o = $ours.TrimStart('.')
                    if ($d -eq $o -or $d.EndsWith('.' + $o) -or $o.EndsWith('.' + $d)) { throw ('Existing DNS policy overlaps AI namespace: ' + $n) }
                }
            }
        }
        try {
            Add-DnsClientNrptRule -Namespace $names -NameServers '127.0.0.2' -DisplayName 'Zapret Hub AI DNS' -Comment $owner -ErrorAction Stop | Out-Null
            $effective = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
            foreach ($n in $names) {
                if (@($effective | Where-Object { $n -in @($_.Namespace) -and '127.0.0.2' -in @(([string]$_.NameServers) -split '[,;\s]+') }).Count -eq 0) {
                    throw 'Local AI DNS rule is overridden by Windows policy'
                }
            }
            Clear-DnsClientCache -ErrorAction Stop
        } catch { $original = $_; Cleanup; throw $original }
        """;

    internal static void Install(string token) { P.Need("раздельный AI DNS"); Run(InstallScript(token)); }
    internal static void Remove(string? token) { P.Need("возврат AI DNS"); Run(Script(token) + "\nCleanup"); }
    private static void Run(string script)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }) psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi) ?? throw new IOException("Не удалось запустить управление DNS Windows");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30000)) { try { process.Kill(true); } catch { } throw new IOException("Windows не завершила изменение правила AI DNS"); }
        Task.WaitAll(output, error);
        if (process.ExitCode != 0) throw new IOException("Не удалось настроить раздельный DNS: " + error.Result.Trim() + output.Result.Trim());
    }

    internal static Process Watch(string token)
    {
        var psi = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var arg in new[] { "--aidns-watchdog", Environment.ProcessId.ToString(), Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks.ToString(), token }) psi.ArgumentList.Add(arg);
        return Process.Start(psi) ?? throw new IOException("Не удалось запустить восстановление DNS");
    }

    internal static int Watchdog(string[] args)
    {
        if (args.Length != 4 || !int.TryParse(args[1], out int pid) || !long.TryParse(args[2], out long started) || !ValidToken(args[3]) || !args[3].StartsWith(pid + ":" + started + ":", StringComparison.Ordinal)) return 2;
        try
        {
            using var parent = Process.GetProcessById(pid);
            if (parent.StartTime.ToUniversalTime().Ticks == started) parent.WaitForExit();
        }
        catch (ArgumentException) { }
        for (int i = 0; i < 3; i++)
        {
            try { Remove(args[3]); return 0; }
            catch (Exception e) { Log.Warn("AI DNS восстановление: " + e.Message); Thread.Sleep(1000); }
        }
        return 1;
    }
}

internal sealed class AiDnsRuntime : IDisposable
{
    private readonly object _sync = new();
    private string _lifecycleError = "";
    private AiDnsRelay? _relay;
    private string? _token;
    private Process? _watchdog;
    private readonly Action<string> _install;
    private readonly Action<string> _remove;
    private readonly Func<string, Process?> _watch;
    private readonly IPAddress _address;
    private readonly int _port;
    private readonly Action<DnsFailover>? _prepare;
    private object? _lastState;
    internal AiDnsRuntime(Action<string>? install = null, Action<string>? remove = null, Func<string, Process?>? watch = null, IPAddress? address = null, int port = 53, Action<DnsFailover>? prepare = null)
    {
        _install = install ?? AiDnsPolicy.Install; _remove = remove ?? (x => AiDnsPolicy.Remove(x));
        _watch = watch ?? AiDnsPolicy.Watch; _address = address ?? AiDnsPolicy.ListenAddress; _port = port;
        _prepare = prepare;
    }
    internal bool Running => _relay?.Running == true;
    internal object? State
    {
        get { lock (_sync) {
            var state=System.Text.Json.JsonSerializer.SerializeToNode(_relay?.State ?? _lastState) ?? new System.Text.Json.Nodes.JsonObject();
            state["listenerRunning"]=Running; state["lifecycleError"]=_lifecycleError;
            if(_lifecycleError.Length>0)state["error"]=_lifecycleError;
            return state;
        } }
    }
    internal void Start(IEnumerable<DnsServer> servers, IReadOnlyDictionary<string, string[]>? plan = null, AiDnsMonitor? monitor = null, CancellationToken ct = default)
    {
        lock (_sync) {
        if (_relay is not null) { if(Running)throw new InvalidOperationException("AI DNS уже запущен"); Stop(); }
        _lifecycleError="";
        var upstreams = new DnsFailover(servers, plan: plan, monitor: monitor);
        try { _relay = new AiDnsRelay(upstreams, _address, _port); }
        catch { upstreams.Dispose(); throw; }
        _token = AiDnsPolicy.NewToken();
        try
        {
            if (_prepare is null) upstreams.Warmup(ct).GetAwaiter().GetResult(); else _prepare(upstreams);
            _watchdog = _watch(_token);
            _install(_token);
            if(!_relay.Running)throw new IOException("DNS Relay остановился во время включения");
            _ = Observe(_relay);
        }
        catch { Stop(); throw; }
        }
    }
    private async Task Observe(AiDnsRelay relay)
    {
        await relay.Completion.ConfigureAwait(false);
        for(int attempt=0;attempt<3;attempt++)
        {
          lock(_sync)
          {
            if(!ReferenceEquals(_relay,relay)||relay.Running)return;
            _lifecycleError="DNS Relay остановлен: "+relay.Failure+"; выполняется безопасный откат NRPT";
            Log.Warn("AI DNS: "+_lifecycleError);
            try { Stop(); _lifecycleError="DNS Relay остановлен; собственное NRPT удалено. Требуется повторное включение"; return; }
            catch(Exception e) { _lifecycleError="DNS Relay остановлен; откат NRPT не выполнен: "+e.Message; Log.Warn("AI DNS: "+_lifecycleError); }
          }
          if(attempt<2)await Task.Delay(1000).ConfigureAwait(false);
        }
    }
    internal void Stop()
    {
        lock (_sync) {
        // Keep the relay available if Windows cannot remove the rule. The UI can retry.
        if (_token is not null) _remove(_token);
        _token = null; _lastState = _relay?.State ?? _lastState; _relay?.Dispose(); _relay = null;
        if (_watchdog is not null) { try { _watchdog.Kill(); } catch { } _watchdog.Dispose(); _watchdog = null; }
        }
    }
    public void Dispose() => Stop();
}
