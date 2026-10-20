using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretHub;

public interface IWindow
{
    void Minimize();
    bool ToggleMaximize();
    bool IsMaximized();
    void BeginResize(string edge);
    void HideToTray();
    void Quit();
}

/// <summary>Контракт интерфейса: методы window.pywebview.api.* из Zapret Hub 1.2.1. Каждый возвращает {"ok": bool, ...}.</summary>
public sealed class Api
{
    private static readonly Dictionary<string, string> BusyText = new()
    {
        ["update"] = "Идёт обновление — подождите",
        ["test"] = "Идёт подбор стратегии — подождите или остановите его",
        ["switch"] = "Обход переключается — подождите",
    };
    private static readonly string[] BoolOptions = { "auto_update", "autostart", "start_minimized", "close_to_tray", "autoconnect" };
    private static readonly string[] OptionKeys = { "auto_update", "update_interval_h", "autostart", "start_minimized", "close_to_tray", "autoconnect" };
    private static readonly Dictionary<string, string> Links = new()
    {
        ["flowseal"] = $"https://github.com/{P.Repo}", ["zapret"] = "https://github.com/bol-van/zapret",
        ["release"] = $"https://github.com/{P.Repo}/releases/latest", ["tgproxy"] = $"https://github.com/{TgProxy.Repo}",
        ["author"] = "https://github.com/oilqwer",
    };
    private static readonly Dictionary<string, string> ComponentNames = new() { ["zapret"] = "zapret", ["tg"] = "tg-ws-proxy" };

    private readonly Settings _s;
    private readonly Engine _e;
    private readonly TgProxy _tg = new();
    private readonly Action<string, object?> _pushRaw;
    public IWindow? Window;

    private string? _busy;
    private readonly object _busyLock = new();
    private readonly Dictionary<string, Release?> _latest = new() { ["zapret"] = null, ["tg"] = null };
    private object _update = new { stage = "idle" };
    private object _test = new { running = false };
    private CancellationTokenSource _cancel = new();

    public Api(Settings s, Engine e, Action<string, object?> push) { _s = s; _e = e; _pushRaw = push; }

    // ---------- вызов по имени ----------

    public JsonObject Call(string method, JsonArray args)
    {
        try
        {
            object? r = Dispatch(method, args);
            var node = r is null ? new JsonObject() : JsonSerializer.SerializeToNode(r, Json.Opts) as JsonObject ?? new JsonObject();
            node["ok"] = true;
            return node;
        }
        catch (Exception ex)
        {
            var inner = ex is System.Reflection.TargetInvocationException { InnerException: { } i } ? i : ex;
            Log.Error($"{method}: {inner.Message}");
            return new JsonObject { ["ok"] = false, ["error"] = inner.Message };
        }
    }

    private static string A(JsonArray a, int i) => i < a.Count ? a[i]?.GetValue<string>() ?? "" : "";
    private static bool B(JsonArray a, int i) => i < a.Count && a[i] is { } n && (n.GetValueKind() == JsonValueKind.True || (n.GetValueKind() == JsonValueKind.Number && n.GetValue<double>() != 0));

    private object? Dispatch(string m, JsonArray a)
    {
        switch (m)
        {
            case "get_state": return GetState();
            case "toggle": return Toggle(B(a, 0));
            case "set_strategy": return SetStrategy(A(a, 0));
            case "set_run_mode": return SetRunMode(A(a, 0));
            case "set_option": return SetOption(A(a, 0), a[1]);
            case "get_filters": return GetFilters();
            case "set_game_filter": EngineFiles.SetGameFilter(A(a, 0), A(a, 1), A(a, 2)); RestartIfRunning(); return null;
            case "set_ipset": EngineFiles.SetIpsetMode(A(a, 0)); RestartIfRunning(); return null;
            case "update_ipset": return UpdateIpset();
            case "set_fake": return SetFake(A(a, 0), A(a, 1));
            case "get_list": return new { text = EngineFiles.ReadUserList(A(a, 0)) };
            case "save_list": return SaveList(A(a, 0), A(a, 1));
            case "check_update": return CheckUpdate(a.Count > 0 ? A(a, 0) : "zapret");
            case "install_update": return StartInstall(a.Count > 0 ? A(a, 0) : "zapret", A(a, 1));
            case "tg_toggle": return TgToggle(B(a, 0));
            case "tg_save": return TgSave(a[0]!, A(a, 1), B(a, 2));
            case "tg_new_secret": return TgNewSecret();
            case "tg_open": Sys.OpenShell(TgProxy.Link(TgCfgGet())); return null;
            case "aidns_adapters": return AiAdapters();
            case "aidns_save": return AiSave(a[0]!, a[1]!, a[2]!);
            case "aidns_toggle": return AiToggle(B(a, 0));
            case "aidns_check": return AiCheck(a[0]!, a[1]!);
            case "aidns_recommended": return new { primary = AiDns.RecPrimary(), alternate = AiDns.RecAlternate() };
            case "start_test": return StartTest(a[0]!.AsArray().Select(x => x!.GetValue<string>()).ToList(), B(a, 1), B(a, 2));
            case "cancel_test": _cancel.Cancel(); return null;
            case "quick_check": return QuickCheck();
            case "run_diagnostics": return new { items = Diagnostics.RunAll() };
            case "fix": return Fix(A(a, 0));
            case "defender_status": return DefenderCtl.Status();
            case "defender_add": DefenderCtl.Add(B(a, 0)); return null;
            case "defender_remove": return new { removed = DefenderCtl.Remove(B(a, 0)) };
            case "get_log": return new { lines = Log.Last(150) };
            case "open_log": Sys.OpenShell(P.LogFile); return null;
            case "open_link": Sys.OpenShell(Links[A(a, 0)]); return null;
            case "win_minimize": Window?.Minimize(); return null;
            case "win_toggle_max": return new { maximized = Window?.ToggleMaximize() ?? false };
            case "win_resize": Window?.BeginResize(A(a, 0)); return null;
            case "win_state": return new { maximized = Window?.IsMaximized() ?? false };
            case "win_close":
                if (_s.Bool("close_to_tray")) Window?.HideToTray(); else Window?.Quit();
                return null;
            case "quit_app": Window?.Quit(); return null;
        }
        throw new NotSupportedException($"Метод не поддерживается: {m}");
    }

    // ---------- служебное ----------

    public void Push(string kind, object? data = null) => _pushRaw(kind, data ?? new { });
    private void Toast(string msg, string kind = "info") => Push("toast", new { msg, kind });

    private void Begin(string what)
    {
        lock (_busyLock)
        {
            if (_busy != null) throw new InvalidOperationException(BusyText[_busy]);
            _busy = what;
        }
    }

    private void End() => _busy = null;

    private void StartEngine(string? name = null)
    {
        var names = Strategies.List();
        name ??= _s.Str("strategy");
        if (!names.Contains(name))
        {
            if (names.Count == 0) throw new InvalidOperationException("Стратегии не найдены — установите zapret");
            string fb = names.Contains("general") ? "general" : names[0];
            Log.Warn($"Стратегия «{name}» не найдена, использую «{fb}»");
            name = fb;
            _s.Set("strategy", name);
        }
        _e.Start(name, _s.Str("run_mode", "app"));
        _s.Set("enabled", true);
    }

    private void RestartIfRunning()
    {
        if (!_e.Status().running) return;
        Begin("switch");
        try { StartEngine(); } finally { End(); }
    }

    private void ReapplyFakes()
    {
        if (_s.Node("fakes") is not JsonObject fakes) return;
        foreach (var kv in fakes)
        {
            try { EngineFiles.SetFake(kv.Key, kv.Value!.GetValue<string>()); }
            catch (Exception e) { Log.Warn($"Fake-файл {kv.Value} больше не доступен: {e.Message}"); }
        }
    }

    // ---------- состояние ----------

    private object? PublicRelease(string c) => _latest[c] is { } r ? new { r.version, r.notes, date = r.date } : null;

    private object GetState()
    {
        var scores = _s.Node("scores") as JsonObject;
        bool installed = EngineFiles.Installed();
        var options = new Dictionary<string, object?>();
        foreach (var k in OptionKeys) options[k] = _s.Node(k);
        options["run_mode"] = _s.Str("run_mode", "app");
        return new
        {
            app_version = P.AppVersion,
            installed,
            engine_version = Updater.LocalVersion(),
            status = _e.Status(),
            strategy = _s.Str("strategy"),
            strategies = Strategies.List().Select(n => new { name = n, score = scores?[n]?.DeepClone() }).ToList(),
            options,
            game_filter = EngineFiles.GameFilter(),
            ipset = EngineFiles.IpsetMode(),
            groups = installed ? Tester.Groups() : new List<string> { "Discord", "YouTube", "Google", "Cloudflare" },
            test_groups = _s.Node("test_groups"),
            busy = _busy,
            latest = PublicRelease("zapret"),
            update = _update,
            test = _test,
            tg = TgState(),
            aidns = AiState(),
        };
    }

    // ---------- обход ----------

    private object? Toggle(bool on)
    {
        Begin("switch");
        try
        {
            if (on) StartEngine();
            else
            {
                _e.Stop();
                _s.Set("enabled", false);
                Log.Info("Обход выключен");
            }
        }
        finally { End(); }
        return null;
    }

    private object? SetStrategy(string name)
    {
        if (!Strategies.List().Contains(name)) throw new ArgumentException("Нет такой стратегии");
        _s.Set("strategy", name);
        RestartIfRunning();
        return null;
    }

    private object? SetRunMode(string mode)
    {
        if (mode is not ("app" or "service")) throw new ArgumentException("Неизвестный режим");
        _s.Set("run_mode", mode);
        RestartIfRunning();
        return null;
    }

    private object? SetOption(string key, JsonNode? value)
    {
        if (!OptionKeys.Contains(key)) throw new ArgumentException("Неизвестная настройка");
        if (BoolOptions.Contains(key))
        {
            bool v = value?.GetValueKind() == JsonValueKind.True || (value?.GetValueKind() == JsonValueKind.Number && value.GetValue<double>() != 0);
            if (key == "autostart") Sys.SetAutostart(v);
            _s.Set(key, v);
        }
        else _s.Set(key, (int)(value?.GetValue<double>() ?? 6));
        if (key is "auto_update" or "update_interval_h") _s.Set("last_update_check", 0);
        return null;
    }

    // ---------- фильтры и списки ----------

    private object GetFilters() => new
    {
        game_filter = EngineFiles.GameFilter(), ipset = EngineFiles.IpsetMode(), ipset_count = EngineFiles.IpsetCount(),
        fakes = EngineFiles.Installed() ? (object)EngineFiles.Fakes() : new { files = new List<string>() },
    };

    private object UpdateIpset()
    {
        var (bytes, source) = Net.FetchFirst(Updater.IpsetUrls, b => EngineFiles.IpsetTextValid(System.Text.Encoding.UTF8.GetString(b)), 30);
        Log.Info("Список IP загружен из " + Net.Host(source));
        string text = System.Text.Encoding.UTF8.GetString(bytes);
        int count = EngineFiles.SaveIpsetList(text);
        RestartIfRunning();
        return new { count };
    }

    private object? SetFake(string kind, string name)
    {
        EngineFiles.SetFake(kind, name);
        var fakes = _s.Node("fakes") as JsonObject ?? new JsonObject();
        fakes[kind] = name;
        _s.Set("fakes", fakes);
        RestartIfRunning();
        return null;
    }

    private object SaveList(string key, string text)
    {
        var entries = EngineFiles.WriteUserList(key, text);
        RestartIfRunning();
        return new { text = string.Join("\n", entries), count = entries.Count };
    }

    // ---------- обновления ----------

    private string? LocalVersionOf(string c) => c == "zapret" ? Updater.LocalVersion() : TgProxy.LocalVersion;
    private bool InstalledOf(string c) => c == "zapret" ? EngineFiles.Installed() : TgProxy.Installed;

    private Release Check(string c)
    {
        _latest[c] = null; // неудачная проверка не должна оставлять старую версию и «последняя версия»
        var rel = Updater.LatestRelease();
        _latest[c] = rel;
        return rel;
    }

    private object CheckUpdate(string c)
    {
        if (c != "zapret") return new { version = "встроенный", newer = false };
        var rel = Check(c);
        return new { rel.version, newer = Updater.IsNewer(rel.version, LocalVersionOf(c)) };
    }

    private object? StartInstall(string c, string mode = "")
    {
        if (c != "zapret") throw new NotSupportedException("Ядро Telegram-прокси встроено в приложение и обновляется вместе с Zapret Hub");
        Begin("update");
        new Thread(() => Install(c, mode)) { IsBackground = true }.Start();
        return null;
    }

    /// <summary>mode "reinstall" — скачать с GitHub Flowseal ту же версию, что установлена; иначе — последний стабильный релиз.</summary>
    private void Install(string c, string mode = "")
    {
        string name = ComponentNames[c];
        bool wasRunning = false;
        try
        {
            Release rel;
            if (mode == "reinstall" && Updater.LocalVersion() is { } cur) rel = Updater.ReleaseForVersion(cur);
            else rel = _latest[c] ?? Check(c);
            var upd = new Dictionary<string, object?> { ["stage"] = "download", ["done"] = 0L, ["total"] = 0L, ["version"] = rel.version, ["component"] = c };
            _update = upd;
            Push("update", upd);
            long lastTick = 0;
            void Progress(long done, long total)
            {
                upd["done"] = done; upd["total"] = total;
                long now = Environment.TickCount64;
                if (now - lastTick > 150) { lastTick = now; Push("update", upd); }
            }
            var st = _e.Status();
            wasRunning = st.running && !st.external; // чужой winws не наш: после обновления его не запускаем второй раз
            string version = Updater.Install(rel, () =>
            {
                upd["stage"] = "install";
                Push("update", upd);
                _e.StopForUpdate();
            }, Progress);
            ReapplyFakes();
            if (wasRunning) StartEngine();
            _update = new { stage = "done", version, component = c };
            Toast($"{name} {version} установлен", "ok");
        }
        catch (Exception e)
        {
            Log.Error($"Обновление {name} не удалось: {e.Message}");
            _update = new { stage = "error", error = e.Message, component = c };
            // Ошибка уже показана в статусе раздела «Обновления» и на онбординге; тост — один, без повтора причины.
            Toast(e is SourceUnavailableException ? e.Message : $"Обновление {name} не удалось: {e.Message}", "err");
            // Откат движка выполнен в Updater.Install; если обход был включён и его остановили, возвращаем его с прежним движком.
            if (wasRunning && EngineFiles.Installed() && !_e.Status().running)
            {
                try { ReapplyFakes(); StartEngine(); }
                catch (Exception re) { Log.Warn("Не удалось вернуть обход после неудачного обновления: " + re.Message); }
            }
        }
        finally
        {
            End();
            Push("update", _update);
            Push("state");
        }
    }

    /// <summary>Фоновый поток: проверка по расписанию и тихая установка.</summary>
    public void AutoUpdateTick()
    {
        if (P.Sandbox || !_s.Bool("auto_update") || _busy != null) return;
        if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() - _s.Dbl("last_update_check") < _s.Int("update_interval_h") * 3600.0) return;
        _s.Set("last_update_check", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        if (!EngineFiles.Installed()) return;
        try
        {
            var rel = Check("zapret");
            Push("state");
            if (Updater.IsNewer(rel.version, Updater.LocalVersion()))
            {
                Log.Info($"Найдена новая версия zapret {rel.version} — обновляю");
                Begin("update");
                Install("zapret");
            }
        }
        catch (Exception e) { Log.Warn("Проверка обновлений zapret не удалась: " + e.Message); }
    }

    // ---------- Telegram-прокси ----------

    private TgCfg TgCfgGet()
    {
        var cfg = _s.Get<TgCfg>("tg") ?? new TgCfg();
        if (string.IsNullOrEmpty(cfg.secret))
        {
            cfg.secret = TgProxy.NewSecret();
            _s.Set("tg", cfg);
        }
        return cfg;
    }

    private object TgState()
    {
        var cfg = TgCfgGet();
        return new
        {
            cfg.enabled, cfg.port, cfg.secret, cfg.dc_ip, cfg.cfproxy,
            installed = TgProxy.Installed, version = TgProxy.LocalVersion, running = _tg.Running,
            link = TgProxy.Link(cfg), latest = PublicRelease("tg"),
        };
    }

    public void TgAutostart()
    {
        var cfg = TgCfgGet();
        if (P.Sandbox || !cfg.enabled || !TgProxy.Installed || _busy != null) return;
        if (!Monitor.TryEnter(_tg.Lock)) return;
        try
        {
            if (!_tg.Running) { _tg.Start(cfg); Push("state"); }
        }
        catch (Exception e) { Log.Warn("Telegram-прокси не поднялся: " + e.Message); }
        finally { Monitor.Exit(_tg.Lock); }
    }

    public void TgStop() => _tg.Stop();

    private object? TgToggle(bool on)
    {
        var cfg = TgCfgGet();
        if (on) _tg.Start(cfg);
        else
        {
            _tg.Stop();
            Log.Info("Telegram-прокси выключен");
        }
        cfg.enabled = on;
        _s.Set("tg", cfg);
        return null;
    }

    private object TgSave(JsonNode portNode, string dcText, bool cf)
    {
        int port = int.Parse(portNode.ToString());
        if (port is < 1024 or > 65535) throw new ArgumentException("Порт должен быть от 1024 до 65535");
        var dc = dcText.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        var bad = dc.FirstOrDefault(l => !TgProxy.ValidDcIp(l));
        if (bad != null) throw new ArgumentException($"Неверная строка DC → IP: «{bad}». Формат: 4:149.154.167.220");
        var cfg = TgCfgGet();
        cfg.port = port; cfg.dc_ip = dc; cfg.cfproxy = cf;
        _s.Set("tg", cfg);
        if (_tg.Running) _tg.Start(cfg);
        return new { link = TgProxy.Link(cfg) };
    }

    private object TgNewSecret()
    {
        var cfg = TgCfgGet();
        cfg.secret = TgProxy.NewSecret();
        _s.Set("tg", cfg);
        if (_tg.Running) _tg.Start(cfg);
        return new { link = TgProxy.Link(cfg) };
    }

    // ---------- AI DNS ----------

    private AiCfg AiCfgGet()
    {
        var cfg = _s.Get<AiCfg>("aidns");
        if (cfg is null)
        {
            cfg = AiDns.ImportStandalone() ?? AiDns.DefaultConfig();
            _s.Set("aidns", cfg);
        }
        return cfg;
    }

    private object AiState()
    {
        var cfg = AiCfgGet();
        return new
        {
            cfg.enabled, cfg.primary, cfg.alternate, cfg.imported,
            standalone = File.Exists(AiDns.StandaloneIni), services = AiDns.Services,
        };
    }

    private static DnsServer AiServer(JsonNode n) => new()
    {
        address = (n["address"]?.ToString() ?? "").Trim(), doh = n["doh"]?.GetValue<bool>() ?? false,
        template = (n["template"]?.ToString() ?? "").Trim(), fallback = n["fallback"]?.GetValue<bool>() ?? false,
    };

    /// <summary>Возвращает прежние DNS; адаптеры, которых больше нет (USB-модем, VPN), просто забываем.</summary>
    private static List<string> AiRestore(AiCfg cfg, IEnumerable<string> ids)
    {
        var failed = new List<string>();
        HashSet<string>? present = null;
        foreach (var id in ids.ToList())
        {
            try
            {
                AiDns.Restore(id, cfg.backup[id]);
                cfg.backup.Remove(id);
            }
            catch (IOException)
            {
                present ??= AiDns.Adapters().Select(x => x.id).ToHashSet();
                if (present.Contains(id)) failed.Add(id); else cfg.backup.Remove(id);
            }
        }
        return failed;
    }

    private object AiAdapters()
    {
        var selected = AiCfgGet().adapters;
        var items = AiDns.Adapters();
        foreach (var a in items) a.selected = selected is null ? a.physical : selected.Contains(a.id);
        return new { items };
    }

    private object AiSave(JsonNode p, JsonNode al, JsonNode ids)
    {
        var primary = AiServer(p); var alternate = AiServer(al);
        AiDns.Validate(primary, false, "предпочтительного DNS");
        AiDns.Validate(alternate, true, "дополнительного DNS");
        var adapterIds = ids.AsArray().Select(x => x!.GetValue<string>()).ToList();
        if (adapterIds.Count == 0) throw new ArgumentException("Включите хотя бы один сетевой адаптер");
        var cfg = AiCfgGet();
        cfg.primary = primary; cfg.alternate = alternate; cfg.adapters = adapterIds;
        try
        {
            if (cfg.enabled)
            {
                AiRestore(cfg, cfg.backup.Keys.Where(i => !adapterIds.Contains(i)));
                AiDns.ApplyToSelected(cfg, adapterIds);
            }
        }
        finally { _s.Set("aidns", cfg); }
        return new { applied = cfg.enabled };
    }

    private object? AiToggle(bool on)
    {
        var cfg = AiCfgGet();
        if (on)
        {
            var selected = cfg.adapters ?? AiDns.Adapters().Where(a => a.physical).Select(a => a.id).ToList();
            if (selected.Count == 0) throw new ArgumentException("Включите хотя бы один сетевой адаптер");
            cfg.adapters = selected;
            try
            {
                AiDns.ApplyToSelected(cfg, selected);
                cfg.enabled = true;
            }
            finally { _s.Set("aidns", cfg); }
            Log.Info("AI DNS включён: " + string.Join(", ", AiDns.ServersOf(cfg).Select(s => s.address)));
            return null;
        }
        var failed = AiRestore(cfg, cfg.backup.Keys);
        cfg.enabled = failed.Count > 0;
        _s.Set("aidns", cfg);
        if (failed.Count > 0) throw new InvalidOperationException("Не удалось вернуть DNS для части адаптеров");
        Log.Info("AI DNS выключен, прежние DNS возвращены");
        return null;
    }

    private object AiCheck(JsonNode p, JsonNode al)
    {
        var primary = AiServer(p); var alternate = AiServer(al);
        AiDns.Validate(primary, false, "предпочтительного DNS");
        AiDns.Validate(alternate, true, "дополнительного DNS");
        var pt = Task.Run(() => AiDns.Check(primary));
        var at = alternate.address.Length > 0 ? Task.Run(() => AiDns.Check(alternate)) : null;
        return new { primary = pt.GetAwaiter().GetResult(), alternate = at?.GetAwaiter().GetResult() ?? new ProbeResult(1, "Дополнительный DNS не задан") };
    }

    /// <summary>При запуске: держим настроенные DNS на месте (Windows или DHCP могли их сбросить).</summary>
    public void AiReapply()
    {
        if (P.Sandbox) return;
        var cfg = AiCfgGet();
        if (!cfg.enabled || cfg.adapters is not { Count: > 0 }) return;
        try { AiDns.ApplyToSelected(cfg, cfg.adapters); }
        catch (IOException e) { Log.Warn("AI DNS: не удалось применить DNS: " + e.Message); }
        finally { _s.Set("aidns", cfg); }
    }

    // ---------- автоподбор ----------

    private object? StartTest(List<string> groups, bool quick, bool apply)
    {
        if (!EngineFiles.Installed()) throw new InvalidOperationException("Сначала установите zapret");
        Begin("test");
        _s.Set("test_groups", groups);
        _cancel = new CancellationTokenSource();
        var token = _cancel.Token;
        new Thread(() => RunTest(groups, quick, apply, token)) { IsBackground = true }.Start();
        return null;
    }

    private void RunTest(List<string> groups, bool quick, bool apply, CancellationToken token)
    {
        var was = _e.Status();
        var names = Strategies.List();
        string current = _s.Str("strategy");
        if (names.Remove(current)) names.Insert(0, current); // текущую проверяем первой

        void Emit(TestState st)
        {
            _test = JsonSerializer.Deserialize<JsonNode>(JsonSerializer.Serialize(st, Json.Opts))!;
            if (st.results.Count > 0)
            {
                var r = st.results[^1];
                var scores = _s.Node("scores") as JsonObject ?? new JsonObject();
                scores[r.name!] = new JsonObject { ["ok"] = r.ok, ["total"] = r.total, ["ms"] = r.ms, ["ts"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0 };
                _s.Set("scores", scores);
            }
            Push("test", _test);
        }

        try
        {
            Log.Info($"Автоподбор: {string.Join(", ", groups)}, {(quick ? "быстрый" : "полный")}");
            var state = Tester.AutoSelect(_e, names, groups, quick, token, Emit);
            var best = state.best;
            if (best != null && apply && state.phase == "done")
            {
                _s.Set("strategy", best);
                StartEngine(best);
                Log.Info($"Лучшая стратегия: {best} — применена");
                Toast($"Готово! Включена стратегия «{best}»", "ok");
            }
            else if (was.running && was.strategy != null) StartEngine(was.strategy);
            if (best == null) Toast("Ни одна стратегия не открыла выбранные сервисы. Загляните в «Диагностику»", "err");
        }
        catch (Exception e)
        {
            Log.Error("Автоподбор прерван: " + e.Message);
            _test = new { running = false, phase = "error", error = e.Message };
            Push("test", _test);
        }
        finally
        {
            End();
            Push("state");
        }
    }

    private object QuickCheck()
    {
        if (_busy == "test") throw new InvalidOperationException(BusyText["test"]);
        return Tester.Check(Tester.LoadTargets().Where(t => t.url != null));
    }

    // ---------- диагностика ----------

    private object Fix(string action)
    {
        if (action == "reinstall")
        {
            _latest["zapret"] = null;
            StartInstall("zapret");
            return new { message = "Переустанавливаю zapret…" };
        }
        return new { message = Diagnostics.Fix(action) };
    }
}
