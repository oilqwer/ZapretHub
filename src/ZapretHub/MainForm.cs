using System.Drawing.Imaging;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace ZapretHub;

public sealed class MainForm : Form, IWindow
{
    private const string Host = "https://zapret-hub.local/";
    private const int MinW = 1000, MinH = 660;

    // Мост window.pywebview.api.* <-> C#: вызовы идут через chrome.webview.postMessage, ответы и события — обратно.
    private const string Shim = """
(() => {
  let seq = 0; const pending = new Map();
  window.__errs = [];
  window.addEventListener('error', e => window.__errs.push(String(e.message) + ' @' + e.filename + ':' + e.lineno));
  window.addEventListener('unhandledrejection', e => window.__errs.push('rejection: ' + String(e.reason)));
  const post = o => chrome.webview.postMessage(o);
  window.pywebview = { api: new Proxy({}, { get: (_, method) => (...args) => new Promise((resolve, reject) => {
    const id = ++seq; pending.set(id, { resolve, reject }); post({ id, method, args });
  }) }) };
  chrome.webview.addEventListener('message', e => {
    const m = e.data;
    if (m.t === 'res') { const p = pending.get(m.id); if (p) { pending.delete(m.id); p.resolve(m.res); } }
    else if (m.t === 'evt') { if (window.hub && window.hub.onEvent) window.hub.onEvent(m.kind, m.data); }
  });
  document.addEventListener('mousedown', e => {
    if (e.button !== 0) return;
    const t = e.target;
    if (t.closest && t.closest('.pywebview-drag-region') && !t.closest('.win, button, a, input')) post({ drag: true });
  }, true);
  document.addEventListener('contextmenu', e => { if (!window.__debug) e.preventDefault(); });
  window.addEventListener('DOMContentLoaded', () => window.dispatchEvent(new Event('pywebviewready')));
})();
""";

    private readonly bool _debug;
    private readonly string? _selfTestDir;
    private readonly bool _startHidden;
    private readonly Settings _s = new();
    private readonly Engine _eng = new();
    private readonly Api _api;
    private readonly WebView2 _web = new() { Dock = DockStyle.Fill, DefaultBackgroundColor = Color.FromArgb(7, 7, 13) };
    private readonly NotifyIcon _tray = new();
    private readonly ManualResetEventSlim _quitting = new(false);
    private readonly Icon _iconOn, _iconOff;
    private readonly ToolStripMenuItem _toggleItem = new("Включить обход");
    private bool _uiReady, _allowShow;
    private bool? _lastRunning;

    public MainForm(bool debug, string? selfTestDir, bool startHidden)
    {
        _debug = debug; _selfTestDir = selfTestDir; _startHidden = startHidden;
        Text = P.AppName;
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        BackColor = Color.FromArgb(7, 7, 13);
        AutoScaleMode = AutoScaleMode.None;
        Controls.Add(_web);

        _iconOn = BrandIcon(SystemInformation.SmallIconSize);
        _iconOff = LoadIcon(true);
        Icon = BrandIcon(SystemInformation.IconSize); // иначе окно без рамки получает стандартный значок «два окна»

        _api = new Api(_s, _eng, PushEvent) { Window = this };

        _tray.Icon = _iconOff;
        _tray.Text = P.AppName;
        var menu = new ContextMenuStrip();
        menu.Items.Add("Открыть Zapret Hub", null, (_, _) => ShowWindow());
        _toggleItem.Click += (_, _) => Task.Run(() =>
        {
            _api.Call("toggle", new JsonArray(!_eng.Status().running));
            PushEvent("state", null);
        });
        menu.Items.Add(_toggleItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Выход", null, (_, _) => Quit());
        _tray.ContextMenuStrip = menu;
        _tray.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) ShowWindow(); };
        _tray.Visible = true;

        // Размер окна — в логических пикселях, как в 1.2.1.
        var handle = Handle; // создаём окно (оно остаётся скрытым, пока не загрузится интерфейс)
        float scale = DeviceDpi / 96f;
        var wa = Screen.FromPoint(Cursor.Position).WorkingArea;
        int w = (int)Math.Min(1220 * scale, wa.Width - 60 * scale), h = (int)Math.Min(800 * scale, wa.Height - 80 * scale);
        Bounds = new Rectangle(wa.Left + (wa.Width - w) / 2, wa.Top + (wa.Height - h) / 2, w, h);
        int round = 2, border = 0x00302626;
        Sys.DwmSetWindowAttribute(handle, 33, ref round, 4);
        Sys.DwmSetWindowAttribute(handle, 34, ref border, 4);
    }

    /// <summary>Фирменный значок из встроенного assets/icon.ico (тот же файл, что и значок EXE) нужного размера.</summary>
    private static Icon BrandIcon(Size size)
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("assets/icon.ico")!;
        return new Icon(s, size);
    }

    private void SetWindowIcons()
    {
        // Явно задаём малый (заголовок/Alt-Tab) и большой (панель задач) значки нужного размера.
        const int WM_SETICON = 0x80;
        _small = BrandIcon(SystemInformation.SmallIconSize); _big = BrandIcon(SystemInformation.IconSize);
        Sys.SendMessage(Handle, WM_SETICON, 0, _small.Handle);
        Sys.SendMessage(Handle, WM_SETICON, 1, _big.Handle);
    }
    private Icon? _small, _big;

    private Icon LoadIcon(bool gray)
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("assets/icon.png")!;
        using var src = new Bitmap(s);
        using var bmp = new Bitmap(32, 32, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bmp))
        {
            g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            if (gray)
            {
                var cm = new ColorMatrix(new[]
                {
                    new[] { .22f, .22f, .22f, 0, 0 }, new[] { .45f, .45f, .45f, 0, 0 }, new[] { .08f, .08f, .08f, 0, 0 },
                    new[] { 0f, 0, 0, 1, 0 }, new[] { 0f, 0, 0, 0, 1 },
                });
                using var ia = new ImageAttributes();
                ia.SetColorMatrix(cm);
                g.DrawImage(src, new Rectangle(0, 0, 32, 32), 0, 0, src.Width, src.Height, GraphicsUnit.Pixel, ia);
            }
            else g.DrawImage(src, 0, 0, 32, 32);
        }
        return Icon.FromHandle(bmp.GetHicon());
    }

    // ---------- окно ----------

    protected override void SetVisibleCore(bool value) => base.SetVisibleCore(value && _allowShow);

    public void ShowWindow()
    {
        if (!_uiReady) return; // окно появится само, как только интерфейс загрузится
        if (InvokeRequired) { BeginInvoke(ShowWindow); return; }
        _allowShow = true;
        Show();
        if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
        Activate();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_quitting.IsSet)
        {
            e.Cancel = true;
            if (_s.Bool("close_to_tray")) Hide(); else Quit();
        }
        base.OnFormClosing(e);
    }

    [StructLayout(LayoutKind.Sequential)] private struct MINMAXINFO { public Sys.POINT Reserved, MaxSize, MaxPosition, MinTrack, MaxTrack; }
    [StructLayout(LayoutKind.Sequential)] private struct MONITORINFO { public int cbSize; public Sys.RECT Monitor, Work; public int Flags; }
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr h, uint flags);
    [DllImport("user32.dll")] private static extern bool GetMonitorInfo(IntPtr mon, ref MONITORINFO mi);

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == 0x0024) // WM_GETMINMAXINFO: развёрнутое окно без рамки не должно закрывать панель задач
        {
            base.WndProc(ref m);
            var mmi = Marshal.PtrToStructure<MINMAXINFO>(m.LParam);
            var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
            if (GetMonitorInfo(MonitorFromWindow(Handle, 2), ref mi))
            {
                mmi.MaxPosition = new Sys.POINT { X = mi.Work.Left - mi.Monitor.Left, Y = mi.Work.Top - mi.Monitor.Top };
                mmi.MaxSize = new Sys.POINT { X = mi.Work.Right - mi.Work.Left, Y = mi.Work.Bottom - mi.Work.Top };
            }
            float scale = DeviceDpi / 96f;
            mmi.MinTrack = new Sys.POINT { X = (int)(MinW * scale), Y = (int)(MinH * scale) };
            Marshal.StructureToPtr(mmi, m.LParam, false);
            return;
        }
        base.WndProc(ref m);
    }

    public void Minimize() => Invoke(() => WindowState = FormWindowState.Minimized);

    public bool ToggleMaximize()
    {
        bool max = false;
        Invoke(() =>
        {
            WindowState = WindowState == FormWindowState.Maximized ? FormWindowState.Normal : FormWindowState.Maximized;
            max = WindowState == FormWindowState.Maximized;
        });
        return max;
    }

    public bool IsMaximized() => IsHandleCreated && Sys.IsZoomed(Handle);

    public void BeginResize(string edge)
    {
        if (edge is not ("n" or "s" or "e" or "w" or "ne" or "nw" or "se" or "sw")) throw new ArgumentException("Неизвестный край окна");
        Sys.DragLoop(Handle, edge, MinW, MinH);
    }

    public void HideToTray() => Invoke(Hide);

    public void Quit()
    {
        if (_quitting.IsSet) return;
        _quitting.Set();
        Task.Run(() =>
        {
            try
            {
                if (_s.Str("run_mode", "app") == "app") _eng.StopOwn(); // служба Windows и чужие winws продолжают работать
                _api.TgStop();
            }
            catch { }
            BeginInvoke(() =>
            {
                _tray.Visible = false;
                _tray.Dispose();
                Application.Exit();
            });
        });
    }

    // ---------- WebView2 ----------

    protected override async void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        if (DesignMode) return;
        SetWindowIcons();
        try
        {
            Directory.CreateDirectory(P.WebViewData);
            var env = await CoreWebView2Environment.CreateAsync(null, P.WebViewData);
            await _web.EnsureCoreWebView2Async(env);
        }
        catch (Exception ex)
        {
            Log.Error("WebView2: " + ex.Message);
            MessageBox.Show("Не удалось запустить компонент WebView2 (Microsoft Edge WebView2 Runtime).\n\n" + ex.Message, P.AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            _quitting.Set();
            Application.Exit();
            return;
        }
        var core = _web.CoreWebView2;
        core.Settings.AreDevToolsEnabled = _debug;
        core.Settings.AreDefaultContextMenusEnabled = _debug;
        core.Settings.IsStatusBarEnabled = false;
        core.Settings.IsZoomControlEnabled = false;
        core.Settings.AreBrowserAcceleratorKeysEnabled = _debug;
        await core.AddScriptToExecuteOnDocumentCreatedAsync((_debug ? "window.__debug=true;" : "") + Shim);
        core.AddWebResourceRequestedFilter(Host + "*", CoreWebView2WebResourceContext.All);
        core.WebResourceRequested += OnResource;
        core.WebMessageReceived += OnMessage;
        core.NavigationCompleted += (_, _) => OnUiLoaded();
        core.NewWindowRequested += (s, a) => { a.Handled = true; };
        core.Navigate(Host + "index.html");
        Task.Run(async () => { await Task.Delay(15000); if (!_uiReady) { Log.Warn("Интерфейс не загрузился за 15 с — показываю окно как есть"); BeginInvoke(OnUiLoaded); } });
    }

    private void OnResource(object? sender, CoreWebView2WebResourceRequestedEventArgs e)
    {
        string path = new Uri(e.Request.Uri).AbsolutePath.TrimStart('/');
        if (path.Length == 0) path = "index.html";
        var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("ui/" + path);
        var env = _web.CoreWebView2.Environment;
        if (stream is null)
        {
            e.Response = env.CreateWebResourceResponse(null, 404, "Not Found", "");
            return;
        }
        string ct = Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".html" => "text/html; charset=utf-8", ".css" => "text/css; charset=utf-8", ".js" => "text/javascript; charset=utf-8",
            ".png" => "image/png", ".svg" => "image/svg+xml", _ => "application/octet-stream",
        };
        e.Response = env.CreateWebResourceResponse(stream, 200, "OK", $"Content-Type: {ct}\r\nCache-Control: no-store");
    }

    private void OnMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        JsonNode? msg;
        try { msg = JsonNode.Parse(e.WebMessageAsJson); } catch { return; }
        if (msg is null) return;
        if (msg["drag"] is not null)
        {
            var h = Handle;
            Task.Run(() => Sys.DragLoop(h, "", MinW, MinH));
            return;
        }
        int id = msg["id"]?.GetValue<int>() ?? 0;
        string method = msg["method"]?.GetValue<string>() ?? "";
        var args = msg["args"]?.AsArray() ?? new JsonArray();
        Task.Run(() =>
        {
            var res = _api.Call(method, args);
            Post(new JsonObject { ["t"] = "res", ["id"] = id, ["res"] = res });
        });
    }

    private void Post(JsonNode node)
    {
        if (_quitting.IsSet || !IsHandleCreated) return;
        string json = node.ToJsonString(Json.Opts);
        try
        {
            BeginInvoke(() =>
            {
                try { _web.CoreWebView2?.PostWebMessageAsJson(json); } catch { }
            });
        }
        catch { }
    }

    private void PushEvent(string kind, object? data)
    {
        var node = JsonSerializer.SerializeToNode(data ?? new { }, Json.Opts);
        Post(new JsonObject { ["t"] = "evt", ["kind"] = kind, ["data"] = node });
    }

    private void OnUiLoaded()
    {
        if (_uiReady) return;
        _uiReady = true;
        if (_selfTestDir != null) { _allowShow = true; Show(); _ = SelfTest(_selfTestDir); }
        else if (!_startHidden) ShowWindow();
        StartBackground();
    }

    // ---------- фоновые задачи ----------

    private void StartBackground()
    {
        if (_selfTestDir != null || P.Sandbox) return; // в тестовом режиме ничего не трогаем в системе
        new Thread(() =>
        {
            try { _api.AiReapply(); } catch (Exception e) { Log.Warn("AI DNS: " + e.Message); }
            if (EngineFiles.Installed() && _s.Bool("autoconnect") && _s.Bool("enabled") && _s.Str("run_mode", "app") == "app" && !_eng.Status().running)
            {
                _api.Call("toggle", new JsonArray(true));
                PushEvent("state", null);
            }
            long lastUpdate = 0, lastTg = 0;
            while (!_quitting.IsSet)
            {
                var st = _eng.Status();
                SetTray(st);
                long now = Environment.TickCount64;
                if (now - lastUpdate > 60_000) { lastUpdate = now; Task.Run(_api.AutoUpdateTick); }
                if (now - lastTg > 30_000) { lastTg = now; Task.Run(_api.TgAutostart); }
                _quitting.Wait(3000);
            }
        }) { IsBackground = true }.Start();
    }

    private void SetTray(EngineStatus st)
    {
        if (_lastRunning == st.running) return;
        _lastRunning = st.running;
        try
        {
            BeginInvoke(() =>
            {
                _tray.Icon = st.running ? _iconOn : _iconOff;
                string t = $"{P.AppName} — {(st.running ? "обход активен: " + st.strategy : "обход выключен")}";
                _tray.Text = t.Length > 127 ? t[..127] : t;
                _toggleItem.Text = st.running ? "Выключить обход" : "Включить обход";
            });
        }
        catch { }
    }

    public void ShowFromSecondInstance() => ShowWindow();

    // ---------- самопроверка (--selftest <папка>): скриншоты всех страниц и ошибки JS ----------

    private async Task SelfTest(string dir)
    {
        Directory.CreateDirectory(dir);
        var core = _web.CoreWebView2;
        var report = new List<string>();
        try
        {
            await Task.Delay(3000);
            foreach (var page in new[] { "home", "strategies", "telegram", "aidns", "filters", "lists", "diag", "updates", "settings" })
            {
                await core.ExecuteScriptAsync($"go('{page}')");
                await Task.Delay(1500);
                using var fs = File.Create(Path.Combine(dir, page + ".png"));
                await core.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, fs);
            }
            // окно исключения Защитника: реальное состояние (в тесте без прав администратора) и имитация «широкое исключение уже есть»
            await core.ExecuteScriptAsync("go('diag')");
            await Task.Delay(1000);
            await core.ExecuteScriptAsync("actions['def-open']()");
            await Task.Delay(2500);
            using (var fs = File.Create(Path.Combine(dir, "defender-real.png"))) await core.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, fs);
            report.Add("defender dialog state: " + await core.ExecuteScriptAsync("document.getElementById('defState').textContent"));
            report.Add("defender add disabled: " + await core.ExecuteScriptAsync("document.getElementById('defAdd').disabled"));
            await core.ExecuteScriptAsync("defSt={available:true,root:true,bin:false,existing:['C:\\\\ProgramData\\\\ZapretHub'],addPath:'C:\\\\ProgramData\\\\ZapretHub\\\\engine\\\\bin'}; defRender();");
            await Task.Delay(500);
            using (var fs = File.Create(Path.Combine(dir, "defender-existing.png"))) await core.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, fs);
            report.Add("defender (имитация) add disabled: " + await core.ExecuteScriptAsync("document.getElementById('defAdd').disabled") + ", remove hidden: " + await core.ExecuteScriptAsync("document.getElementById('defRemove').classList.contains('hidden')"));
            report.Add("errors: " + await core.ExecuteScriptAsync("JSON.stringify(window.__errs)"));
            report.Add("title: " + await core.ExecuteScriptAsync("document.title"));
            report.Add("tbText: " + await core.ExecuteScriptAsync("document.getElementById('tbText').textContent"));
            report.Add("S.strategies: " + await core.ExecuteScriptAsync("S && S.strategies.length"));
            report.Add("S.installed: " + await core.ExecuteScriptAsync("S && S.installed"));
        }
        catch (Exception e) { report.Add("EXC: " + e); }
        File.WriteAllLines(Path.Combine(dir, "report.txt"), report);
        Quit();
    }
}
