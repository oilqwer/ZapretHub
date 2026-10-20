using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretHub;

/// <summary>Пути и константы. Формат данных совместим с Zapret Hub 1.2.1 (C:\ProgramData\ZapretHub).</summary>
public static class P
{
    public const string AppName = "Zapret Hub";
    public const string AppVersion = "2.0.2";
    public const string Repo = "Flowseal/zapret-discord-youtube";

    /// <summary>Тестовый режим (ZAPRETHUB_DATA задан): системные изменения и чужие процессы не трогаем.</summary>
    public static readonly bool Sandbox = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ZAPRETHUB_DATA"));

    public static readonly string Root = Sandbox
        ? Environment.GetEnvironmentVariable("ZAPRETHUB_DATA")!
        : Path.Combine(Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData", "ZapretHub");

    public static readonly string Engine = Path.Combine(Root, "engine");
    public static readonly string Bin = Path.Combine(Engine, "bin");
    public static readonly string Lists = Path.Combine(Engine, "lists");
    public static readonly string Utils = Path.Combine(Engine, "utils");
    public static readonly string SettingsFile = Path.Combine(Root, "settings.json");
    public static readonly string LogFile = Path.Combine(Root, "zapret-hub.log");
    public static readonly string WinwsLog = Path.Combine(Root, "winws.log");
    public static readonly string WebViewData = Path.Combine(Root, "webview2");

    public static void Need(string what)
    {
        if (Sandbox) throw new InvalidOperationException($"Недоступно в тестовом режиме: {what}");
    }
}

public static class Log
{
    public sealed record Entry(double t, string lvl, string msg);
    private static readonly List<Entry> Ring = new();
    private static readonly object Gate = new();

    public static List<Entry> Last(int n)
    {
        lock (Gate) return Ring.Skip(Math.Max(0, Ring.Count - n)).ToList();
    }

    private static void Write(string lvl, string msg)
    {
        double t = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        lock (Gate)
        {
            Ring.Add(new Entry(t, lvl, msg));
            if (Ring.Count > 300) Ring.RemoveAt(0);
            try
            {
                Directory.CreateDirectory(P.Root);
                if (File.Exists(P.LogFile) && new FileInfo(P.LogFile).Length > 1_000_000)
                {
                    try { File.Move(P.LogFile, P.LogFile + ".1", true); } catch { }
                }
                using var fs = new FileStream(P.LogFile, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                using var w = new StreamWriter(fs, new UTF8Encoding(false));
                w.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss,fff} {lvl.ToUpperInvariant()} {msg}");
            }
            catch { }
        }
    }

    public static void Info(string m) => Write("info", m);
    public static void Warn(string m) => Write("warning", m);
    public static void Error(string m) => Write("error", m);
}

public sealed class Settings
{
    private readonly object _lock = new();
    public JsonObject Data;

    private static JsonObject Defaults() => new()
    {
        ["strategy"] = "general",
        ["run_mode"] = "app",
        ["enabled"] = false,
        ["auto_update"] = true,
        ["update_interval_h"] = 6,
        ["autostart"] = false,
        ["start_minimized"] = true,
        ["close_to_tray"] = true,
        ["autoconnect"] = true,
        ["fakes"] = new JsonObject(),
        ["test_groups"] = new JsonArray("Discord", "YouTube"),
        ["scores"] = new JsonObject(),
        ["last_update_check"] = 0,
    };

    public Settings()
    {
        Data = Defaults();
        try
        {
            if (JsonNode.Parse(File.ReadAllText(P.SettingsFile)) is JsonObject saved)
                foreach (var kv in saved.ToList())
                {
                    saved.Remove(kv.Key);
                    Data[kv.Key] = kv.Value;
                }
        }
        catch { }
    }

    public JsonNode? Node(string key)
    {
        lock (_lock) return Data[key]?.DeepClone();
    }

    public T? Get<T>(string key)
    {
        lock (_lock)
        {
            var n = Data[key];
            if (n is null) return default;
            try { return n.Deserialize<T>(Json.Opts); } catch { return default; }
        }
    }

    public string Str(string key, string def = "") => Get<string>(key) ?? def;
    public bool Bool(string key) => Get<bool>(key);
    public int Int(string key) => Get<int>(key);
    public double Dbl(string key) => Get<double>(key);

    public void Set(string key, object? value)
    {
        lock (_lock)
        {
            Data[key] = value is null ? null : JsonSerializer.SerializeToNode(value, Json.Opts);
            try
            {
                Directory.CreateDirectory(P.Root);
                var tmp = P.SettingsFile + ".tmp";
                File.WriteAllText(tmp, Data.ToJsonString(Json.Indented), new UTF8Encoding(false));
                File.Move(tmp, P.SettingsFile, true);
            }
            catch (Exception e) { Log.Warn("Не удалось сохранить настройки: " + e.Message); }
        }
    }
}

public static class Json
{
    public static readonly JsonSerializerOptions Opts = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = null,
        IncludeFields = true,
    };
    public static readonly JsonSerializerOptions Indented = new(Opts) { WriteIndented = true };
}

public static class Sys
{
    public static readonly Encoding Oem;

    static Sys()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        try { Oem = Encoding.GetEncoding((int)GetOEMCP()); } catch { Oem = Encoding.UTF8; }
    }

    [DllImport("kernel32.dll")] private static extern uint GetOEMCP();

    /// <summary>Запускает консольную утилиту скрыто. Возвращает (код, вывод).</summary>
    public static (int code, string output) Run(string file, IEnumerable<string> args, int timeoutSec = 30)
    {
        var psi = new ProcessStartInfo(file)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
            StandardOutputEncoding = Oem, StandardErrorEncoding = Oem,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            p.StandardInput.Close();
            var so = p.StandardOutput.ReadToEndAsync();
            var se = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutSec * 1000))
            {
                try { p.Kill(true); } catch { }
                return (1, "timeout");
            }
            Task.WaitAll(new Task[] { so, se }, 3000);
            return (p.ExitCode, (so.IsCompletedSuccessfully ? so.Result : "") + (se.IsCompletedSuccessfully ? se.Result : ""));
        }
        catch (Exception e) { return (1, e.Message); }
    }

    public static (int code, string output) Run(string file, params string[] args) => Run(file, args, 30);

    public static bool IsAdmin()
    {
        try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
        catch { return false; }
    }

    public static void OpenShell(string target)
    {
        try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); }
        catch (Exception e) { throw new InvalidOperationException(e.Message); }
    }

    // ---------- автозапуск (задача планировщика, без UAC при входе) ----------

    public static string TaskName => P.Sandbox ? "ZapretHub2Sandbox" : "ZapretHub";

    public static bool AutostartEnabled() => Run("schtasks", "/Query", "/TN", TaskName).code == 0;

    public static void SetAutostart(bool enabled)
    {
        if (!enabled)
        {
            Run("schtasks", "/Delete", "/TN", TaskName, "/F");
            return;
        }
        string exe = Environment.ProcessPath ?? "";
        string user = $"{Environment.UserDomainName}\\{Environment.UserName}";
        string Esc(string s) => System.Security.SecurityElement.Escape(s) ?? "";
        string xml = $"""
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{Esc(user)}</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{Esc(user)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>{Esc(exe)}</Command><Arguments>--tray</Arguments></Exec></Actions>
</Task>
""";
        string tmp = Path.Combine(Path.GetTempPath(), "zapret-hub-task.xml");
        File.WriteAllText(tmp, xml, Encoding.Unicode);
        var (code, output) = Run("schtasks", "/Create", "/TN", TaskName, "/XML", tmp, "/F");
        try { File.Delete(tmp); } catch { }
        if (code != 0) throw new InvalidOperationException("Не удалось включить автозапуск: " + output.Trim());
    }

    // ---------- окно без рамки ----------

    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }

    [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr h);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vk);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int i);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int w, int hh, uint flags);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr wParam, IntPtr lParam);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] public static extern int SetCurrentProcessExplicitAppUserModelID(string appId);
    [DllImport("dwmapi.dll")] public static extern int DwmSetWindowAttribute(IntPtr h, int attr, ref int val, int size);

    /// <summary>Перетаскивание или изменение размера окна без рамки: пока зажата кнопка мыши, край следует за курсором.
    /// edge: "" — перемещение, иначе n/s/e/w/ne/nw/se/sw.</summary>
    public static void DragLoop(IntPtr hwnd, string edge, int minW, int minH)
    {
        if (hwnd == IntPtr.Zero || IsZoomed(hwnd)) return;
        double scale = (GetDpiForWindow(hwnd) is var d && d > 0 ? d : 96) / 96.0;
        minW = (int)Math.Round(minW * scale); minH = (int)Math.Round(minH * scale);
        int button = GetSystemMetrics(23) != 0 ? 0x02 : 0x01; // SM_SWAPBUTTON
        GetWindowRect(hwnd, out var r0);
        GetCursorPos(out var p0);
        (int, int, int, int)? last = null;
        while ((GetAsyncKeyState(button) & 0x8000) != 0)
        {
            GetCursorPos(out var p);
            int dx = p.X - p0.X, dy = p.Y - p0.Y;
            int left = r0.Left, top = r0.Top, right = r0.Right, bottom = r0.Bottom;
            uint flags = 0x0004 | 0x0010; // SWP_NOZORDER | SWP_NOACTIVATE
            if (edge == "")
            {
                left += dx; top += dy; right += dx; bottom += dy;
            }
            else
            {
                if (edge.Contains('e')) right = Math.Max(r0.Right + dx, left + minW);
                if (edge.Contains('w')) left = Math.Min(r0.Left + dx, right - minW);
                if (edge.Contains('s')) bottom = Math.Max(r0.Bottom + dy, top + minH);
                if (edge.Contains('n')) top = Math.Min(r0.Top + dy, bottom - minH);
            }
            var rect = (left, top, right - left, bottom - top);
            if (last != rect)
            {
                SetWindowPos(hwnd, IntPtr.Zero, rect.left, rect.top, rect.Item3, rect.Item4, flags);
                last = rect;
            }
            Thread.Sleep(8);
        }
    }
}
