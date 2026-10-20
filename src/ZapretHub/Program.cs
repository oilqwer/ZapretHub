using System.Text.Json.Nodes;

namespace ZapretHub;

internal static class Program
{
    private const string MutexName = "Local\\ZapretHub2.Instance";
    private const string ShowEvent = "Local\\ZapretHub2.Show";

    [STAThread]
    private static int Main(string[] args)
    {
        string? selfTest = null;
        for (int i = 0; i < args.Length - 1; i++) if (args[i] == "--selftest") selfTest = args[i + 1];

#if MANIFEST_TEST
        // ТЕСТОВАЯ СБОРКА: подписанный манифест берётся из локальной папки, подпись проверяется тестовым ключом из неё же.
        for (int i = 0; i < args.Length - 2; i++)
            if (args[i] == "--make-test-manifest") return TestManifest.Make(args[i + 1], args[i + 2]);
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i] == "--manifest-dir")
            {
                string dir = Path.GetFullPath(args[i + 1]);
                if (!File.Exists(Path.Combine(dir, "components.json")) || !File.Exists(Path.Combine(dir, "components.json.sig")) || !File.Exists(Path.Combine(dir, "test.pub")))
                {
                    MessageBox.Show("В папке нет components.json, components.json.sig, test.pub:\n" + dir, P.AppName + " [тест манифеста]", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return 2;
                }
                Integrity.TestUrl = "file:///" + Path.Combine(dir, "components.json").Replace('\\', '/');
                Integrity.TestPubKey = File.ReadAllText(Path.Combine(dir, "test.pub")).Trim();
                Log.Warn("ТЕСТОВАЯ СБОРКА: манифест из " + dir + ", проверяется тестовым ключом (рабочий манифест и ключ не используются)");
            }
#endif
#if MANIFEST_TEST
        if (args.Length >= 2 && args[0] == "--tgmocktest" && P.Sandbox) return TgMockTest.Run(args[1]);
#endif
        if (args.Length >= 4 && args[0] == "--tgserve" && P.Sandbox) return SelfTest.TgServe(args[1..]);
        if (args.Length >= 6 && args[0] == "--tgburst" && P.Sandbox) return SelfTest.TgBurst(args[1..]);
        if (args.Length >= 6 && args[0] == "--tgclient" && P.Sandbox) return SelfTest.TgClient(args[1..]);
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--tgtest" && P.Sandbox) return SelfTest.TgTest(args[i + 1]);
            if (args[i] == "--tgdiag" && P.Sandbox) return SelfTest.TgDiag(args[i + 1]);
            if (args[i] == "--apitest" && P.Sandbox) return SelfTest.ApiTest(args[i + 1]);
            if (args[i] == "--integritytest" && P.Sandbox) return SelfTest.IntegrityTest(args[i + 1]);
            if (args[i] == "--updatetest" && P.Sandbox) return SelfTest.UpdateTest(args[i + 1]);
            if (args[i] == "--nettest" && P.Sandbox) return SelfTest.NetTest(args[i + 1]);
            if (args[i] == "--defendertest" && P.Sandbox) return SelfTest.DefenderTest(args[i + 1]);
        }

        if (selfTest is null && !P.Sandbox && !Sys.IsAdmin())
        {
            MessageBox.Show("Zapret Hub нужны права администратора: без них драйвер WinDivert не запустится.", P.AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }

        string suffix = P.Sandbox ? ".Sandbox" : "";
        using var mutex = new Mutex(true, MutexName + suffix, out bool created);
        if (!created)
        {
            // уже запущен — просим открыть его окно
            if (EventWaitHandle.TryOpenExisting(ShowEvent + suffix, out var ev)) { ev.Set(); ev.Dispose(); }
            return 0;
        }

        // Один постоянный AppUserModelID: панель задач группирует окно и значок трея под одним приложением и берёт значок EXE, а не общий.
        Sys.SetCurrentProcessExplicitAppUserModelID("Ebowsky.ZapretHub" + suffix);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        AppDomain.CurrentDomain.UnhandledException += (_, e) => Log.Error("Необработанная ошибка: " + e.ExceptionObject);
        Application.ThreadException += (_, e) => Log.Error("Ошибка потока интерфейса: " + e.Exception);

        Log.Info($"Запуск Zapret Hub {P.AppVersion}" + (P.Sandbox ? " (тестовый режим)" : ""));
        bool debug = args.Contains("--debug");
        bool hidden = args.Contains("--tray");
        var settingsProbe = new Settings();
        var form = new MainForm(debug, selfTest, hidden && settingsProbe.Bool("start_minimized"));

        var showEv = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEvent + (P.Sandbox ? ".Sandbox" : ""));
        new Thread(() =>
        {
            while (showEv.WaitOne()) form.ShowFromSecondInstance();
        }) { IsBackground = true }.Start();

        Application.Run(form);
        return 0;
    }
}
