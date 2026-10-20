using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace ZapretHub;

/// <summary>Проверки без интерфейса: --tgtest <файл-отчёт>. Запускается только в тестовом режиме (ZAPRETHUB_DATA).</summary>
internal static class SelfTest
{
    /// <summary>Настоящий переход версий через GitHub API Flowseal в изолированной папке (--updatetest папка-отчёта; нужен ZAPRETHUB_DATA и интернет).
    /// Ставит 1.10.3, кладёт пользовательский список, обновляет до последнего релиза, затем «переустанавливает» и проверяет отказ при неверном SHA-256.</summary>
    public static int UpdateTest(string dir)
    {
        var sb = new StringBuilder();
        int fails = 0;
        void Check(string name, bool ok) { sb.AppendLine($"{(ok ? "PASS" : "FAIL")}  {name}"); if (!ok) fails++; }
        try
        {
            Directory.CreateDirectory(dir);
            Updater.TryDelete(P.Engine);
            Updater.TryDelete(Path.Combine(P.Root, "engine.backup"));
            var latest = Updater.LatestRelease();
            sb.AppendLine($"latest: {latest.version}  {latest.url}\n        sha256={latest.sha256}  date={latest.date}  notes={latest.notes.Length} симв.");
            Check("API: последний релиз получен с SHA-256 и описанием", latest.sha256.Length == 64 && latest.notes.Length > 0);
            var old = Updater.ReleaseForVersion("1.10.3");
            sb.AppendLine($"1.10.3: {old.url}\n        sha256={old.sha256}");
            string v = Updater.Install(old, () => { }, null);
            Check("установлена 1.10.3 (по тегу, SHA-256 из API)", v == "1.10.3" && Updater.LocalVersion() == "1.10.3");
            Check("«новее» определяется верно", Updater.IsNewer(latest.version, "1.10.3") == (Updater.VersionTuple(latest.version).SequenceEqual(new[] { 1, 10, 3 }) ? false : true));
            Directory.CreateDirectory(P.Lists);
            File.WriteAllText(Path.Combine(P.Lists, "list-general-user.txt"), "my-own.example.org\n");
            File.WriteAllText(Path.Combine(P.Utils, "game_filter.enabled"), "all");
            if (Updater.IsNewer(latest.version, "1.10.3"))
            {
                v = Updater.Install(latest, () => { }, null);
                Check($"обновление 1.10.3 → {latest.version}", v == latest.version && Updater.LocalVersion() == latest.version);
                Check("пользовательский список и game_filter сохранены", File.ReadAllText(Path.Combine(P.Lists, "list-general-user.txt")).Contains("my-own.example.org") && File.Exists(Path.Combine(P.Utils, "game_filter.enabled")));
                Check("резервная копия 1.10.3 сохранена", File.ReadAllText(Path.Combine(P.Root, "engine.backup", "service.bat")).Contains("1.10.3"));
            }
            else sb.AppendLine($"SKIP  на GitHub сейчас {latest.version} — перехода после 1.10.3 нет");
            var again = Updater.ReleaseForVersion(Updater.LocalVersion()!);
            v = Updater.Install(again, () => { }, null);
            Check("переустановка текущей версии с GitHub", v == Updater.LocalVersion() && v == again.version);
            Check("после переустановки копия предыдущей версии (1.10.3) сохранена", File.ReadAllText(Path.Combine(P.Root, "engine.backup", "service.bat")).Contains("1.10.3") || !Updater.IsNewer(latest.version, "1.10.3"));
            string before = Updater.LocalVersion()!;
            string err = "";
            try { Updater.Install(again with { sha256 = new string('0', 64) }, () => { }, null); } catch (Exception e) { err = e.Message; }
            Check("неверный SHA-256 отклонён, движок не изменён", err.Contains("Контрольная сумма") && Updater.LocalVersion() == before && !File.Exists(Path.Combine(P.Root, "download.zip")) && !Directory.Exists(Path.Combine(P.Root, "staging")));
        }
        catch (Exception e) { sb.AppendLine("ОШИБКА: " + e.GetType().Name + ": " + e.Message); fails++; }
        sb.AppendLine(fails == 0 ? "ИТОГО: все проверки пройдены" : $"ИТОГО: провалено {fails}");
        File.WriteAllText(Path.Combine(dir, "update-report.txt"), sb.ToString(), new UTF8Encoding(false));
        return fails == 0 ? 0 : 1;
    }

    /// <summary>Проверка Ed25519/SHA-256 и установки по подписанному манифесту на локальных данных (--integritytest папка-с-фикстурами).</summary>
    public static int IntegrityTest(string dir)
    {
        var sb = new StringBuilder();
        int fails = 0;
        void Check(string name, bool ok) { sb.AppendLine($"{(ok ? "PASS" : "FAIL")}  {name}"); if (!ok) fails++; }
        bool Throws<T>(Action a, out string msg) where T : Exception
        {
            try { a(); msg = ""; return false; } catch (T e) { msg = e.Message; return true; } catch (Exception e) { msg = "другое: " + e.Message; return false; }
        }
        string F(string n) => Path.Combine(dir, n);

        // 1. Ed25519 против независимой реализации
        var vectors = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(F("vectors.json")))!.AsArray();
        int good = 0, rejected = 0;
        foreach (var v in vectors)
        {
            var pub = Convert.FromBase64String(v!["pub"]!.GetValue<string>());
            var msg = Convert.FromBase64String(v["msg"]!.GetValue<string>());
            var sig = Convert.FromBase64String(v["sig"]!.GetValue<string>());
            if (Ed25519.Verify(pub, msg, sig)) good++;
            var bad = (byte[])sig.Clone(); bad[10] ^= 1;
            var badMsg = msg.Concat(new byte[] { 1 }).ToArray();
            if (!Ed25519.Verify(pub, msg, bad) && !Ed25519.Verify(pub, badMsg, sig)) rejected++;
        }
        Check($"подписи Python cryptography приняты ({good}/{vectors.Count})", good == vectors.Count);
        Check($"изменённые подпись/сообщение отклонены ({rejected}/{vectors.Count})", rejected == vectors.Count);
        var rfc = vectors[^1]!;
        Check("RFC 8032 test 1 (пустое сообщение)", rfc["rfc_pub_hex"]!.GetValue<string>() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            && rfc["rfc_sig_hex"]!.GetValue<string>().StartsWith("e5564300c360ac72")
            && Ed25519.Verify(Convert.FromHexString(rfc["rfc_pub_hex"]!.GetValue<string>()), Array.Empty<byte>(), Convert.FromHexString(rfc["rfc_sig_hex"]!.GetValue<string>())));

        // 2. Настоящий подписанный манифест автора (копия из ZapretHub-public) с зашитым ключом
        string real = F("real-components.json");
        if (File.Exists(real))
        {
            var data = File.ReadAllBytes(real);
            string sig = File.ReadAllText(real + ".sig");
            Check("манифест автора: подпись верна с зашитым ключом", !Throws<IntegrityException>(() => Integrity.VerifySignature(data, sig), out _));
            var t = (byte[])data.Clone(); t[20] ^= 1;
            Check("манифест автора: изменённый байт отклонён", Throws<IntegrityException>(() => Integrity.VerifySignature(t, sig), out _));
            Check("манифест автора: чужой ключ отклонён", Throws<IntegrityException>(() => Integrity.VerifySignature(data, sig, File.ReadAllText(F("test.pub"))), out _));
            Check("манифест автора: мусор вместо подписи отклонён", Throws<IntegrityException>(() => Integrity.VerifySignature(data, "!!!не-base64", null), out _));
        }

        // Несколько источников манифеста: выбирается валидный с максимальным sequence, любые сбои не открывают обход проверки
        {
            string tk = File.ReadAllText(F("test.pub")).Trim();
            byte[] Fx(string n) => File.ReadAllBytes(F(n));
            Func<Dictionary<string, string>, Func<string, byte[]>> mk = map => u =>
            {
                if (!map.TryGetValue(u.EndsWith(".sig") ? u[..^4] : u, out var file)) throw new IOException("нет соединения (имитация)");
                return Fx(u.EndsWith(".sig") ? file + ".sig" : file);
            };
            try { File.Delete(Integrity.SequenceFile); } catch { }
            var m1 = mk(new() { ["https://s2/m"] = "tampered.json", ["https://s3/m"] = "old.json", ["https://s4/m"] = "good.json", ["https://s5/m"] = "foreign.json" });
            var srcs = new[] { "https://s1/m", "https://s2/m", "https://s3/m", "https://s4/m", "https://s5/m" };
            var picked = Integrity.LoadFrom(srcs, m1, tk);
            Check("источники: 1 недоступен, 2 изменён, 5 чужая подпись — принят валидный с наибольшим sequence", picked["sequence"]!.GetValue<int>() == 10);
            Check("источники: sequence 10 сохранён", File.ReadAllText(Integrity.SequenceFile).Trim() == "10");
            Check("источники: устаревший, но валидный (seq 3) не выбран, пока есть новее", picked["sequence"]!.GetValue<int>() != 3);
            Check("источники: ни один не валиден — установка запрещена", Throws<IntegrityException>(() => Integrity.LoadFrom(new[] { "https://s1/m", "https://s2/m", "https://s5/m" }, m1, tk), out _));
            Check("источники: только устаревший (seq 3 < принятого 10) — отказ (откат)", Throws<IntegrityException>(() => Integrity.LoadFrom(new[] { "https://s3/m" }, m1, tk), out var msg) && msg.Contains("откат"));
            Check("источники: рабочий ключ не принимает тестовые подписи", Throws<IntegrityException>(() => Integrity.LoadFrom(new[] { "https://s4/m" }, m1, Integrity.PublicKey), out _));
            try { File.Delete(Integrity.SequenceFile); } catch { }
        }
        foreach (var (ip, want) in new[] { ("127.0.0.1", true), ("0.0.0.0", true), ("10.1.1.1", true), ("192.168.1.5", true), ("100.64.0.1", true), ("169.254.1.1", true), ("::1", true), ("185.199.108.133", false), ("1.1.1.1", false), ("151.101.1.229", false) })
            Check($"Net.Bogus({ip}) = {want}", Net.Bogus(System.Net.IPAddress.Parse(ip)) == want);
        // IP-список: настоящий список из установленного zapret проходит строгую проверку, а мусор — нет
        string sample = F("ipset-sample.txt");
        if (File.Exists(sample))
        {
            Directory.CreateDirectory(P.Lists);
            Check("настоящий список IP проходит проверку", !Throws<InvalidOperationException>(() => EngineFiles.SaveIpsetList(File.ReadAllText(sample)), out _));
            var lines = File.ReadAllLines(sample).Take(30).ToList();
            foreach (var (bad, why) in new[] { ("10.0.0.0/8", "приватная сеть"), ("127.0.0.1", "loopback"), ("evil.example.com", "имя"), ("1.2.3.4/99", "маска"), ("1.2.3.4; rm", "мусор") })
            {
                var l2 = lines.Concat(new[] { bad });
                Check($"список с недопустимой записью отклонён ({why})", Throws<InvalidOperationException>(() => EngineFiles.SaveIpsetList(string.Join("\n", l2)), out _));
            }
        }
        // 3. Релизы Flowseal: разбор ответа GitHub API (без сети) и распаковка архива
        {
            string P_ = Updater.Owner + "/zapret-discord-youtube";
            JsonObject Rel(Action<JsonObject>? tweak = null)
            {
                var o = new JsonObject
                {
                    ["tag_name"] = "1.10.4", ["draft"] = false, ["prerelease"] = false, ["body"] = "Что нового", ["published_at"] = "2026-10-01T00:00:00Z",
                    ["html_url"] = $"https://github.com/{P_}/releases/tag/1.10.4",
                    ["assets"] = new JsonArray(new JsonObject
                    {
                        ["name"] = "zapret-discord-youtube-1.10.4.zip", ["state"] = "uploaded", ["size"] = 1000,
                        ["browser_download_url"] = $"https://github.com/{P_}/releases/download/1.10.4/zapret-discord-youtube-1.10.4.zip",
                        ["digest"] = "sha256:" + new string('a', 64),
                    }),
                };
                tweak?.Invoke(o);
                return o;
            }
            JsonObject A0(JsonObject o) => (JsonObject)o["assets"]![0]!;
            var ok = Updater.ParseRelease(Rel());
            Check("релиз Flowseal: версия, sha256 и адрес разобраны", ok.version == "1.10.4" && ok.sha256 == new string('a', 64) && ok.url.StartsWith("https://github.com/Flowseal/") && ok.notes == "Что нового");
            Check("релиз: нет digest — отказ", Throws<IntegrityException>(() => Updater.ParseRelease(Rel(o => A0(o).Remove("digest"))), out _));
            Check("релиз: digest не sha256 — отказ", Throws<IntegrityException>(() => Updater.ParseRelease(Rel(o => A0(o)["digest"] = "md5:abc")), out _));
            Check("релиз: чужой репозиторий в html_url — отказ", Throws<IntegrityException>(() => Updater.ParseRelease(Rel(o => o["html_url"] = "https://github.com/evil/zapret-discord-youtube/releases/tag/1.10.4")), out _));
            Check("релиз: архив из чужого репозитория — отказ", Throws<IntegrityException>(() => Updater.ParseRelease(Rel(o => A0(o)["browser_download_url"] = "https://github.com/evil/x/releases/download/1.10.4/a.zip")), out _));
            Check("релиз: архив по http — отказ", Throws<IntegrityException>(() => Updater.ParseRelease(Rel(o => A0(o)["browser_download_url"] = $"http://github.com/{P_}/releases/download/1.10.4/a.zip")), out _));
            Check("релиз: чужой хост архива — отказ", Throws<IntegrityException>(() => Updater.ParseRelease(Rel(o => A0(o)["browser_download_url"] = $"https://evil.com/{P_}/releases/download/1.10.4/a.zip")), out _));
            Check("релиз: prerelease — отказ", Throws<IntegrityException>(() => Updater.ParseRelease(Rel(o => o["prerelease"] = true)), out _));
            Check("релиз: нет ZIP — отказ", Throws<IntegrityException>(() => Updater.ParseRelease(Rel(o => o["assets"] = new JsonArray())), out _));
            Check("релиз: мусор вместо версии — отказ", Throws<IntegrityException>(() => Updater.ParseRelease(Rel(o => o["tag_name"] = "latest; rm")), out _));
            Check("версии: 1.10.4 новее 1.10.3, 1.10.3 не новее 1.10.3", Updater.IsNewer("1.10.4", "1.10.3") && !Updater.IsNewer("1.10.3", "1.10.3") && !Updater.IsNewer("1.9.9", "1.10.3"));

            string evil = Path.Combine(dir, "evil.zip"), outDir = Path.Combine(dir, "extract");
            foreach (var name in new[] { "../evil.txt", "a/../../evil.txt", "/abs.txt", "C:/abs.txt", "..\\evil.txt" })
            {
                try { File.Delete(evil); } catch { }
                using (var z = System.IO.Compression.ZipFile.Open(evil, System.IO.Compression.ZipArchiveMode.Create))
                {
                    var en = z.CreateEntry(name); using var w = new StreamWriter(en.Open()); w.Write("x");
                }
                Updater.TryDelete(outDir);
                Check($"распаковка: путь «{name}» отклонён", Throws<InvalidOperationException>(() => Updater.ExtractSafe(evil, outDir), out _) && !File.Exists(Path.Combine(dir, "evil.txt")));
            }
            Updater.TryDelete(outDir);
            Updater.ExtractSafe(F("engine-9.9.9.zip"), outDir);
            Check("распаковка: обычный архив распакован", File.Exists(Path.Combine(outDir, "zapret-9.9.9", "service.bat")));
            Updater.TryDelete(outDir);
        }
#if MANIFEST_TEST
        // 4. Установка из локального архива (file:/// — без сети): SHA-256 обязателен, резервная копия, откат
        string zip = F("engine-9.9.9.zip"), zsha = Integrity.Sha256File(zip), zuri = "file:///" + zip.Replace('\\', '/');
        string Install(string sha)
        {
            try { Updater.Install(new Release("9.9.9", zuri, "", null, sha), () => { }, null); return "OK " + Updater.LocalVersion(); }
            catch (Exception e) { return e.GetType().Name + ": " + e.Message; }
        }
        Directory.CreateDirectory(P.Bin);
        File.WriteAllText(Path.Combine(P.Engine, "service.bat"), "set \"LOCAL_VERSION=1.0.0\"\r\n");
        File.WriteAllText(Path.Combine(P.Bin, "winws.exe"), "old");
        Directory.CreateDirectory(P.Lists);
        File.WriteAllText(Path.Combine(P.Lists, "list-general-user.txt"), "my.example.org\n");
        File.WriteAllText(Path.Combine(P.Lists, "custom-user.txt"), "custom\n");

        string r;
        r = Install(new string('0', 64)); sb.AppendLine("  badsha -> " + r); Check("неверный SHA-256 архива отклонён, движок не изменён", r.Contains("Контрольная сумма") && Updater.LocalVersion() == "1.0.0" && !File.Exists(Path.Combine(P.Root, "download.zip")));
        r = Install(""); sb.AppendLine("  nosha -> " + r); Check("нет SHA-256 — установка отклонена", r.StartsWith("IntegrityException") && Updater.LocalVersion() == "1.0.0");
        r = Install(zsha); sb.AppendLine("  good -> " + r); Check("корректный архив: установка прошла", r == "OK 9.9.9");
        Check("пользовательские списки перенесены", File.ReadAllText(Path.Combine(P.Lists, "list-general-user.txt")).Contains("my.example.org") && File.Exists(Path.Combine(P.Lists, "custom-user.txt")));
        Check("резервная копия прежнего движка сохранена", File.ReadAllText(Path.Combine(P.Root, "engine.backup", "service.bat")).Contains("1.0.0") && !Directory.Exists(Path.Combine(P.Root, "engine.old")));
        r = Install(zsha); sb.AppendLine("  reinstall -> " + r); Check("повторная установка той же версии: копия предыдущей (1.0.0) не вытеснена", r == "OK 9.9.9" && File.ReadAllText(Path.Combine(P.Root, "engine.backup", "service.bat")).Contains("1.0.0") && !Directory.Exists(Path.Combine(P.Root, "engine.old")));
        // сбой при замене: подсовываем архив без winws.exe — движок и копия остаются прежними
        string broken = Path.Combine(dir, "broken.zip");
        try { File.Delete(broken); } catch { }
        using (var z = System.IO.Compression.ZipFile.Open(broken, System.IO.Compression.ZipArchiveMode.Create)) { var en = z.CreateEntry("x/service.bat"); using var w = new StreamWriter(en.Open()); w.Write("x"); }
        try { Updater.Install(new Release("9.9.9", "file:///" + broken.Replace('\\', '/'), "", null, Integrity.Sha256File(broken)), () => { }, null); r = "OK"; } catch (Exception e) { r = e.Message; }
        Check("архив с неожиданной структурой отклонён, движок не изменён", r.Contains("структур") && Updater.LocalVersion() == "9.9.9" && EngineFiles.Installed());
#else
        sb.AppendLine("(проверка установки из архива — только в тестовой сборке ZapretHub-ManifestTest.exe)");
#endif
        sb.AppendLine(fails == 0 ? "ИТОГО: все проверки пройдены" : $"ИТОГО: провалено {fails}");
        File.WriteAllText(Path.Combine(dir, "report.txt"), sb.ToString(), new UTF8Encoding(false));
        return fails == 0 ? 0 : 1;
    }

    /// <summary>Пошаговая диагностика подключения к WS-шлюзу Telegram: TCP, TLS (варианты), HTTP-апгрейд (--tgdiag файл).</summary>
    public static int TgDiag(string reportFile)
    {
        var sb = new StringBuilder();
        string ip = "149.154.167.220";
        async Task<string> Step(string name, Func<CancellationToken, Task<string>> action)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            using var cts = new CancellationTokenSource(8000);
            try { var r = await action(cts.Token); return $"{name}: OK {r} ({sw.ElapsedMilliseconds} мс)"; }
            catch (Exception e) { return $"{name}: {e.GetType().Name} {(e.InnerException?.Message ?? e.Message)} ({sw.ElapsedMilliseconds} мс)"; }
        }
        async Task<System.Net.Security.SslStream> Tls(string sni, System.Security.Authentication.SslProtocols proto, CancellationToken ct, bool noRevocation = true)
        {
            var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(ip, 443, ct);
            var ssl = new System.Net.Security.SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = sni, EnabledSslProtocols = proto }, ct);
            return ssl;
        }
        foreach (var mode in new[] { "dual", "v4", "dual", "v4", "dual", "v4" })
        {
            var sw0 = System.Diagnostics.Stopwatch.StartNew();
            var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(async () =>
            {
                var s = mode == "v4" ? new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp) : new TcpClient().Client;
                try { using var c = new CancellationTokenSource(8000); await s.ConnectAsync(new System.Net.IPEndPoint(System.Net.IPAddress.Parse(ip), 443), c.Token); return sw0.ElapsedMilliseconds; }
                catch { return -1L; }
                finally { s.Dispose(); }
            })).ToArray();
            Task.WaitAll(tasks);
            var okc = tasks.Select(x => x.Result).Where(x => x >= 0).ToList();
            sb.AppendLine($"16 параллельных TCP ({mode}): успешно {okc.Count}/16, макс время успеха {(okc.Count > 0 ? okc.Max() : 0)} мс");
        }
        for (int i = 0; i < 3; i++)
            sb.AppendLine(Step($"TCP {ip}:443 #{i}", async ct => { using var c = new TcpClient(); await c.ConnectAsync(ip, 443, ct); return ""; }).GetAwaiter().GetResult());
        foreach (var (name, proto) in new[] { ("по умолчанию", System.Security.Authentication.SslProtocols.None), ("TLS1.2", System.Security.Authentication.SslProtocols.Tls12), ("TLS1.3", System.Security.Authentication.SslProtocols.Tls13) })
            for (int i = 0; i < 3; i++)
                sb.AppendLine(Step($"TLS kws2.web.telegram.org {name} #{i}", async ct => { using var s = await Tls("kws2.web.telegram.org", proto, ct); return s.SslProtocol + " " + s.NegotiatedCipherSuite; }).GetAwaiter().GetResult());
        sb.AppendLine(Step("TLS SNI=sprinthost.ru (маскировка)", async ct => { using var s = await Tls("sprinthost.ru", System.Security.Authentication.SslProtocols.None, ct); return s.SslProtocol.ToString(); }).GetAwaiter().GetResult());
        for (int i = 0; i < 4; i++)
            sb.AppendLine(Step($"WS-апгрейд kws2 (RawWs) #{i}", async ct => { var w = await RawWs.Connect(ip, "kws2.web.telegram.org", 8); w.Dispose(); return ""; }).GetAwaiter().GetResult());
        for (int i = 0; i < 2; i++)
            sb.AppendLine(Step($"WS-апгрейд kws2 маскировка #{i}", async ct => { var w = await RawWs.Connect(ip, "kws2.web.telegram.org", 7, "/apiws", "sprinthost.ru"); w.Dispose(); return ""; }).GetAwaiter().GetResult());
        File.WriteAllText(reportFile, sb.ToString(), new UTF8Encoding(false));
        return 0;
    }
    /// <summary>Поднимает наш прокси на заданном порту на N секунд (--tgserve порт секрет секунды), журнал — в песочнице.</summary>
    public static int TgServe(string[] a)
    {
        var cfg = new TgCfg { port = int.Parse(a[0]), secret = a[1] };
        var p = new TgProxy();
        p.Start(cfg);
        Thread.Sleep(int.Parse(a[2]) * 1000);
        p.Stop();
        return 0;
    }

    /// <summary>Один клиент MTProto (obfuscated2, padded intermediate как у Telegram Desktop с dd-секретом): count незашифрованных req_pq_multi
    /// подряд в одном соединении. Возвращает число полученных resPQ, времена ответов (мс) и ошибку.</summary>
    private static (int ok, List<long> times, string? error) OneClient(int port, byte[] secret, int dc, int count, int timeoutMs)
    {
        var times = new List<long>(); int ok = 0;
        try
        {
            var init = RandomNumberGenerator.GetBytes(64);
            while (init[0] == 0xEF || (init[4] | init[5] | init[6] | init[7]) == 0) init = RandomNumberGenerator.GetBytes(64);
            init[56] = init[57] = init[58] = init[59] = 0xDD;
            BitConverter.GetBytes((short)dc).CopyTo(init, 60);
            var prekeyIv = init[8..56];
            using var enc = new AesCtr(SHA256.HashData(prekeyIv[..32].Concat(secret).ToArray()), prekeyIv[32..]);
            var encInit = enc.Update(init);
            var rev = prekeyIv.Reverse().ToArray();
            using var dec = new AesCtr(SHA256.HashData(rev[..32].Concat(secret).ToArray()), rev[32..]);
            var sendInit = (byte[])init.Clone(); Array.Copy(encInit, 56, sendInit, 56, 8);

            var sw = System.Diagnostics.Stopwatch.StartNew();
            using var tcp = new TcpClient { NoDelay = true };
            tcp.Connect("127.0.0.1", port);
            tcp.ReceiveTimeout = timeoutMs;
            var ns = tcp.GetStream();
            ns.Write(sendInit);
            for (int i = 0; i < count; i++)
            {
                var payload = new byte[40];
                BitConverter.GetBytes((DateTimeOffset.UtcNow.ToUnixTimeSeconds() << 32) & ~3L).CopyTo(payload, 8);
                BitConverter.GetBytes(20).CopyTo(payload, 16);
                BitConverter.GetBytes(0xbe7e8ef1u).CopyTo(payload, 20);
                RandomNumberGenerator.GetBytes(16).CopyTo(payload, 24);
                int pad = RandomNumberGenerator.GetInt32(4);
                var pkt = new byte[4 + payload.Length + pad];
                BitConverter.GetBytes(payload.Length + pad).CopyTo(pkt, 0);
                payload.CopyTo(pkt, 4);
                var t0 = sw.ElapsedMilliseconds;
                ns.Write(enc.Update(pkt));
                var hdr = new byte[4]; int got = 0;
                while (got < 4) { int n = ns.Read(hdr, got, 4 - got); if (n == 0) return (ok, times, "закрыто прокси"); got += n; }
                int len = BitConverter.ToInt32(dec.Update(hdr)) & 0x7FFFFFFF;
                var body = new byte[len]; got = 0;
                while (got < len) { int n = ns.Read(body, got, len - got); if (n == 0) return (ok, times, "закрыто прокси"); got += n; }
                var plain = dec.Update(body);
                if (BitConverter.ToUInt32(plain, 20) == 0x05162463u) { ok++; times.Add(sw.ElapsedMilliseconds - t0 + (i == 0 ? t0 : 0)); }
            }
            return (ok, times, null);
        }
        catch (Exception e) { return (ok, times, e.GetType().Name + ": " + e.Message); }
    }

    /// <summary>Один клиент к любому прокси (--tgclient порт секрет dc count файл); dc<0 — медиа.</summary>
    public static int TgClient(string[] a)
    {
        var (ok, times, err) = OneClient(int.Parse(a[0]), Convert.FromHexString(a[1]), int.Parse(a[2]), int.Parse(a[3]), 30000);
        File.AppendAllText(a[4], $"dc={a[2]} запросов={a[3]} resPQ={ok} первый={times.FirstOrDefault()} мс{(err != null ? " ОШИБКА " + err : "")}\n", new UTF8Encoding(false));
        return 0;
    }

    /// <summary>Нагрузка как у Telegram Desktop при старте: n клиентов одновременно по DC 2, 4, 2m, 4m (--tgburst порт секрет n timeout_с файл).</summary>
    public static int TgBurst(string[] a)
    {
        int port = int.Parse(a[0]); var secret = Convert.FromHexString(a[1]); int n = int.Parse(a[2]); int timeoutMs = int.Parse(a[3]) * 1000;
        var dcs = new[] { 2, 4, -2, -4 };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var tasks = Enumerable.Range(0, n).Select(i => Task.Run(() => { var dc = dcs[i % dcs.Length]; var r = OneClient(port, secret, dc, 3, timeoutMs); return (dc, r.ok, first: r.times.FirstOrDefault(), r.error); })).ToArray();
        Task.WaitAll(tasks);
        var res = tasks.Select(t => t.Result).ToList();
        var good = res.Where(r => r.ok == 3).ToList();
        var lat = good.Select(r => r.first).OrderBy(x => x).ToList();
        string P(double q) => lat.Count == 0 ? "-" : lat[Math.Min(lat.Count - 1, (int)(q * lat.Count))].ToString();
        var sb = new StringBuilder();
        sb.AppendLine($"клиентов={n} полностью успешных={good.Count} ({100.0 * good.Count / n:F0}%) всего {sw.ElapsedMilliseconds} мс; время первого ответа, мс: p50={P(0.5)} p90={P(0.9)} макс={(lat.Count > 0 ? lat.Max() : 0)}");
        foreach (var g in res.GroupBy(r => r.dc).OrderBy(g => g.Key)) sb.AppendLine($"  dc={g.Key}: успешно {g.Count(r => r.ok == 3)}/{g.Count()}");
        foreach (var e in res.Where(r => r.error != null).GroupBy(r => r.error!.Length > 70 ? r.error![..70] : r.error!).Take(3)) sb.AppendLine($"  ошибка x{e.Count()}: {e.Key}");
        File.AppendAllText(a[4], sb.ToString(), new UTF8Encoding(false));
        return 0;
    }
    /// <summary>Доступность IP-списка, списка CF-доменов и редиректов при ТЕКУЩЕМ системном DNS (--nettest файл). Только чтение публичных файлов по HTTPS.</summary>
    public static int NetTest(string reportFile)
    {
        var sb = new StringBuilder();
        void Line(string s) => sb.AppendLine(s);
        foreach (var h in new[] { "raw.githubusercontent.com", "github.com", "cdn.jsdelivr.net", "gitlab.com", "codeberg.org" })
        {
            string ips; try { ips = string.Join(",", System.Net.Dns.GetHostAddresses(h).Select(a => a + (Net.Bogus(a) ? "(ПОДМЕНА)" : ""))); } catch (Exception e) { ips = "ошибка: " + e.Message; }
            Line($"DNS {h} -> {ips}");
        }
        string Try(string url, Func<byte[], string> info)
        {
            try { var d = Net.Fetch(url, 30); return "OK " + info(d); }
            catch (Exception e) { return "ОШИБКА " + (e.InnerException?.Message ?? e.Message); }
        }
        foreach (var u in Updater.IpsetUrls) Line($"IP-список {Net.Host(u)}: " + Try(u, d => $"{d.Length} байт, строк {Encoding.UTF8.GetString(d).Split('\n').Count(x => x.Trim().Length > 0)}, валиден={EngineFiles.IpsetTextValid(Encoding.UTF8.GetString(d))}"));
        try { var (d, s) = Net.FetchFirst(Updater.IpsetUrls, b => EngineFiles.IpsetTextValid(Encoding.UTF8.GetString(b)), 30); Line($"IP-список FetchFirst -> {Net.Host(s)}, {d.Length} байт"); }
        catch (Exception e) { Line("IP-список FetchFirst ОШИБКА " + e.Message); }
        foreach (var u in new[] { "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt", "https://cdn.jsdelivr.net/gh/Flowseal/tg-ws-proxy@main/.github/cfproxy-domains.txt" })
            Line($"CF-домены {Net.Host(u)}: " + Try(u, d => $"{d.Length} байт, доменов после декодирования: {Encoding.UTF8.GetString(d).Split('\n').Count(x => x.Trim().Length > 0 && !x.StartsWith('#'))}"));
        // редирект: github.com/.../raw/... отвечает 302 на raw.githubusercontent.com
        Line("редирект github.com/raw -> raw.githubusercontent.com: " + Try("https://github.com/Flowseal/zapret-discord-youtube/raw/main/.service/version.txt", d => "версия " + Encoding.UTF8.GetString(d).Trim()));
        // источники манифеста: репозитория ещё нет, поэтому ждём ответ 404 (он доказывает, что соединение с хостом и TLS работают)
        foreach (var u in Integrity.ManifestUrls) Line($"манифест {Net.Host(u)}: " + Try(u, d => d.Length + " байт"));
        try { Integrity.LoadManifest(); Line("LoadManifest: ПРИНЯТ"); } catch (Exception e) { Line("LoadManifest: " + e.GetType().Name + ": " + e.Message); }
        Line("--- журнал ---");
        foreach (var l in Log.Last(40)) Line($"{l.lvl}: {l.msg}");
        File.WriteAllText(reportFile, sb.ToString(), new UTF8Encoding(false));
        return 0;
    }

    /// <summary>Логика кнопки Защитника на подменённом PowerShell: настройки Защитника не затрагиваются (--defendertest файл).</summary>
    public static int DefenderTest(string reportFile)
    {
        var sb = new StringBuilder();
        int fails = 0;
        void Check(string n, bool ok) { sb.AppendLine($"{(ok ? "PASS" : "FAIL")}  {n}"); if (!ok) fails++; }
        var calls = new List<string>();
        var exclusions = new List<string>();
        string mode = "ok";
        DefenderCtl.Ps = script =>
        {
            calls.Add(script);
            if (script.Contains("Get-MpPreference"))
                return mode == "noadmin" ? (0, "[\"N/A: Must be an administrator to view exclusions\"]") : mode == "nomp" ? (1, "") : (0, exclusions.Count == 0 ? "[]" : System.Text.Json.JsonSerializer.Serialize(exclusions));
            if (script.StartsWith("Add-MpPreference")) { exclusions.Add(script.Split('\'')[1]); return (0, ""); }
            if (script.StartsWith("Remove-MpPreference")) { exclusions.Remove(script.Split('\'')[1]); return (0, ""); }
            return (1, "?");
        };
        var st = DefenderCtl.Status();
        Check("состояние без исключений", st.available && !st.root && !st.bin && st.existing.Count == 0);
        Check("при чтении состояния ничего не меняется", calls.All(c => c.Contains("Get-MpPreference")));
        calls.Clear();
        Check("добавление без согласия отклонено, команд нет", Throws(() => DefenderCtl.Add(false)) && calls.Count == 0);
        Check("удаление без согласия отклонено, команд нет", Throws(() => DefenderCtl.Remove(false)) && calls.Count == 0);
        DefenderCtl.Add(true);
        Check("добавлена только папка движка (bin), не весь корень", exclusions.Count == 1 && exclusions[0] == P.Bin);
        st = DefenderCtl.Status();
        Check("состояние: bin добавлен", st.bin && !st.root && st.existing.Count == 1);
        Check("повторное добавление отклонено", Throws(() => DefenderCtl.Add(true)));
        exclusions.Clear(); exclusions.Add(P.Root); exclusions.Add(@"C:\Другое\Папка"); exclusions.Add(@"C:\Users\x\AppData\Local\Temp");
        st = DefenderCtl.Status();
        Check("существующее исключение корня видно, чужие не считаются нашими", st.root && st.existing.Count == 1 && st.existing[0] == P.Root);
        calls.Clear();
        Check("добавление при уже имеющемся широком исключении отклонено, ничего не меняется", Throws(() => DefenderCtl.Add(true)) && exclusions.Count == 3);
        var removed = DefenderCtl.Remove(true);
        Check("удаление убирает только наши пути, чужие остались", removed.Count == 1 && exclusions.Count == 2 && !exclusions.Contains(P.Root) && exclusions.Contains(@"C:\Другое\Папка"));
        Check("удаление при отсутствии наших исключений отклонено", Throws(() => DefenderCtl.Remove(true)));
        mode = "noadmin"; st = DefenderCtl.Status();
        Check("нет прав администратора — состояние недоступно, добавление отклонено", !st.available && Throws(() => DefenderCtl.Add(true)));
        mode = "nomp"; st = DefenderCtl.Status();
        Check("Защитник недоступен — понятное состояние", !st.available);
        // никаких автоматических вызовов: в коде приложения вызовы только из Api по консенту
        sb.AppendLine(fails == 0 ? "ИТОГО: все проверки пройдены" : $"ИТОГО: провалено {fails}");
        File.WriteAllText(reportFile, sb.ToString(), new UTF8Encoding(false));
        return fails == 0 ? 0 : 1;

        static bool Throws(Action a) { try { a(); return false; } catch (InvalidOperationException) { return true; } }
    }
    /// <summary>Проверка функций бэкенда через тот же Api.Call, что вызывает интерфейс (--apitest файл).</summary>
    public static int ApiTest(string reportFile)
    {
        var sb = new StringBuilder();
        var s = new Settings();
        var eng = new Engine();
        var api = new Api(s, eng, (k, d) => { });
        string Call(string m, params object?[] a)
        {
            var arr = new System.Text.Json.Nodes.JsonArray();
            foreach (var x in a) arr.Add(x is null ? null : System.Text.Json.JsonSerializer.SerializeToNode(x));
            var r = api.Call(m, arr).ToJsonString(Json.Opts);
            return r.Length > 700 ? r[..700] + "…" : r;
        }
        void T(string title, string m, params object?[] a) => sb.AppendLine($"[{title}] {Call(m, a)}");

        T("state", "get_state");
        // команды всех стратегий — для сравнения с Python-версией
        foreach (var n in Strategies.List())
            sb.AppendLine("CMD\t" + n + "\t" + Strategies.BuildCommand(n, EngineFiles.GameFilterVars()));
        T("filters", "get_filters");
        T("game_filter set", "set_game_filter", "tcp", "1024-65535", "1024-1934,1936-65535");
        T("game_filter get", "get_filters");
        T("game_filter bad", "set_game_filter", "all", "abc", "1-2");
        T("game_filter back", "set_game_filter", "disabled", "1024-65535", "1024-65535");
        T("ipset any", "set_ipset", "any");
        T("ipset none", "set_ipset", "none");
        T("ipset loaded (до загрузки)", "set_ipset", "loaded");
        T("list save", "save_list", "general", "https://WWW.Example.com/path\nfoo.bar\nfoo.bar\n# c");
        T("list get", "get_list", "general");
        T("list ipset_exclude", "save_list", "ipset_exclude", "10.0.0.0/8\n192.168.0.0/16");
        T("list reset", "save_list", "general", "");
        T("list reset", "save_list", "ipset_exclude", "");
        T("set_option", "set_option", "update_interval_h", 12);
        T("set_option bool", "set_option", "close_to_tray", true);
        T("set_option bad", "set_option", "nope", 1);
        T("strategy", "set_strategy", "general (ALT3)");
        T("strategy bad", "set_strategy", "zzz");
        T("run_mode", "set_run_mode", "app");
        T("fix sandbox", "fix", "tcp_timestamps");
        T("diagnostics", "run_diagnostics");
        T("aidns_adapters", "aidns_adapters");
        T("aidns_recommended", "aidns_recommended");
        T("aidns_check", "aidns_check", new { address = "31.31.207.68", doh = true, template = "https://d.webshiftvpn.ru/dns-query", fallback = true },
            new { address = "", doh = false, template = "", fallback = false });
        T("aidns bad ip", "aidns_check", new { address = "999.1.1.1", doh = false, template = "", fallback = false }, new { address = "", doh = false, template = "", fallback = false });
        T("aidns apply (sandbox)", "aidns_toggle", true);
        T("tg save bad dc", "tg_save", 1443, "x:y", true);
        T("tg save", "tg_save", 14999, "2:149.154.167.220\n4:149.154.167.220", true);
        T("tg new_secret", "tg_new_secret");
        T("check_update zapret", "check_update");
        T("check_update tg", "check_update", "tg");
        T("quick_check", "quick_check");
        T("log", "get_log");
        // запуск/остановка процесса-пустышки вместо winws (в тестовом режиме чужие winws не трогаем)
        T("start (fake winws)", "toggle", true);
        sb.AppendLine("status after start: " + System.Text.Json.JsonSerializer.Serialize(eng.Status()));
        T("restart on setting change", "set_game_filter", "all", "1024-65535", "1024-65535");
        sb.AppendLine("status after restart: " + System.Text.Json.JsonSerializer.Serialize(eng.Status()));
        T("stop", "toggle", false);
        sb.AppendLine("status after stop: " + System.Text.Json.JsonSerializer.Serialize(eng.Status()));
        T("game_filter back", "set_game_filter", "disabled", "1024-65535", "1024-65535");
        // автозапуск: временная задача планировщика с отдельным именем
        try { Sys.SetAutostart(true); sb.AppendLine("autostart on: " + Sys.AutostartEnabled()); Sys.SetAutostart(false); sb.AppendLine("autostart off: " + !Sys.AutostartEnabled()); }
        catch (Exception e) { sb.AppendLine("autostart EXC: " + e.Message); }
        File.WriteAllText(reportFile, sb.ToString(), new UTF8Encoding(false));
        return 0;
    }

    /// <summary>Поднимает Telegram-прокси на свободном порту и пропускает через него настоящий запрос req_pq_multi к DC2.</summary>
    public static int TgTest(string reportFile)
    {
        var sb = new StringBuilder();
        int rc = 1;
        try
        {
            var cfg = new TgCfg { port = 14430 + Random.Shared.Next(500), secret = TgProxy.NewSecret() };
            var proxy = new TgProxy();
            proxy.Start(cfg);
            sb.AppendLine($"proxy running={proxy.Running} port={cfg.port}");
            Thread.Sleep(2500); // прогрев пула WS

            var secret = Convert.FromHexString(cfg.secret);
            var init = RandomNumberGenerator.GetBytes(64);
            while (init[0] == 0xEF || (init[4] | init[5] | init[6] | init[7]) == 0) init = RandomNumberGenerator.GetBytes(64);
            init[56] = init[57] = init[58] = init[59] = 0xEF; // abridged
            init[60] = 2; init[61] = 0;                       // DC2
            var prekeyIv = init[8..56];
            using var enc = new AesCtr(SHA256.HashData(prekeyIv[..32].Concat(secret).ToArray()), prekeyIv[32..]);
            var encInit = enc.Update(init);
            var rev = prekeyIv.Reverse().ToArray();
            using var dec = new AesCtr(SHA256.HashData(rev[..32].Concat(secret).ToArray()), rev[32..]);

            // req_pq_multi: abridged-пакет [длина/4][auth_key_id=0, message_id, длина=20, 0xbe7e8ef1, nonce16]
            var payload = new byte[40];
            long msgId = (DateTimeOffset.UtcNow.ToUnixTimeSeconds() << 32) & ~3L;
            BitConverter.GetBytes(msgId).CopyTo(payload, 8);
            BitConverter.GetBytes(20).CopyTo(payload, 16);
            BitConverter.GetBytes(0xbe7e8ef1u).CopyTo(payload, 20);
            RandomNumberGenerator.GetBytes(16).CopyTo(payload, 24);
            var packet = new byte[41];
            packet[0] = (byte)(payload.Length / 4);
            payload.CopyTo(packet, 1);

            using var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", cfg.port);
            tcp.ReceiveTimeout = 20000;
            var ns = tcp.GetStream();
            var sendInit = (byte[])init.Clone();
            Array.Copy(encInit, 56, sendInit, 56, 8);
            ns.Write(sendInit);
            ns.Write(enc.Update(packet));

            var buf = new byte[512];
            int got = 0;
            while (got < 1 + 4 * 14) // resPQ ≥ 56 байт
            {
                int n = ns.Read(buf, got, buf.Length - got);
                if (n == 0) break;
                got += n;
            }
            var plain = dec.Update(buf.AsSpan(0, got));
            int len = plain[0] * 4;
            uint ctor = BitConverter.ToUInt32(plain, 1 + 20);
            sb.AppendLine($"reply bytes={got} len={len} ctor=0x{ctor:x8} authKeyId0={plain.Skip(1).Take(8).All(b => b == 0)}");
            if (ctor == 0x05162463u) { sb.AppendLine("OK: resPQ получен от Telegram через прокси"); rc = 0; }
            proxy.Stop();
            sb.AppendLine("proxy stopped, running=" + proxy.Running);
        }
        catch (Exception e) { sb.AppendLine("EXC: " + e); }
        sb.AppendLine("--- log ---");
        foreach (var l in Log.Last(50)) sb.AppendLine($"{l.lvl}: {l.msg}");
        File.WriteAllText(reportFile, sb.ToString(), new UTF8Encoding(false));
        return rc;
    }
}

#if MANIFEST_TEST
/// <summary>Тестовая сборка: готовит локальный подписанный манифест (тестовый ключ) для настоящего архива zapret.</summary>
internal static class TestManifest
{
    public static int Make(string zip, string outDir)
    {
        try
        {
            zip = Path.GetFullPath(zip);
            string version;
            using (var z = System.IO.Compression.ZipFile.OpenRead(zip))
            {
                var e = z.Entries.FirstOrDefault(x => x.Name.Equals("service.bat", StringComparison.OrdinalIgnoreCase)) ?? throw new InvalidOperationException("В архиве нет service.bat — это не релиз zapret-discord-youtube");
                using var r = new StreamReader(e.Open());
                var m = System.Text.RegularExpressions.Regex.Match(r.ReadToEnd(), "LOCAL_VERSION=([^\"\\r\\n]+)");
                version = m.Success ? m.Groups[1].Value.Trim() : throw new InvalidOperationException("В service.bat нет LOCAL_VERSION");
            }
            Directory.CreateDirectory(outDir);
            var manifest = new System.Text.Json.Nodes.JsonObject
            {
                ["components"] = new System.Text.Json.Nodes.JsonObject
                {
                    ["zapret"] = new System.Text.Json.Nodes.JsonObject { ["sha256"] = Integrity.Sha256File(zip), ["url"] = "file:///" + zip.Replace('\\', '/'), ["version"] = version },
                },
                ["schema"] = 1, ["sequence"] = 1,
            };
            var data = Encoding.UTF8.GetBytes(manifest.ToJsonString(Json.Indented) + "\n");
            var (priv, pub) = Ed25519.NewKeyPair();
            File.WriteAllBytes(Path.Combine(outDir, "components.json"), data);
            File.WriteAllText(Path.Combine(outDir, "components.json.sig"), Convert.ToBase64String(Ed25519.Sign(priv, data)) + "\n");
            File.WriteAllText(Path.Combine(outDir, "test.pub"), Convert.ToBase64String(pub));
            if (!P.Sandbox) MessageBox.Show($"Готово: zapret {version}\nПапка: {Path.GetFullPath(outDir)}\n\nЗапуск:\nZapretHub-ManifestTest.exe --manifest-dir \"{Path.GetFullPath(outDir)}\"", "Zapret Hub [тест манифеста]");
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Zapret Hub [тест манифеста]", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
#endif