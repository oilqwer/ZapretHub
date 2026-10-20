#if MANIFEST_TEST
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ZapretHub;

/// <summary>ТОЛЬКО тестовая сборка: проверка потока данных прокси на больших объёмах (аналог загрузки медиа) и переподключений
/// против локального имитатора WS-шлюза Telegram. Имитатор реализует серверную сторону obfuscated2 и эхо/выдачу данных.</summary>
internal static class TgMockTest
{
    /// <summary>Разбор пакетов транспорта MTProto (abridged / intermediate / padded intermediate) из потока открытого текста.</summary>
    private sealed class Parser
    {
        private readonly byte tag; private readonly List<byte> buf = new();
        public Parser(byte tag) { this.tag = tag; }
        public List<byte[]> Feed(byte[] plain)
        {
            buf.AddRange(plain);
            var res = new List<byte[]>();
            while (true)
            {
                if (tag == 0xEF)
                {
                    if (buf.Count < 1) break;
                    int first = buf[0], words, hdr;
                    if (first >= 0x7F) { if (buf.Count < 4) break; words = buf[1] | (buf[2] << 8) | (buf[3] << 16); hdr = 4; }
                    else { words = first; hdr = 1; }
                    int len = words * 4;
                    if (buf.Count < hdr + len) break;
                    res.Add(buf.GetRange(hdr, len).ToArray()); buf.RemoveRange(0, hdr + len);
                }
                else
                {
                    if (buf.Count < 4) break;
                    int len = (buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)) & 0x7FFFFFFF;
                    if (buf.Count < 4 + len) break;
                    res.Add(buf.GetRange(4, len).ToArray()); buf.RemoveRange(0, 4 + len);
                }
            }
            return res;
        }
    }

    private static byte[] Pack(byte tag, byte[] body)
    {
        if (tag == 0xEF)
        {
            int words = body.Length / 4;
            var hdr = words < 0x7F ? new[] { (byte)words } : new byte[] { 0x7F, (byte)words, (byte)(words >> 8), (byte)(words >> 16) };
            return hdr.Concat(body).ToArray();
        }
        return BitConverter.GetBytes(body.Length).Concat(body).ToArray();
    }

    /// <summary>Паттерн для проверки целостности выдачи: байт зависит от позиции и номера пакета.</summary>
    private static byte[] Pattern(int seq, int len) { var b = new byte[len]; for (int i = 0; i < len; i++) b[i] = (byte)(i * 31 + seq * 7); return b; }

    // ---------- имитатор Telegram (WS-шлюз + MTProto-сервер) ----------
    private sealed class Mock
    {
        public readonly TcpListener Listener = new(IPAddress.Loopback, 0);
        public readonly ConcurrentDictionary<TcpClient, int> Conns = new();
        public readonly ConcurrentQueue<string> Trace = new(); public int Accepted, Ended, InitSeen, DataFrames, EchoSent, UpgradeSeen; public string LastError = "";
        public int Port => ((IPEndPoint)Listener.LocalEndpoint).Port;
        public void Start()
        {
            Listener.Start();
            _ = Task.Run(async () =>
            {
                try { while (true) { var c = await Listener.AcceptTcpClientAsync(); Conns[c] = 1; Interlocked.Increment(ref Accepted); _ = Task.Run(() => Serve(c)); } }
                catch { }
            });
        }
        public void DropAll() { foreach (var c in Conns.Keys) { try { c.Client.Close(0); } catch { } } Conns.Clear(); }
        public void Stop() { try { Listener.Stop(); } catch { } DropAll(); }

        private static async Task<byte[]> ReadN(Stream s, int n)
        {
            var b = new byte[n]; int got = 0;
            while (got < n) { int r = await s.ReadAsync(b.AsMemory(got, n - got)); if (r == 0) throw new EndOfStreamException(); got += r; }
            return b;
        }

        private static byte[] ServerFrame(byte[] data)
        {
            var hdr = data.Length < 126 ? new byte[] { 0x82, (byte)data.Length }
                : data.Length < 65536 ? new byte[] { 0x82, 126, (byte)(data.Length >> 8), (byte)data.Length }
                : new byte[] { 0x82, 127, 0, 0, 0, 0, (byte)(data.Length >> 24), (byte)(data.Length >> 16), (byte)(data.Length >> 8), (byte)data.Length };
            return hdr.Concat(data).ToArray();
        }

        private async Task Serve(TcpClient c)
        {
            int rport = ((IPEndPoint)c.Client.RemoteEndPoint!).Port; var swc = System.Diagnostics.Stopwatch.StartNew(); int nframes = 0;
            void T(string m) => Trace.Enqueue($"ws-порт {rport}: {m} (+{swc.ElapsedMilliseconds} мс)");
            T("принято");
            try
            {
                var s = c.GetStream();
                var head = new List<byte>(); var one = new byte[1];
                while (!(head.Count >= 4 && head[^4] == '\r' && head[^3] == '\n' && head[^2] == '\r' && head[^1] == '\n')) { if (await s.ReadAsync(one) == 0) return; head.Add(one[0]); }
                Interlocked.Increment(ref UpgradeSeen);
                await s.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"));

                AesCtr? dec = null, enc = null; Parser? parser = null; byte tag = 0;
                while (true)
                {
                    var h = await ReadN(s, 2);
                    nframes++; if (nframes <= 3) T($"кадр #{nframes} первый байт {h[0]:x2} {h[1]:x2}");
                    int op = h[0] & 0x0F; long len = h[1] & 0x7F;
                    if (len == 126) { var x = await ReadN(s, 2); len = (x[0] << 8) | x[1]; }
                    else if (len == 127) { var x = await ReadN(s, 8); len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | x[i]; }
                    var mask = (h[1] & 0x80) != 0 ? await ReadN(s, 4) : null;
                    var payload = await ReadN(s, (int)len);
                    if (mask != null) for (int i = 0; i < payload.Length; i++) payload[i] ^= mask[i & 3];
                    if (op == 8) return;
                    if (op != 2) continue;
                    if (dec == null)
                    {
                        if (payload.Length != 64) return;
                        dec = new AesCtr(payload[8..40], payload[40..56]);
                        var rev = payload[8..56].Reverse().ToArray();
                        enc = new AesCtr(rev[..32], rev[32..]);
                        var d = dec.Update(payload);
                        tag = d[56];
                        parser = new Parser(tag);
                        Interlocked.Increment(ref InitSeen);
                        continue;
                    }
                    Interlocked.Increment(ref DataFrames);
                    var plainData = dec.Update(payload);
                    var bodies = parser!.Feed(plainData);
                    if (nframes <= 4) T($"данные: {payload.Length} Б, plain[0..8]={Convert.ToHexString(plainData.AsSpan(0, Math.Min(8, plainData.Length)))}, пакетов {bodies.Count}, tag={tag:x2}");
                    foreach (var body in bodies)
                    {
                        if (body.Length >= 6 && body[0] == 'D' && body[1] == 'L')
                        {
                            int total = BitConverter.ToInt32(body, 2), seq = 0;
                            for (int sent = 0; sent < total; seq++)
                            {
                                int n = Math.Min(131072, total - sent);
                                await s.WriteAsync(ServerFrame(enc!.Update(Pack(tag, Pattern(seq, n)))));
                                sent += n;
                            }
                        }
                        else { var fr = ServerFrame(enc!.Update(Pack(tag, body))); await s.WriteAsync(fr); Interlocked.Increment(ref EchoSent); if (nframes <= 4) T($"эхо отправлено: кадр {fr.Length} Б, заголовок {Convert.ToHexString(fr.AsSpan(0, 4))}"); }
                    }
                }
            }
            catch (Exception e) { LastError = e.GetType().Name + ": " + e.Message; T("исключение " + LastError); }
            finally { T($"завершён, кадров {nframes}"); Interlocked.Increment(ref Ended); try { c.Dispose(); } catch { } }
        }
    }

    // ---------- клиент obfuscated2 ----------
    private sealed class Client : IDisposable
    {
        private readonly TcpClient tcp = new() { NoDelay = true };
        private readonly NetworkStream ns;
        private readonly AesCtr enc, dec;
        private readonly byte tag;
        private readonly Parser parser;
        private readonly Queue<byte[]> ready = new();

        public Client(int port, byte[] secret, int dc, byte tag, int timeoutMs = 30000)
        {
            this.tag = tag;
            tcp.Connect("127.0.0.1", port);
            tcp.ReceiveTimeout = timeoutMs; ns = tcp.GetStream();
            var init = RandomNumberGenerator.GetBytes(64);
            while (init[0] == 0xEF || (init[4] | init[5] | init[6] | init[7]) == 0) init = RandomNumberGenerator.GetBytes(64);
            init[56] = init[57] = init[58] = init[59] = tag;
            BitConverter.GetBytes((short)dc).CopyTo(init, 60);
            var pk = init[8..56];
            enc = new AesCtr(SHA256.HashData(pk[..32].Concat(secret).ToArray()), pk[32..]);
            var rev = pk.Reverse().ToArray();
            dec = new AesCtr(SHA256.HashData(rev[..32].Concat(secret).ToArray()), rev[32..]);
            var e = enc.Update(init); var send = (byte[])init.Clone(); Array.Copy(e, 56, send, 56, 8);
            ns.Write(send);
            parser = new Parser(tag);
        }

        public void Send(byte[] body) => ns.Write(enc.Update(Pack(tag, body)));

        /// <summary>Следующий пакет; null — соединение закрыто прокси.</summary>
        public byte[]? Receive()
        {
            var buf = new byte[262144];
            while (ready.Count == 0)
            {
                int n;
                try { n = ns.Read(buf, 0, buf.Length); } catch (IOException) { return null; }
                if (n == 0) return null;
                foreach (var b in parser.Feed(dec.Update(buf.AsSpan(0, n)))) ready.Enqueue(b);
            }
            return ready.Dequeue();
        }

        public void Dispose() { tcp.Dispose(); enc.Dispose(); dec.Dispose(); }
    }

    public static int Run(string reportFile)
    {
        var sb = new StringBuilder();
        int fails = 0;
        void Check(string n, bool ok, string extra = "") { sb.AppendLine($"{(ok ? "PASS" : "FAIL")}  {n}{(extra.Length > 0 ? "  [" + extra + "]" : "")}"); if (!ok) fails++; }

        var mock = new Mock(); mock.Start();
        TgProxy.MockWs = ("127.0.0.1", mock.Port);
        var cfg = new TgCfg { port = 15000 + Random.Shared.Next(2000), secret = TgProxy.NewSecret(), cfproxy = false };
        var proxy = new TgProxy();
        proxy.Start(cfg);
        var secret = Convert.FromHexString(cfg.secret);
        Thread.Sleep(1500);
        Check("прокси запущен, пул WS набран из имитатора", proxy.Running && mock.Accepted >= 4, $"подключений к шлюзу: {mock.Accepted}");

        bool Echo(byte tag, int size, int dc = 2)
        {
            using var c = new Client(cfg.port, secret, dc, tag, 5000);
            var body = RandomNumberGenerator.GetBytes(size / 4 * 4);
            c.Send(body);
            var r = c.Receive();
            return r != null && r.AsSpan().SequenceEqual(body);
        }
        Check("эхо 100 Б (padded intermediate)", Echo(0xDD, 100));
        Check("эхо 100 Б (intermediate)", Echo(0xEE, 100));
        Check("эхо 100 Б (abridged)", Echo(0xEF, 100));
        Check("эхо 70 000 Б (кадр WS > 64 КБ)", Echo(0xDD, 70000));
        Check("эхо 1 000 000 Б (кадр 64-битной длины)", Echo(0xDD, 1_000_000));
        Check("эхо медиа-DC (dc=-4) 200 КБ", Echo(0xDD, 200_000, -4));
        Check("эхо abridged 300 КБ", Echo(0xEF, 300_000));

        // регрессия: кадры WS с расширенной длиной 126 и «битом маски» в байте длины (404, 128..255, 384..511 …) раньше вешали приём
        {
            using var c = new Client(cfg.port, secret, 2, 0xDD, 10000);
            var rnd = new Random(7); int okc = 0, total = 0; var bad = new List<int>();
            var sizes = new List<int> { 124, 128, 132, 252, 256, 380, 384, 400, 404, 508, 512, 636, 640, 892, 65532 };
            sizes.AddRange(Enumerable.Range(0, 300).Select(_ => rnd.Next(30, 16000) * 4));
            foreach (var sz in sizes)
            {
                total++;
                var b = RandomNumberGenerator.GetBytes(sz);
                c.Send(b);
                var r = c.Receive();
                if (r != null && r.AsSpan().SequenceEqual(b)) okc++; else { bad.Add(sz); break; }
            }
            Check("315 эхо разной длины (124…65532, включая 128–255, 384–511 и т. д.) в одном сеансе", okc == total, $"успешно {okc}/{total}" + (bad.Count > 0 ? ", сбой на размере " + bad[0] : ""));
        }

        // выгрузка на сервер: 16 пакетов по 512 КБ подряд, возврат эхом, сверка по хэшу
        {
            using var c = new Client(cfg.port, secret, 2, 0xDD);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var sent = new List<byte[]>();
            var sender = Task.Run(() => { for (int i = 0; i < 16; i++) { var b = RandomNumberGenerator.GetBytes(524288); sent.Add(b); c.Send(b); } });
            bool ok = true;
            for (int i = 0; i < 16 && ok; i++) { var r = c.Receive(); while (r != null && sent.Count <= i) { Thread.Sleep(1); } ok = r != null && sent.Count > i && SHA256.HashData(r).AsSpan().SequenceEqual(SHA256.HashData(sent[i])); }
            sender.Wait();
            Check("выгрузка 8 МБ (16×512 КБ) и возврат без искажений", ok, $"{sw.ElapsedMilliseconds} мс, {8.0 / sw.Elapsed.TotalSeconds * 2:F0} МБ/с в обе стороны");
        }

        // загрузка с сервера (медиа): 12 МБ пакетами по 128 КБ, проверка паттерна
        {
            using var c = new Client(cfg.port, secret, -2, 0xDD);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            int total = 12 * 1024 * 1024;
            c.Send(new byte[] { (byte)'D', (byte)'L' }.Concat(BitConverter.GetBytes(total)).Concat(new byte[4]).ToArray());
            long got = 0; int seq = 0; bool ok = true;
            while (got < total)
            {
                var r = c.Receive();
                if (r == null) { ok = false; break; }
                if (!r.AsSpan().SequenceEqual(Pattern(seq, r.Length))) { ok = false; break; }
                got += r.Length; seq++;
            }
            Check("загрузка 12 МБ с сервера (media DC) без искажений", ok && got == total, $"{sw.ElapsedMilliseconds} мс, {12.0 / sw.Elapsed.TotalSeconds:F0} МБ/с");
        }

        // параллельные клиенты: 12 одновременно, по 1 МБ эхо + 4 МБ загрузки
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var tasks = Enumerable.Range(0, 12).Select(i => Task.Run(() =>
            {
                using var c = new Client(cfg.port, secret, new[] { 2, 4, -2, -4 }[i % 4], 0xDD);
                var b = RandomNumberGenerator.GetBytes(1_000_000); c.Send(b);
                var r = c.Receive(); if (r == null || !r.AsSpan().SequenceEqual(b)) return false;
                c.Send(new byte[] { (byte)'D', (byte)'L' }.Concat(BitConverter.GetBytes(4 * 1024 * 1024)).Concat(new byte[4]).ToArray());
                long got = 0; int seq = 0;
                while (got < 4 * 1024 * 1024) { var p = c.Receive(); if (p == null || !p.AsSpan().SequenceEqual(Pattern(seq, p.Length))) return false; got += p.Length; seq++; }
                return true;
            })).ToArray();
            Task.WaitAll(tasks);
            Check("12 параллельных клиентов (эхо 1 МБ + загрузка 4 МБ каждый)", tasks.All(t => t.Result), $"{sw.ElapsedMilliseconds} мс");
        }

        {
            int okc = 0; var sw1 = System.Diagnostics.Stopwatch.StartNew(); var times = new List<string>();
            for (int i = 0; i < 2; i++) { var t0 = sw1.ElapsedMilliseconds; try { var okE = Echo(0xDD, 400); if (okE) okc++; times.Add((okE ? "ok " : "нет ответа/закрыто ") + (sw1.ElapsedMilliseconds - t0)); } catch (Exception e) { times.Add(e.GetType().Name + ":" + e.Message + " " + (sw1.ElapsedMilliseconds - t0)); } }
            Check("8 последовательных эхо через пул сразу после нагрузки", okc == 2, $"успешно {okc}/2, {string.Join(" | ", times.Take(2))}; шлюз: принято {mock.Accepted}, апгрейдов {mock.UpgradeSeen}, init {mock.InitSeen}, кадров данных {mock.DataFrames}, эхо отправлено {mock.EchoSent}, завершено {mock.Ended}, ошибка: {mock.LastError}");
        }

        // переподключение 1: шлюз внезапно рвёт все WS-сессии — клиентские соединения закрываются, новое подключение работает
        {
            using var c = new Client(cfg.port, secret, 2, 0xDD, 10000);
            var b = RandomNumberGenerator.GetBytes(400); c.Send(b);
            bool first = c.Receive() is { } r1 && r1.AsSpan().SequenceEqual(b);
            mock.DropAll();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            bool closed = c.Receive() == null;
            Check("обрыв WS на стороне шлюза: клиент получает закрытие соединения (а не зависание)", first && closed, $"эхо до обрыва={first}, закрытие={closed}, {sw.ElapsedMilliseconds} мс");
            sw.Restart();
            bool again = false;
            for (int i = 0; i < 5 && !again; i++) { try { again = Echo(0xDD, 600); } catch { Thread.Sleep(300); } }
            Check("после обрыва новое подключение клиента работает (WS создаётся заново)", again, $"{sw.ElapsedMilliseconds} мс");
        }

        // переподключение 2: рестарт прокси на том же порту (смена настроек), старые соединения закрываются, новые работают
        {
            using var c = new Client(cfg.port, secret, 4, 0xDD, 10000);
            var b = RandomNumberGenerator.GetBytes(400); c.Send(b); c.Receive();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            proxy.Start(cfg);
            bool oldClosed = c.Receive() == null;
            bool works = false;
            for (int i = 0; i < 10 && !works; i++) { try { works = Echo(0xDD, 800, 4); } catch { Thread.Sleep(300); } }
            Check("рестарт прокси на том же порту: старое соединение закрыто, новое работает", oldClosed && works, $"{sw.ElapsedMilliseconds} мс");
        }

        // неверный секрет: соединение не должно зависать и не должно давать доступ
        {
            bool rejected;
            try { using var c = new Client(cfg.port, Convert.FromHexString(TgProxy.NewSecret()), 2, 0xDD, 5000); c.Send(new byte[100]); rejected = c.Receive() == null; }
            catch { rejected = true; }
            Check("клиент с чужим секретом не получает ответ", rejected);
        }

        // шлюз полностью недоступен: клиент получает закрытие за ограниченное время (не минуты)
        {
            mock.Stop();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            bool closedFast;
            try { using var c = new Client(cfg.port, secret, 2, 0xDD, 60000); c.Send(new byte[100]); closedFast = c.Receive() == null; }
            catch { closedFast = true; }
            Check("шлюз недоступен: ответ клиенту/закрытие не позже чем через 30 с", closedFast && sw.Elapsed.TotalSeconds < 30, $"{sw.Elapsed.TotalSeconds:F1} с");
        }

        proxy.Stop();
        sb.AppendLine("--- события шлюза ---");
        foreach (var l in mock.Trace) sb.AppendLine(l);
        sb.AppendLine("--- журнал прокси (последние) ---");
        foreach (var l in Log.Last(300)) sb.AppendLine($"{l.lvl}: {l.msg}");
        sb.AppendLine(fails == 0 ? "ИТОГО: все проверки пройдены" : $"ИТОГО: провалено {fails}");
        File.WriteAllText(reportFile, sb.ToString(), new UTF8Encoding(false));
        return fails == 0 ? 0 : 1;
    }
}
#endif
