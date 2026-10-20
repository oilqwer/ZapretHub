using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace ZapretHub;

/// <summary>Проверка подписи Ed25519 (RFC 8032) — реализация BouncyCastle.Cryptography (лицензия MIT, совместима с GPL-3.0).</summary>
public static class Ed25519
{
    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        try { return Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.Verify(signature, 0, publicKey, 0, message, 0, message.Length); }
        catch (Exception) { return false; }
    }

#if MANIFEST_TEST
    /// <summary>Только тестовая сборка: пара ключей и подпись для локального манифеста.</summary>
    public static (byte[] priv, byte[] pub) NewKeyPair()
    {
        var priv = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var pub = new byte[32];
        Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.GeneratePublicKey(priv, 0, pub, 0);
        return (priv, pub);
    }

    public static byte[] Sign(byte[] priv, byte[] message)
    {
        var pub = new byte[32];
        Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.GeneratePublicKey(priv, 0, pub, 0);
        var sig = new byte[64];
        Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.Sign(priv, 0, pub, 0, null, message, 0, message.Length, sig, 0);
        return sig;
    }
#endif
}
public class IntegrityException : InvalidOperationException
{
    public IntegrityException(string msg) : base(msg) { }
}

/// <summary>Ни один источник манифеста не отдал данные (HTTP 404/403, нет сети). Проверки подписи и sha256 это не затрагивает.</summary>
public sealed class SourceUnavailableException : IntegrityException
{
    public SourceUnavailableException(string msg = "Источник обновлений пока недоступен") : base(msg) { }
}

/// <summary>Подлинность и целостность загружаемых компонентов: манифест одобренных версий подписан Ed25519 (ключ зашит в приложение),
/// архив сверяется по SHA-256 из подписанного манифеста. Неподписанное, устаревшее или неизвестное отклоняется; проверка не отключается при ошибках.</summary>
public static class Integrity
{
    // Публичный релизный ключ автора (base64, 32 байта). Приватный ключ хранится вне репозитория.
    public const string PublicKey = "BrHfnLE4nBMog1515GehB57h0IT2n6HBrTj97WF4oMg=";
    // Источники подписанного манифеста: независимые домены первыми (с DNS, подменяющим raw.githubusercontent.com, они доступны),
    // канонический GitHub — следом. Любой источник равноправен: принимается только манифест с валидной подписью,
    // из всех валидных берётся с наибольшим sequence, откат ниже ранее принятого запрещён.
    public static readonly string[] ManifestUrls =
    {
        "https://cdn.jsdelivr.net/gh/oilqwer/ZapretHub@main/manifest/components.json",
        "https://gitlab.com/oilqwer/ZapretHub/-/raw/main/manifest/components.json",
        "https://codeberg.org/oilqwer/ZapretHub/raw/branch/main/manifest/components.json",
        "https://raw.githubusercontent.com/oilqwer/ZapretHub/main/manifest/components.json",
        "https://github.com/oilqwer/ZapretHub/raw/main/manifest/components.json",
    };
#if MANIFEST_TEST
    // Тестовый манифест ведёт свой номер, чтобы не повлиять на защиту от отката для рабочего манифеста.
    public static string SequenceFile => Path.Combine(P.Root, TestUrl != null ? "manifest.sequence.test" : "manifest.sequence");
#else
    public static string SequenceFile => Path.Combine(P.Root, "manifest.sequence");
#endif

#if MANIFEST_TEST
    // ТОЛЬКО тестовая сборка (ZapretHub-ManifestTest.exe): адрес манифеста и ключ задаются локально (--manifest-dir).
    // В рабочем EXE этого кода нет: адрес и ключ зашиты константами выше.
    public static string? TestUrl, TestPubKey;
    private static string[] Urls => TestUrl != null ? new[] { TestUrl } : ManifestUrls;
    private static string Key => TestPubKey ?? PublicKey;
#else
    private static string[] Urls => ManifestUrls;
    private static string Key => PublicKey;
#endif
    public static void VerifySignature(byte[] data, string signatureB64, string? publicKeyB64 = null)
    {
        bool ok;
        try
        {
            ok = Ed25519.Verify(Convert.FromBase64String(publicKeyB64 ?? PublicKey), data, Convert.FromBase64String(signatureB64.Trim()));
        }
        catch (FormatException) { ok = false; }
        if (!ok) throw new IntegrityException("Подпись манифеста компонентов недействительна");
    }

    private static long LastSequence()
    {
        try { return long.Parse(File.ReadAllText(SequenceFile).Trim()); } catch { return 0; }
    }

    /// <summary>Скачивает манифест и подпись со всех источников параллельно, оставляет прошедшие проверку подписи,
    /// выбирает с наибольшим sequence и применяет защиту от отката. Без валидного манифеста — IntegrityException.</summary>
    public static JsonObject LoadManifest() => LoadFrom(Urls, u => Net.Fetch(u), Key);

    public static JsonObject LoadFrom(IReadOnlyList<string> sources, Func<string, byte[]> fetch, string publicKeyB64)
    {
        var tasks = sources.Select(u => Task.Run(() =>
        {
            var data = fetch(u);
            var sig = fetch(u + ".sig");
            return Validate(data, Encoding.ASCII.GetString(sig), publicKeyB64);
        })).ToArray();
        try { Task.WaitAll(tasks); } catch (AggregateException) { }
        var errors = new List<string>();
        (JsonObject m, long seq)? best = null;
        for (int i = 0; i < tasks.Length; i++)
        {
            if (tasks[i].IsCompletedSuccessfully)
            {
                var r = tasks[i].Result;
                if (best is null || r.seq > best.Value.seq) best = r;
            }
            else
            {
                var e = tasks[i].Exception?.GetBaseException();
                errors.Add($"{Net.Host(sources[i])}: {Short(e)}");
                if (e is IntegrityException) Log.Warn($"Манифест из {Net.Host(sources[i])} отклонён: {e.Message}");
            }
        }
        if (best is null)
        {
            // Ни один источник не ответил (404/403/сеть) — манифест просто ещё не опубликован или сеть недоступна.
            // Если хоть один ответ пришёл, но не прошёл проверку (подпись, формат), это не «недоступность», а отказ по безопасности.
            bool onlyUnreachable = tasks.All(t => t.Exception?.GetBaseException() is HttpRequestException or IOException or TaskCanceledException or System.Net.Sockets.SocketException);
            if (onlyUnreachable)
            {
                Log.Warn("Источники манифеста недоступны: " + string.Join("; ", errors));
                throw new SourceUnavailableException();
            }
            throw new IntegrityException("Не удалось получить подписанный манифест компонентов ни из одного источника: " + string.Join("; ", errors));
        }
        Accept(best.Value.seq);
        return best.Value.m;
    }

    private static string Short(Exception? e) =>
        e is HttpRequestException { StatusCode: { } c } ? $"HTTP {(int)c}" : (e?.InnerException?.Message ?? e?.Message ?? "ошибка") is var s && s.Length > 80 ? s[..80] : (e?.InnerException?.Message ?? e?.Message ?? "ошибка");

    public static JsonObject Parse(byte[] data, string signatureB64, string? publicKeyB64 = null)
    {
        var (m, seq) = Validate(data, signatureB64, publicKeyB64);
        Accept(seq);
        return m;
    }

    private static (JsonObject m, long seq) Validate(byte[] data, string signatureB64, string? publicKeyB64)
    {
        VerifySignature(data, signatureB64, publicKeyB64);
        JsonObject manifest;
        try { manifest = (JsonObject)JsonNode.Parse(data)!; }
        catch { throw new IntegrityException("Неподдерживаемый формат манифеста"); }
        if (manifest["schema"]?.GetValueKind() != System.Text.Json.JsonValueKind.Number || manifest["schema"]!.GetValue<int>() != 1
            || manifest["sequence"]?.GetValueKind() != System.Text.Json.JsonValueKind.Number)
            throw new IntegrityException("Неподдерживаемый формат манифеста");
        return (manifest, manifest["sequence"]!.GetValue<long>());
    }

    private static void Accept(long seq)
    {
        if (seq < LastSequence()) throw new IntegrityException("Манифест старее ранее принятого (возможен откат)");
        try
        {
            Directory.CreateDirectory(P.Root);
            File.WriteAllText(SequenceFile, seq.ToString());
        }
        catch { }
    }
    /// <summary>Одобренный автором компонент: version, url, sha256.</summary>
    public static (string version, string url, string sha256) Approved(JsonObject manifest, string name)
    {
        var item = manifest["components"]?[name] as JsonObject;
        string? version = item?["version"]?.GetValue<string>(), url = item?["url"]?.GetValue<string>(), sha = item?["sha256"]?.GetValue<string>();
        if (string.IsNullOrEmpty(version) || string.IsNullOrEmpty(url)) throw new IntegrityException($"В манифесте нет компонента {name}");
        if (string.IsNullOrEmpty(sha)) throw new IntegrityException($"В манифесте нет контрольной суммы {name}");
        return (version, url, sha.ToLowerInvariant());
    }

    public static string Sha256File(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }

    public static void VerifyFile(string name, string version, string expectedSha, string path)
    {
        if (!string.Equals(Sha256File(path), expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new IntegrityException($"Контрольная сумма {name} {version} не совпадает с ожидаемой SHA-256");
    }
}
