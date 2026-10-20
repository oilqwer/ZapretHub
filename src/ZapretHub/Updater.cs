using System.IO.Compression;
using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ZapretHub;

public sealed record Release(string version, string url, string notes, string? date, string sha256 = "");

/// <summary>Движок zapret обновляется напрямую с GitHub Flowseal: версия и описание — из GitHub API, архив — официальный ZIP релиза.
/// Подлинность архива подтверждается только SHA-256 из поля <c>digest</c> того же ответа GitHub API (подписи Flowseal нет и не проверяется).
/// Собственный Ed25519-манифест для zapret не используется — он нужен только компонентам, которые выпускает автор Zapret Hub.</summary>
public static class Updater
{
    public const string Owner = "Flowseal";
    public static readonly string ApiLatest = $"https://api.github.com/repos/{P.Repo}/releases/latest";
    public static string ApiTag(string tag) => $"https://api.github.com/repos/{P.Repo}/releases/tags/{Uri.EscapeDataString(tag)}";
    public static readonly string VersionTxt = $"https://raw.githubusercontent.com/{P.Repo}/main/.service/version.txt";
    // Для списков два независимых домена: если системный DNS подменяет raw.githubusercontent.com, сработает jsDelivr (и DoH-запасной путь в Net).
    public static readonly string[] IpsetUrls =
    {
        $"https://raw.githubusercontent.com/{P.Repo}/refs/heads/main/.service/ipset-service.txt",
        $"https://cdn.jsdelivr.net/gh/{P.Repo}@main/.service/ipset-service.txt",
    };
    public static readonly string HostsUrl = $"https://raw.githubusercontent.com/{P.Repo}/refs/heads/main/.service/hosts";

    // Что переносим из старой версии в новую (плюс все lists/*-user.txt).
    private static readonly string[] Preserve =
    {
        "lists/list-general-user.txt", "lists/list-exclude-user.txt", "lists/ipset-exclude-user.txt", "utils/game_filter.enabled",
    };

    private const long MaxArchive = 300L << 20, MaxUnpacked = 1L << 30;
    private const int MaxEntries = 5000;

    public static int[] VersionTuple(string? v) =>
        Regex.Matches(v ?? "", @"\d+").Select(m => int.TryParse(m.Value, out var x) ? x : 0).ToArray();

    public static bool IsNewer(string remote, string? local)
    {
        if (local is null) return true;
        var a = VersionTuple(remote); var b = VersionTuple(local);
        for (int i = 0; i < Math.Max(a.Length, b.Length); i++)
        {
            int x = i < a.Length ? a[i] : 0, y = i < b.Length ? b[i] : 0;
            if (x != y) return x > y;
        }
        return false;
    }

    public static string? LocalVersion()
    {
        try
        {
            var m = Regex.Match(File.ReadAllText(Path.Combine(P.Engine, "service.bat")), "LOCAL_VERSION=([^\"\\r\\n]+)");
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }
        catch { return null; }
    }

    private static string? VersionIn(string engineDir)
    {
        try
        {
            var m = Regex.Match(File.ReadAllText(Path.Combine(engineDir, "service.bat")), "LOCAL_VERSION=([^\"\\r\\n]+)");
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }
        catch { return null; }
    }

    // ---------- GitHub API Flowseal ----------

    /// <summary>Последний стабильный релиз Flowseal. Источник — только GitHub API; манифест автора не нужен.</summary>
    public static Release LatestRelease(string? apiUrl = null) => FromApi(apiUrl ?? ApiLatest);

    /// <summary>Релиз именно этой версии (для «Переустановить»): пробуем тег как есть и с префиксом v.</summary>
    public static Release ReleaseForVersion(string version, Func<string, string>? tagUrl = null)
    {
        foreach (var tag in new[] { version, "v" + version })
        {
            try
            {
                var rel = FromApi((tagUrl ?? ApiTag)(tag));
                if (VersionTuple(rel.version).SequenceEqual(VersionTuple(version))) return rel;
            }
            catch (HttpRequestException e) when (e.StatusCode == HttpStatusCode.NotFound) { }
        }
        throw new IntegrityException($"Релиз {version} не найден в репозитории {P.Repo}");
    }

    private static Release FromApi(string url)
    {
        string json;
        try { json = Net.FetchGitHubApi(url); }
        catch (RateLimitException e) { throw new SourceUnavailableException(e.Message); }
        catch (HttpRequestException e) when (e.StatusCode == HttpStatusCode.NotFound) { throw; }
        catch (Exception e) when (e is HttpRequestException or IOException or TaskCanceledException or System.Net.Sockets.SocketException)
        {
            Log.Warn($"GitHub API недоступен: {e.Message}");
            throw new SourceUnavailableException("Не удалось связаться с GitHub (api.github.com) — проверьте подключение к интернету");
        }
        JsonObject? obj;
        try { obj = JsonNode.Parse(json) as JsonObject; } catch { obj = null; }
        return obj is null ? throw new IntegrityException("GitHub вернул ответ неизвестного формата") : ParseRelease(obj);
    }

    /// <summary>Разбор и проверка ответа GitHub API: стабильный релиз Flowseal, HTTPS-адрес ZIP в его репозитории, обязательный SHA-256 digest.</summary>
    public static Release ParseRelease(JsonObject j)
    {
        static string? S(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
        static bool Flag(JsonNode? n) => n is JsonValue v && v.TryGetValue<bool>(out var b) && b;
        if (Flag(j["draft"]) || Flag(j["prerelease"])) throw new IntegrityException("Релиз не является стабильным");
        string? tag = S(j["tag_name"]);
        string version = (tag ?? "").Trim().TrimStart('v', 'V');
        if (!Regex.IsMatch(version, @"^\d+(\.\d+){1,3}$")) throw new IntegrityException("Неподдерживаемая версия в релизе GitHub: " + tag);
        string prefix = $"/{P.Repo}/";
        if (!Uri.TryCreate(S(j["html_url"]), UriKind.Absolute, out var page) || page.Scheme != "https"
            || !page.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) || !page.AbsolutePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new IntegrityException($"Релиз не принадлежит репозиторию {P.Repo}");

        var zips = (j["assets"] as JsonArray ?? new JsonArray()).OfType<JsonObject>()
            .Where(a => (S(a["name"]) ?? "").EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && S(a["state"]) is null or "uploaded").ToList();
        var asset = zips.FirstOrDefault(a => S(a["name"])!.StartsWith("zapret-discord-youtube", StringComparison.OrdinalIgnoreCase))
            ?? (zips.Count == 1 ? zips[0] : null) ?? throw new IntegrityException("В релизе нет официального ZIP-архива");

        string url = S(asset["browser_download_url"]) ?? "";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var dl) || dl.Scheme != "https" || !dl.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
            || !dl.AbsolutePath.StartsWith(prefix + "releases/download/", StringComparison.OrdinalIgnoreCase))
            throw new IntegrityException("Адрес архива не принадлежит релизам " + P.Repo);
        if (asset["size"] is JsonValue sz && sz.TryGetValue<long>(out var size) && (size <= 0 || size > MaxArchive))
            throw new IntegrityException("Недопустимый размер архива релиза");

        var m = Regex.Match(S(asset["digest"]) ?? "", @"^sha256:([0-9a-fA-F]{64})$");
        if (!m.Success) throw new IntegrityException("GitHub не передал SHA-256 (digest) архива — установка отклонена");
        return new(version, url, (S(j["body"]) ?? "").Trim(), S(j["published_at"]), m.Groups[1].Value.ToLowerInvariant());
    }

    private static void Retry(Action action, int attempts = 20)
    {
        for (int i = 0; i < attempts; i++)
        {
            try { action(); return; }
            catch (IOException) { if (i == attempts - 1) throw; Thread.Sleep(300); }
            catch (UnauthorizedAccessException) { if (i == attempts - 1) throw; Thread.Sleep(300); }
        }
    }

    /// <summary>Распаковка в пустую временную папку: пути, выходящие за её пределы, абсолютные и с «..» — отказ; ограничены число и размер файлов.</summary>
    public static void ExtractSafe(string archive, string target)
    {
        string root = Path.GetFullPath(target).TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
        Directory.CreateDirectory(root);
        using var zip = ZipFile.OpenRead(archive);
        if (zip.Entries.Count > MaxEntries) throw new InvalidOperationException("Архив содержит слишком много файлов");
        long total = 0;
        foreach (var e in zip.Entries)
        {
            string name = e.FullName.Replace('\\', '/');
            if (name.StartsWith('/') || name.Contains(':') || name.Split('/').Any(p => p == ".."))
                throw new InvalidOperationException("Архив содержит недопустимый путь: " + e.FullName);
            string dest = Path.GetFullPath(Path.Combine(root, name));
            if (!dest.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Архив пытается выйти за пределы папки распаковки: " + e.FullName);
            if (name.EndsWith('/')) { Directory.CreateDirectory(dest); continue; }
            if ((total += e.Length) > MaxUnpacked) throw new InvalidOperationException("Архив слишком большой после распаковки");
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            using var src = e.Open();
            using var dst = new FileStream(dest, FileMode.CreateNew, FileAccess.Write);
            long copied = 0; var buf = new byte[81920]; int n;
            while ((n = src.Read(buf, 0, buf.Length)) > 0)
            {
                copied += n;
                if (copied > e.Length) throw new InvalidOperationException("Размер файла в архиве не совпадает с заявленным: " + e.FullName);
                dst.Write(buf, 0, n);
            }
        }
    }

    /// <summary>Скачивает релиз и подменяет папку движка. stopEverything вызывается прямо перед заменой.
    /// Старый движок сохраняется в engine.backup; при любой ошибке после остановки восстанавливается из него.</summary>
    public static string Install(Release release, Action stopEverything, Action<long, long>? progress)
    {
        Directory.CreateDirectory(P.Root);
        string archive = Path.Combine(P.Root, "download.zip"), staging = Path.Combine(P.Root, "staging"),
            old = Path.Combine(P.Root, "engine.old"), backup = Path.Combine(P.Root, "engine.backup");
        if (!Regex.IsMatch(release.sha256 ?? "", "^[0-9a-f]{64}$")) throw new IntegrityException("Для релиза нет SHA-256 из GitHub API — установка отклонена");
        TryDelete(staging);
        try
        {
            Net.Download(release.url, archive, progress);
            try { Integrity.VerifyFile("zapret", release.version, release.sha256, archive); }
            catch { try { File.Delete(archive); } catch { } throw; }
            ExtractSafe(archive, staging);
        }
        catch { TryDelete(staging); try { File.Delete(archive); } catch { } throw; }
        File.Delete(archive);

        string? src = Directory.EnumerateFiles(staging, "winws.exe", SearchOption.AllDirectories)
            .Where(f => string.Equals(Path.GetFileName(Path.GetDirectoryName(f)), "bin", StringComparison.OrdinalIgnoreCase))
            .Select(f => Path.GetDirectoryName(Path.GetDirectoryName(f))!).FirstOrDefault();
        if (src is null || !File.Exists(Path.Combine(src, "service.bat")))
        {
            TryDelete(staging);
            throw new InvalidOperationException("Архив релиза имеет неожиданную структуру");
        }

        string? prevIpset = EngineFiles.Installed() ? EngineFiles.IpsetMode() : null;
        try
        {
            var keep = Preserve.ToList();
            string userLists = Path.Combine(P.Engine, "lists");
            if (Directory.Exists(userLists))
                keep.AddRange(Directory.GetFiles(userLists, "*-user.txt").Select(f => "lists/" + Path.GetFileName(f)));
            foreach (var rel in keep.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                string from = Path.Combine(P.Engine, rel);
                if (File.Exists(from))
                {
                    string to = Path.Combine(src, rel);
                    Directory.CreateDirectory(Path.GetDirectoryName(to)!);
                    File.Copy(from, to, true);
                }
            }
        }
        catch { TryDelete(staging); throw; }

        stopEverything();
        TryDelete(old);
        bool hadOld = Directory.Exists(P.Engine);
        void Rollback()
        {
            try
            {
                if (Directory.Exists(old))
                {
                    TryDelete(P.Engine);
                    Directory.Move(old, P.Engine);
                    Log.Warn("Обновление не удалось — прежний движок восстановлен");
                }
            }
            catch (Exception e) { Log.Error("Не удалось восстановить прежний движок: " + e.Message + " (копия: " + old + ")"); }
        }
        if (hadOld)
        {
            try { Retry(() => Directory.Move(P.Engine, old)); }
            catch { TryDelete(staging); throw new InvalidOperationException("Файлы zapret заняты другим процессом. Перезагрузите ПК и повторите обновление"); }
        }
        try
        {
            Retry(() => Directory.Move(src, P.Engine));
            if (!EngineFiles.Installed() || !File.Exists(Path.Combine(P.Engine, "service.bat"))) throw new InvalidOperationException("Установленный движок неполный");
        }
        catch
        {
            Rollback();
            TryDelete(staging);
            throw;
        }
        if (hadOld)
        {
            // Повторная установка той же версии не должна вытеснять копию предыдущей версии: она остаётся для отката.
            string? oldVer = VersionIn(old), newVer = LocalVersion();
            if (oldVer != null && newVer != null && VersionTuple(oldVer).SequenceEqual(VersionTuple(newVer)) && VersionIn(backup) != null)
                TryDelete(old);
            else
            {
                TryDelete(backup);
                try { Directory.Move(old, backup); } catch (Exception e) { Log.Warn("Резервная копия движка не сохранена: " + e.Message); TryDelete(old); }
            }
        }
        TryDelete(staging);

        if (prevIpset != null)
        {
            try { EngineFiles.SetIpsetMode(prevIpset); }
            catch (Exception e) { Log.Warn("Не удалось вернуть режим IPSet: " + e.Message); }
        }
        string? version = LocalVersion();
        if (version != null && !VersionTuple(version).SequenceEqual(VersionTuple(release.version)))
            Log.Warn($"В service.bat версия {version}, в релизе GitHub {release.version}");
        Log.Info("Установлен zapret " + version);
        return version ?? "?";
    }

    public static void TryDelete(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
    }
}
