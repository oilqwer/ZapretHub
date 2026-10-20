using System.Text.Json.Nodes;

namespace ZapretHub;

/// <summary>Исключения Защитника Windows для файлов движка. Ничего не добавляется и не удаляется автоматически:
/// изменение возможно только по явному согласию пользователя (consent=true из окна с предупреждением).
/// Существующие исключения программа не трогает, пока пользователь сам не нажал «Удалить».</summary>
public static class DefenderCtl
{
    /// <summary>Запуск PowerShell; подменяется в тестах, чтобы не менять настройки Защитника.</summary>
    private static Func<string, (int code, string output)> _ps = script =>
        Sys.Run("powershell", new[] { "-NoProfile", "-NonInteractive", "-Command", script }, 60);
    private static bool _faked;
    public static Func<string, (int code, string output)> Ps { get => _ps; set { _ps = value; _faked = true; } }
    private static void Guard() { if (!_faked) P.Need("исключение Защитника"); }

    /// <summary>Что добавляем: только папка с winws.exe и драйвером WinDivert (а не вся папка данных).</summary>
    public static string AddPath => P.Bin;
    /// <summary>Какие наши пути считаем «исключениями Zapret Hub» (в том числе добавленный ранее корень — старыми версиями).</summary>
    public static string[] RelatedPaths => new[] { P.Root, P.Bin };

    private static string Norm(string p) => p.Trim().TrimEnd('\\').ToLowerInvariant();
    private static string Q(string p) => "'" + p.Replace("'", "''") + "'";

    public sealed record State(bool available, string? error, bool root, bool bin, List<string> existing, string addPath);

    public static State Status()
    {
        var (code, output) = Ps("$p=(Get-MpPreference -ErrorAction Stop).ExclusionPath; if($null -eq $p){'[]'}else{ConvertTo-Json -InputObject @($p) -Compress}");
        output = output.Trim();
        if (code != 0 || !output.StartsWith('['))
            return new(false, "Защитник Windows недоступен (возможно, установлен другой антивирус)", false, false, new(), AddPath);
        List<string> list;
        try { list = JsonNode.Parse(output)!.AsArray().Select(x => x?.GetValue<string>() ?? "").Where(s => s.Length > 0).ToList(); }
        catch { return new(false, "Не удалось прочитать список исключений", false, false, new(), AddPath); }
        if (list.Any(s => s.StartsWith("N/A", StringComparison.OrdinalIgnoreCase)))
            return new(false, "Нет прав администратора для чтения исключений", false, false, new(), AddPath);
        var set = list.Select(Norm).ToHashSet();
        var ours = list.Where(s => RelatedPaths.Select(Norm).Contains(Norm(s))).ToList();
        return new(true, null, set.Contains(Norm(P.Root)), set.Contains(Norm(P.Bin)), ours, AddPath);
    }

    public static void Add(bool consent)
    {
        if (!consent) throw new InvalidOperationException("Исключение добавляется только с явного согласия пользователя");
        Guard();
        var st = Status();
        if (!st.available) throw new InvalidOperationException(st.error ?? "Защитник недоступен");
        if (st.root || st.bin) throw new InvalidOperationException("Папка уже входит в исключения");
        var (code, _) = Ps($"Add-MpPreference -ExclusionPath {Q(AddPath)} -ErrorAction Stop");
        if (code != 0) throw new InvalidOperationException("Защитник отказал (возможно, включена защита от подделки или стоит другой антивирус)");
        Log.Info("Пользователь добавил исключение Защитника: " + AddPath);
    }

    public static List<string> Remove(bool consent)
    {
        if (!consent) throw new InvalidOperationException("Исключение удаляется только с явного согласия пользователя");
        Guard();
        var st = Status();
        if (!st.available) throw new InvalidOperationException(st.error ?? "Защитник недоступен");
        if (st.existing.Count == 0) throw new InvalidOperationException("Исключений Zapret Hub нет");
        foreach (var path in st.existing)
        {
            var (code, _) = Ps($"Remove-MpPreference -ExclusionPath {Q(path)} -ErrorAction Stop");
            if (code != 0) throw new InvalidOperationException("Не удалось удалить исключение: " + path);
            Log.Info("Пользователь удалил исключение Защитника: " + path);
        }
        return st.existing;
    }
}
