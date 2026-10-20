namespace ZapretHub;

public sealed class TgCfg
{
    public bool enabled { get; set; }
    public int port { get; set; } = 1443;
    public string secret { get; set; } = "";
    public List<string> dc_ip { get; set; } = new(TgProxy.DefaultDcIp);
    public bool cfproxy { get; set; } = true;
}

/// <summary>Telegram-прокси (MTProto → WebSocket). Порт ядра tg-ws-proxy на C#.</summary>
public sealed partial class TgProxy
{
    public const string Repo = "Flowseal/tg-ws-proxy";
    public static readonly string[] DefaultDcIp = { "2:149.154.167.220", "4:149.154.167.220" };
    public readonly object Lock = new();

    public static string NewSecret() => Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
    public static string Link(TgCfg c) => $"tg://proxy?server=127.0.0.1&port={c.port}&secret=dd{c.secret}";

    public static bool ValidDcIp(string line)
    {
        var m = System.Text.RegularExpressions.Regex.Match(line.Trim(), @"^(\d+):(\d{1,3}(?:\.\d{1,3}){3})$");
        return m.Success && m.Groups[2].Value.Split('.').All(x => int.Parse(x) <= 255);
    }
}
