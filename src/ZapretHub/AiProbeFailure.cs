using System.Net.Http;
using System.Security.Authentication;

namespace ZapretHub;

internal sealed class AiProbeFailure : IOException
{
    internal string Kind { get; }
    internal string Stage => Context(this, "AiDnsStage") ?? (Kind is "region" or "service_rejected" ? "регион/сервис" : Kind);
    internal string Target => Context(this, "AiDnsTarget") ?? "";
    internal static string? Context(Exception? e, string key)
    { for (; e is not null; e = e.InnerException) if (e.Data[key] is string s) return s; return null; }
    internal static Exception At(Exception e, string stage, string target)
    { e.Data["AiDnsStage"] = stage; e.Data["AiDnsTarget"] = target; return e; }
    internal AiProbeFailure(string kind, string message, Exception? inner = null) : base(message, inner) => Kind = kind;
    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(8);
    internal static async Task WithinDeadline(Func<CancellationToken, Task> check, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(Timeout);
        try { await check(deadline.Token); }
        catch (OperationCanceledException e) when (deadline.IsCancellationRequested && !ct.IsCancellationRequested)
        { throw new AiProbeFailure("timeout", "Тайм-аут проверки DNS/HTTPS (8 с) · " + Context(e, "AiDnsStage") + " " + Context(e, "AiDnsTarget"), e); }
        catch (OperationCanceledException e) when (!ct.IsCancellationRequested)
        { throw new AiProbeFailure("timeout", "Тайм-аут транспорта DNS/HTTPS: " + e.GetBaseException().Message, e); }
    }
    internal static AiProbeFailure Classify(string stage, Exception e)
    {
        if (e is AiProbeFailure known) return known;
        if (e is HttpRequestException { StatusCode: not null } http) return new("http", stage + ": HTTP " + (int)http.StatusCode.Value, e);
        if (e is OperationCanceledException) return new("timeout", stage + ": время ожидания истекло", e);
        if (e is AuthenticationException || e.InnerException is AuthenticationException ||
            e is HttpRequestException { HttpRequestError: HttpRequestError.SecureConnectionError })
            return new("tls", stage + ": TLS: " + e.GetBaseException().Message, e);
        if (e is HttpRequestException { HttpRequestError: HttpRequestError.ConnectionError } || e is System.Net.Sockets.SocketException)
            return new("connection", stage + ": не удалось подключиться", e);
        return new(stage == "DNS/DoH" ? "dns" : "https", stage + ": " + e.Message, e);
    }
    internal static long Cooldown(Exception e) => e is AiProbeFailure { Kind: "region" or "service_rejected" } ? 600_000 : 30_000;
}
