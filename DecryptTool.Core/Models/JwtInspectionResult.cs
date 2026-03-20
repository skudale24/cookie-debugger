namespace CookieDebugger.Models;

public sealed class JwtInspectionResult
{
    public IReadOnlyList<string> PayloadLines { get; init; } = Array.Empty<string>();

    public string IssuedAtReadable { get; init; } = "Not present";

    public string NotBeforeReadable { get; init; } = "Not present";

    public string ExpiresReadable { get; init; } = "Not present";

    public string TokenLifetime { get; init; } = "Unknown";

    public string RemainingTimeUntilExpiration { get; init; } = "Unknown";

    public bool IsExpired { get; init; }
}
