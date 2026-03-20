namespace CookieDebugger.Models;

public sealed class CookieDebugResult
{
    public required AppEnvironment Environment { get; init; }

    public required string Fingerprint { get; init; }

    public required string CookieString { get; init; }

    public required string DecryptedJwt { get; init; }

    public required JwtInspectionResult Report { get; init; }
}
