namespace CookieDebugger.Models;

public sealed class RawJwtInspectionResult
{
    public required string Jwt { get; init; }

    public required string HeaderJson { get; init; }

    public required string PayloadJson { get; init; }

    public required IReadOnlyList<KeyValuePair<string, string>> Claims { get; init; }

    public required JwtInspectionResult Report { get; init; }
}
