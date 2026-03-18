namespace CookieDebugger.Models;

public sealed class JwtReadabilityResult
{
    public required string Input { get; init; }

    public required bool CanRead { get; init; }

    public required int SegmentCount { get; init; }

    public required string Message { get; init; }
}
