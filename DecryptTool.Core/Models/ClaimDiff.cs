namespace CookieDebugger.Models;

public sealed class ClaimDiff
{
    public required string Claim { get; init; }

    public required string CookieValue { get; init; }

    public required string AuthValue { get; init; }

    public required string Status { get; init; }
}
