namespace CookieDebugger.Models;

public sealed class TokenComparisonResult
{
    public required string CookiePayloadJson { get; init; }

    public required string AuthPayloadJson { get; init; }

    public required string AuthDecryptedPayloadJson { get; init; }

    public required bool AuthPayloadWasAlreadyPlainText { get; init; }

    public required bool AuthPayloadDecryptionFailed { get; init; }

    public required IReadOnlyList<ClaimDiff> Differences { get; init; }
}
