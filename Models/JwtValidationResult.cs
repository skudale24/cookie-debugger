namespace CookieDebugger.Models;

public sealed class JwtValidationResult
{
    public required string Jwt { get; init; }

    public required bool CanRead { get; init; }

    public required bool SignatureValid { get; init; }

    public required bool HasExpiration { get; init; }

    public required bool IsExpired { get; init; }

    public required bool IsNotYetValid { get; init; }

    public required bool IsLifetimeCurrentlyValid { get; init; }

    public required string IssuedAtReadable { get; init; }

    public required string NotBeforeReadable { get; init; }

    public required string ExpiresReadable { get; init; }

    public required string OverallStatus { get; init; }

    public required IReadOnlyList<string> Messages { get; init; }
}
