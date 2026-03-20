namespace CookieDebugger.Models;

public sealed class HarDebugResult
{
    public required string HarFilePath { get; init; }

    public required string EncryptedFingerprint { get; init; }

    public required string AuthorizationJwt { get; init; }

    public required CookieDebugResult CookieDebug { get; init; }
}
