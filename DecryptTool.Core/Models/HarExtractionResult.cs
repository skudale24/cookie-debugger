namespace CookieDebugger.Models;

public sealed class HarExtractionResult
{
    public string EncryptedFingerprint { get; init; } = string.Empty;

    public string CookieString { get; init; } = string.Empty;

    public string AuthorizationJwt { get; init; } = string.Empty;
}
