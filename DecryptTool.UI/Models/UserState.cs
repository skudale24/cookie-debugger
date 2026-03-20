namespace CookieDebugger.Models;

public sealed class UserState
{
    public string LastEnvironment { get; set; } = "Dev";

    public string LastHarFilePath { get; set; } = string.Empty;

    public string LastFingerprint { get; set; } = string.Empty;

    public string LastEncryptedCookie { get; set; } = string.Empty;

    public string LastDecryptedJwt { get; set; } = string.Empty;
}
