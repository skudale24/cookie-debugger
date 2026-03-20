namespace CookieDebugger.Models;

public sealed class AppSettings
{
    public PassPhrases PassPhrases { get; set; } = new();
}

public sealed class PassPhrases
{
    public string Dev { get; set; } = string.Empty;

    public string Stage { get; set; } = string.Empty;

    public string Production { get; set; } = string.Empty;
}

public enum AppEnvironment
{
    Dev = 1,
    Stage = 2,
    Production = 3
}
