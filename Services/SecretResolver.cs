namespace CookieDebugger.Services;

public sealed class SecretResolver
{
    public const string EncryptionKeyEnvVar = "TOK_ENCRYPTION_KEY";
    public const string CookieFingerprintEnvVar = "TOK_COOKIE_FINGERPRINT";
    private string? _cachedEncryptionKey;
    private string? _cachedCookieFingerprint;
    private string? _cachedJwtSigningKey;

    public string ResolveEncryptionKey(bool forcePrompt = false)
    {
        if (forcePrompt)
        {
            _cachedEncryptionKey = PromptHidden("Encryption Key");
            return _cachedEncryptionKey;
        }

        _cachedEncryptionKey ??= ResolveSecret(EncryptionKeyEnvVar, "Encryption Key");
        return _cachedEncryptionKey;
    }

    public string? GetCachedOrEnvironmentEncryptionKey()
    {
        if (!string.IsNullOrWhiteSpace(_cachedEncryptionKey))
        {
            return _cachedEncryptionKey;
        }

        var environmentValue = Environment.GetEnvironmentVariable(EncryptionKeyEnvVar);
        return string.IsNullOrWhiteSpace(environmentValue)
            ? null
            : environmentValue.Trim();
    }

    public string ResolveCookieFingerprint(string? providedFingerprint = null, bool forcePrompt = false)
    {
        if (!string.IsNullOrWhiteSpace(providedFingerprint))
        {
            _cachedCookieFingerprint = providedFingerprint.Trim();
            return _cachedCookieFingerprint;
        }

        if (forcePrompt)
        {
            _cachedCookieFingerprint = PromptHidden("Fingerprint");
            return _cachedCookieFingerprint;
        }

        _cachedCookieFingerprint ??= ResolveSecret(CookieFingerprintEnvVar, "Fingerprint");
        return _cachedCookieFingerprint;
    }

    public string ResolveJwtSigningKey(string? providedKey = null)
    {
        if (!string.IsNullOrWhiteSpace(providedKey))
        {
            _cachedJwtSigningKey = NormalizeJwtSigningKey(providedKey);
            return _cachedJwtSigningKey;
        }

        _cachedJwtSigningKey ??= NormalizeJwtSigningKey(PromptHidden("JWT Signing Key"));
        return _cachedJwtSigningKey;
    }

    private static string ResolveSecret(string envVarName, string promptLabel)
    {
        var environmentValue = Environment.GetEnvironmentVariable(envVarName);
        if (!string.IsNullOrWhiteSpace(environmentValue))
        {
            return environmentValue.Trim();
        }

        return PromptHidden(promptLabel);
    }

    private static string PromptHidden(string label)
    {
        if (Console.IsInputRedirected)
        {
            Console.Write($"{label}: ");
            var redirectedInput = Console.ReadLine()?.Trim();
            if (string.IsNullOrWhiteSpace(redirectedInput))
            {
                throw new ArgumentException($"{label} is required.");
            }

            return redirectedInput;
        }

        Console.Write($"{label} [hidden input]: ");
        var buffer = new List<char>();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Count > 0)
                {
                    buffer.RemoveAt(buffer.Count - 1);
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                buffer.Add(key.KeyChar);
            }
        }

        var secret = new string(buffer.ToArray()).Trim();
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new ArgumentException($"{label} is required.");
        }

        return secret;
    }

    private static string NormalizeJwtSigningKey(string value)
    {
        var normalized = value;
        var trimmed = value.Trim();

        if (trimmed.Length >= 2 &&
            ((trimmed[0] == '"' && trimmed[^1] == '"') ||
             (trimmed[0] == '\'' && trimmed[^1] == '\'')))
        {
            normalized = trimmed[1..^1];
        }
        else
        {
            normalized = trimmed;
        }

        if (normalized.Contains("\\n", StringComparison.Ordinal) &&
            normalized.Contains("BEGIN", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized
                .Replace("\\r\\n", "\n", StringComparison.Ordinal)
                .Replace("\\n", "\n", StringComparison.Ordinal)
                .Replace("\\r", "\r", StringComparison.Ordinal);
        }

        return normalized;
    }
}
