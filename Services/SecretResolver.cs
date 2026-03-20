namespace CookieDebugger.Services;

public sealed class SecretResolver
{
    public const string EncryptionKeyEnvVar = "TOK_ENCRYPTION_KEY";
    public const string JwtSigningKeyEnvVar = "TOK_JWT_SIGNING_KEY";

    private string? _cachedEncryptionKey;
    private string? _cachedJwtSigningKey;

    public string ResolveEncryptionKey()
    {
        _cachedEncryptionKey ??= ResolveSecret(EncryptionKeyEnvVar, "Encryption Key");
        return _cachedEncryptionKey;
    }

    public string ResolveJwtSigningKey(string? providedKey = null)
    {
        if (!string.IsNullOrWhiteSpace(providedKey))
        {
            _cachedJwtSigningKey = providedKey.Trim();
            return _cachedJwtSigningKey;
        }

        _cachedJwtSigningKey ??= ResolveSecret(JwtSigningKeyEnvVar, "JWT Signing Key");
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
}
