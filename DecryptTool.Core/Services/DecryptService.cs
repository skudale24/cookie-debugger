using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using CookieDebugger.Interfaces;
using CookieDebugger.Models;
using Microsoft.IdentityModel.Tokens;

namespace CookieDebugger.Services;

public sealed class DecryptService(
    IPassphraseProvider passphraseProvider,
    CookieParser cookieParser,
    HarFileParser harFileParser,
    FingerprintDecryptor fingerprintDecryptor,
    JwtDecryptor jwtDecryptor,
    JwtInspector jwtInspector)
{
    public async Task<string> DecryptAsync(string cookie, string environment, string fingerprint)
    {
        var decrypted = await InspectCookieAsync(cookie, environment, fingerprint);
        return decrypted.DecryptedJwt;
    }

    public Task<CookieDebugResult> InspectCookieAsync(string cookie, string environment, string fingerprint)
    {
        var parsedEnvironment = ParseEnvironment(environment);
        return Task.FromResult(InspectCookie(cookie, fingerprint, parsedEnvironment));
    }

    public Task<CookieDebugResult> InspectCookieAsync(string cookie, AppEnvironment environment, string fingerprint)
    {
        return Task.FromResult(InspectCookie(cookie, fingerprint, environment));
    }

    public CookieDebugResult InspectCookie(string cookieString, string fingerprint, AppEnvironment environment)
    {
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            throw new ArgumentException("Fingerprint is required.");
        }

        if (string.IsNullOrWhiteSpace(cookieString))
        {
            throw new ArgumentException("Encrypted cookie string is required.");
        }

        var encryptedJwt = cookieParser.ExtractEncryptedJwt(cookieString);
        var decryptedJwt = jwtDecryptor.Decrypt(encryptedJwt, fingerprint, passphraseProvider.GetPassPhrase(environment));

        return new CookieDebugResult
        {
            Environment = environment,
            Fingerprint = fingerprint,
            CookieString = cookieString,
            DecryptedJwt = decryptedJwt,
            Report = jwtInspector.Inspect(decryptedJwt)
        };
    }

    public HarDebugResult InspectHar(string harFilePath, AppEnvironment environment, string encryptionKey)
    {
        var normalizedPath = NormalizeDroppedPath(harFilePath);
        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            throw new ArgumentException("HAR file path is required.");
        }

        var harExtraction = harFileParser.Extract(normalizedPath);
        var fingerprint = DecryptPayload(harExtraction.EncryptedFingerprint, encryptionKey);

        return new HarDebugResult
        {
            HarFilePath = normalizedPath,
            EncryptedFingerprint = harExtraction.EncryptedFingerprint,
            AuthorizationJwt = harExtraction.AuthorizationJwt,
            CookieDebug = InspectCookie(harExtraction.CookieString, fingerprint, environment)
        };
    }

    public RawJwtInspectionResult InspectRawJwt(string jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
        {
            throw new ArgumentException("A JWT string is required.");
        }

        var normalizedJwt = NormalizeJwtInput(jwt);
        JwtSecurityToken token;
        try
        {
            token = new JwtSecurityTokenHandler().ReadJwtToken(normalizedJwt);
        }
        catch (Exception ex)
        {
            throw new ArgumentException($"Value is not a valid JWT. {ex.Message}", ex);
        }

        var claims = token.Claims
            .GroupBy(claim => claim.Type, StringComparer.Ordinal)
            .Select(group => new KeyValuePair<string, string>(
                group.Key,
                string.Join(" | ", group.Select(claim => claim.Value))))
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new RawJwtInspectionResult
        {
            Jwt = normalizedJwt,
            HeaderJson = SerializeJsonObject(token.Header),
            PayloadJson = SerializeJsonObject(token.Payload),
            Claims = claims,
            Report = jwtInspector.Inspect(normalizedJwt)
        };
    }

    public JwtReadabilityResult CanReadJwt(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException("A value is required.");
        }

        var trimmed = NormalizeJwtInput(input);
        var segmentCount = trimmed.Split('.', StringSplitOptions.RemoveEmptyEntries).Length;
        var canRead = new JwtSecurityTokenHandler().CanReadToken(trimmed);

        return new JwtReadabilityResult
        {
            Input = trimmed,
            CanRead = canRead,
            SegmentCount = segmentCount,
            Message = canRead
                ? "The value can be parsed as a JWT."
                : "The value does not look like a readable JWT."
        };
    }

    public bool LooksLikeEncryptedPayload(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        return cookieParser.LooksLikeEncryptedPayload(input);
    }

    public bool HasEncryptedJwtClaims(string jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
        {
            return false;
        }

        var normalizedJwt = NormalizeJwtInput(jwt);
        JwtSecurityToken token;
        try
        {
            token = new JwtSecurityTokenHandler().ReadJwtToken(normalizedJwt);
        }
        catch (Exception ex)
        {
            throw new ArgumentException($"Value is not a valid JWT. {ex.Message}", ex);
        }

        return token.Payload.Values.Any(ContainsEncryptedPayloadCandidate);
    }

    public bool CanDecryptJwtClaims(string jwt, string encryptionKey)
    {
        if (string.IsNullOrWhiteSpace(jwt) || string.IsNullOrWhiteSpace(encryptionKey))
        {
            return false;
        }

        var normalizedJwt = NormalizeJwtInput(jwt);
        JwtSecurityToken token;
        try
        {
            token = new JwtSecurityTokenHandler().ReadJwtToken(normalizedJwt);
        }
        catch (Exception ex)
        {
            throw new ArgumentException($"Value is not a valid JWT. {ex.Message}", ex);
        }

        return token.Payload.Values.Any(value => ContainsSuccessfullyDecryptedPayloadCandidate(value, encryptionKey));
    }

    public JwtValidationResult ValidateRawJwt(string jwt, string key)
    {
        if (string.IsNullOrWhiteSpace(jwt))
        {
            throw new ArgumentException("A JWT string is required.");
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("A signing key is required.");
        }

        key = NormalizeJwtSigningKey(key);

        var trimmed = NormalizeJwtInput(jwt);
        var readability = CanReadJwt(trimmed);
        if (!readability.CanRead)
        {
            return new JwtValidationResult
            {
                Jwt = trimmed,
                CanRead = false,
                SignatureValid = false,
                HasExpiration = false,
                IsExpired = false,
                IsNotYetValid = false,
                IsLifetimeCurrentlyValid = false,
                IssuedAtReadable = "N/A",
                NotBeforeReadable = "N/A",
                ExpiresReadable = "N/A",
                OverallStatus = "Unreadable JWT",
                Messages = new[]
                {
                    "The token could not be parsed as a JWT."
                }
            };
        }

        var report = jwtInspector.Inspect(trimmed);
        var token = new JwtSecurityTokenHandler().ReadJwtToken(trimmed);
        var hasExpiration = token.Payload.TryGetValue("exp", out var expValue) && expValue is not null;
        var hasNotBefore = token.Payload.TryGetValue("nbf", out var nbfValue) && nbfValue is not null;
        var nowUtc = DateTimeOffset.UtcNow;
        var isExpired = report.IsExpired;
        var isNotYetValid = hasNotBefore && token.ValidFrom > nowUtc.UtcDateTime;

        var messages = new List<string>
        {
            "Structure is readable as a JWT."
        };

        var signatureValid = false;
        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                RequireSignedTokens = true
            };

            new JwtSecurityTokenHandler().ValidateToken(trimmed, validationParameters, out _);
            signatureValid = true;
            messages.Add("Signature validation succeeded with the provided key.");
        }
        catch (SecurityTokenExpiredException)
        {
            signatureValid = true;
            messages.Add("Signature validation succeeded, but the token is expired.");
        }
        catch (SecurityTokenNotYetValidException)
        {
            signatureValid = true;
            messages.Add("Signature validation succeeded, but the token is not yet valid.");
        }
        catch (Exception ex) when (ex is SecurityTokenException or ArgumentException)
        {
            messages.Add($"Signature validation failed: {ex.Message}");
        }

        if (!hasExpiration)
        {
            messages.Add("No exp claim was found, so expiration could not be evaluated.");
        }
        else if (isExpired)
        {
            messages.Add("The token is expired based on its exp claim.");
        }
        else
        {
            messages.Add("The token is not expired based on its exp claim.");
        }

        if (hasNotBefore)
        {
            messages.Add(isNotYetValid
                ? "The token is not yet valid based on its nbf claim."
                : "The token is within its nbf validity window.");
        }

        var isLifetimeCurrentlyValid = signatureValid && (!hasExpiration || !isExpired) && !isNotYetValid;
        var overallStatus = !signatureValid
            ? "Invalid Signature"
            : isExpired
                ? "Signature Valid, Token Expired"
                : isNotYetValid
                    ? "Signature Valid, Token Not Yet Valid"
                    : isLifetimeCurrentlyValid
                        ? "Signature and Lifetime Valid"
                        : "Signature Valid, Lifetime Check Failed";

        return new JwtValidationResult
        {
            Jwt = trimmed,
            CanRead = readability.CanRead,
            SignatureValid = signatureValid,
            HasExpiration = hasExpiration,
            IsExpired = isExpired,
            IsNotYetValid = isNotYetValid,
            IsLifetimeCurrentlyValid = isLifetimeCurrentlyValid,
            IssuedAtReadable = report.IssuedAtReadable,
            NotBeforeReadable = report.NotBeforeReadable,
            ExpiresReadable = report.ExpiresReadable,
            OverallStatus = overallStatus,
            Messages = messages
        };
    }

    public string DecryptPayload(string encryptedText, string encryptionKey)
    {
        if (string.IsNullOrWhiteSpace(encryptedText))
        {
            throw new ArgumentException("Encrypted payload is required.");
        }

        if (string.IsNullOrWhiteSpace(encryptionKey))
        {
            throw new ArgumentException("Encryption key is required.");
        }

        return fingerprintDecryptor.Decrypt(
            encryptedText,
            encryptionKey,
            encryptionKey);
    }

    public string TryDecryptClaimValue(string rawValue, string encryptionKey)
    {
        if (string.IsNullOrWhiteSpace(rawValue) || string.IsNullOrWhiteSpace(encryptionKey))
        {
            return rawValue;
        }

        try
        {
            return fingerprintDecryptor.Decrypt(
                rawValue,
                encryptionKey,
                encryptionKey);
        }
        catch (FormatException)
        {
            return rawValue;
        }
        catch (CryptographicException)
        {
            return rawValue;
        }
        catch (ArgumentException)
        {
            return rawValue;
        }
    }

    public static string NormalizeDroppedPath(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var value = input.Trim();

        if (value.StartsWith("& ", StringComparison.Ordinal))
        {
            value = value[2..].TrimStart();
        }

        if (value.StartsWith("@", StringComparison.Ordinal))
        {
            value = value[1..].TrimStart();
        }

        if (value.Length >= 2)
        {
            var first = value[0];
            var last = value[^1];
            if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
            {
                value = value[1..^1].Trim();
            }
        }

        return value.Trim().Trim('"');
    }

    public static AppEnvironment ParseEnvironment(string? environment)
    {
        if (string.IsNullOrWhiteSpace(environment))
        {
            return AppEnvironment.Dev;
        }

        var normalized = environment.Trim();
        if (normalized.Equals("Prod", StringComparison.OrdinalIgnoreCase))
        {
            normalized = nameof(AppEnvironment.Production);
        }

        return Enum.TryParse<AppEnvironment>(normalized, ignoreCase: true, out var parsed)
            ? parsed
            : throw new ArgumentException($"Unsupported environment '{environment}'. Expected Dev, Stage, or Production.");
    }

    public static string NormalizeJwtInput(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var value = input.Trim();
        if (value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            value = value["Bearer ".Length..].Trim();
        }

        return value;
    }

    public static string NormalizeJwtSigningKey(string value)
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

    private static string SerializeJsonObject(IEnumerable<KeyValuePair<string, object>> values)
    {
        var dictionary = values.ToDictionary(
            pair => pair.Key,
            pair => NormalizeJwtValue(pair.Value),
            StringComparer.Ordinal);

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Indented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }))
        {
            WriteJsonObject(writer, dictionary);
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static object? NormalizeJwtValue(object? value)
    {
        return value switch
        {
            null => null,
            JsonElement jsonElement => NormalizeJsonElement(jsonElement),
            IEnumerable<object?> enumerable => enumerable.Select(NormalizeJwtValue).ToList(),
            _ => value
        };
    }

    private static object? NormalizeJsonElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Object => element.EnumerateObject().ToDictionary(
                property => property.Name,
                property => NormalizeJsonElement(property.Value),
                StringComparer.Ordinal),
            JsonValueKind.Array => element.EnumerateArray().Select(NormalizeJsonElement).ToList(),
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number => element.ToString(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => element.ToString()
        };
    }

    private bool ContainsEncryptedPayloadCandidate(object? value)
    {
        return value switch
        {
            null => false,
            string stringValue => IsPotentialEncryptedClaimString(stringValue),
            JsonElement jsonElement => ContainsEncryptedPayloadCandidate(jsonElement),
            IEnumerable<object?> enumerable => enumerable.Any(ContainsEncryptedPayloadCandidate),
            _ => false
        };
    }

    private bool ContainsEncryptedPayloadCandidate(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => IsPotentialEncryptedClaimString(element.GetString() ?? string.Empty),
            JsonValueKind.Array => element.EnumerateArray().Any(ContainsEncryptedPayloadCandidate),
            JsonValueKind.Object => element.EnumerateObject().Any(property => ContainsEncryptedPayloadCandidate(property.Value)),
            _ => false
        };
    }

    private bool ContainsSuccessfullyDecryptedPayloadCandidate(object? value, string encryptionKey)
    {
        return value switch
        {
            null => false,
            string stringValue => IsSuccessfullyDecryptedPayloadCandidate(stringValue, encryptionKey),
            JsonElement jsonElement => ContainsSuccessfullyDecryptedPayloadCandidate(jsonElement, encryptionKey),
            IEnumerable<object?> enumerable => enumerable.Any(item => ContainsSuccessfullyDecryptedPayloadCandidate(item, encryptionKey)),
            _ => false
        };
    }

    private bool ContainsSuccessfullyDecryptedPayloadCandidate(JsonElement element, string encryptionKey)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => IsSuccessfullyDecryptedPayloadCandidate(element.GetString() ?? string.Empty, encryptionKey),
            JsonValueKind.Array => element.EnumerateArray().Any(item => ContainsSuccessfullyDecryptedPayloadCandidate(item, encryptionKey)),
            JsonValueKind.Object => element.EnumerateObject().Any(property => ContainsSuccessfullyDecryptedPayloadCandidate(property.Value, encryptionKey)),
            _ => false
        };
    }

    private bool IsSuccessfullyDecryptedPayloadCandidate(string value, string encryptionKey)
    {
        if (!IsPotentialEncryptedClaimString(value))
        {
            return false;
        }

        var decrypted = TryDecryptClaimValue(value, encryptionKey);
        return !string.Equals(decrypted, value, StringComparison.Ordinal);
    }

    private static bool IsPotentialEncryptedClaimString(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Trim().Replace(" ", "+", StringComparison.Ordinal);
        if (normalized.Length < 16)
        {
            return false;
        }

        try
        {
            var bytes = Convert.FromBase64String(normalized);
            return bytes.Length >= 16;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static void WriteJsonObject(Utf8JsonWriter writer, IReadOnlyDictionary<string, object?> values)
    {
        writer.WriteStartObject();
        foreach (var pair in values)
        {
            writer.WritePropertyName(pair.Key);
            WriteJsonValue(writer, pair.Value);
        }

        writer.WriteEndObject();
    }

    private static void WriteJsonValue(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                return;
            case JsonElement element:
                element.WriteTo(writer);
                return;
            case string stringValue:
                writer.WriteStringValue(stringValue);
                return;
            case bool boolValue:
                writer.WriteBooleanValue(boolValue);
                return;
            case byte byteValue:
                writer.WriteNumberValue(byteValue);
                return;
            case short shortValue:
                writer.WriteNumberValue(shortValue);
                return;
            case int intValue:
                writer.WriteNumberValue(intValue);
                return;
            case long longValue:
                writer.WriteNumberValue(longValue);
                return;
            case float floatValue:
                writer.WriteNumberValue(floatValue);
                return;
            case double doubleValue:
                writer.WriteNumberValue(doubleValue);
                return;
            case decimal decimalValue:
                writer.WriteNumberValue(decimalValue);
                return;
            case uint uintValue:
                writer.WriteNumberValue(uintValue);
                return;
            case ulong ulongValue:
                writer.WriteNumberValue(ulongValue);
                return;
            case IReadOnlyDictionary<string, object?> dictionary:
                WriteJsonObject(writer, dictionary);
                return;
            case IDictionary<string, object?> dictionary:
                WriteJsonObject(writer, new Dictionary<string, object?>(dictionary, StringComparer.Ordinal));
                return;
            case IEnumerable<object?> enumerable:
                writer.WriteStartArray();
                foreach (var item in enumerable)
                {
                    WriteJsonValue(writer, item);
                }

                writer.WriteEndArray();
                return;
            default:
                writer.WriteStringValue(value.ToString());
                return;
        }
    }
}
