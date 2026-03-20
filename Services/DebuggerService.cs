using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using CookieDebugger.Models;
using Microsoft.IdentityModel.Tokens;

namespace CookieDebugger.Services;

public sealed class DebuggerService(
    AppSettingsProvider settingsProvider,
    CookieParser cookieParser,
    HarFileParser harFileParser,
    SecretResolver secretResolver,
    FingerprintDecryptor fingerprintDecryptor,
    JwtDecryptor jwtDecryptor,
    JwtInspector jwtInspector)
{
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
        var decryptedJwt = jwtDecryptor.Decrypt(encryptedJwt, fingerprint, settingsProvider.GetPassPhrase(environment));

        return new CookieDebugResult
        {
            Environment = environment,
            Fingerprint = fingerprint,
            CookieString = cookieString,
            DecryptedJwt = decryptedJwt,
            Report = jwtInspector.Inspect(decryptedJwt)
        };
    }

    public HarDebugResult InspectHar(string harFilePath, AppEnvironment environment)
    {
        var normalizedPath = NormalizeDroppedPath(harFilePath);
        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            throw new ArgumentException("HAR file path is required.");
        }

        var harExtraction = harFileParser.Extract(normalizedPath);
        var encryptionKey = secretResolver.ResolveEncryptionKey();
        var fingerprint = fingerprintDecryptor.Decrypt(
            harExtraction.EncryptedFingerprint,
            encryptionKey,
            encryptionKey);

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

        JwtSecurityToken token;
        try
        {
            token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
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
            Jwt = jwt,
            HeaderJson = SerializeJsonObject(token.Header),
            PayloadJson = SerializeJsonObject(token.Payload),
            Claims = claims,
            Report = jwtInspector.Inspect(jwt)
        };
    }

    public JwtReadabilityResult CanReadJwt(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException("A value is required.");
        }

        var trimmed = input.Trim();
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

        var trimmed = jwt.Trim();
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
            Messages = messages
        };
    }

    public string DecryptPayload(string encryptedText)
    {
        if (string.IsNullOrWhiteSpace(encryptedText))
        {
            throw new ArgumentException("Encrypted payload is required.");
        }

        var encryptionKey = secretResolver.ResolveEncryptionKey();
        return fingerprintDecryptor.Decrypt(
            encryptedText,
            encryptionKey,
            encryptionKey);
    }

    public string TryDecryptClaimValue(string rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return rawValue;
        }

        var encryptionKey = secretResolver.ResolveEncryptionKey();

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
