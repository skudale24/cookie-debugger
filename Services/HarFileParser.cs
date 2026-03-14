using System.Text.Json;
using CookieDebugger.Models;

namespace CookieDebugger.Services;

public sealed class HarFileParser
{
    public HarExtractionResult Extract(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("HAR file path is required.");
        }

        if (!File.Exists(filePath))
        {
            throw new ArgumentException($"HAR file was not found: {filePath}");
        }

        using var stream = File.OpenRead(filePath);
        using var document = JsonDocument.Parse(stream);

        var root = document.RootElement;
        var cookieString = FindEncinfoCookie(root);
        var authorizationJwt = FindAuthorizationJwt(root);
        var encryptedFingerprint = !string.IsNullOrWhiteSpace(authorizationJwt)
            ? ExtractClientIdFromJwt(authorizationJwt)
            : FindClientIdClaimObject(root);

        if (string.IsNullOrWhiteSpace(cookieString))
        {
            throw new ArgumentException(BuildMissingCookieMessage(root));
        }

        if (string.IsNullOrWhiteSpace(encryptedFingerprint))
        {
            throw new ArgumentException("Could not find a fingerprint in the HAR file. Expected a JWT claim named 'ClientID' or a claim object where ClaimName is 'ClientID'.");
        }

        return new HarExtractionResult
        {
            CookieString = cookieString,
            EncryptedFingerprint = encryptedFingerprint,
            AuthorizationJwt = authorizationJwt
        };
    }

    private static string FindEncinfoCookie(JsonElement root)
    {
        if (!TryGetEntries(root, out var entries))
        {
            return string.Empty;
        }

        foreach (var entry in entries.EnumerateArray())
        {
            if (!entry.TryGetProperty("request", out var request))
            {
                continue;
            }

            if (request.TryGetProperty("cookies", out var cookies) &&
                cookies.ValueKind == JsonValueKind.Array)
            {
                foreach (var cookie in cookies.EnumerateArray())
                {
                    if (TryReadProperty(cookie, "name", out var name) &&
                        name.Equals("encinfo", StringComparison.OrdinalIgnoreCase) &&
                        TryReadProperty(cookie, "value", out var value) &&
                        !string.IsNullOrWhiteSpace(value))
                    {
                        return value;
                    }
                }
            }

            if (request.TryGetProperty("headers", out var headers) &&
                headers.ValueKind == JsonValueKind.Array)
            {
                foreach (var header in headers.EnumerateArray())
                {
                    if (!TryReadProperty(header, "name", out var headerName) ||
                        !headerName.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
                        !TryReadProperty(header, "value", out var headerValue))
                    {
                        continue;
                    }

                    var cookieValue = ExtractCookieValue(headerValue, "encinfo");
                    if (!string.IsNullOrWhiteSpace(cookieValue))
                    {
                        return cookieValue;
                    }
                }
            }
        }

        return string.Empty;
    }

    private static string BuildMissingCookieMessage(JsonElement root)
    {
        if (!TryGetEntries(root, out var entries))
        {
            return "The HAR file does not contain log.entries, so no encinfo cookie could be read.";
        }

        string? firstUrl = null;
        var foundEncryptedRequestPayload = false;
        var foundEncryptedResponsePayload = false;
        var foundCookieHeader = false;
        var foundSetCookieHeader = false;

        foreach (var entry in entries.EnumerateArray())
        {
            if (firstUrl is null &&
                entry.TryGetProperty("request", out var requestForUrl) &&
                TryReadProperty(requestForUrl, "url", out var url))
            {
                firstUrl = url;
            }

            if (entry.TryGetProperty("request", out var request))
            {
                if (request.TryGetProperty("headers", out var requestHeaders) &&
                    requestHeaders.ValueKind == JsonValueKind.Array)
                {
                    foreach (var header in requestHeaders.EnumerateArray())
                    {
                        if (TryReadProperty(header, "name", out var headerName) &&
                            headerName.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
                        {
                            foundCookieHeader = true;
                        }
                    }
                }

                if (request.TryGetProperty("postData", out var postData) &&
                    postData.TryGetProperty("text", out var postText) &&
                    postText.ValueKind == JsonValueKind.String)
                {
                    var text = postText.GetString() ?? string.Empty;
                    if (text.Contains("\"ENC\"", StringComparison.Ordinal))
                    {
                        foundEncryptedRequestPayload = true;
                    }
                }
            }

            if (entry.TryGetProperty("response", out var response))
            {
                if (response.TryGetProperty("headers", out var responseHeaders) &&
                    responseHeaders.ValueKind == JsonValueKind.Array)
                {
                    foreach (var header in responseHeaders.EnumerateArray())
                    {
                        if (TryReadProperty(header, "name", out var headerName) &&
                            headerName.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                        {
                            foundSetCookieHeader = true;
                        }
                    }
                }

                if (response.TryGetProperty("content", out var content) &&
                    content.TryGetProperty("text", out var responseText) &&
                    responseText.ValueKind == JsonValueKind.String &&
                    !string.IsNullOrWhiteSpace(responseText.GetString()))
                {
                    foundEncryptedResponsePayload = true;
                }
            }
        }

        if (foundEncryptedRequestPayload || foundEncryptedResponsePayload)
        {
            return $"Could not find the 'encinfo' cookie in the HAR file. This HAR looks like an encrypted API capture instead of a browser cookie capture: request Cookie header present = {foundCookieHeader}, response Set-Cookie present = {foundSetCookieHeader}, encrypted request body present = {foundEncryptedRequestPayload}, encrypted response body present = {foundEncryptedResponsePayload}. First request URL: {firstUrl ?? "unknown"}.";
        }

        return $"Could not find the 'encinfo' cookie in the HAR file. No request Cookie header or request.cookies entry with encinfo was present. First request URL: {firstUrl ?? "unknown"}.";
    }

    private static string FindAuthorizationJwt(JsonElement root)
    {
        if (!TryGetEntries(root, out var entries))
        {
            return string.Empty;
        }

        foreach (var entry in entries.EnumerateArray())
        {
            if (!entry.TryGetProperty("request", out var request) ||
                !request.TryGetProperty("headers", out var headers) ||
                headers.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var header in headers.EnumerateArray())
            {
                if (!TryReadProperty(header, "name", out var headerName) ||
                    !headerName.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
                    !TryReadProperty(header, "value", out var headerValue))
                {
                    continue;
                }

                var token = ExtractBearerToken(headerValue);
                if (!string.IsNullOrWhiteSpace(token))
                {
                    return token;
                }
            }
        }

        return string.Empty;
    }

    private static string FindClientIdClaimObject(JsonElement root)
    {
        return TryFindClientIdClaimObject(root, out var fingerprint) ? fingerprint : string.Empty;
    }

    private static bool TryFindClientIdClaimObject(JsonElement element, out string fingerprint)
    {
        fingerprint = string.Empty;

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                if (TryReadClaimValue(element, out fingerprint))
                {
                    return true;
                }

                foreach (var property in element.EnumerateObject())
                {
                    if (TryFindClientIdClaimObject(property.Value, out fingerprint))
                    {
                        return true;
                    }
                }

                return false;

            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (TryFindClientIdClaimObject(item, out fingerprint))
                    {
                        return true;
                    }
                }

                return false;

            default:
                return false;
        }
    }

    private static bool TryReadClaimValue(JsonElement element, out string fingerprint)
    {
        fingerprint = string.Empty;

        if (!TryReadProperty(element, "ClaimName", out var claimName) &&
            !TryReadProperty(element, "claimName", out claimName))
        {
            return false;
        }

        if (!claimName.Equals("ClientID", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (TryReadProperty(element, "ClaimValue", out fingerprint) ||
            TryReadProperty(element, "claimValue", out fingerprint) ||
            TryReadProperty(element, "Value", out fingerprint) ||
            TryReadProperty(element, "value", out fingerprint))
        {
            return !string.IsNullOrWhiteSpace(fingerprint);
        }

        return false;
    }

    private static string ExtractBearerToken(string headerValue)
    {
        const string bearerPrefix = "Bearer ";
        return headerValue.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase)
            ? headerValue[bearerPrefix.Length..].Trim()
            : string.Empty;
    }

    private static string ExtractClientIdFromJwt(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
        {
            return string.Empty;
        }

        try
        {
            var payload = DecodeBase64Url(parts[1]);
            using var document = JsonDocument.Parse(payload);
            return TryReadProperty(document.RootElement, "ClientID", out var clientId)
                ? clientId
                : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static byte[] DecodeBase64Url(string input)
    {
        var normalized = input.Replace('-', '+').Replace('_', '/');
        var padding = normalized.Length % 4;
        if (padding > 0)
        {
            normalized = normalized.PadRight(normalized.Length + (4 - padding), '=');
        }

        return Convert.FromBase64String(normalized);
    }

    private static bool TryGetEntries(JsonElement root, out JsonElement entries)
    {
        entries = default;

        return root.TryGetProperty("log", out var log) &&
               log.TryGetProperty("entries", out entries) &&
               entries.ValueKind == JsonValueKind.Array;
    }

    private static string ExtractCookieValue(string headerValue, string cookieName)
    {
        var parts = headerValue.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            var separatorIndex = part.IndexOf('=');
            if (separatorIndex <= 0)
            {
                continue;
            }

            var name = part[..separatorIndex].Trim();
            if (!name.Equals(cookieName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return part[(separatorIndex + 1)..].Trim();
        }

        return string.Empty;
    }

    private static bool TryReadProperty(JsonElement element, string propertyName, out string value)
    {
        value = string.Empty;

        if (!element.TryGetProperty(propertyName, out var property))
        {
            return false;
        }

        value = property.ValueKind switch
        {
            JsonValueKind.String => property.GetString() ?? string.Empty,
            JsonValueKind.Number => property.ToString(),
            JsonValueKind.True => bool.TrueString,
            JsonValueKind.False => bool.FalseString,
            _ => string.Empty
        };

        return !string.IsNullOrWhiteSpace(value);
    }
}
