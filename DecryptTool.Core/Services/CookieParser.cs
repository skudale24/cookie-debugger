using System.Net;

namespace CookieDebugger.Services;

public sealed class CookieParser
{
    private const string Delimiter = "|#**#|";

    public string ExtractEncryptedJwt(string cookieString)
    {
        if (string.IsNullOrWhiteSpace(cookieString))
        {
            throw new ArgumentException("Cookie string cannot be empty.");
        }

        var decoded = WebUtility.UrlDecode(cookieString);
        var workingValue = decoded.Contains(Delimiter, StringComparison.Ordinal) ? decoded : cookieString;

        var segments = workingValue.Split(Delimiter, StringSplitOptions.None);
        if (segments.Length >= 2)
        {
            var encryptedJwt = segments[0].Trim().Replace(" ", "+", StringComparison.Ordinal);
            if (string.IsNullOrWhiteSpace(encryptedJwt))
            {
                throw new ArgumentException("Encrypted JWT portion was empty after parsing the cookie string.");
            }

            return encryptedJwt;
        }

        var normalized = NormalizeEncryptedPayloadCandidate(decoded);
        if (!LooksLikeEncryptedPayload(normalized))
        {
            throw new ArgumentException(
                $"Cookie string does not contain the expected delimiter '{Delimiter}' and is not a recognized encrypted payload.");
        }

        return normalized;
    }

    public bool LooksLikeEncryptedPayload(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var normalized = NormalizeEncryptedPayloadCandidate(input);
        if (string.IsNullOrWhiteSpace(normalized) || normalized.Length <= 24)
        {
            return false;
        }

        try
        {
            var payloadBytes = Convert.FromBase64String(normalized);
            return payloadBytes.Length > 16;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string NormalizeEncryptedPayloadCandidate(string input)
    {
        return input.Trim().Replace(" ", "+", StringComparison.Ordinal);
    }
}
