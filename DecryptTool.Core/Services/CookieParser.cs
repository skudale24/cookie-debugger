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
        if (string.IsNullOrWhiteSpace(normalized))
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

        return !string.IsNullOrWhiteSpace(NormalizeEncryptedPayloadCandidate(input));
    }

    public string NormalizeEncryptedPayloadCandidate(string input)
    {
        foreach (var candidate in GetEncryptedPayloadCandidates(input))
        {
            if (IsValidEncryptedPayload(candidate))
            {
                return candidate;
            }
        }

        return string.Empty;
    }

    private static IEnumerable<string> GetEncryptedPayloadCandidates(string input)
    {
        var trimmed = input.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            yield break;
        }

        yield return trimmed.Replace(" ", "+", StringComparison.Ordinal);

        var withoutWhitespace = string.Concat(trimmed.Where(c => !char.IsWhiteSpace(c)));
        if (!string.Equals(withoutWhitespace, trimmed, StringComparison.Ordinal))
        {
            yield return withoutWhitespace;
            yield return withoutWhitespace.Replace(" ", "+", StringComparison.Ordinal);
        }
    }

    private static bool IsValidEncryptedPayload(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate) || candidate.Length < 24)
        {
            return false;
        }

        try
        {
            var payloadBytes = Convert.FromBase64String(candidate);
            return payloadBytes.Length >= 16;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
