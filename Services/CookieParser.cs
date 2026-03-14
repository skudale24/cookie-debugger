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
        if (segments.Length < 2)
        {
            throw new ArgumentException($"Cookie string does not contain the expected delimiter '{Delimiter}'.");
        }

        var encryptedJwt = segments[0].Trim().Replace(" ", "+", StringComparison.Ordinal);
        if (string.IsNullOrWhiteSpace(encryptedJwt))
        {
            throw new ArgumentException("Encrypted JWT portion was empty after parsing the cookie string.");
        }

        return encryptedJwt;
    }
}
