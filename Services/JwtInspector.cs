using System.IdentityModel.Tokens.Jwt;
using CookieDebugger.Models;

namespace CookieDebugger.Services;

public sealed class JwtInspector
{
    public JwtInspectionResult Inspect(string jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
        {
            throw new ArgumentException("Decrypted JWT is empty.");
        }

        JwtSecurityToken token;
        try
        {
            token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
        }
        catch (Exception ex)
        {
            throw new ArgumentException($"Decrypted value is not a valid JWT. {ex.Message}", ex);
        }

        var payloadLines = token.Claims
            .Select(claim => $"{claim.Type}: {claim.Value}")
            .ToList();

        if (payloadLines.Count == 0)
        {
            payloadLines = token.Payload
                .Select(kvp => $"{kvp.Key}: {kvp.Value}")
                .ToList();
        }

        if (payloadLines.Count == 0)
        {
            payloadLines.Add("No payload values found.");
        }

        var issuedAt = ReadUnixTimeClaim(token, JwtRegisteredClaimNames.Iat);
        var notBefore = ReadUnixTimeClaim(token, JwtRegisteredClaimNames.Nbf);
        var expires = ReadUnixTimeClaim(token, JwtRegisteredClaimNames.Exp);

        var lifetime = issuedAt.HasValue && expires.HasValue
            ? FormatDuration(expires.Value - issuedAt.Value)
            : "Unknown";

        var remaining = expires.HasValue
            ? FormatRemaining(expires.Value - DateTimeOffset.UtcNow)
            : "Unknown";

        return new JwtInspectionResult
        {
            PayloadLines = payloadLines,
            IssuedAtReadable = FormatDate(issuedAt),
            NotBeforeReadable = FormatDate(notBefore),
            ExpiresReadable = FormatDate(expires),
            TokenLifetime = lifetime,
            RemainingTimeUntilExpiration = remaining,
            IsExpired = expires.HasValue && expires.Value <= DateTimeOffset.UtcNow
        };
    }

    private static DateTimeOffset? ReadUnixTimeClaim(JwtSecurityToken token, string claimType)
    {
        var rawValue = token.Claims.FirstOrDefault(claim => claim.Type == claimType)?.Value;
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return null;
        }

        return long.TryParse(rawValue, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }

    private static string FormatDate(DateTimeOffset? value)
    {
        return value?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz") ?? "Not present";
    }

    private static string FormatDuration(TimeSpan duration)
    {
        var absolute = duration.Duration();
        var sign = duration < TimeSpan.Zero ? "-" : string.Empty;
        return $"{sign}{absolute.Days}d {absolute.Hours}h {absolute.Minutes}m {absolute.Seconds}s";
    }

    private static string FormatRemaining(TimeSpan remaining)
    {
        return remaining < TimeSpan.Zero
            ? $"Expired {FormatDuration(remaining)} ago"
            : FormatDuration(remaining);
    }
}
