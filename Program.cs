using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using CookieDebugger.Models;
using CookieDebugger.Services;
using CookieDebugger.State;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);

builder.Services.Configure<AppSettings>(builder.Configuration);
builder.Services.AddSingleton<CookieParser>();
builder.Services.AddSingleton<HarFileParser>();
builder.Services.AddSingleton<FingerprintDecryptor>();
builder.Services.AddSingleton<JwtDecryptor>();
builder.Services.AddSingleton<JwtInspector>();
builder.Services.AddSingleton<UserStateStore>();

using var host = builder.Build();

var configuration = host.Services.GetRequiredService<IConfiguration>();
var settings = configuration.Get<AppSettings>() ?? new AppSettings();
var stateStore = host.Services.GetRequiredService<UserStateStore>();
var cookieParser = host.Services.GetRequiredService<CookieParser>();
var harFileParser = host.Services.GetRequiredService<HarFileParser>();
var fingerprintDecryptor = host.Services.GetRequiredService<FingerprintDecryptor>();
var jwtDecryptor = host.Services.GetRequiredService<JwtDecryptor>();
var jwtInspector = host.Services.GetRequiredService<JwtInspector>();

if (settings.PassPhrases is null ||
    string.IsNullOrWhiteSpace(settings.PassPhrases.Dev) ||
    string.IsNullOrWhiteSpace(settings.PassPhrases.Stage) ||
    string.IsNullOrWhiteSpace(settings.PassPhrases.Production))
{
    WriteError("appsettings.json is missing one or more pass phrases.");
    return;
}

if (settings.FingerprintDecryption is null ||
    string.IsNullOrWhiteSpace(settings.FingerprintDecryption.Key) ||
    string.IsNullOrWhiteSpace(settings.FingerprintDecryption.IV))
{
    WriteError("appsettings.json is missing the fingerprint decryption key or IV.");
    return;
}

var state = await stateStore.LoadAsync();

while (true)
{
    SafeClearScreen();
    Console.WriteLine("Cookie Debugger");
    Console.WriteLine("---------------");

    if (!string.IsNullOrWhiteSpace(state.LastDecryptedJwt))
    {
        Console.WriteLine();
        WriteSection("Last Decrypted JWT");
        Console.WriteLine(state.LastDecryptedJwt);
    }

    try
    {
        var inputType = PromptForInputType();

        if (inputType == CookieInputType.DecryptedRequestResponse)
        {
            var encryptedText = PromptRequired("Paste Decrypted Request/Response");
            var clearText = fingerprintDecryptor.Decrypt(
                encryptedText,
                settings.FingerprintDecryption.Key,
                settings.FingerprintDecryption.IV);

            Console.WriteLine();
            WriteSection("Clear Text");
            Console.WriteLine(clearText);
        }
        else
        {
            var environment = PromptForEnvironment();
            var baselinePassPhrase = environment switch
            {
                AppEnvironment.Dev => settings.PassPhrases.Dev,
                AppEnvironment.Stage => settings.PassPhrases.Stage,
                AppEnvironment.Production => settings.PassPhrases.Production,
                _ => throw new InvalidOperationException("Unsupported environment selected.")
            };

            string fingerprint;
            string cookieString;
            string authorizationJwt = string.Empty;
            var isHarInput = inputType == CookieInputType.HarFile;

            if (inputType == CookieInputType.EncryptedCookie)
            {
                fingerprint = PromptWithDefault("Fingerprint", state.LastFingerprint);
                if (string.IsNullOrWhiteSpace(fingerprint))
                {
                    throw new ArgumentException("Fingerprint is required.");
                }

                cookieString = PromptWithDefault("Encrypted Cookie String", state.LastEncryptedCookie);
                if (string.IsNullOrWhiteSpace(cookieString))
                {
                    throw new ArgumentException("Encrypted cookie string is required.");
                }
            }
            else
            {
                var harFilePath = PromptForHarFilePath(state.LastHarFilePath);
                if (string.IsNullOrWhiteSpace(harFilePath))
                {
                    throw new ArgumentException("HAR file path is required.");
                }

                var harExtraction = harFileParser.Extract(harFilePath);
                fingerprint = fingerprintDecryptor.Decrypt(
                    harExtraction.EncryptedFingerprint,
                    settings.FingerprintDecryption.Key,
                    settings.FingerprintDecryption.IV);

                state.LastHarFilePath = harFilePath;
                cookieString = harExtraction.CookieString;
                authorizationJwt = harExtraction.AuthorizationJwt;

                Console.WriteLine();
                WriteSection("Cookie Extraction");
                Console.WriteLine($"Encrypted ClientID: {harExtraction.EncryptedFingerprint}");
                Console.WriteLine($"Fingerprint: {fingerprint}");
                Console.WriteLine("Encrypted cookie string extracted from encinfo.");
            }

            state.LastFingerprint = fingerprint;
            state.LastEncryptedCookie = cookieString;
            await stateStore.SaveAsync(state);

            var encryptedJwt = cookieParser.ExtractEncryptedJwt(cookieString);
            var decryptedJwt = jwtDecryptor.Decrypt(encryptedJwt, fingerprint, baselinePassPhrase);
            state.LastDecryptedJwt = decryptedJwt;
            await stateStore.SaveAsync(state);

            var report = jwtInspector.Inspect(decryptedJwt);

            if (isHarInput)
            {
                Console.WriteLine();
                WriteSection("Cookie JWT");
                Console.WriteLine(decryptedJwt);

                Console.WriteLine();
                WriteSection("Auth JWT");
                if (string.IsNullOrWhiteSpace(authorizationJwt))
                {
                    Console.WriteLine("No JWT was found in the Authorization header of the request.");
                }
                else
                {
                    Console.WriteLine(authorizationJwt);
                }

                Console.WriteLine();
                WriteSection("JWT Claim Comparison");
                if (string.IsNullOrWhiteSpace(authorizationJwt))
                {
                    Console.WriteLine("No JWT was found in the Authorization header of the request.");
                }
                else
                {
                    WriteClaimsComparisonTable(
                        decryptedJwt,
                        authorizationJwt,
                        rawValue => TryDecryptClaimValue(rawValue, fingerprintDecryptor, settings.FingerprintDecryption.Key, settings.FingerprintDecryption.IV));
                }
            }
            else
            {
                Console.WriteLine();
                WriteSection("Decrypted JWT");
                Console.WriteLine(decryptedJwt);

                Console.WriteLine();
                WriteSection("JWT Payload");
                foreach (var line in report.PayloadLines)
                {
                    Console.WriteLine(line);
                }

                Console.WriteLine();
                WriteSection("iat (Readable)");
                Console.WriteLine(report.IssuedAtReadable);

                Console.WriteLine();
                WriteSection("nbf (Readable)");
                Console.WriteLine(report.NotBeforeReadable);

                Console.WriteLine();
                WriteSection("exp (Readable)");
                Console.WriteLine(report.ExpiresReadable);

                Console.WriteLine();
                WriteSection("Token Lifetime");
                Console.WriteLine(report.TokenLifetime);

                Console.WriteLine();
                WriteSection("Remaining Time Until Expiration");
                Console.WriteLine(report.RemainingTimeUntilExpiration);

                Console.WriteLine();
                WriteSection("Is Expired");
                Console.WriteLine(report.IsExpired ? "Yes" : "No");
            }
        }
    }
    catch (FormatException ex)
    {
        WriteError(ex.Message);
    }
    catch (CryptographicException ex)
    {
        WriteError($"Unable to decrypt the value. {ex.Message}");
    }
    catch (ArgumentException ex)
    {
        WriteError(ex.Message);
    }
    catch (Exception ex)
    {
        WriteError($"Unexpected error: {ex.Message}");
    }

    if (!PromptForAnotherSession())
    {
        break;
    }
}

return;

static CookieInputType PromptForInputType()
{
    while (true)
    {
        Console.WriteLine();
        Console.WriteLine("Choose input type");
        Console.WriteLine("1. Paste encrypted cookie");
        Console.WriteLine("2. Load HAR file");
        Console.WriteLine("3. Paste Decrypted Request/Response");
        Console.Write("Choice [1]: ");

        var input = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(input) || input == "1")
        {
            return CookieInputType.EncryptedCookie;
        }

        if (input == "2")
        {
            return CookieInputType.HarFile;
        }

        if (input == "3")
        {
            return CookieInputType.DecryptedRequestResponse;
        }

        WriteError("Please choose 1, 2, or 3.");
    }
}

static AppEnvironment PromptForEnvironment()
{
    while (true)
    {
        Console.WriteLine();
        Console.WriteLine("Select environment:");
        Console.WriteLine("1. Dev");
        Console.WriteLine("2. Stage");
        Console.WriteLine("3. Production");
        Console.Write("Choice [1]: ");

        var input = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(input) || input == "1" || input?.Equals("Dev", StringComparison.OrdinalIgnoreCase) == true)
        {
            return AppEnvironment.Dev;
        }

        if (input == "2" || input?.Equals("Stage", StringComparison.OrdinalIgnoreCase) == true)
        {
            return AppEnvironment.Stage;
        }

        if (input == "3" || input?.Equals("Production", StringComparison.OrdinalIgnoreCase) == true)
        {
            return AppEnvironment.Production;
        }

        WriteError("Please choose Dev, Stage, or Production.");
    }
}

static string PromptForHarFilePath(string? defaultValue)
{
    Console.WriteLine();
    Console.WriteLine("Drag HAR file here or paste path:");
    Console.WriteLine();
    Console.WriteLine("Example:");
    Console.WriteLine(@"C:\Users\siddharth\Downloads\session.har");

    var prompt = string.IsNullOrWhiteSpace(defaultValue)
        ? "HAR file path: "
        : $"HAR file path [{defaultValue}]: ";

    Console.Write(prompt);
    var input = Console.ReadLine();

    if (string.IsNullOrWhiteSpace(input))
    {
        return defaultValue ?? string.Empty;
    }

    return NormalizeDroppedPath(input) ?? string.Empty;
}

static string? NormalizeDroppedPath(string? input)
{
    if (string.IsNullOrWhiteSpace(input))
    {
        return null;
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

static string PromptWithDefault(string label, string? defaultValue)
{
    var prompt = string.IsNullOrWhiteSpace(defaultValue)
        ? $"{label}: "
        : $"{label} [{defaultValue}]: ";

    Console.Write(prompt);
    var input = Console.ReadLine();

    if (string.IsNullOrWhiteSpace(input))
    {
        return defaultValue ?? string.Empty;
    }

    return input.Trim();
}

static string PromptRequired(string label)
{
    Console.Write($"{label}: ");
    var input = Console.ReadLine()?.Trim();
    if (string.IsNullOrWhiteSpace(input))
    {
        throw new ArgumentException($"{label} is required.");
    }

    return input;
}

static bool PromptForAnotherSession()
{
    Console.WriteLine();
    Console.Write("Press Enter to process another session, or type X to exit: ");
    var input = Console.ReadLine()?.Trim();
    return !string.Equals(input, "X", StringComparison.OrdinalIgnoreCase);
}

static void SafeClearScreen()
{
    try
    {
        if (!Console.IsOutputRedirected)
        {
            Console.Clear();
            return;
        }
    }
    catch (IOException)
    {
    }
    catch (InvalidOperationException)
    {
    }

    Console.WriteLine();
    Console.WriteLine(new string('=', 60));
    Console.WriteLine();
}

static void WriteSection(string title)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(title);
    Console.ResetColor();
}

static void WriteError(string message)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine(message);
    Console.ResetColor();
}

static void WriteClaimsComparisonTable(string cookieJwt, string authJwt, Func<string, string> authValueTransformer)
{
    var cookieClaims = ReadJwtClaims(cookieJwt);
    var authClaims = ReadJwtClaims(authJwt, authValueTransformer);
    var claimNames = cookieClaims.Keys
        .Union(authClaims.Keys, StringComparer.Ordinal)
        .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
        .ToList();

    var totalWidth = GetTableWidth();
    var innerWidth = totalWidth - 4;
    var claimWidth = Math.Max(12, Math.Min(24, innerWidth / 5));
    var valueWidth = (innerWidth - claimWidth - 4) / 2;

    Console.WriteLine(BuildSeparator(claimWidth, valueWidth, valueWidth));
    Console.WriteLine(BuildThreeColumnRow("Claim", claimWidth, "Cookie JWT", valueWidth, "Auth JWT", valueWidth));
    Console.WriteLine(BuildSeparator(claimWidth, valueWidth, valueWidth));

    foreach (var claimName in claimNames)
    {
        var leftValue = cookieClaims.TryGetValue(claimName, out var cookieValue) ? cookieValue : string.Empty;
        var rightValue = authClaims.TryGetValue(claimName, out var authValue) ? authValue : string.Empty;

        var claimLines = WrapText(claimName, claimWidth);
        var leftLines = WrapText(leftValue, valueWidth);
        var rightLines = WrapText(rightValue, valueWidth);
        var rowCount = Math.Max(claimLines.Count, Math.Max(leftLines.Count, rightLines.Count));

        for (var i = 0; i < rowCount; i++)
        {
            var claim = i < claimLines.Count ? claimLines[i] : string.Empty;
            var left = i < leftLines.Count ? leftLines[i] : string.Empty;
            var right = i < rightLines.Count ? rightLines[i] : string.Empty;
            Console.WriteLine(BuildThreeColumnRow(claim, claimWidth, left, valueWidth, right, valueWidth));
        }

        Console.WriteLine(BuildSeparator(claimWidth, valueWidth, valueWidth));
    }
}

static Dictionary<string, string> ReadJwtClaims(string jwt, Func<string, string>? valueTransformer = null)
{
    var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
    return token.Claims
        .GroupBy(claim => claim.Type, StringComparer.Ordinal)
        .ToDictionary(
            group => group.Key,
            group => string.Join(" | ", group.Select(claim => valueTransformer is null ? claim.Value : valueTransformer(claim.Value))),
            StringComparer.Ordinal);
}

static string TryDecryptClaimValue(string rawValue, FingerprintDecryptor decryptor, string key, string iv)
{
    if (string.IsNullOrWhiteSpace(rawValue))
    {
        return rawValue;
    }

    try
    {
        return decryptor.Decrypt(rawValue, key, iv);
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

static int GetTableWidth()
{
    try
    {
        return Math.Clamp(Console.WindowWidth > 0 ? Console.WindowWidth - 1 : 140, 100, 180);
    }
    catch
    {
        return 140;
    }
}

static List<string> WrapText(string value, int width)
{
    if (string.IsNullOrEmpty(value))
    {
        return new List<string> { string.Empty };
    }

    var normalized = value.Replace("\r", string.Empty);
    var lines = new List<string>();

    foreach (var paragraph in normalized.Split('\n'))
    {
        if (string.IsNullOrEmpty(paragraph))
        {
            lines.Add(string.Empty);
            continue;
        }

        var remaining = paragraph;
        while (remaining.Length > width)
        {
            lines.Add(remaining[..width]);
            remaining = remaining[width..];
        }

        lines.Add(remaining);
    }

    return lines;
}

static string BuildSeparator(params int[] widths)
{
    return "+" + string.Join("+", widths.Select(width => new string('-', width + 2))) + "+";
}

static string BuildThreeColumnRow(string first, int firstWidth, string second, int secondWidth, string third, int thirdWidth)
{
    return $"| {Pad(first, firstWidth)} | {Pad(second, secondWidth)} | {Pad(third, thirdWidth)} |";
}

static string Pad(string value, int width)
{
    return value.Length >= width ? value[..width] : value.PadRight(width);
}

enum CookieInputType
{
    EncryptedCookie = 1,
    HarFile = 2,
    DecryptedRequestResponse = 3
}
