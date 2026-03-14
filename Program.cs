using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text;
using System.Text.Json;
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
            var encryptedText = PromptRequired("Paste Encrypted Request/Response");
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
                WriteSection("JWT Comparison");
                if (string.IsNullOrWhiteSpace(authorizationJwt))
                {
                    Console.WriteLine("No JWT was found in the Authorization header of the request.");
                }
                else
                {
                    var authReport = jwtInspector.Inspect(authorizationJwt);

                    WriteJsonComparisonSections(
                        decryptedJwt,
                        authorizationJwt,
                        rawValue => TryDecryptClaimValue(rawValue, fingerprintDecryptor, settings.FingerprintDecryption.Key, settings.FingerprintDecryption.IV));
                    Console.WriteLine();
                    WriteTokenStatusComparisonTable(report, authReport);
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
        Console.WriteLine("3. Paste Encrypted Request/Response");
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

static void WriteJsonComparisonSections(string cookieJwt, string authJwt, Func<string, string> authValueTransformer)
{
    var cookieHeaderJson = GetJwtHeaderJson(cookieJwt);
    var authHeaderJson = GetJwtHeaderJson(authJwt);
    var cookieRawPayloadJson = GetJwtPayloadJson(cookieJwt);
    var authRawPayloadJson = GetJwtPayloadJson(authJwt);
    var cookieDecryptedPayloadJson = BuildDecryptedPayloadJson(cookieJwt, null);
    var authDecryptedPayloadJson = BuildDecryptedPayloadJson(authJwt, authValueTransformer);

    WriteTwoColumnTextTable("Header JSON", "Cookie JWT", cookieHeaderJson, "Auth JWT", authHeaderJson);
    Console.WriteLine();
    WriteTwoColumnTextTable("Raw Payload JSON", "Cookie JWT", cookieRawPayloadJson, "Auth JWT", authRawPayloadJson);
    Console.WriteLine();
    WriteTwoColumnTextTable("Decrypted Payload Values", "Cookie JWT", cookieDecryptedPayloadJson, "Auth JWT", authDecryptedPayloadJson);
}

static void WriteTokenStatusComparisonTable(JwtInspectionResult cookieReport, JwtInspectionResult authReport)
{
    var cookieJson = BuildTokenStatusJson(cookieReport);
    var authJson = BuildTokenStatusJson(authReport);
    WriteTwoColumnTextTable("Token Status", "Cookie JWT", cookieJson, "Auth JWT", authJson);
}

static string GetJwtHeaderJson(string jwt)
{
    var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
    return SerializeJsonObject(token.Header);
}

static string GetJwtPayloadJson(string jwt)
{
    var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
    return SerializeJsonObject(token.Payload);
}

static string BuildDecryptedPayloadJson(string jwt, Func<string, string>? valueTransformer)
{
    var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
    var payload = token.Payload.ToDictionary(
        pair => pair.Key,
        pair => TransformJwtValue(pair.Value, valueTransformer),
        StringComparer.Ordinal);

    return JsonSerializer.Serialize(payload, CreatePrettyJsonOptions());
}

static string BuildTokenStatusJson(JwtInspectionResult report)
{
    var payload = new Dictionary<string, object?>
    {
        ["expReadable"] = report.ExpiresReadable,
        ["remainingTimeUntilExpiration"] = report.RemainingTimeUntilExpiration,
        ["isExpired"] = report.IsExpired
    };

    return JsonSerializer.Serialize(payload, CreatePrettyJsonOptions());
}

static object? TransformJwtValue(object? value, Func<string, string>? valueTransformer)
{
    if (valueTransformer is null || value is null)
    {
        return value;
    }

    return value switch
    {
        string stringValue => valueTransformer(stringValue),
        JsonElement jsonElement => TransformJsonElement(jsonElement, valueTransformer),
        IEnumerable<object?> enumerable => enumerable.Select(item => TransformJwtValue(item, valueTransformer)).ToList(),
        _ => value
    };
}

static object? TransformJsonElement(JsonElement element, Func<string, string> valueTransformer)
{
    return element.ValueKind switch
    {
        JsonValueKind.String => valueTransformer(element.GetString() ?? string.Empty),
        JsonValueKind.Array => element.EnumerateArray().Select(item => TransformJsonElement(item, valueTransformer)).ToList(),
        JsonValueKind.Object => element.EnumerateObject().ToDictionary(
            property => property.Name,
            property => TransformJsonElement(property.Value, valueTransformer),
            StringComparer.Ordinal),
        JsonValueKind.Number => element.ToString(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        _ => element.ToString()
    };
}

static string SerializeJsonObject(IEnumerable<KeyValuePair<string, object>> values)
{
    var dictionary = values.ToDictionary(
        pair => pair.Key,
        pair => NormalizeJwtValue(pair.Value),
        StringComparer.Ordinal);

    return JsonSerializer.Serialize(dictionary, CreatePrettyJsonOptions());
}

static object? NormalizeJwtValue(object? value)
{
    return value switch
    {
        null => null,
        JsonElement jsonElement => NormalizeJsonElement(jsonElement),
        IEnumerable<object?> enumerable => enumerable.Select(NormalizeJwtValue).ToList(),
        _ => value
    };
}

static object? NormalizeJsonElement(JsonElement element)
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

static void WriteTwoColumnTextTable(string title, string leftHeader, string leftValue, string rightHeader, string rightValue)
{
    var totalWidth = GetTableWidth();
    var innerWidth = totalWidth - 3;
    var columnWidth = (innerWidth - 3) / 2;
    var leftLines = WrapText(leftValue, columnWidth);
    var rightLines = WrapText(rightValue, columnWidth);
    var rowCount = Math.Max(leftLines.Count, rightLines.Count);

    Console.WriteLine(title);
    Console.WriteLine(BuildSeparator(columnWidth, columnWidth));
    Console.WriteLine(BuildTwoColumnRow(leftHeader, columnWidth, rightHeader, columnWidth));
    Console.WriteLine(BuildSeparator(columnWidth, columnWidth));

    for (var i = 0; i < rowCount; i++)
    {
        var left = i < leftLines.Count ? leftLines[i] : string.Empty;
        var right = i < rightLines.Count ? rightLines[i] : string.Empty;
        Console.WriteLine(BuildTwoColumnRow(left, columnWidth, right, columnWidth));
    }

    Console.WriteLine(BuildSeparator(columnWidth, columnWidth));
}

static string BuildTwoColumnRow(string first, int firstWidth, string second, int secondWidth)
{
    return $"| {Pad(first, firstWidth)} | {Pad(second, secondWidth)} |";
}

static string Pad(string value, int width)
{
    return value.Length >= width ? value[..width] : value.PadRight(width);
}

static JsonSerializerOptions CreatePrettyJsonOptions()
{
    return new JsonSerializerOptions
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
}

enum CookieInputType
{
    EncryptedCookie = 1,
    HarFile = 2,
    DecryptedRequestResponse = 3
}
