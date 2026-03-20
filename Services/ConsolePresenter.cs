using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using CookieDebugger.Models;
using Spectre.Console;

namespace CookieDebugger.Services;

public sealed class ConsolePresenter(DebuggerService debuggerService)
{
    public void WriteClearText(string clearText)
    {
        AnsiConsole.Write(new Rule("[cyan]Payload Decrypt[/]").LeftJustified());
        AnsiConsole.Write(CreateTextPanel(FormatTextForDisplay(clearText), "Clear Text"));
    }

    public void WriteCookieInspection(CookieDebugResult result)
    {
        var rawJwt = BuildRawJwtInspectionResult(result.DecryptedJwt, result.Report);

        AnsiConsole.Write(new Rule("[cyan]Cookie JWT[/]").LeftJustified());
        AnsiConsole.Write(CreateRawJwtPanel(rawJwt.Jwt, "Decrypted JWT"));
        AnsiConsole.Write(CreateCookieContextGrid(result));
        AnsiConsole.Write(CreateJwtStatusGrid(rawJwt.Report));
        AnsiConsole.Write(CreateClaimsTable(rawJwt.Claims));
        AnsiConsole.Write(CreateJsonGrid(rawJwt.HeaderJson, rawJwt.PayloadJson, "Header JSON", "Payload JSON"));
    }

    public void WriteHarInspection(HarDebugResult result)
    {
        AnsiConsole.Write(new Rule("[cyan]HAR Inspect[/]").LeftJustified());
        AnsiConsole.Write(CreateHarSummaryGrid(result));
        AnsiConsole.Write(CreateRawJwtPanel(result.CookieDebug.DecryptedJwt, "Cookie JWT"));

        if (string.IsNullOrWhiteSpace(result.AuthorizationJwt))
        {
            AnsiConsole.Write(CreateTextPanel("No JWT was found in the Authorization header of the request.", "Auth JWT"));
            return;
        }

        AnsiConsole.Write(CreateRawJwtPanel(result.AuthorizationJwt, "Auth JWT"));

        var authReport = new JwtInspector().Inspect(result.AuthorizationJwt);

        WriteJsonComparisonSections(
            result.CookieDebug.DecryptedJwt,
            result.AuthorizationJwt,
            debuggerService.TryDecryptClaimValue);

        WriteTokenStatusComparisonTable(result.CookieDebug.Report, authReport);
    }

    public void WriteRawJwtInspection(RawJwtInspectionResult result)
    {
        AnsiConsole.Write(new Rule("[cyan]JWT Inspect[/]").LeftJustified());
        AnsiConsole.Write(CreateRawJwtPanel(result.Jwt, "Raw JWT"));
        AnsiConsole.Write(CreateJwtStatusGrid(result.Report));
        AnsiConsole.Write(CreateClaimsTable(result.Claims));
        AnsiConsole.Write(CreateJsonGrid(result.HeaderJson, result.PayloadJson, "Header JSON", "Payload JSON"));
    }

    public void WriteRawJwtDecode(RawJwtInspectionResult result)
    {
        AnsiConsole.Write(new Rule("[cyan]JWT Decode[/]").LeftJustified());
        AnsiConsole.Write(CreateRawJwtPanel(result.Jwt, "Raw JWT"));
        AnsiConsole.Write(CreateJwtStatusGrid(result.Report));
        AnsiConsole.Write(CreateJsonGrid(result.HeaderJson, result.PayloadJson, "Header JSON", "Payload JSON"));
    }

    public void WriteJwtReadability(JwtReadabilityResult result)
    {
        var panelText = new Markup($"[bold]Can Read[/]: {(result.CanRead ? "[green]Yes[/]" : "[red]No[/]")}\n" +
                                   $"[bold]Segments[/]: {result.SegmentCount}\n" +
                                   $"[bold]Message[/]: {EscapeMarkup(result.Message)}");
        AnsiConsole.Write(new Panel(panelText)
            .Header("JWT Can Read")
            .Border(BoxBorder.Rounded)
            .Expand());
    }

    public void WriteJwtValidation(JwtValidationResult result)
    {
        var rawJwt = BuildRawJwtInspectionResult(result.Jwt, new JwtInspector().Inspect(result.Jwt));
        AnsiConsole.Write(new Rule("[cyan]JWT Validate[/]").LeftJustified());
        AnsiConsole.Write(CreateRawJwtPanel(result.Jwt, "JWT"));
        AnsiConsole.Write(CreateValidationSummaryPanel(result));

        var statusTable = new Table().Border(TableBorder.Rounded).Expand();
        statusTable.AddColumn("[cyan]Check[/]");
        statusTable.AddColumn("[cyan]Result[/]");
        statusTable.AddRow("Readable", result.CanRead ? "[green]Yes[/]" : "[red]No[/]");
        statusTable.AddRow("Signature Valid", result.SignatureValid ? "[green]Yes[/]" : "[red]No[/]");
        statusTable.AddRow("Has exp", result.HasExpiration ? "[green]Yes[/]" : "[yellow]No[/]");
        statusTable.AddRow("Expired", result.IsExpired ? "[red]Yes[/]" : "[green]No[/]");
        statusTable.AddRow("Not Yet Valid", result.IsNotYetValid ? "[yellow]Yes[/]" : "[green]No[/]");
        statusTable.AddRow("Lifetime Valid Now", result.IsLifetimeCurrentlyValid ? "[green]Yes[/]" : "[red]No[/]");
        AnsiConsole.Write(statusTable);

        var timing = new Grid();
        timing.AddColumn();
        timing.AddColumn();
        timing.AddRow(
            new Panel(new Markup($"[bold]iat[/]\n{EscapeMarkup(result.IssuedAtReadable)}")).Border(BoxBorder.Rounded),
            new Panel(new Markup($"[bold]nbf[/]\n{EscapeMarkup(result.NotBeforeReadable)}")).Border(BoxBorder.Rounded));
        timing.AddRow(
            new Panel(new Markup($"[bold]exp[/]\n{EscapeMarkup(result.ExpiresReadable)}")).Border(BoxBorder.Rounded),
            new Panel(new Markup($"[bold]Signature[/]\n{(result.SignatureValid ? "[green]Verified[/]" : "[red]Invalid[/]")}")).Border(BoxBorder.Rounded));
        AnsiConsole.Write(timing);
        AnsiConsole.Write(CreateClaimsTable(rawJwt.Claims));

        var messages = new Rows(result.Messages.Select(message => new Markup($"[grey]-[/] {EscapeMarkup(message)}")));
        AnsiConsole.Write(new Panel(messages)
            .Header("Validation Notes")
            .Border(BoxBorder.Rounded)
            .Expand());
    }

    public void WriteDecryptedPayloadValues(string jwt, Func<string, string> valueTransformer)
    {
        var decryptedPayloadJson = BuildDecryptedPayloadJson(jwt, valueTransformer);
        AnsiConsole.Write(new Rule("[cyan]Decrypted Payload Values[/]").LeftJustified());
        AnsiConsole.Write(CreateTextPanel(decryptedPayloadJson, "JWT"));
    }

    public void WriteEnvKeyNotice(string envVarName)
    {
        var body = new Markup($"[bold]Encryption key source[/]\nRead from env variable [cyan]{EscapeMarkup(envVarName)}[/]\nKey: XXXXXXX");
        AnsiConsole.Write(new Panel(body)
            .Header("Encryption Key")
            .Border(BoxBorder.Rounded));
    }

    public void WriteHeader()
    {
        Console.WriteLine("Cookie Debugger");
        Console.WriteLine("---------------");
    }

    public void WriteLastDecryptedJwt(string lastDecryptedJwt)
    {
        if (string.IsNullOrWhiteSpace(lastDecryptedJwt))
        {
            return;
        }

        Console.WriteLine();
        WriteSection("Last Decrypted JWT");
        Console.WriteLine(lastDecryptedJwt);
    }

    public void WriteSection(string title)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(title);
        Console.ResetColor();
    }

    public void WriteError(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(message);
        Console.ResetColor();
    }

    public void SafeClearScreen()
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

    private static Panel CreateRawJwtPanel(string jwt, string header)
    {
        return new Panel(new Markup(EscapeMarkup(jwt)))
            .Header(header)
            .Border(BoxBorder.Rounded)
            .Expand();
    }

    private static Grid CreateJwtStatusGrid(JwtInspectionResult report)
    {
        var overview = new Grid();
        overview.AddColumn();
        overview.AddColumn();
        overview.AddRow(
            new Panel(new Markup($"[bold]Expires[/]\n{EscapeMarkup(report.ExpiresReadable)}")).Header("exp").Border(BoxBorder.Rounded),
            new Panel(new Markup($"[bold]Remaining[/]\n{EscapeMarkup(report.RemainingTimeUntilExpiration)}")).Header("ttl").Border(BoxBorder.Rounded));
        overview.AddRow(
            new Panel(new Markup($"[bold]Issued At[/]\n{EscapeMarkup(report.IssuedAtReadable)}")).Header("iat").Border(BoxBorder.Rounded),
            new Panel(new Markup($"[bold]Expired[/]\n{(report.IsExpired ? "[red]Yes[/]" : "[green]No[/]")}")).Header("status").Border(BoxBorder.Rounded));
        return overview;
    }

    private static Table CreateClaimsTable(IReadOnlyList<KeyValuePair<string, string>> claims)
    {
        var claimsTable = new Table().Border(TableBorder.Rounded).Expand();
        claimsTable.AddColumn("[cyan]Claim[/]");
        claimsTable.AddColumn("[cyan]Value[/]");

        foreach (var claim in claims)
        {
            claimsTable.AddRow(EscapeMarkup(claim.Key), EscapeMarkup(claim.Value));
        }

        return claimsTable;
    }

    private static Grid CreateJsonGrid(string leftJson, string rightJson, string leftHeader, string rightHeader)
    {
        var jsonGrid = new Grid();
        jsonGrid.AddColumn();
        jsonGrid.AddColumn();
        jsonGrid.AddRow(
            new Panel(new Text(leftJson)).Header(leftHeader).Border(BoxBorder.Rounded).Expand(),
            new Panel(new Text(rightJson)).Header(rightHeader).Border(BoxBorder.Rounded).Expand());
        return jsonGrid;
    }

    private static Grid CreateCookieContextGrid(CookieDebugResult result)
    {
        var grid = new Grid();
        grid.AddColumn();
        grid.AddColumn();
        grid.AddRow(
            new Panel(new Markup($"[bold]Environment[/]\n{EscapeMarkup(result.Environment.ToString())}")).Border(BoxBorder.Rounded),
            new Panel(new Markup($"[bold]Fingerprint[/]\n{EscapeMarkup(result.Fingerprint)}")).Border(BoxBorder.Rounded));
        return grid;
    }

    private static Grid CreateHarSummaryGrid(HarDebugResult result)
    {
        var grid = new Grid();
        grid.AddColumn();
        grid.AddColumn();
        grid.AddRow(
            new Panel(new Markup($"[bold]HAR File[/]\n{EscapeMarkup(result.HarFilePath)}")).Border(BoxBorder.Rounded),
            new Panel(new Markup($"[bold]Encrypted ClientID[/]\n{EscapeMarkup(result.EncryptedFingerprint)}")).Border(BoxBorder.Rounded));
        grid.AddRow(
            new Panel(new Markup($"[bold]Fingerprint[/]\n{EscapeMarkup(result.CookieDebug.Fingerprint)}")).Border(BoxBorder.Rounded),
            new Panel(new Markup("[bold]Cookie Source[/]\nEncrypted cookie string extracted from encinfo.")).Border(BoxBorder.Rounded));
        return grid;
    }

    private static Panel CreateTextPanel(string text, string header)
    {
        return new Panel(new Text(text))
            .Header(header)
            .Border(BoxBorder.Rounded)
            .Expand();
    }

    private static Panel CreateValidationSummaryPanel(JwtValidationResult result)
    {
        var statusMarkup = result.SignatureValid && result.IsLifetimeCurrentlyValid
            ? "[green]"
            : result.SignatureValid
                ? "[yellow]"
                : "[red]";

        var body = new Markup($"{statusMarkup}[bold]{EscapeMarkup(result.OverallStatus)}[/][/]");
        return new Panel(body)
            .Header("Overall Result")
            .Border(BoxBorder.Rounded)
            .Expand();
    }

    private static string EscapeMarkup(string value)
    {
        return Markup.Escape(value ?? string.Empty);
    }

    private static string FormatTextForDisplay(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim();
        if (!LooksLikeJson(trimmed))
        {
            return trimmed;
        }

        try
        {
            using var document = JsonDocument.Parse(trimmed);
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Indented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            }))
            {
                document.RootElement.WriteTo(writer);
            }

            return Encoding.UTF8.GetString(stream.ToArray());
        }
        catch (JsonException)
        {
            return trimmed;
        }
    }

    private static bool LooksLikeJson(string value)
    {
        return (value.StartsWith("{", StringComparison.Ordinal) && value.EndsWith("}", StringComparison.Ordinal)) ||
               (value.StartsWith("[", StringComparison.Ordinal) && value.EndsWith("]", StringComparison.Ordinal));
    }

    private static RawJwtInspectionResult BuildRawJwtInspectionResult(string jwt, JwtInspectionResult report)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
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
            Report = report
        };
    }

    private void WriteJsonComparisonSections(string cookieJwt, string authJwt, Func<string, string> authValueTransformer)
    {
        var cookieHeaderJson = GetJwtHeaderJson(cookieJwt);
        var authHeaderJson = GetJwtHeaderJson(authJwt);
        var cookieRawPayloadJson = GetJwtPayloadJson(cookieJwt);
        var authRawPayloadJson = GetJwtPayloadJson(authJwt);
        var cookieDecryptedPayloadJson = BuildDecryptedPayloadJson(cookieJwt, null);
        var authDecryptedPayloadJson = BuildDecryptedPayloadJson(authJwt, authValueTransformer);

        AnsiConsole.Write(new Rule("[cyan]Header JSON[/]").LeftJustified());
        AnsiConsole.Write(CreateJsonGrid(cookieHeaderJson, authHeaderJson, "Cookie JWT", "Auth JWT"));
        AnsiConsole.Write(new Rule("[cyan]Raw Payload JSON[/]").LeftJustified());
        AnsiConsole.Write(CreateJsonGrid(cookieRawPayloadJson, authRawPayloadJson, "Cookie JWT", "Auth JWT"));
        AnsiConsole.Write(new Rule("[cyan]Decrypted Payload Values[/]").LeftJustified());
        AnsiConsole.Write(CreateJsonGrid(cookieDecryptedPayloadJson, authDecryptedPayloadJson, "Cookie JWT", "Auth JWT"));
    }

    private void WriteTokenStatusComparisonTable(JwtInspectionResult cookieReport, JwtInspectionResult authReport)
    {
        var cookieJson = BuildTokenStatusJson(cookieReport);
        var authJson = BuildTokenStatusJson(authReport);
        AnsiConsole.Write(new Rule("[cyan]Token Status[/]").LeftJustified());
        AnsiConsole.Write(CreateJsonGrid(cookieJson, authJson, "Cookie JWT", "Auth JWT"));
    }

    private static string GetJwtHeaderJson(string jwt)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
        return SerializeJsonObject(token.Header);
    }

    private static string GetJwtPayloadJson(string jwt)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
        return SerializeJsonObject(token.Payload);
    }

    private static string BuildDecryptedPayloadJson(string jwt, Func<string, string>? valueTransformer)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
        var payload = token.Payload.ToDictionary(
            pair => pair.Key,
            pair => TransformJwtValue(pair.Value, valueTransformer),
            StringComparer.Ordinal);

        return SerializeIndentedJson(payload);
    }

    private static string BuildTokenStatusJson(JwtInspectionResult report)
    {
        var payload = new Dictionary<string, object?>
        {
            ["expReadable"] = report.ExpiresReadable,
            ["remainingTimeUntilExpiration"] = report.RemainingTimeUntilExpiration,
            ["isExpired"] = report.IsExpired
        };

        return SerializeIndentedJson(payload);
    }

    private static object? TransformJwtValue(object? value, Func<string, string>? valueTransformer)
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

    private static object? TransformJsonElement(JsonElement element, Func<string, string> valueTransformer)
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

    private static string SerializeJsonObject(IEnumerable<KeyValuePair<string, object>> values)
    {
        var dictionary = values.ToDictionary(
            pair => pair.Key,
            pair => NormalizeJwtValue(pair.Value),
            StringComparer.Ordinal);

        return SerializeIndentedJson(dictionary);
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

    private static string SerializeIndentedJson(IReadOnlyDictionary<string, object?> values)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Indented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }))
        {
            WriteJsonObject(writer, values);
        }

        return Encoding.UTF8.GetString(stream.ToArray());
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
