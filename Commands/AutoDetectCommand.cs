using System.Security.Cryptography;
using CookieDebugger.Models;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class AutoDetectCommand : Command<AutoDetectSettings>
{
    private readonly DebuggerService _debuggerService;
    private readonly ConsolePresenter _consolePresenter;

    public AutoDetectCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
    }

    public override int Execute(CommandContext context, AutoDetectSettings settings)
    {
        try
        {
            var normalizedInput = DebuggerService.NormalizeDroppedPath(settings.Input);
            if (IsHarInput(normalizedInput))
            {
                var harResult = _debuggerService.InspectHar(normalizedInput, settings.Environment);
                _consolePresenter.WriteHarInspection(harResult);
                return 0;
            }

            var readability = _debuggerService.CanReadJwt(normalizedInput);
            if (readability.CanRead)
            {
                var jwtResult = _debuggerService.InspectRawJwt(normalizedInput);
                _consolePresenter.WriteRawJwtInspection(jwtResult);
                return 0;
            }

            if (string.IsNullOrWhiteSpace(settings.Fingerprint))
            {
                return WriteCookieFingerprintError();
            }

            var cookieResult = _debuggerService.InspectCookie(normalizedInput, settings.Fingerprint, settings.Environment);
            _consolePresenter.WriteCookieInspection(cookieResult);
            return 0;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or FormatException or CryptographicException)
        {
            _consolePresenter.WriteError(ex is CryptographicException
                ? $"Unable to process the value. {ex.Message}"
                : ex.Message);
            return -1;
        }
    }

    private int WriteCookieFingerprintError()
    {
        _consolePresenter.WriteError("The input was not recognized as a JWT or HAR file. To treat it as an encrypted cookie, provide --fp and optionally --env.");
        return -1;
    }

    private static bool IsHarInput(string input)
    {
        return !string.IsNullOrWhiteSpace(input) &&
               File.Exists(input) &&
               Path.GetExtension(input).Equals(".har", StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class AutoDetectSettings : CommandSettings
{
    [CommandArgument(0, "<input>")]
    public string Input { get; init; } = string.Empty;

    [CommandOption("--fp|--fingerprint <FINGERPRINT>")]
    public string Fingerprint { get; init; } = string.Empty;

    [CommandOption("--env|--environment <ENVIRONMENT>")]
    public AppEnvironment Environment { get; init; } = AppEnvironment.Dev;

    public override ValidationResult Validate()
    {
        return string.IsNullOrWhiteSpace(Input)
            ? ValidationResult.Error("An input value is required.")
            : ValidationResult.Success();
    }
}
