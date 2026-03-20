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
    private readonly SecretResolver _secretResolver;

    public AutoDetectCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter, SecretResolver secretResolver)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
        _secretResolver = secretResolver;
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

            if (_debuggerService.LooksLikeEncryptedPayload(normalizedInput))
            {
                var clearText = _debuggerService.DecryptPayload(normalizedInput);
                _consolePresenter.WriteClearText(clearText);
                return 0;
            }

            var fingerprint = _secretResolver.ResolveCookieFingerprint(settings.Fingerprint);
            var cookieResult = InspectCookieWithRetry(normalizedInput, fingerprint, settings.Environment);
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

    private CookieDebugResult InspectCookieWithRetry(string cookie, string fingerprint, AppEnvironment environment)
    {
        try
        {
            return _debuggerService.InspectCookie(cookie, fingerprint, environment);
        }
        catch (CryptographicException)
        {
            var promptedFingerprint = _secretResolver.ResolveCookieFingerprint(forcePrompt: true);
            return _debuggerService.InspectCookie(cookie, promptedFingerprint, environment);
        }
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
