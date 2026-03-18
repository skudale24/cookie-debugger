using System.Security.Cryptography;
using CookieDebugger.Models;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class JwtCookieCommand : Command<JwtCookieSettings>
{
    private readonly DebuggerService _debuggerService;
    private readonly ConsolePresenter _consolePresenter;

    public JwtCookieCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
    }

    public override int Execute(CommandContext context, JwtCookieSettings settings)
    {
        try
        {
            var result = _debuggerService.InspectCookie(settings.Cookie, settings.Fingerprint, settings.Environment);
            _consolePresenter.WriteCookieInspection(result);
            return 0;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or FormatException or CryptographicException)
        {
            _consolePresenter.WriteError(ex is CryptographicException
                ? $"Unable to decrypt the value. {ex.Message}"
                : ex.Message);
            return -1;
        }
    }
}

public sealed class JwtCookieSettings : CommandSettings
{
    [CommandOption("-c|--cookie <COOKIE>")]
    public string Cookie { get; init; } = string.Empty;

    [CommandOption("-f|--fingerprint <FINGERPRINT>")]
    public string Fingerprint { get; init; } = string.Empty;

    [CommandOption("-e|--environment <ENVIRONMENT>")]
    public AppEnvironment Environment { get; init; } = AppEnvironment.Dev;

    public override ValidationResult Validate()
    {
        if (string.IsNullOrWhiteSpace(Cookie))
        {
            return ValidationResult.Error("A cookie string is required. Use --cookie.");
        }

        if (string.IsNullOrWhiteSpace(Fingerprint))
        {
            return ValidationResult.Error("A fingerprint is required. Use --fingerprint.");
        }

        return ValidationResult.Success();
    }
}
