using System.Security.Cryptography;
using CookieDebugger.Models;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class DecryptCommand : Command<DecryptSettings>
{
    private readonly DebuggerService _debuggerService;
    private readonly ConsolePresenter _consolePresenter;

    public DecryptCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
    }

    public override int Execute(CommandContext context, DecryptSettings settings)
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

public sealed class DecryptSettings : CommandSettings
{
    [CommandArgument(0, "<cookie>")]
    public string Cookie { get; init; } = string.Empty;

    [CommandOption("--fp|--fingerprint <FINGERPRINT>")]
    public string Fingerprint { get; init; } = string.Empty;

    [CommandOption("--env|--environment <ENVIRONMENT>")]
    public AppEnvironment Environment { get; init; } = AppEnvironment.Dev;

    public override ValidationResult Validate()
    {
        if (string.IsNullOrWhiteSpace(Cookie))
        {
            return ValidationResult.Error("An encrypted cookie string is required.");
        }

        if (string.IsNullOrWhiteSpace(Fingerprint))
        {
            return ValidationResult.Error("A fingerprint is required. Use --fp.");
        }

        return ValidationResult.Success();
    }
}
