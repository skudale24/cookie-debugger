using System.Security.Cryptography;
using CookieDebugger.Models;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class DecryptCommand : Command<DecryptSettings>
{
    private readonly DecryptService _decryptService;
    private readonly ConsolePresenter _consolePresenter;
    private readonly SecretResolver _secretResolver;

    public DecryptCommand(DecryptService decryptService, ConsolePresenter consolePresenter, SecretResolver secretResolver)
    {
        _decryptService = decryptService;
        _consolePresenter = consolePresenter;
        _secretResolver = secretResolver;
    }

    public override int Execute(CommandContext context, DecryptSettings settings)
    {
        try
        {
            var fingerprint = _secretResolver.ResolveCookieFingerprint(settings.Fingerprint);
            var result = InspectCookieWithRetry(settings.Cookie, fingerprint, settings.Environment);
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

    private CookieDebugResult InspectCookieWithRetry(string cookie, string fingerprint, AppEnvironment environment)
    {
        try
        {
            return _decryptService.InspectCookie(cookie, fingerprint, environment);
        }
        catch (CryptographicException)
        {
            var promptedFingerprint = _secretResolver.ResolveCookieFingerprint(forcePrompt: true);
            return _decryptService.InspectCookie(cookie, promptedFingerprint, environment);
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

        return ValidationResult.Success();
    }
}
