using System.Security.Cryptography;
using CookieDebugger.Models;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class HarCommand : Command<HarSettings>
{
    private readonly DecryptService _decryptService;
    private readonly ConsolePresenter _consolePresenter;
    private readonly SecretResolver _secretResolver;

    public HarCommand(DecryptService decryptService, ConsolePresenter consolePresenter, SecretResolver secretResolver)
    {
        _decryptService = decryptService;
        _consolePresenter = consolePresenter;
        _secretResolver = secretResolver;
    }

    public override int Execute(CommandContext context, HarSettings settings)
    {
        try
        {
            var harInspection = InspectHarWithRetry(settings.FilePath, settings.Environment);
            _consolePresenter.WriteHarInspection(
                harInspection.Result,
                value => _decryptService.TryDecryptClaimValue(value, harInspection.EncryptionKey));
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

    private (HarDebugResult Result, string EncryptionKey) InspectHarWithRetry(string filePath, AppEnvironment environment)
    {
        var encryptionKey = _secretResolver.ResolveEncryptionKey();

        try
        {
            return (_decryptService.InspectHar(filePath, environment, encryptionKey), encryptionKey);
        }
        catch (CryptographicException)
        {
            var promptedKey = _secretResolver.ResolveEncryptionKey(forcePrompt: true);
            return (_decryptService.InspectHar(filePath, environment, promptedKey), promptedKey);
        }
    }
}

public sealed class HarSettings : CommandSettings
{
    [CommandArgument(0, "<file>")]
    public string FilePath { get; init; } = string.Empty;

    [CommandOption("--env|--environment <ENVIRONMENT>")]
    public AppEnvironment Environment { get; init; } = AppEnvironment.Dev;

    public override ValidationResult Validate()
    {
        return string.IsNullOrWhiteSpace(FilePath)
            ? ValidationResult.Error("A HAR file path is required.")
            : ValidationResult.Success();
    }
}
