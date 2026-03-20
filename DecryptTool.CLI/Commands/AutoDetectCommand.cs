using System.Security.Cryptography;
using CookieDebugger.Models;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class AutoDetectCommand : Command<AutoDetectSettings>
{
    private readonly DecryptService _decryptService;
    private readonly ConsolePresenter _consolePresenter;
    private readonly SecretResolver _secretResolver;

    public AutoDetectCommand(DecryptService decryptService, ConsolePresenter consolePresenter, SecretResolver secretResolver)
    {
        _decryptService = decryptService;
        _consolePresenter = consolePresenter;
        _secretResolver = secretResolver;
    }

    public override int Execute(CommandContext context, AutoDetectSettings settings)
    {
        try
        {
            var normalizedInput = DecryptService.NormalizeDroppedPath(settings.Input);
            if (IsHarInput(normalizedInput))
            {
                var harInspection = InspectHarWithRetry(normalizedInput, settings.Environment);
                _consolePresenter.WriteHarInspection(
                    harInspection.Result,
                    value => _decryptService.TryDecryptClaimValue(value, harInspection.EncryptionKey));
                return 0;
            }

            var readability = _decryptService.CanReadJwt(normalizedInput);
            if (readability.CanRead)
            {
                var jwtResult = _decryptService.InspectRawJwt(normalizedInput);
                _consolePresenter.WriteRawJwtInspection(jwtResult);
                return 0;
            }

            if (_decryptService.LooksLikeEncryptedPayload(normalizedInput))
            {
                var clearText = DecryptPayloadWithRetry(normalizedInput);
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
            return _decryptService.InspectCookie(cookie, fingerprint, environment);
        }
        catch (CryptographicException)
        {
            var promptedFingerprint = _secretResolver.ResolveCookieFingerprint(forcePrompt: true);
            return _decryptService.InspectCookie(cookie, promptedFingerprint, environment);
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

    private string DecryptPayloadWithRetry(string encryptedPayload)
    {
        var encryptionKey = _secretResolver.ResolveEncryptionKey();

        try
        {
            return _decryptService.DecryptPayload(encryptedPayload, encryptionKey);
        }
        catch (CryptographicException)
        {
            var promptedKey = _secretResolver.ResolveEncryptionKey(forcePrompt: true);
            return _decryptService.DecryptPayload(encryptedPayload, promptedKey);
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
