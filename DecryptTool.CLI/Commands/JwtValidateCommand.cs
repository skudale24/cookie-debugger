using System.Security.Cryptography;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class JwtValidateCommand : Command<JwtValidateSettings>
{
    private readonly DecryptService _decryptService;
    private readonly ConsolePresenter _consolePresenter;
    private readonly SecretResolver _secretResolver;

    public JwtValidateCommand(DecryptService decryptService, ConsolePresenter consolePresenter, SecretResolver secretResolver)
    {
        _decryptService = decryptService;
        _consolePresenter = consolePresenter;
        _secretResolver = secretResolver;
    }

    public override int Execute(CommandContext context, JwtValidateSettings settings)
    {
        try
        {
            var signingKey = _secretResolver.ResolveJwtSigningKey(settings.Key);
            var result = _decryptService.ValidateRawJwt(settings.Jwt, signingKey);
            _consolePresenter.WriteJwtValidation(result);
            if (_decryptService.HasEncryptedJwtClaims(result.Jwt))
            {
                var encryptionKey = _secretResolver.GetCachedOrEnvironmentEncryptionKey();
                var usedEnvKey = !string.IsNullOrWhiteSpace(encryptionKey) && _decryptService.CanDecryptJwtClaims(result.Jwt, encryptionKey);
                if (!usedEnvKey)
                {
                    encryptionKey = _secretResolver.ResolveEncryptionKey(forcePrompt: true);
                }

                if (usedEnvKey)
                {
                    _consolePresenter.WriteEnvKeyNotice(SecretResolver.EncryptionKeyEnvVar);
                }

                var resolvedEncryptionKey = encryptionKey!;
                _consolePresenter.WriteDecryptedPayloadValues(
                    result.Jwt,
                    value => _decryptService.TryDecryptClaimValue(value, resolvedEncryptionKey));
            }

            return result.CanRead && result.SignatureValid && result.IsLifetimeCurrentlyValid ? 0 : -1;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or FormatException or CryptographicException)
        {
            _consolePresenter.WriteError(ex is CryptographicException
                ? $"Unable to validate the value. {ex.Message}"
                : ex.Message);
            return -1;
        }
    }
}

public sealed class JwtValidateSettings : CommandSettings
{
    [CommandArgument(0, "<jwt>")]
    public string Jwt { get; init; } = string.Empty;

    [CommandOption("--key|-k <KEY>")]
    public string Key { get; init; } = string.Empty;

    public override ValidationResult Validate()
    {
        if (string.IsNullOrWhiteSpace(Jwt))
        {
            return ValidationResult.Error("A JWT string is required.");
        }

        return ValidationResult.Success();
    }
}
