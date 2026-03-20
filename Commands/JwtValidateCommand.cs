using System.Security.Cryptography;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class JwtValidateCommand : Command<JwtValidateSettings>
{
    private readonly DebuggerService _debuggerService;
    private readonly ConsolePresenter _consolePresenter;
    private readonly SecretResolver _secretResolver;

    public JwtValidateCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter, SecretResolver secretResolver)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
        _secretResolver = secretResolver;
    }

    public override int Execute(CommandContext context, JwtValidateSettings settings)
    {
        try
        {
            var signingKey = _secretResolver.ResolveJwtSigningKey(settings.Key);
            var result = _debuggerService.ValidateRawJwt(settings.Jwt, signingKey);
            _consolePresenter.WriteJwtValidation(result);
            if (_debuggerService.HasEncryptedJwtClaims(result.Jwt))
            {
                var encryptionKey = _secretResolver.GetCachedOrEnvironmentEncryptionKey();
                var usedEnvKey = !string.IsNullOrWhiteSpace(encryptionKey) && _debuggerService.CanDecryptJwtClaims(result.Jwt, encryptionKey);
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
                    value => _debuggerService.TryDecryptClaimValue(value, resolvedEncryptionKey));
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
