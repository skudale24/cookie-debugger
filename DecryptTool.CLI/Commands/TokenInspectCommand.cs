using System.Security.Cryptography;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class JwtInspectCommand : Command<JwtInspectSettings>
{
    private readonly DecryptService _decryptService;
    private readonly ConsolePresenter _consolePresenter;
    private readonly SecretResolver _secretResolver;

    public JwtInspectCommand(DecryptService decryptService, ConsolePresenter consolePresenter, SecretResolver secretResolver)
    {
        _decryptService = decryptService;
        _consolePresenter = consolePresenter;
        _secretResolver = secretResolver;
    }

    public override int Execute(CommandContext context, JwtInspectSettings settings)
    {
        try
        {
            var result = _decryptService.InspectRawJwt(settings.Jwt);
            _consolePresenter.WriteRawJwtInspection(result);
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

            return 0;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or FormatException or CryptographicException)
        {
            _consolePresenter.WriteError(ex is CryptographicException
                ? $"Unable to inspect the value. {ex.Message}"
                : ex.Message);
            return -1;
        }
    }
}

public sealed class JwtInspectSettings : CommandSettings
{
    [CommandArgument(0, "<jwt>")]
    public string Jwt { get; init; } = string.Empty;

    public override ValidationResult Validate()
    {
        return string.IsNullOrWhiteSpace(Jwt)
            ? ValidationResult.Error("A JWT string is required.")
            : ValidationResult.Success();
    }
}
