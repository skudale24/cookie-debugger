using System.Security.Cryptography;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class JwtInspectCommand : Command<JwtInspectSettings>
{
    private readonly DebuggerService _debuggerService;
    private readonly ConsolePresenter _consolePresenter;
    private readonly SecretResolver _secretResolver;

    public JwtInspectCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter, SecretResolver secretResolver)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
        _secretResolver = secretResolver;
    }

    public override int Execute(CommandContext context, JwtInspectSettings settings)
    {
        try
        {
            var result = _debuggerService.InspectRawJwt(settings.Jwt);
            _consolePresenter.WriteRawJwtInspection(result);
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
