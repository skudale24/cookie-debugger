using System.Security.Cryptography;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class JwtDecodeCommand : Command<JwtDecodeSettings>
{
    private readonly DecryptService _decryptService;
    private readonly ConsolePresenter _consolePresenter;

    public JwtDecodeCommand(DecryptService decryptService, ConsolePresenter consolePresenter)
    {
        _decryptService = decryptService;
        _consolePresenter = consolePresenter;
    }

    public override int Execute(CommandContext context, JwtDecodeSettings settings)
    {
        try
        {
            var result = _decryptService.InspectRawJwt(settings.Jwt);
            _consolePresenter.WriteRawJwtDecode(result);
            return 0;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or FormatException or CryptographicException)
        {
            _consolePresenter.WriteError(ex is CryptographicException
                ? $"Unable to decode the value. {ex.Message}"
                : ex.Message);
            return -1;
        }
    }
}

public sealed class JwtDecodeSettings : CommandSettings
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
