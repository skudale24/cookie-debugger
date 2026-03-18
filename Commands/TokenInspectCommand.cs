using System.Security.Cryptography;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class JwtInspectCommand : Command<JwtInspectSettings>
{
    private readonly DebuggerService _debuggerService;
    private readonly ConsolePresenter _consolePresenter;

    public JwtInspectCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
    }

    public override int Execute(CommandContext context, JwtInspectSettings settings)
    {
        try
        {
            var result = _debuggerService.InspectRawJwt(settings.Jwt);
            _consolePresenter.WriteRawJwtInspection(result);
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
