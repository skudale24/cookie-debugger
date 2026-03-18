using System.Security.Cryptography;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class JwtCanReadCommand : Command<JwtCanReadSettings>
{
    private readonly DebuggerService _debuggerService;
    private readonly ConsolePresenter _consolePresenter;

    public JwtCanReadCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
    }

    public override int Execute(CommandContext context, JwtCanReadSettings settings)
    {
        try
        {
            var result = _debuggerService.CanReadJwt(settings.Value);
            _consolePresenter.WriteJwtReadability(result);
            return result.CanRead ? 0 : -1;
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

public sealed class JwtCanReadSettings : CommandSettings
{
    [CommandArgument(0, "<value>")]
    public string Value { get; init; } = string.Empty;

    public override ValidationResult Validate()
    {
        return string.IsNullOrWhiteSpace(Value)
            ? ValidationResult.Error("A value is required.")
            : ValidationResult.Success();
    }
}
