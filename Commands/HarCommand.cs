using System.Security.Cryptography;
using CookieDebugger.Models;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class HarCommand : Command<HarSettings>
{
    private readonly DebuggerService _debuggerService;
    private readonly ConsolePresenter _consolePresenter;

    public HarCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
    }

    public override int Execute(CommandContext context, HarSettings settings)
    {
        try
        {
            var result = _debuggerService.InspectHar(settings.FilePath, settings.Environment);
            _consolePresenter.WriteHarInspection(result);
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
