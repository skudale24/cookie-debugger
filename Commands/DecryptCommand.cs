using System.Security.Cryptography;
using CookieDebugger.Services;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class DecryptCommand : Command<DecryptSettings>
{
    private readonly DebuggerService _debuggerService;
    private readonly ConsolePresenter _consolePresenter;

    public DecryptCommand(DebuggerService debuggerService, ConsolePresenter consolePresenter)
    {
        _debuggerService = debuggerService;
        _consolePresenter = consolePresenter;
    }

    public override int Execute(CommandContext context, DecryptSettings settings)
    {
        try
        {
            var clearText = _debuggerService.DecryptPayload(settings.CipherText);
            _consolePresenter.WriteClearText(clearText);
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

public sealed class DecryptSettings : CommandSettings
{
    [CommandArgument(0, "<ciphertext>")]
    public string CipherText { get; init; } = string.Empty;

    public override ValidationResult Validate()
    {
        return string.IsNullOrWhiteSpace(CipherText)
            ? ValidationResult.Error("An encrypted payload is required.")
            : ValidationResult.Success();
    }
}
