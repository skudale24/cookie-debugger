using CookieDebugger.Services;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class PowerShellCompletionCommand : Command<PowerShellCompletionSettings>
{
    private readonly CompletionService _completionService;

    public PowerShellCompletionCommand(CompletionService completionService)
    {
        _completionService = completionService;
    }

    public override int Execute(CommandContext context, PowerShellCompletionSettings settings)
    {
        Console.WriteLine(_completionService.BuildPowerShellScript());
        return 0;
    }
}

public sealed class PowerShellCompletionSettings : CommandSettings
{
}
