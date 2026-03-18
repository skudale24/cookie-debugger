using CookieDebugger.Services;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class InteractiveCommand : AsyncCommand<CommandSettings>
{
    private readonly InteractiveModeService _interactiveModeService;

    public InteractiveCommand(InteractiveModeService interactiveModeService)
    {
        _interactiveModeService = interactiveModeService;
    }

    public override Task<int> ExecuteAsync(CommandContext context, CommandSettings settings)
    {
        return _interactiveModeService.RunAsync();
    }
}
