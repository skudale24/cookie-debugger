using CookieDebugger.Services;
using Spectre.Console.Cli;

namespace CookieDebugger.Commands;

public sealed class BashCompletionCommand : Command<BashCompletionSettings>
{
    private readonly CompletionService _completionService;

    public BashCompletionCommand(CompletionService completionService)
    {
        _completionService = completionService;
    }

    public override int Execute(CommandContext context, BashCompletionSettings settings)
    {
        Console.WriteLine(_completionService.BuildBashScript());
        return 0;
    }
}

public sealed class BashCompletionSettings : CommandSettings
{
}
