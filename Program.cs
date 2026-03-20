using CookieDebugger.Commands;
using CookieDebugger.Infrastructure;
using CookieDebugger.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

var services = new ServiceCollection();

var configuration = new ConfigurationManager();
configuration
    .AddJsonFile(Path.Combine(AppContext.BaseDirectory, "appsettings.json"), optional: true)
    .AddEnvironmentVariables();

services.AddSingleton<IConfiguration>(configuration);
services.AddSingleton<AppSettingsProvider>();
services.AddSingleton<CookieParser>();
services.AddSingleton<HarFileParser>();
services.AddSingleton<FingerprintDecryptor>();
services.AddSingleton<JwtDecryptor>();
services.AddSingleton<JwtInspector>();
services.AddSingleton<DebuggerService>();
services.AddSingleton<ConsolePresenter>();
services.AddSingleton<CompletionService>();
services.AddSingleton<SecretResolver>();

var registrar = new TypeRegistrar(services);
var app = new CommandApp(registrar);

app.Configure(config =>
{
    config.SetApplicationName("tok");

    config.AddCommand<HarCommand>("har")
        .WithDescription("Extract auth data from a HAR file and compare the cookie JWT with the auth JWT. Uses TOK_ENCRYPTION_KEY or prompts if missing.")
        .WithExample(new[] { "har", "session.har" });

    config.AddCommand<DecryptCommand>("decrypt")
        .WithDescription("Decrypt and inspect an encrypted cookie using a fingerprint and environment.")
        .WithExample(new[] { "decrypt", "<cookie>", "--fp", "<fingerprint>", "--env", "Dev" });

    config.AddCommand<JwtInspectCommand>("inspect")
        .WithDescription("Inspect a raw JWT string and render its header, claims, and token status.")
        .WithExample(new[] { "inspect", "<jwt>" });

    config.AddCommand<JwtValidateCommand>("validate")
        .WithDescription("Validate a raw JWT using --key, prompting securely if missing.")
        .WithExample(new[] { "validate", "<jwt>", "--key", "<key>" });

    config.AddBranch("completion", completion =>
    {
        completion.SetDescription("Generate shell completion scripts.");
        completion.AddCommand<PowerShellCompletionCommand>("powershell")
            .WithAlias("pwsh")
            .WithAlias("ps")
            .WithDescription("Print a PowerShell script that enables tab completion for tok.")
            .WithExample(new[] { "completion", "powershell" });
        completion.AddCommand<BashCompletionCommand>("bash")
            .WithAlias("sh")
            .WithDescription("Print a bash completion script for tok.")
            .WithExample(new[] { "completion", "bash" });
    });
});
app.SetDefaultCommand<AutoDetectCommand>();

using var provider = services.BuildServiceProvider();

if (args.Length > 0 && string.Equals(args[0], "__complete", StringComparison.Ordinal))
{
    return provider.GetRequiredService<CompletionService>().RunHiddenCompletion(args.Skip(1).ToArray());
}

if (args.Length == 0)
{
    return await app.RunAsync(["--help"]);
}

return await app.RunAsync(NormalizeOptionValueArgs(args));

static string[] NormalizeOptionValueArgs(string[] rawArgs)
{
    if (rawArgs.Length == 0)
    {
        return rawArgs;
    }

    var normalized = new List<string>(rawArgs.Length);

    for (var i = 0; i < rawArgs.Length; i++)
    {
        var current = rawArgs[i];
        if (RequiresAttachedValue(current) && i + 1 < rawArgs.Length)
        {
            normalized.Add($"{current}={rawArgs[i + 1]}");
            i++;
            continue;
        }

        normalized.Add(current);
    }

    return normalized.ToArray();
}

static bool RequiresAttachedValue(string arg)
{
    return string.Equals(arg, "--key", StringComparison.Ordinal) ||
           string.Equals(arg, "-k", StringComparison.Ordinal) ||
           string.Equals(arg, "--fp", StringComparison.Ordinal) ||
           string.Equals(arg, "--fingerprint", StringComparison.Ordinal);
}
