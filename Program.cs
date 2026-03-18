using CookieDebugger.Commands;
using CookieDebugger.Infrastructure;
using CookieDebugger.Services;
using CookieDebugger.State;
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
services.AddSingleton<UserStateStore>();
services.AddSingleton<DebuggerService>();
services.AddSingleton<ConsolePresenter>();
services.AddSingleton<InteractiveModeService>();
services.AddSingleton<CompletionService>();

var registrar = new TypeRegistrar(services);
var app = new CommandApp(registrar);

app.Configure(config =>
{
    config.SetApplicationName("bcd");

    config.AddBranch("jwt", jwt =>
    {
        jwt.SetDescription("Work with JWTs from cookies or raw token strings.");
        jwt.AddCommand<JwtCookieCommand>("cookie")
            .WithAlias("c")
            .WithDescription("Decrypt and inspect a cookie JWT using a cookie string and fingerprint.")
            .WithExample(new[] { "jwt", "cookie", "--cookie", "<cookie>", "--fingerprint", "<fingerprint>" });
        jwt.AddCommand<JwtInspectCommand>("inspect")
            .WithAlias("i")
            .WithDescription("Inspect a raw JWT string and render its header, claims, and token status.")
            .WithExample(new[] { "jwt", "inspect", "<jwt>" });
        jwt.AddCommand<JwtDecodeCommand>("decode")
            .WithAlias("d")
            .WithDescription("Decode a raw JWT and render the header, payload, and token status.")
            .WithExample(new[] { "jwt", "decode", "<jwt>" });
        jwt.AddCommand<JwtValidateCommand>("validate")
            .WithAlias("v")
            .WithDescription("Validate a raw JWT for readability and lifetime checks without verifying the signature.")
            .WithExample(new[] { "jwt", "validate", "<jwt>" });
        jwt.AddCommand<JwtCanReadCommand>("can-read")
            .WithAlias("cr")
            .WithAlias("canread")
            .WithDescription("Quickly check whether a value can be read as a JWT.")
            .WithExample(new[] { "jwt", "can-read", "<value>" });
    });

    config.AddCommand<HarCommand>("har")
        .WithDescription("Extract auth data from a HAR file and compare the cookie JWT with the auth JWT.")
        .WithExample(new[] { "har", "session.har" });

    config.AddCommand<DecryptCommand>("decrypt")
        .WithDescription("Decrypt an encrypted request or response payload.")
        .WithExample(new[] { "decrypt", "<ciphertext>" });

    config.AddBranch("completion", completion =>
    {
        completion.SetDescription("Generate shell completion scripts.");
        completion.AddCommand<PowerShellCompletionCommand>("powershell")
            .WithAlias("pwsh")
            .WithAlias("ps")
            .WithDescription("Print a PowerShell script that enables tab completion for bcd.")
            .WithExample(new[] { "completion", "powershell" });
        completion.AddCommand<BashCompletionCommand>("bash")
            .WithAlias("sh")
            .WithDescription("Print a bash completion script for bcd.")
            .WithExample(new[] { "completion", "bash" });
    });
});

using var provider = services.BuildServiceProvider();

if (args.Length > 0 && string.Equals(args[0], "__complete", StringComparison.Ordinal))
{
    return provider.GetRequiredService<CompletionService>().RunHiddenCompletion(args.Skip(1).ToArray());
}

if (args.Length == 0)
{
    return await provider.GetRequiredService<InteractiveModeService>().RunAsync();
}

return await app.RunAsync(args);
