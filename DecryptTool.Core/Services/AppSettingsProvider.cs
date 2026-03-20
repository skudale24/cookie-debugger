using CookieDebugger.Models;
using CookieDebugger.Interfaces;
using Microsoft.Extensions.Configuration;

namespace CookieDebugger.Services;

public sealed class AppSettingsProvider : IPassphraseProvider
{
    public AppSettingsProvider(IConfiguration configuration)
    {
        Settings = LoadAppSettings(configuration);
        Validate(Settings);
    }

    public AppSettings Settings { get; }

    public string GetPassPhrase(AppEnvironment environment)
    {
        return environment switch
        {
            AppEnvironment.Dev => Settings.PassPhrases.Dev,
            AppEnvironment.Stage => Settings.PassPhrases.Stage,
            AppEnvironment.Production => Settings.PassPhrases.Production,
            _ => throw new InvalidOperationException("Unsupported environment selected.")
        };
    }

    private static AppSettings LoadAppSettings(IConfiguration configuration)
    {
        return new AppSettings
        {
            PassPhrases = new PassPhrases
            {
                Dev = configuration["PassPhrases:Dev"] ?? string.Empty,
                Stage = configuration["PassPhrases:Stage"] ?? string.Empty,
                Production = configuration["PassPhrases:Production"] ?? string.Empty
            }
        };
    }

    private static void Validate(AppSettings settings)
    {
        if (settings.PassPhrases is null ||
            string.IsNullOrWhiteSpace(settings.PassPhrases.Dev) ||
            string.IsNullOrWhiteSpace(settings.PassPhrases.Stage) ||
            string.IsNullOrWhiteSpace(settings.PassPhrases.Production))
        {
            throw new InvalidOperationException("appsettings.json is missing one or more pass phrases.");
        }
    }
}
