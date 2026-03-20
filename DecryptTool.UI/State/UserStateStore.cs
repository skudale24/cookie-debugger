using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using CookieDebugger.Models;

namespace CookieDebugger.State;

public sealed class UserStateStore
{
    private readonly string _stateFilePath;

    public UserStateStore()
    {
        var appDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DecryptTool");
        Directory.CreateDirectory(appDataFolder);
        _stateFilePath = Path.Combine(appDataFolder, "userstate.json");
    }

    public async Task<UserState> LoadAsync()
    {
        if (!File.Exists(_stateFilePath))
        {
            return new UserState();
        }

        await using var stream = File.OpenRead(_stateFilePath);
        var state = await JsonSerializer.DeserializeAsync(
            stream,
            UserStateJsonContext.Default.UserState);
        return state ?? new UserState();
    }

    public async Task SaveAsync(UserState state)
    {
        await using var stream = File.Create(_stateFilePath);
        await JsonSerializer.SerializeAsync(
            stream,
            state,
            UserStateJsonContext.Default.UserState);
    }
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(UserState))]
internal sealed partial class UserStateJsonContext : JsonSerializerContext
{
}
