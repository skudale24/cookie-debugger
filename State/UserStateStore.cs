using System.Text.Json;
using CookieDebugger.Models;

namespace CookieDebugger.State;

public sealed class UserStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _stateFilePath = Path.Combine(Directory.GetCurrentDirectory(), "userstate.json");

    public async Task<UserState> LoadAsync()
    {
        if (!File.Exists(_stateFilePath))
        {
            return new UserState();
        }

        await using var stream = File.OpenRead(_stateFilePath);
        var state = await JsonSerializer.DeserializeAsync<UserState>(stream);
        return state ?? new UserState();
    }

    public async Task SaveAsync(UserState state)
    {
        await using var stream = File.Create(_stateFilePath);
        await JsonSerializer.SerializeAsync(stream, state, JsonOptions);
    }
}
