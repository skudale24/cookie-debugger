using CookieDebugger.Models;

namespace CookieDebugger.Interfaces;

public interface IPassphraseProvider
{
    string GetPassPhrase(AppEnvironment environment);
}
