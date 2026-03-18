using System.Security.Cryptography;
using CookieDebugger.Models;
using CookieDebugger.State;

namespace CookieDebugger.Services;

public sealed class InteractiveModeService(
    DebuggerService debuggerService,
    ConsolePresenter consolePresenter,
    UserStateStore stateStore)
{
    public async Task<int> RunAsync()
    {
        var state = await stateStore.LoadAsync();

        while (true)
        {
            consolePresenter.SafeClearScreen();
            consolePresenter.WriteHeader();
            consolePresenter.WriteLastDecryptedJwt(state.LastDecryptedJwt);

            try
            {
                var inputType = PromptForInputType();

                if (inputType == CookieInputType.DecryptedRequestResponse)
                {
                    var encryptedText = PromptRequired("Paste Encrypted Request/Response");
                    var clearText = debuggerService.DecryptPayload(encryptedText);
                    consolePresenter.WriteClearText(clearText);
                }
                else
                {
                    var environment = PromptForEnvironment();

                    if (inputType == CookieInputType.EncryptedCookie)
                    {
                        var fingerprint = PromptWithDefault("Fingerprint", state.LastFingerprint);
                        var cookieString = PromptWithDefault("Encrypted Cookie String", state.LastEncryptedCookie);
                        var result = debuggerService.InspectCookie(cookieString, fingerprint, environment);

                        state.LastFingerprint = result.Fingerprint;
                        state.LastEncryptedCookie = result.CookieString;
                        state.LastDecryptedJwt = result.DecryptedJwt;
                        await stateStore.SaveAsync(state);

                        consolePresenter.WriteCookieInspection(result);
                    }
                    else
                    {
                        var harFilePath = PromptForHarFilePath(state.LastHarFilePath);
                        var result = debuggerService.InspectHar(harFilePath, environment);

                        state.LastHarFilePath = result.HarFilePath;
                        state.LastFingerprint = result.CookieDebug.Fingerprint;
                        state.LastEncryptedCookie = result.CookieDebug.CookieString;
                        state.LastDecryptedJwt = result.CookieDebug.DecryptedJwt;
                        await stateStore.SaveAsync(state);

                        consolePresenter.WriteHarInspection(result);
                    }
                }
            }
            catch (FormatException ex)
            {
                consolePresenter.WriteError(ex.Message);
            }
            catch (CryptographicException ex)
            {
                consolePresenter.WriteError($"Unable to decrypt the value. {ex.Message}");
            }
            catch (ArgumentException ex)
            {
                consolePresenter.WriteError(ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                consolePresenter.WriteError(ex.Message);
            }
            catch (Exception ex)
            {
                consolePresenter.WriteError($"Unexpected error: {ex.Message}");
            }

            if (!PromptForAnotherSession())
            {
                break;
            }
        }

        return 0;
    }

    private CookieInputType PromptForInputType()
    {
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Choose input type");
            Console.WriteLine("1. Paste encrypted cookie and fingerprint");
            Console.WriteLine("2. Load HAR file");
            Console.WriteLine("3. Paste Encrypted Request/Response");
            Console.Write("Choice [1]: ");

            var input = Console.ReadLine()?.Trim();
            if (string.IsNullOrWhiteSpace(input) || input == "1")
            {
                return CookieInputType.EncryptedCookie;
            }

            if (input == "2")
            {
                return CookieInputType.HarFile;
            }

            if (input == "3")
            {
                return CookieInputType.DecryptedRequestResponse;
            }

            consolePresenter.WriteError("Please choose 1, 2, or 3.");
        }
    }

    private AppEnvironment PromptForEnvironment()
    {
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Select environment:");
            Console.WriteLine("1. Dev");
            Console.WriteLine("2. Stage");
            Console.WriteLine("3. Production");
            Console.Write("Choice [1]: ");

            var input = Console.ReadLine()?.Trim();
            if (string.IsNullOrWhiteSpace(input) || input == "1" || input?.Equals("Dev", StringComparison.OrdinalIgnoreCase) == true)
            {
                return AppEnvironment.Dev;
            }

            if (input == "2" || input?.Equals("Stage", StringComparison.OrdinalIgnoreCase) == true)
            {
                return AppEnvironment.Stage;
            }

            if (input == "3" || input?.Equals("Production", StringComparison.OrdinalIgnoreCase) == true)
            {
                return AppEnvironment.Production;
            }

            consolePresenter.WriteError("Please choose Dev, Stage, or Production.");
        }
    }

    private static string PromptForHarFilePath(string? defaultValue)
    {
        Console.WriteLine();
        Console.WriteLine("Drag HAR file here or paste path:");

        var prompt = string.IsNullOrWhiteSpace(defaultValue)
            ? "HAR file path: "
            : $"HAR file path [{defaultValue}]: ";

        Console.Write(prompt);
        var input = Console.ReadLine();

        if (string.IsNullOrWhiteSpace(input))
        {
            return defaultValue ?? string.Empty;
        }

        return DebuggerService.NormalizeDroppedPath(input);
    }

    private static string PromptWithDefault(string label, string? defaultValue)
    {
        var prompt = string.IsNullOrWhiteSpace(defaultValue)
            ? $"{label}: "
            : $"{label} [{defaultValue}]: ";

        Console.Write(prompt);
        var input = Console.ReadLine();

        if (string.IsNullOrWhiteSpace(input))
        {
            return defaultValue ?? string.Empty;
        }

        return input.Trim();
    }

    private static string PromptRequired(string label)
    {
        Console.Write($"{label}: ");
        var input = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException($"{label} is required.");
        }

        return input;
    }

    private static bool PromptForAnotherSession()
    {
        Console.WriteLine();
        Console.Write("Press Enter to process another session, or type X to exit: ");
        var input = Console.ReadLine()?.Trim();
        return !string.Equals(input, "X", StringComparison.OrdinalIgnoreCase);
    }
}

public enum CookieInputType
{
    EncryptedCookie = 1,
    HarFile = 2,
    DecryptedRequestResponse = 3
}
