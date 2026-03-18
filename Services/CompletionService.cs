namespace CookieDebugger.Services;

public sealed class CompletionService
{
    private static readonly string[] TopLevelCommands = ["jwt", "har", "decrypt", "completion"];
    private static readonly string[] TopLevelOptions = ["--help", "-h"];
    private static readonly string[] JwtCommands = ["cookie", "c", "inspect", "i", "decode", "d", "validate", "v", "can-read", "cr", "canread"];
    private static readonly string[] EnvironmentValues = ["Dev", "Stage", "Production"];
    private static readonly string[] JwtCookieOptions = ["--cookie", "-c", "--fingerprint", "-f", "--environment", "-e", "--help", "-h"];
    private static readonly string[] HarOptions = ["--environment", "-e", "--help", "-h"];
    private static readonly string[] CompletionCommands = ["powershell", "pwsh", "ps", "bash", "sh"];

    public string BuildPowerShellScript()
    {
        return """
$commandNames = @('bcd', 'BlazorCookieDebugger', 'BlazorCookieDebugger.exe')

Register-ArgumentCompleter -Native -CommandName $commandNames -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $tokens = @($commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text })
    $exe = $commandAst.CommandElements[0].Extent.Text
    $results = & $exe __complete --shell powershell --word $wordToComplete -- @tokens 2>$null

    foreach ($result in $results) {
        [System.Management.Automation.CompletionResult]::new($result, $result, 'ParameterValue', $result)
    }
}
""";
    }

    public string BuildBashScript()
    {
        return """
_bcd_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local exe="${COMP_WORDS[0]}"
    local words=("${COMP_WORDS[@]:1}")

    mapfile -t COMPREPLY < <("$exe" __complete --shell bash --word "$cur" -- "${words[@]}" 2>/dev/null)
}

complete -F _bcd_completions bcd BlazorCookieDebugger BlazorCookieDebugger.exe
""";
    }

    public int RunHiddenCompletion(string[] args)
    {
        var currentWord = string.Empty;
        var shell = "powershell";
        var tokenIndex = Array.IndexOf(args, "--");
        var metaArgs = tokenIndex >= 0 ? args[..tokenIndex] : args;
        var tokens = tokenIndex >= 0 ? args[(tokenIndex + 1)..] : Array.Empty<string>();

        for (var i = 0; i < metaArgs.Length; i++)
        {
            if (string.Equals(metaArgs[i], "--word", StringComparison.Ordinal) && i + 1 < metaArgs.Length)
            {
                currentWord = metaArgs[i + 1];
                i++;
                continue;
            }

            if (string.Equals(metaArgs[i], "--shell", StringComparison.Ordinal) && i + 1 < metaArgs.Length)
            {
                shell = metaArgs[i + 1];
                i++;
            }
        }

        foreach (var suggestion in GetSuggestions(tokens, currentWord, shell))
        {
            Console.WriteLine(suggestion);
        }

        return 0;
    }

    private IReadOnlyList<string> GetSuggestions(IReadOnlyList<string> tokens, string currentWord, string shell)
    {
        var effectiveTokens = tokens.ToList();
        if (effectiveTokens.Count > 0 &&
            !string.IsNullOrEmpty(currentWord) &&
            string.Equals(effectiveTokens[^1], currentWord, StringComparison.Ordinal))
        {
            effectiveTokens.RemoveAt(effectiveTokens.Count - 1);
        }

        IReadOnlyList<string> suggestions;
        if (effectiveTokens.Count == 0)
        {
            suggestions = FilterStartsWith(TopLevelCommands.Concat(TopLevelOptions), currentWord);
        }
        else
        {
            var first = effectiveTokens[0];
            suggestions = first switch
            {
                "jwt" => GetJwtSuggestions(effectiveTokens.Skip(1).ToArray(), currentWord),
                "har" => GetHarSuggestions(effectiveTokens.Skip(1).ToArray(), currentWord),
                "decrypt" => GetDecryptSuggestions(currentWord),
                "completion" => GetCompletionSuggestions(effectiveTokens.Skip(1).ToArray(), currentWord),
                _ => FilterStartsWith(TopLevelCommands.Concat(TopLevelOptions), currentWord)
            };
        }

        return FormatSuggestionsForShell(suggestions, shell);
    }

    private static IReadOnlyList<string> GetJwtSuggestions(IReadOnlyList<string> tokens, string currentWord)
    {
        if (tokens.Count == 0)
        {
            return FilterStartsWith(JwtCommands.Concat(TopLevelOptions), currentWord);
        }

        var command = tokens[0];
        var commandTokens = tokens.Skip(1).ToArray();

        return command switch
        {
            "cookie" or "c" => GetJwtCookieSuggestions(commandTokens, currentWord),
            "inspect" or "i" or "decode" or "d" or "validate" or "v" or "can-read" or "cr" or "canread"
                => FilterStartsWith(TopLevelOptions, currentWord),
            _ => FilterStartsWith(JwtCommands.Concat(TopLevelOptions), currentWord)
        };
    }

    private static IReadOnlyList<string> GetJwtCookieSuggestions(IReadOnlyList<string> tokens, string currentWord)
    {
        if (ShouldSuggestEnvironment(tokens))
        {
            return FilterStartsWith(EnvironmentValues, currentWord);
        }

        return FilterStartsWith(JwtCookieOptions.Except(tokens, StringComparer.Ordinal), currentWord);
    }

    private static IReadOnlyList<string> GetHarSuggestions(IReadOnlyList<string> tokens, string currentWord)
    {
        if (ShouldSuggestEnvironment(tokens))
        {
            return FilterStartsWith(EnvironmentValues, currentWord);
        }

        if (LooksLikeOption(currentWord))
        {
            return FilterStartsWith(HarOptions.Except(tokens, StringComparer.Ordinal), currentWord);
        }

        var fileSuggestions = GetHarFileSuggestions(currentWord);
        if (fileSuggestions.Count > 0)
        {
            return fileSuggestions;
        }

        return FilterStartsWith(HarOptions.Except(tokens, StringComparer.Ordinal), currentWord);
    }

    private static IReadOnlyList<string> GetDecryptSuggestions(string currentWord)
    {
        return FilterStartsWith(TopLevelOptions, currentWord);
    }

    private static IReadOnlyList<string> GetCompletionSuggestions(IReadOnlyList<string> tokens, string currentWord)
    {
        if (tokens.Count == 0)
        {
            return FilterStartsWith(CompletionCommands.Concat(TopLevelOptions), currentWord);
        }

        return FilterStartsWith(TopLevelOptions, currentWord);
    }

    private static bool ShouldSuggestEnvironment(IReadOnlyList<string> tokens)
    {
        if (tokens.Count == 0)
        {
            return false;
        }

        var last = tokens[^1];
        return string.Equals(last, "--environment", StringComparison.Ordinal) ||
               string.Equals(last, "-e", StringComparison.Ordinal);
    }

    private static bool LooksLikeOption(string currentWord)
    {
        return currentWord.StartsWith("-", StringComparison.Ordinal);
    }

    private static IReadOnlyList<string> GetHarFileSuggestions(string currentWord)
    {
        try
        {
            var normalized = currentWord.Trim().Trim('"');
            var directory = Path.GetDirectoryName(normalized);
            var searchPattern = Path.GetFileName(normalized);

            if (string.IsNullOrWhiteSpace(directory))
            {
                directory = Directory.GetCurrentDirectory();
            }

            if (!Directory.Exists(directory))
            {
                return Array.Empty<string>();
            }

            searchPattern = string.IsNullOrWhiteSpace(searchPattern) ? "*" : $"{searchPattern}*";
            return Directory
                .EnumerateFiles(directory, searchPattern, SearchOption.TopDirectoryOnly)
                .Where(path => path.EndsWith(".har", StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .Take(20)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static IReadOnlyList<string> FormatSuggestionsForShell(IReadOnlyList<string> suggestions, string shell)
    {
        if (string.Equals(shell, "bash", StringComparison.OrdinalIgnoreCase))
        {
            return suggestions
                .Select(value => value.Replace(" ", "\\ "))
                .ToArray();
        }

        return suggestions;
    }

    private static IReadOnlyList<string> FilterStartsWith(IEnumerable<string> values, string currentWord)
    {
        return values
            .Where(value => string.IsNullOrWhiteSpace(currentWord) || value.StartsWith(currentWord, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
