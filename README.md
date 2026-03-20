# Cookie Debugger

Console utility for decrypting and inspecting cookies/JWTs, comparing cookie and auth JWT claims from HAR files, and automating common JWT workflows from the command line.

## Local Setup

Set the encryption key before using payload or HAR decryption:

```powershell
setx TOK_ENCRYPTION_KEY ********
```

Open a new terminal after running `setx`.

The repository is now split into a single solution with separate shared/core, CLI, and WPF projects:

```text
DecryptTool.sln
|- DecryptTool.Core
|- DecryptTool.CLI
|- DecryptTool.UI
```

Create a local config file from the template:

```bash
cp appsettings.template.json appsettings.json
```

Publish targets:

```powershell
dotnet publish .\DecryptTool.CLI\DecryptTool.CLI.csproj
dotnet publish .\DecryptTool.UI\DecryptTool.UI.csproj
```

PowerShell:

```powershell
Copy-Item appsettings.template.json appsettings.json
```

Then edit `appsettings.json` and replace the placeholder values with your real secrets.

`appsettings.json` is local-only and is ignored by Git.

## CLI Usage

```bash
dotnet run --project .\DecryptTool.CLI -- --help
```

Or after publishing:

```bash
tok --help
```

Running with no arguments shows command help.

## Commands

Primary commands:

```bash
tok <input>
tok decrypt <cookie> --fp <fingerprint> --env <env>
tok inspect <jwt>
tok validate <jwt> --key <key>
tok har <file>
```

How `tok <input>` auto-detects:

- JWT -> `inspect`
- Encrypted cookie with delimiter -> `decrypt`
- Raw encrypted payload -> decrypt to clear text using `TOK_ENCRYPTION_KEY`, prompting if missing
- HAR file -> `har`

Notes:

- For encrypted cookie auto-detection, pass `--fp` and optionally `--env` alongside the input.
- Encrypted cookie decryption resolves the fingerprint in this order: `--fp`, then `TOK_COOKIE_FINGERPRINT`, then a visible prompt. If the first fingerprint cannot decrypt the cookie, `tok` prompts again.
- Raw encrypted payload auto-detection resolves the encryption key in this order: `TOK_ENCRYPTION_KEY`, then a visible prompt. If the first key cannot decrypt the payload, `tok` prompts again.
- `validate` resolves the JWT signing key in this order: `--key`, then a visible prompt. You can pass `--key <value>` directly on the command line, including PEM-like values that start with hyphens.
- JWT-oriented commands such as `inspect`, `decode`, `validate`, and `can-read` accept either a raw JWT or an `Authorization`-style value like `Bearer <token>`.
- `inspect` and `validate` render their normal JWT output first. If payload claims look encrypted, `tok` checks `TOK_ENCRYPTION_KEY` first, prompts only if needed, and then appends a `Decrypted Payload Values` section.
- Secrets are never written back to environment variables automatically.
- `har` defaults to `Dev` unless you pass `--env`.

Examples:

```bash
tok eyJhbGciOi...
tok "C:\Users\me\Downloads\session.har"
tok <encrypted-cookie> --fp 1303908839 --env Dev
tok <encrypted-payload>
tok decrypt <encrypted-cookie> --fp 1303908839 --env Dev
tok inspect <jwt>
tok validate <jwt> --key my-signing-key
tok har session.har --env Stage
```

## Autocomplete

PowerShell and bash tab completion are supported.

Preview the PowerShell script:

```powershell
tok completion powershell
```

Enable it for the current session:

```powershell
tok completion powershell | Out-String | Invoke-Expression
```

Persist it in your PowerShell profile:

```powershell
"`n# tok completions`n$(tok completion powershell | Out-String)" | Add-Content $PROFILE
```

Preview the bash script:

```bash
tok completion bash
```

Enable it for the current shell:

```bash
eval "$(tok completion bash)"
```

Persist it in your shell startup file:

```bash
echo '' >> ~/.bashrc
echo '# tok completions' >> ~/.bashrc
echo 'eval "$(tok completion bash)"' >> ~/.bashrc
```

After loading the script, `Tab` completion works for:

- top-level commands like `inspect`, `validate`, `decrypt`, `har`, and `completion`
- command options such as `--fp`, `--env`, and `--key`
- environment values like `Dev`, `Stage`, and `Production`
- `.har` file paths for `tok har` and auto-detect input

## Build

```bash
dotnet build
```

## Publish

The CLI publish settings are stored in `DecryptTool.CLI/DecryptTool.CLI.csproj`, so a release package can be created with:

```bash
dotnet publish .\DecryptTool.CLI\DecryptTool.CLI.csproj -c Release
```

The published app will appear under:

```text
DecryptTool.CLI/bin/Release/net8.0/win-x64/publish/
```

The published executable is:

```text
DecryptTool.CLI/bin/Release/net8.0/win-x64/publish/tok.exe
```

## Build Script

You can also use the repo-local script:

```powershell
.\build.ps1
```

## Optional Shell Alias

PowerShell profile:

```powershell
function build-cookie {
    dotnet publish .\DecryptTool.CLI\DecryptTool.CLI.csproj -c Release
}
```

Bash / Git Bash:

```bash
alias buildcookie="dotnet publish ./DecryptTool.CLI/DecryptTool.CLI.csproj -c Release"
```

## Publish This Folder To GitHub

1. Create a new empty repository in GitHub.
2. Initialize Git locally if needed:

```bash
git init
git branch -M main
git add .
git commit -m "Initial commit"
```

3. Add your remote and push:

```bash
git remote add origin <YOUR_GITHUB_REPO_URL>
git push -u origin main
```
