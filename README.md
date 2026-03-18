# Cookie Debugger

Console utility for decrypting and inspecting cookies/JWTs, comparing cookie and auth JWT claims from HAR files, decrypting pasted encrypted request/response payloads, and automating common JWT workflows from the command line.

## Local Setup

Create a local config file from the template:

```bash
cp appsettings.template.json appsettings.json
```

PowerShell:

```powershell
Copy-Item appsettings.template.json appsettings.json
```

Then edit `appsettings.json` and replace the placeholder values with your real secrets.

`appsettings.json` is local-only and is ignored by Git.

## Interactive Mode

```bash
dotnet run
```

Or after publishing:

```bash
bcd
```

Running with no arguments opens the interactive console flow.

## CLI Commands

Top-level commands:

```bash
bcd jwt ...
bcd har <file.har>
bcd decrypt <ciphertext>
bcd completion powershell
bcd completion bash
```

### JWT Commands

Grouped under `jwt`:

```bash
bcd jwt cookie --cookie <cookie> --fingerprint <fingerprint> [--environment Dev|Stage|Production]
bcd jwt inspect <jwt>
bcd jwt decode <jwt>
bcd jwt validate <jwt>
bcd jwt can-read <value>
```

Shortcuts:

```bash
bcd jwt c --cookie <cookie> --fingerprint <fingerprint>
bcd jwt i <jwt>
bcd jwt d <jwt>
bcd jwt v <jwt>
bcd jwt cr <value>
bcd jwt canread <value>
```

What each command does:

- `jwt cookie` decrypts the cookie JWT using the supplied cookie string and fingerprint, then prints the decoded token details.
- `jwt inspect` shows the raw JWT, claims, header JSON, payload JSON, and token timing details.
- `jwt decode` gives a more compact decode view focused on the token structure and timing.
- `jwt validate` performs readability and lifetime checks only. It does not verify the signature.
- `jwt can-read` is a quick structural check to tell whether a value can be parsed as a JWT.
- `har` extracts the cookie/auth JWTs from a HAR and compares them.
- `decrypt` decrypts an encrypted request/response payload using the configured AES key and IV.
- `completion powershell` prints a PowerShell tab-completion script for the CLI.
- `completion bash` prints a bash completion script for the CLI.

## Autocomplete

PowerShell and bash tab completion are supported.

Preview the PowerShell script:

```powershell
bcd completion powershell
```

Enable it for the current session:

```powershell
bcd completion powershell | Out-String | Invoke-Expression
```

Persist it in your PowerShell profile:

```powershell
"`n# bcd completions`n$(bcd completion powershell | Out-String)" | Add-Content $PROFILE
```

Preview the bash script:

```bash
bcd completion bash
```

Enable it for the current shell:

```bash
eval "$(bcd completion bash)"
```

Persist it in your shell startup file:

```bash
echo '' >> ~/.bashrc
echo '# bcd completions' >> ~/.bashrc
echo 'eval "$(bcd completion bash)"' >> ~/.bashrc
```

After loading the script, `Tab` completion works for:

- top-level commands like `jwt`, `har`, `decrypt`, and `completion`
- JWT subcommands like `cookie`, `inspect`, `decode`, `validate`, and `can-read`
- command options such as `--environment`
- environment values like `Dev`, `Stage`, and `Production`
- `.har` file paths for the `har` command

## Build

```bash
dotnet build
```

## Publish

Project publish settings are stored in `CookieDebugger.csproj`, so a release package can be created with:

```bash
dotnet publish -c Release
```

The published app will appear under:

```text
bin/Release/net8.0/win-x64/publish/
```

The published executable is:

```text
bin/Release/net8.0/win-x64/publish/BlazorCookieDebugger.exe
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
    dotnet publish -c Release
}
```

Bash / Git Bash:

```bash
alias buildcookie="dotnet publish -c Release"
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
