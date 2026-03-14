# Cookie Debugger

Console utility for decrypting and inspecting cookies/JWTs, comparing cookie and auth JWT claims from HAR files, and decrypting pasted encrypted request/response payloads.

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

## Run

```bash
dotnet run
```

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
