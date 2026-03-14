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
