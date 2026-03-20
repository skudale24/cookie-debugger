dotnet publish .\DecryptTool.CLI\DecryptTool.CLI.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
Write-Host "Build complete"
