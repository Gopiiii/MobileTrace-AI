$ErrorActionPreference = "Stop"

# Always work relative to the project root, not the caller's current folder.
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Url = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
$ToolsDir = Join-Path $ProjectRoot "tools"
$ZipPath = Join-Path $ToolsDir "platform-tools-latest-windows.zip"

New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
Write-Host "Downloading official Google Android SDK Platform-Tools..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing

Write-Host "Extracting to $ToolsDir\platform-tools..."
Expand-Archive -Path $ZipPath -DestinationPath $ToolsDir -Force
Remove-Item $ZipPath -Force

$AdbExe = Join-Path $ToolsDir "platform-tools\adb.exe"
if (Test-Path $AdbExe) {
    & $AdbExe version
    Write-Host "ADB ready at $AdbExe"
    Write-Host "MobileTrace auto-detects tools\platform-tools\adb.exe (or set MOBILETRACE_ADB_PATH in .env)."
} else {
    throw "Extraction succeeded but adb.exe was not found."
}
