# Warden installer for Windows.
#   irm https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.ps1 | iex
#
# Downloads the latest release binary and installs it to
# %LOCALAPPDATA%\Programs\Warden, adding that folder to your user PATH.

$ErrorActionPreference = 'Stop'
$repo = 'ForrestLasiter/warden'
$asset = 'warden-windows-x64.exe'

$dir = Join-Path $env:LOCALAPPDATA 'Programs\Warden'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir 'warden.exe'
$url = "https://github.com/$repo/releases/latest/download/$asset"

Write-Host "Downloading $asset from the latest release..."
Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing

# Add to the user PATH if it's not already there.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not ($userPath -split ';' | Where-Object { $_ -eq $dir })) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    Write-Host "Added $dir to your user PATH. Restart your terminal to pick it up."
}

Write-Host "Installed Warden to $exe"
Write-Host ""
& $exe version
Write-Host "Run 'warden --help' to get started."
