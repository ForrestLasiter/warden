# Warden installer for Windows.
#
#   irm https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.ps1 | iex
#
# Flags (when run as a downloaded file, e.g.  .\install.ps1 -NoShortcuts):
#   -InstallDir DIR    install here (default %LOCALAPPDATA%\Programs\Warden)
#   -Version TAG       install a specific release tag (default: latest)
#   -NoShortcuts       don't create Desktop/Start Menu launchers
#   -NoPath            don't add the install dir to your PATH
#   -AllowUnverified   proceed even if checksums can't be fetched (NOT advised)
#   -Uninstall         remove Warden, its shortcuts, and PATH entry
# When piped through `irm | iex` use environment variables instead, e.g.
#   $env:WARDEN_NO_SHORTCUTS=1; irm <url> | iex
#
# Safety: the download is checksum-verified against the release's SHA256SUMS
# BEFORE install. If verification can't be performed it FAILS CLOSED unless
# -AllowUnverified. The existing install is untouched until a new binary is
# verified (safe rollback).

param(
    [string] $InstallDir,
    [string] $Version = 'latest',
    [switch] $NoShortcuts,
    [switch] $NoPath,
    [switch] $AllowUnverified,
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
$repo = 'ForrestLasiter/warden'
$asset = 'warden-windows-x64.exe'

# Environment-variable fallbacks (for the `irm | iex` case, which can't take params).
if (-not $InstallDir -and $env:WARDEN_INSTALL_DIR) { $InstallDir = $env:WARDEN_INSTALL_DIR }
if ($env:WARDEN_VERSION)          { $Version = $env:WARDEN_VERSION }
if ($env:WARDEN_NO_SHORTCUTS)     { $NoShortcuts = $true }
if ($env:WARDEN_NO_PATH)          { $NoPath = $true }
if ($env:WARDEN_ALLOW_UNVERIFIED) { $AllowUnverified = $true }
if ($env:WARDEN_UNINSTALL)        { $Uninstall = $true }

if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\Warden' }
$exe = Join-Path $InstallDir 'warden.exe'

# --- uninstall --------------------------------------------------------------
if ($Uninstall) {
    if (Test-Path $exe) { Remove-Item $exe -Force; Write-Host "Removed $exe" }
    foreach ($p in @((Join-Path ([Environment]::GetFolderPath('Programs')) 'Warden.lnk'),
                     (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Warden.lnk'))) {
        if (Test-Path $p) { Remove-Item $p -Force }
    }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $newPath = (($userPath -split ';') | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
    if ($newPath -ne $userPath) {
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "Removed $InstallDir from your PATH."
    }
    Write-Host "Removed Warden shortcuts. Your ~/.warden data was left untouched."
    return
}

if ($Version -eq 'latest') {
    $base = "https://github.com/$repo/releases/latest/download"
} else {
    $base = "https://github.com/$repo/releases/download/$Version"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N') + '.exe')

Write-Host "Downloading $asset ($Version)..."
Invoke-WebRequest -Uri "$base/$asset" -OutFile $tmp -UseBasicParsing

# --- verify (fail closed) ---------------------------------------------------
function Fail-Closed([string] $msg) {
    if ($AllowUnverified) {
        Write-Warning "$msg (continuing because -AllowUnverified was given)."
    } else {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        throw "$msg`nRefusing to install unverified. Re-run with -AllowUnverified to override."
    }
}
$sums = $null
try {
    $sums = (Invoke-WebRequest -Uri "$base/SHA256SUMS" -UseBasicParsing).Content
} catch {
    Fail-Closed "Could not download SHA256SUMS to verify the binary"
}
if ($sums) {
    $line = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($asset) } | Select-Object -First 1)
    $expected = if ($line) { ($line -split '\s+')[0].ToLower() } else { $null }
    $actual = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLower()
    if (-not $expected) {
        Fail-Closed "SHA256SUMS does not list $asset"
    } elseif ($expected -ne $actual) {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        throw "Checksum MISMATCH for $asset (expected $expected, got $actual). The download may be corrupt or tampered with. Aborting."
    } else {
        Write-Host "Checksum verified."
    }
}

# --- install (existing install untouched until now) -------------------------
Move-Item -Force $tmp $exe
Write-Host "Installed Warden to $exe"

if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not ($userPath -split ';' | Where-Object { $_ -eq $InstallDir })) {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDir", 'User')
        Write-Host "Added $InstallDir to your user PATH. Restart your terminal to pick it up."
    }
}

if (-not $NoShortcuts) {
    function New-WardenShortcut([string] $LinkPath) {
        $shell = New-Object -ComObject WScript.Shell
        $sc = $shell.CreateShortcut($LinkPath)
        $sc.TargetPath = $exe
        $sc.Arguments = 'gui'
        $sc.WorkingDirectory = $InstallDir
        $sc.IconLocation = "$exe,0"
        $sc.Description = 'Open the Warden malware scanner dashboard'
        $sc.WindowStyle = 7          # start the console minimized (less scary)
        $sc.Save()
    }
    try {
        New-WardenShortcut (Join-Path ([Environment]::GetFolderPath('Programs')) 'Warden.lnk')
        New-WardenShortcut (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Warden.lnk')
        Write-Host "Created a 'Warden' icon on your Desktop and in the Start Menu."
    } catch {
        Write-Warning "Could not create shortcuts: $($_.Exception.Message)"
    }
}

Write-Host ""
& $exe version
Write-Host ""
Write-Host "Double-click the 'Warden' icon on your Desktop to open the dashboard,"
Write-Host "or run 'warden --help' in a terminal for the command line."
