# Warden installer for Windows.
#
#   irm https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.ps1 | iex
#
# Prefer to read it first? Download, inspect, then run:
#   irm https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.ps1 -OutFile install.ps1
#   notepad .\install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# Flags (when run as a downloaded file, e.g.  .\install.ps1 -NoShortcuts):
#   -InstallDir DIR    install here (default %LOCALAPPDATA%\Programs\Warden)
#   -Version TAG       install a specific release tag (default: latest)
#   -NoShortcuts       don't create Desktop/Start Menu launchers
#   -NoPath            don't add the install dir to your PATH
#   -AllowUnverified   proceed even if checksums can't be fetched (NOT advised)
#   -Rollback          switch back to the version that was installed before
#   -Uninstall         remove Warden, its shortcuts, and PATH entry (data is kept)
# When piped through `irm | iex` use environment variables instead, e.g.
#   $env:WARDEN_NO_SHORTCUTS=1; irm <url> | iex
#
# Running it again upgrades in place (it is safe to re-run: idempotent).
#
# Safety: the download is checksum-verified against the release's SHA256SUMS
# BEFORE install. If verification can't be performed it FAILS CLOSED unless
# -AllowUnverified. The existing install is untouched until a new binary is
# verified; the previous binary is kept as 'warden.previous.exe' and is restored
# automatically if the new one won't start.

param(
    [string] $InstallDir,
    [string] $Version = 'latest',
    [switch] $NoShortcuts,
    [switch] $NoPath,
    [switch] $AllowUnverified,
    [switch] $Rollback,
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
$repo = 'ForrestLasiter/warden'
$asset = 'warden-windows-x64.exe'

# One Windows build is published (x64). Windows on ARM runs it through the
# built-in x64 emulation; 32-bit Windows is not supported.
$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
if ($arch -eq 'x86') {
    throw "Warden needs 64-bit Windows. See https://github.com/$repo#install-dev to run from source."
}
if ($arch -eq 'ARM64') {
    Write-Host "Windows on ARM detected: installing the x64 build (runs under Windows' built-in emulation)." -ForegroundColor Yellow
}

# Environment-variable fallbacks (for the `irm | iex` case, which can't take params).
if (-not $InstallDir -and $env:WARDEN_INSTALL_DIR) { $InstallDir = $env:WARDEN_INSTALL_DIR }
if ($env:WARDEN_VERSION)          { $Version = $env:WARDEN_VERSION }
if ($env:WARDEN_NO_SHORTCUTS)     { $NoShortcuts = $true }
if ($env:WARDEN_NO_PATH)          { $NoPath = $true }
if ($env:WARDEN_ALLOW_UNVERIFIED) { $AllowUnverified = $true }
if ($env:WARDEN_UNINSTALL)        { $Uninstall = $true }
if ($env:WARDEN_ROLLBACK)         { $Rollback = $true }

if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\Warden' }
$exe = Join-Path $InstallDir 'warden.exe'
$previous = Join-Path $InstallDir 'warden.previous.exe'

function Get-WardenVersion([string] $Path) {
    # "Warden 0.5.0" -> "0.5.0"; empty string if the binary won't run.
    try {
        $out = & $Path version 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return '' }
        return (("$out" -split '\s+') | Where-Object { $_ })[-1]
    } catch {
        return ''
    }
}

# --- uninstall --------------------------------------------------------------
if ($Uninstall) {
    if (Test-Path $exe) { Remove-Item $exe -Force; Write-Host "Removed $exe" }
    if (Test-Path $previous) { Remove-Item $previous -Force }
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

# --- rollback ---------------------------------------------------------------
if ($Rollback) {
    if (-not (Test-Path $previous)) {
        throw "No previous version to roll back to ($previous not found)."
    }
    if (Test-Path $exe) {
        # Swap, so rolling back twice returns to where you started.
        $swap = "$exe.swap"
        Move-Item -Force $exe $swap
        Move-Item -Force $previous $exe
        Move-Item -Force $swap $previous
    } else {
        Move-Item -Force $previous $exe
    }
    Write-Host "Rolled back. Warden is now version $(Get-WardenVersion $exe)."
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
function Stop-Unverified([string] $msg) {
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
    Stop-Unverified "Could not download SHA256SUMS to verify the binary"
}
if ($sums) {
    $line = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($asset) } | Select-Object -First 1)
    $expected = if ($line) { ($line -split '\s+')[0].ToLower() } else { $null }
    $actual = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLower()
    if (-not $expected) {
        Stop-Unverified "SHA256SUMS does not list $asset"
    } elseif ($expected -ne $actual) {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        throw "Checksum MISMATCH for $asset (expected $expected, got $actual). The download may be corrupt or tampered with. Aborting."
    } else {
        Write-Host "Checksum verified."
    }
}

# --- install (existing install untouched until now) -------------------------
$oldVersion = ''
if (Test-Path $exe) {
    $oldVersion = Get-WardenVersion $exe
    # Keep the working binary so a bad upgrade can be undone (-Rollback).
    Copy-Item -Force $exe $previous
}
try {
    Move-Item -Force $tmp $exe
} catch {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    throw "Could not replace $exe - is Warden still running? Close it (Quit Warden) and try again. ($($_.Exception.Message))"
}

# The new binary must at least start. If it doesn't, put the old one back.
$newVersion = Get-WardenVersion $exe
if (-not $newVersion) {
    if ($oldVersion -and (Test-Path $previous)) {
        Copy-Item -Force $previous $exe
        throw "The new Warden binary did not start; restored version $oldVersion."
    }
    Remove-Item $exe -Force -ErrorAction SilentlyContinue
    throw "The downloaded Warden binary did not start on this system; nothing was installed."
}

if (-not $oldVersion) {
    Write-Host "Installed Warden $newVersion to $exe"
} elseif ($oldVersion -eq $newVersion) {
    Write-Host "Warden $newVersion is already installed at $exe (reinstalled)."
} else {
    Write-Host "Upgraded Warden $oldVersion -> $newVersion at $exe"
    Write-Host "(To undo: run this installer again with -Rollback.)"
}

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
if (-not $NoShortcuts) {
    Write-Host "Double-click the 'Warden' icon on your Desktop to open the dashboard,"
    Write-Host "or run 'warden --help' in a terminal for the command line."
} else {
    Write-Host "Run 'warden gui' to open the dashboard, or 'warden --help' for the command line."
}
