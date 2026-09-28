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
$base = "https://github.com/$repo/releases/latest/download"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N') + '.exe')

Write-Host "Downloading $asset from the latest release..."
Invoke-WebRequest -Uri "$base/$asset" -OutFile $tmp -UseBasicParsing

# Verify against the published SHA256SUMS before installing.
try {
    $sums = (Invoke-WebRequest -Uri "$base/SHA256SUMS" -UseBasicParsing).Content
    $line = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($asset) } | Select-Object -First 1)
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLower()
    if (-not $expected) {
        Write-Warning "No checksum listed for $asset; proceeding unverified."
    } elseif ($expected -ne $actual) {
        Remove-Item $tmp -Force
        throw "Checksum verification FAILED for $asset (expected $expected, got $actual)."
    } else {
        Write-Host "Checksum verified."
    }
} catch [System.Net.WebException] {
    Write-Warning "Could not fetch SHA256SUMS; proceeding unverified."
}

Move-Item -Force $tmp $exe

# Add to the user PATH if it's not already there.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not ($userPath -split ';' | Where-Object { $_ -eq $dir })) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    Write-Host "Added $dir to your user PATH. Restart your terminal to pick it up."
}

# Create double-clickable "Warden" shortcuts (Desktop + Start Menu) that open
# the dashboard, using the exe's own shield icon. This is the thing a
# non-technical user clicks - no terminal required.
function New-WardenShortcut([string] $LinkPath) {
    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($LinkPath)
    $sc.TargetPath = $exe
    $sc.Arguments = 'gui'
    $sc.WorkingDirectory = $dir
    $sc.IconLocation = "$exe,0"
    $sc.Description = 'Open the Warden malware scanner dashboard'
    $sc.WindowStyle = 7          # start the console minimized (less scary)
    $sc.Save()
}
try {
    $startMenu = [Environment]::GetFolderPath('Programs')
    $desktop = [Environment]::GetFolderPath('Desktop')
    New-WardenShortcut (Join-Path $startMenu 'Warden.lnk')
    New-WardenShortcut (Join-Path $desktop 'Warden.lnk')
    Write-Host "Created a 'Warden' icon on your Desktop and in the Start Menu."
} catch {
    Write-Warning "Could not create shortcuts: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Installed Warden to $exe"
& $exe version
Write-Host ""
Write-Host "Double-click the 'Warden' icon on your Desktop to open the dashboard,"
Write-Host "or run 'warden --help' in a terminal for the command line."
